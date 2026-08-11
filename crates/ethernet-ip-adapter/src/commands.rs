//! # The southbound command surface (§7) — the nine `sb/*` verbs + the three edge-console panels
//!
//! This module owns the whole `gg.commands()` registration: `sb/status`, `sb/read`, `sb/write`,
//! `sb/signals`, `sb/browse`, `sb/pause`, `sb/resume`, `reconnect`, `repoll` — mode-aware (poll vs
//! push), each declaring [`CommandScope::Instance`] (D-EIP-26 / SOUTHBOUND §2.2: the library owns
//! addressing — the topic token, `body.instance`, and the conflict refusal — and hands the handler
//! the resolved instance; [`Commander::resolve`] then applies only the adapter-side policies of
//! D-EIP-13: the sole **running** device when none is addressed — `BAD_ARGS` with several running,
//! `DEVICE_UNAVAILABLE` with none — and `NO_SUCH_INSTANCE` when the addressed id is not running)
//! and the §7.1 error codes
//! (`BAD_ARGS`, `NO_SUCH_INSTANCE`, `WRITE_NOT_ALLOWED`, `WRITE_FAILED`, `DEVICE_UNAVAILABLE`,
//! `READ_FAILED`, `RECONNECT_FAILED`, `BROWSE_UNSUPPORTED`, `BROWSE_FAILED`, `PAUSED`).
//!
//! The inbox handlers never touch the (non-`Sync`) session directly: every session-touching verb is
//! sent to the device's own task as a [`DeviceControl`] and *confirmed* through the reply that rides
//! it. The security-critical guarantee lives here: for `sb/write` the **allow-list check happens
//! BEFORE any device I/O** — a refused entry never becomes a [`DeviceControl::Write`]/`WriteOutput`.
//!
//! Three panels (§7.6) are registered via `commands.register_panel` for the edge-console descriptor
//! surface — `overview`, `signals`, `diagnostics`, each `scope: "instance"` with `order` 10/20/30.
//!
//! ## The surface is registered once and routes dynamically (D-EIP-28)
//!
//! Verbs and panels are registered exactly once, at startup. Routing is therefore resolved per
//! request against the live [`crate::lifecycle::DeviceRegistry`] rather than a startup snapshot, so a
//! configuration change that starts, stops, or restarts instances is answered truthfully by the same
//! registrations: an instance the current configuration no longer runs is `NO_SUCH_INSTANCE`, a newly
//! started one routes the moment it is inserted, and the effective `component.global` behind
//! `sb/signals` is the running generation's. A request that reaches an instance while it is being
//! replaced finds a closed control channel and is answered `DEVICE_UNAVAILABLE`.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use edgecommons::commands::{command_handler, AVAILABILITY_AVAILABLE, AVAILABILITY_UNSUPPORTED};
use edgecommons::prelude::{CommandError, CommandInbox, CommandScope, Severity};
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::app::{BrowseError, DeviceControl, EventSink, Health, LinkState, WriteRequest};
use crate::config::{
    DeviceConfig, DeviceMode, EipType, IoConfig, IoFieldSpec, SignalSpec, MAX_ARRAY_COUNT,
};
use crate::device::{BrowsePage, Quality, Reading};
use crate::lifecycle::{DeviceRegistry, SoleHandle};
use crate::metrics::{CommandTally, DeviceMetrics};

/// The per-device handles the command surface needs: the config (routing, allow-list, address view),
/// the control channel (session-touching verbs), the shared health (status/paused), the metrics
/// emitter (command counters + status snapshot), and the event sink (`write-audit`, §6.3).
#[derive(Clone)]
pub struct DeviceHandle {
    pub cfg: DeviceConfig,
    pub control: tokio::sync::mpsc::Sender<DeviceControl>,
    pub health: Arc<Health>,
    pub dm: Arc<DeviceMetrics>,
    pub events: Arc<dyn EventSink>,
}

/// Register all nine `sb/*` verbs (§7) + the three edge-console panels (§7.6) on the inbox.
///
/// Every verb declares [`CommandScope::Instance`] (D-SC-2 / D-EIP-26): each acts on exactly one
/// device, so the inbox enforces the addressing before dispatch — refusing a `body.instance` that
/// conflicts with the topic's instance token with `BAD_ARGS` — and hands the handler the resolved
/// instance (the topic token, else the body-named one, else `None`).
///
/// Registration happens **once**; the handlers close over the `registry`, so they keep routing
/// correctly across a configuration change that starts, stops, or restarts instances (D-EIP-28).
///
/// When every device the registry runs is in push mode, `repoll` is marked `unsupported` in
/// `describe` via `set_command_availability` (D-EIP-25): the verb is mode-conditional and no
/// instance can service it in an all-push configuration. The verb stays registered — an addressed
/// request still gets its per-instance `BAD_ARGS` refusal (§7.5). The same
/// [`repoll_availability`] rule is re-applied whenever the running set changes, so the describe
/// entry follows the configuration.
///
/// # Errors
/// Propagates [`CommandInbox::register`] / [`CommandInbox::register_panel`] /
/// [`CommandInbox::set_command_availability`] failures (a verb/panel name clash or an invalid
/// token).
pub fn register_all(commands: &CommandInbox, registry: Arc<DeviceRegistry>) -> anyhow::Result<()> {
    let all_push = registry.all_push();
    let commander = Arc::new(Commander::new(registry));

    macro_rules! verb {
        ($name:expr, $method:ident) => {{
            let c = Arc::clone(&commander);
            commands.register(
                $name,
                CommandScope::Instance,
                command_handler(move |req, addressed| {
                    let c = Arc::clone(&c);
                    async move { c.$method(addressed.as_deref(), &req.body).await }
                }),
            )?;
        }};
    }

    verb!("sb/status", status);
    verb!("sb/read", read);
    verb!("sb/write", write);
    verb!("sb/signals", signals);
    verb!("sb/browse", browse);
    verb!("sb/resume", resume);
    verb!("reconnect", reconnect);
    verb!("repoll", repoll);

    // `sb/pause` additionally carries the requester identity path (the `by` field of the
    // `adapter-paused` event, §6.3).
    {
        let c = Arc::clone(&commander);
        commands.register(
            "sb/pause",
            CommandScope::Instance,
            command_handler(move |req, addressed| {
                let c = Arc::clone(&c);
                async move {
                    let by = req.identity.as_ref().map(|i| i.path().to_string());
                    c.pause(addressed.as_deref(), &req.body, by).await
                }
            }),
        )?;
    }

    let (state, reason) = repoll_availability(all_push);
    commands.set_command_availability("repoll", state, reason)?;

    for panel in panels() {
        commands.register_panel(panel)?;
    }
    Ok(())
}

/// The `repoll` describe availability for a running set (D-EIP-25), as the
/// `(state, reason)` pair [`CommandInbox::set_command_availability`] takes.
///
/// `repoll` is mode-conditional: when every running instance is push mode (class-1 cyclic I/O) no
/// instance can service it, so `describe` reports it `unsupported` with the reason. Otherwise it is
/// `available`, which clears any stored describe entry — which is what makes the rule
/// re-appliable: a configuration change that adds the first poll instance to an all-push adapter
/// restores the verb, and one that removes the last poll instance marks it unsupported again.
///
/// One rule, one home: both the registration site and the configuration-change path call it.
#[must_use]
pub fn repoll_availability(all_push: bool) -> (&'static str, Option<&'static str>) {
    if all_push {
        (
            AVAILABILITY_UNSUPPORTED,
            Some("all configured instances are push-mode (class-1 cyclic I/O); repoll applies to poll instances"),
        )
    } else {
        (AVAILABILITY_AVAILABLE, None)
    }
}

/// The three edge-console panel descriptors (§7.6). Core validates `id`/`title`/uniqueness; the rest
/// is console-interpreted (the PHASE3-DESCRIPTOR-PANELS contract), so the widget kinds and bound
/// verbs ride verbatim. `order` 10/20/30 and `scope: "instance"` per the spec — repeated on each
/// command-backed widget, which the console renderer requires. No widget names a `writeVerb`:
/// writes stay on the command surface behind the allow-list.
#[must_use]
pub fn panels() -> Vec<Value> {
    vec![
        json!({
            "id": "overview", "title": "Overview", "order": 10, "scope": "instance",
            "widgets": [
                {
                    "kind": "summary", "id": "overview-summary", "title": "Adapter overview",
                    "rows": [
                        { "label": "Status", "value": "Connected / state / paused / endpoint via cmd/sb/status" },
                        { "label": "Lifecycle", "value": "Pause, resume, reconnect, and repoll the instance" },
                        { "label": "Writes", "value": "Allow-listed via writes.allow[]; checked before device I/O" }
                    ]
                },
                {
                    "kind": "commandSummary", "id": "overview-lifecycle", "title": "Lifecycle bindings",
                    "verbs": ["sb/status", "sb/pause", "sb/resume", "reconnect"]
                }
            ],
            "verbs": ["sb/status", "sb/pause", "sb/resume", "reconnect"]
        }),
        // Descriptor-compat hint: the shipped edge-console signalGrid reads `subscriptionsVerb`
        // (falling back to the removed `sb/subscriptions`). Point that key at the `sb/signals` verb
        // too, so the current console binds correctly until it reads `signalsVerb`. This is a
        // descriptor field alias, NOT a wire-verb alias — no `sb/subscriptions` verb exists.
        json!({
            "id": "signals", "title": "Signals", "order": 20, "scope": "instance",
            "widgets": [
                {
                    "kind": "signalGrid", "id": "configured-signals", "title": "Configured signals",
                    "scope": "instance",
                    "signalsVerb": "sb/signals",
                    "subscriptionsVerb": "sb/signals",
                    "readVerb": "sb/read"
                }
            ],
            "verbs": ["sb/signals", "sb/read", "sb/write", "repoll"]
        }),
        json!({
            "id": "diagnostics", "title": "Diagnostics", "order": 30, "scope": "instance",
            "widgets": [
                {
                    "kind": "treeBrowser", "id": "tag-space", "title": "Device tag space",
                    "scope": "instance", "mode": "hierarchical", "rootRef": "root",
                    "depth": 1, "maxRefs": 200,
                    "browseVerb": "sb/browse", "readVerb": "sb/read"
                },
                {
                    "kind": "keyValueList", "id": "diagnostic-counters", "title": "Diagnostics",
                    "rows": [
                        { "label": "Counters", "value": "Read/write/error tallies via cmd/sb/status `metrics`" },
                        { "label": "Security", "value": "Session posture via cmd/sb/status `security`" }
                    ]
                }
            ],
            "verbs": ["sb/browse", "sb/status"]
        }),
    ]
}

/// The command dispatcher. It holds **no** per-generation state: every request resolves against the
/// live [`DeviceRegistry`] — the running instances in configuration order (the single-instance
/// default depends on that order) and the running `component.global` (effective poll/publish
/// resolution for `sb/signals`).
pub struct Commander {
    registry: Arc<DeviceRegistry>,
}

type Reply = std::result::Result<Option<Value>, CommandError>;

/// The cap on how many pages the hierarchical browse follows before giving up (§7.5).
///
/// The hierarchical mode is the one browse form the adapter drives to completion, so a backend that
/// keeps issuing fresh, strictly-advancing cursors would otherwise hold a command handler open
/// forever. 1024 pages of up to 1000 records is far past any real controller's symbol table, so
/// hitting it means the backend is misbehaving — answered as `BROWSE_FAILED`, not as a hang.
const MAX_BROWSE_PAGES: usize = 1024;

impl Commander {
    fn new(registry: Arc<DeviceRegistry>) -> Self {
        Self { registry }
    }

    /// Route to the addressed device — the adapter-side half of the resolution (D-SC-4, D-EIP-13).
    ///
    /// The library has already resolved the addressing (the delivery topic's instance token, else
    /// the body's `instance` field) and refused any conflict between the two; what needs this
    /// adapter's configuration stays here: an unaddressed request routes to the sole running device
    /// (`BAD_ARGS` otherwise), and an addressed instance that is not running is `NO_SUCH_INSTANCE`.
    ///
    /// The lookup reads the registry per request, so it follows the running configuration rather
    /// than a startup snapshot (D-EIP-28), and it hands back an owned handle so no registry lock is
    /// held across the verb's `.await`s — the alternative (a lock held across device I/O) would
    /// serialize the whole surface behind one instance.
    ///
    /// It resolves through the registry's targeted accessors, so a request clones exactly the one
    /// [`DeviceHandle`] that answers it (each carries a full `DeviceConfig`) instead of the whole
    /// routing snapshot: [`DeviceRegistry::handle`] for an addressed instance,
    /// [`DeviceRegistry::sole_handle`] for the unaddressed default, both a single locked scan.
    fn resolve(&self, addressed: Option<&str>) -> std::result::Result<DeviceHandle, CommandError> {
        match addressed {
            Some(id) => self.registry.handle(id).ok_or_else(|| {
                CommandError::new("NO_SUCH_INSTANCE", format!("no configured device `{id}`"))
            }),
            // Exactly one running instance answers an unaddressed request.
            None => match self.registry.sole_handle() {
                SoleHandle::One(h) => Ok(h),
                // No instance is running: the registry is empty for the length of the stop stage of
                // a configuration change that restarts every instance. Addressing one would only
                // earn a `NO_SUCH_INSTANCE`, so say what is actually true instead of asking for an
                // address.
                SoleHandle::None => Err(CommandError::new(
                    "DEVICE_UNAVAILABLE",
                    "no device is running; a configuration change is being applied",
                )),
                SoleHandle::Many => Err(CommandError::new(
                    "BAD_ARGS",
                    "the request must address an instance when multiple devices are configured",
                )),
            },
        }
    }

    // ---------------------------------------------------------------------------------------------
    // sb/status (§7.1)
    // ---------------------------------------------------------------------------------------------
    async fn status(&self, addressed: Option<&str>, _body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let link = h.health.link();
        let connected = link == LinkState::Online;
        let paused = h.health.paused.load(Ordering::Relaxed);
        let state = if paused && connected {
            "PAUSED"
        } else {
            link.as_str()
        };
        let mut out = serde_json::Map::new();
        out.insert("id".into(), json!(h.cfg.id));
        out.insert("mode".into(), json!(h.cfg.mode.as_str()));
        out.insert("connected".into(), json!(connected));
        out.insert("state".into(), json!(state));
        out.insert("paused".into(), json!(paused));
        out.insert("endpoint".into(), json!(h.cfg.connection.endpoint));
        out.insert("adapter".into(), json!(h.cfg.adapter));
        out.insert("metrics".into(), h.dm.counters_view());
        // CIP Security posture (DESIGN-cip-security.md §3.4): always present so a console can render
        // the security column unconditionally (`{"mode":"plaintext"}` on a plaintext instance).
        out.insert("security".into(), h.dm.security_view());
        if matches!(h.cfg.mode, DeviceMode::Push) {
            out.insert("io".into(), h.dm.io_view());
        }
        h.dm.record_command("sb/status", true, ms(started), CommandTally::default());
        Ok(Some(Value::Object(out)))
    }

    // ---------------------------------------------------------------------------------------------
    // sb/read (§7.2) — poll = live read via ReadNow; push = the last input snapshot
    // ---------------------------------------------------------------------------------------------
    async fn read(&self, addressed: Option<&str>, body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let refs = body
            .get("signals")
            .and_then(|v| v.as_array())
            .ok_or_else(|| CommandError::new("BAD_ARGS", "expected a `signals` array"))?;
        let result = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.read_push(&h, refs).await
        } else {
            self.read_poll(&h, refs).await
        };
        let (ok, served) = match &result {
            Ok((_, n)) => (true, *n),
            Err(_) => (false, 0),
        };
        h.dm.record_command(
            "sb/read",
            ok,
            ms(started),
            CommandTally {
                read_signals: served,
                ..CommandTally::default()
            },
        );
        result.map(|(v, _)| Some(v))
    }

    async fn read_poll(
        &self,
        h: &DeviceHandle,
        refs: &[Value],
    ) -> std::result::Result<(Value, u64), CommandError> {
        // Resolve each ref: a friendly name → the configured spec; an explicit {tagPath,type} → a
        // synthesized spec; anything else → a BAD "UNRESOLVED_REF" entry. A malformed argument
        // (`arrayCount` outside the wire bound) refuses the whole command instead (D-EIP-33).
        let mut plan: Vec<std::result::Result<SignalSpec, String>> = Vec::with_capacity(refs.len());
        let mut specs: Vec<SignalSpec> = Vec::new();
        for r in refs {
            match resolve_poll_ref(&h.cfg, r) {
                Ok(spec) => {
                    specs.push(spec.clone());
                    plan.push(Ok(spec));
                }
                Err(PollRefError::Unresolved(label)) => plan.push(Err(label)),
                Err(PollRefError::BadArgs(m)) => return Err(CommandError::new("BAD_ARGS", m)),
            }
        }

        // A live read of the resolvable refs, serialized on the device task (works while paused, §7.2).
        let readings: HashMap<String, Reading> = if specs.is_empty() {
            HashMap::new()
        } else {
            let (tx, rx) = oneshot::channel();
            h.control
                .send(DeviceControl::ReadNow { specs, reply: tx })
                .await
                .map_err(|_| device_unavailable())?;
            match rx.await {
                Ok(Ok(rs)) => rs.into_iter().map(|r| (r.signal_id.clone(), r)).collect(),
                Ok(Err(e)) => return Err(CommandError::new("READ_FAILED", e)),
                Err(_) => return Err(device_unavailable()),
            }
        };

        // Capture time (four-slot timestamp model): stamped at read completion, before reply assembly.
        let ts = crate::publish::now_iso();
        let mut reads = Vec::with_capacity(plan.len());
        let mut served = 0u64;
        for entry in plan {
            match entry {
                Ok(spec) => match readings.get(&spec.tag_path) {
                    Some(r) => {
                        served += 1;
                        reads.push(json!({
                            "signal": { "id": spec.tag_path, "address": spec.address_json(&h.cfg.connection) },
                            "value": r.value,
                            "quality": quality_str(r.quality),
                            "qualityRaw": r.quality_raw,
                            "serverTs": ts,
                        }));
                    }
                    None => reads.push(bad_read(&spec.tag_path, "NO_DATA")),
                },
                Err(label) => reads.push(bad_read(&label, "UNRESOLVED_REF")),
            }
        }
        Ok((json!({ "id": h.cfg.id, "reads": reads }), served))
    }

    async fn read_push(
        &self,
        h: &DeviceHandle,
        refs: &[Value],
    ) -> std::result::Result<(Value, u64), CommandError> {
        let io = h
            .cfg
            .io
            .as_ref()
            .ok_or_else(|| CommandError::new("BAD_ARGS", "push device missing io block"))?;
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Snapshot { reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let snapshot = rx.await.map_err(|_| device_unavailable())?;

        let by_id: HashMap<&str, &Reading> = snapshot
            .as_ref()
            .map(|s| {
                s.readings
                    .iter()
                    .map(|r| (r.signal_id.as_str(), r))
                    .collect()
            })
            .unwrap_or_default();
        // Capture time (four-slot timestamp model): the snapshot frame's receipt instant.
        let ts = snapshot
            .as_ref()
            .map(|s| crate::publish::iso_at(s.received_at))
            .unwrap_or_else(crate::publish::now_iso);

        let mut reads = Vec::with_capacity(refs.len());
        let mut served = 0u64;
        for r in refs {
            match resolve_push_read_ref(io, &h.cfg.connection, r) {
                Some((id, address)) => {
                    if let Some(rd) = by_id.get(id.as_str()) {
                        served += 1;
                        reads.push(json!({
                            "signal": { "id": id, "address": address },
                            "value": rd.value,
                            "quality": quality_str(rd.quality),
                            "qualityRaw": rd.quality_raw,
                            "serverTs": ts,
                        }));
                    } else {
                        // Connection down / no frame yet (§7.2).
                        reads.push(json!({
                            "signal": { "id": id, "address": address },
                            "value": Value::Null, "quality": "BAD", "qualityRaw": "NO_FRAME",
                        }));
                    }
                }
                None => reads.push(bad_read(&ref_label(r), "UNRESOLVED_REF")),
            }
        }
        Ok((json!({ "id": h.cfg.id, "reads": reads }), served))
    }

    // ---------------------------------------------------------------------------------------------
    // sb/write (§7.3) — allow-list BEFORE any device I/O; confirmed; every entry audited on evt
    // ---------------------------------------------------------------------------------------------
    async fn write(&self, addressed: Option<&str>, body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let entries = write_entries(body)?;
        let result = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.write_push(&h, &entries).await
        } else {
            self.write_poll(&h, &entries).await
        };
        let (ok, attempted, failures) = match &result {
            Ok((_, tally)) => (true, tally.write_signals, tally.write_failures),
            Err(_) => (false, entries.len() as u64, entries.len() as u64),
        };
        h.dm.record_command(
            "sb/write",
            ok,
            ms(started),
            CommandTally {
                write_signals: attempted,
                write_failures: failures,
                ..CommandTally::default()
            },
        );
        result.map(|(v, _)| Some(v))
    }

    async fn write_poll(
        &self,
        h: &DeviceHandle,
        entries: &[Value],
    ) -> std::result::Result<(Value, CommandTally), CommandError> {
        let mut results = Vec::with_capacity(entries.len());
        let mut written = 0u64;
        let mut refused = 0u64;
        let mut failures = 0u64;
        let attempted = entries.len() as u64;

        for entry in entries {
            let value = entry.get("value").cloned();
            match resolve_poll_ref(&h.cfg, entry) {
                Ok(spec) => {
                    let id = spec.tag_path.clone();
                    // THE ALLOW-LIST — checked here, BEFORE the write ever reaches the device. An
                    // adapter that writes whatever it is asked to is a control-system vulnerability.
                    if !h.cfg.writes.permits(&id) {
                        refused += 1;
                        failures += 1;
                        self.audit(h, &id, false, value.as_ref(), Some("not in writes.allow"))
                            .await;
                        results.push(
                            json!({ "signal": id, "ok": false, "error": "not in writes.allow" }),
                        );
                        continue;
                    }
                    let Some(value) = value else {
                        failures += 1;
                        self.audit(h, &id, false, None, Some("missing value")).await;
                        results
                            .push(json!({ "signal": id, "ok": false, "error": "missing value" }));
                        continue;
                    };
                    let (tx, rx) = oneshot::channel();
                    h.control
                        .send(DeviceControl::Write(WriteRequest {
                            signal: spec,
                            value: value.clone(),
                            ack: tx,
                        }))
                        .await
                        .map_err(|_| device_unavailable())?;
                    match rx.await {
                        Ok(Ok(())) => {
                            written += 1;
                            self.audit(h, &id, true, Some(&value), None).await;
                            results.push(json!({ "signal": id, "value": value, "ok": true }));
                        }
                        Ok(Err(e)) => {
                            failures += 1;
                            self.audit(h, &id, false, Some(&value), Some(&e)).await;
                            results.push(
                                json!({ "signal": id, "value": value, "ok": false, "error": e }),
                            );
                        }
                        Err(_) => return Err(device_unavailable()),
                    }
                }
                Err(PollRefError::Unresolved(label)) => {
                    failures += 1;
                    self.audit(h, &label, false, value.as_ref(), Some("unresolved ref"))
                        .await;
                    results
                        .push(json!({ "signal": label, "ok": false, "error": "unresolved ref" }));
                }
                // A malformed argument is refused whole — an out-of-bound `arrayCount` never
                // reaches the device, and no partial batch is written under it (D-EIP-33).
                Err(PollRefError::BadArgs(m)) => return Err(CommandError::new("BAD_ARGS", m)),
            }
        }

        // WRITE_NOT_ALLOWED only when EVERY entry was an allow-list refusal (§7.3).
        if attempted > 0 && refused == attempted {
            return Err(CommandError::new(
                "WRITE_NOT_ALLOWED",
                "no entry is in this instance's writes.allow list",
            ));
        }
        Ok((
            json!({ "id": h.cfg.id, "written": written, "results": results }),
            CommandTally {
                write_signals: attempted,
                write_failures: failures,
                ..CommandTally::default()
            },
        ))
    }

    async fn write_push(
        &self,
        h: &DeviceHandle,
        entries: &[Value],
    ) -> std::result::Result<(Value, CommandTally), CommandError> {
        let io = h
            .cfg
            .io
            .as_ref()
            .ok_or_else(|| CommandError::new("BAD_ARGS", "push device missing io block"))?;
        let mut results = Vec::with_capacity(entries.len());
        let mut written = 0u64;
        let mut refused = 0u64;
        let mut failures = 0u64;
        let attempted = entries.len() as u64;

        for entry in entries {
            let value = entry.get("value").cloned();
            match resolve_push_write_ref(io, entry) {
                Ok((id, field)) => {
                    if !h.cfg.writes.permits(&id) {
                        refused += 1;
                        failures += 1;
                        self.audit(h, &id, false, value.as_ref(), Some("not in writes.allow"))
                            .await;
                        results.push(
                            json!({ "signal": id, "ok": false, "error": "not in writes.allow" }),
                        );
                        continue;
                    }
                    let Some(value) = value else {
                        failures += 1;
                        self.audit(h, &id, false, None, Some("missing value")).await;
                        results
                            .push(json!({ "signal": id, "ok": false, "error": "missing value" }));
                        continue;
                    };
                    let (tx, rx) = oneshot::channel();
                    h.control
                        .send(DeviceControl::WriteOutput {
                            field,
                            value: value.clone(),
                            reply: tx,
                        })
                        .await
                        .map_err(|_| device_unavailable())?;
                    match rx.await {
                        Ok(Ok(())) => {
                            written += 1;
                            self.audit(h, &id, true, Some(&value), None).await;
                            // Confirmation honesty (§7.3): a push write is staged into the O→T buffer
                            // and rides every subsequent cyclic frame — `applied: "next-frame"`.
                            results.push(json!({ "signal": id, "value": value, "ok": true, "applied": "next-frame" }));
                        }
                        Ok(Err(e)) => {
                            failures += 1;
                            self.audit(h, &id, false, Some(&value), Some(&e)).await;
                            results.push(
                                json!({ "signal": id, "value": value, "ok": false, "error": e }),
                            );
                        }
                        Err(_) => return Err(device_unavailable()),
                    }
                }
                Err((label, err)) => {
                    failures += 1;
                    self.audit(h, &label, false, value.as_ref(), Some(&err))
                        .await;
                    results.push(json!({ "signal": label, "ok": false, "error": err }));
                }
            }
        }

        if attempted > 0 && refused == attempted {
            return Err(CommandError::new(
                "WRITE_NOT_ALLOWED",
                "no entry is in this instance's writes.allow list",
            ));
        }
        Ok((
            json!({ "id": h.cfg.id, "written": written, "results": results }),
            CommandTally {
                write_signals: attempted,
                write_failures: failures,
                ..CommandTally::default()
            },
        ))
    }

    /// The `write-audit` event for one `sb/write` entry (§6.3) — Info on success, Warning on failure
    /// or allow-list refusal.
    async fn audit(
        &self,
        h: &DeviceHandle,
        signal_id: &str,
        ok: bool,
        value: Option<&Value>,
        error: Option<&str>,
    ) {
        let severity = if ok {
            Severity::Info
        } else {
            Severity::Warning
        };
        let mut ctx = serde_json::Map::new();
        ctx.insert("instance".into(), json!(h.cfg.id));
        ctx.insert("signalId".into(), json!(signal_id));
        ctx.insert("ok".into(), json!(ok));
        if let Some(v) = value {
            ctx.insert("value".into(), v.clone());
        }
        if let Some(e) = error {
            ctx.insert("error".into(), json!(e));
        }
        h.events
            .emit(severity, "write-audit", None, Some(Value::Object(ctx)))
            .await;
    }

    // ---------------------------------------------------------------------------------------------
    // sb/signals (§7.5) — the resolved config view, no device I/O
    // ---------------------------------------------------------------------------------------------
    async fn signals(&self, addressed: Option<&str>, _body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let out = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.signals_push(&h)
        } else {
            self.signals_poll(&h)
        };
        h.dm.record_command("sb/signals", true, ms(started), CommandTally::default());
        Ok(Some(out))
    }

    fn signals_poll(&self, h: &DeviceHandle) -> Value {
        // The RUNNING generation's global, not a startup snapshot: after a configuration change the
        // resolved cadence/publish mode this reports is the one the poll engine is actually using.
        let global = self.registry.global();
        let mut signals = Vec::new();
        for g in &h.cfg.poll_groups {
            let group = g.id.clone().unwrap_or_default();
            let interval = h.cfg.effective_poll_ms(g, &global);
            let mode = h.cfg.effective_publish_mode(g, &global).as_str();
            for s in &g.signals {
                let mut entry = json!({
                    "name": s.name,
                    "id": s.tag_path,
                    "address": s.address_json(&h.cfg.connection),
                    "pollGroup": group,
                    "pollIntervalMs": interval,
                    "publishMode": mode,
                    "writable": h.cfg.writes.permits(&s.tag_path),
                    "deadband": deadband_json(&s.deadband),
                });
                // The **observed** wire representation (D-EIP-35): what the device declared on this
                // signal's last reply, beside the `address.type` the operator configured. It is a
                // device property, so it is absent until first contact rather than defaulted to the
                // configured type — an empty field says "not yet read", which is a different fact
                // from "reads as configured".
                if let (Some(observed), Some(obj)) =
                    (h.health.observed_type(&s.tag_path), entry.as_object_mut())
                {
                    obj.insert("observedType".to_string(), json!(observed));
                }
                signals.push(entry);
            }
        }
        json!({ "id": h.cfg.id, "mode": "poll", "signals": signals })
    }

    fn signals_push(&self, h: &DeviceHandle) -> Value {
        let global = self.registry.global();
        let mut signals = Vec::new();
        let mode = h
            .cfg
            .defaults
            .publish_mode
            .or(global.defaults.publish_mode)
            .unwrap_or(crate::config::PublishMode::OnChange)
            .as_str();
        if let Some(io) = h.cfg.io.as_ref() {
            let in_asm = io.assemblies.input;
            for f in &io.input.signals {
                signals.push(field_signal(
                    f,
                    in_asm,
                    "input",
                    mode,
                    &h.cfg,
                    &h.cfg.connection,
                ));
            }
            let out_asm = io.assemblies.output;
            if let Some(out) = io.output.as_ref() {
                for f in &out.signals {
                    signals.push(field_signal(
                        f,
                        out_asm,
                        "output",
                        mode,
                        &h.cfg,
                        &h.cfg.connection,
                    ));
                }
            }
        }
        json!({ "id": h.cfg.id, "mode": "push", "signals": signals })
    }

    // ---------------------------------------------------------------------------------------------
    // sb/browse (§7.5) — poll = paged list_tags; push = the configured assembly layout, paged the
    // same way. `ref` additionally selects the hierarchical `treeBrowser` panel mode over the same
    // inventory.
    // ---------------------------------------------------------------------------------------------
    async fn browse(&self, addressed: Option<&str>, body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        // The two request forms are mutually exclusive: `ref`/`depth`/`maxRefs` select the
        // hierarchical panel mode, `cursor`/`max` the paged one — and the hierarchical-only
        // arguments are meaningless without a `ref`.
        let hierarchical_keys = ["ref", "depth", "maxRefs"]
            .iter()
            .any(|k| body.get(*k).is_some());
        let paged_keys = ["cursor", "max"].iter().any(|k| body.get(*k).is_some());
        if hierarchical_keys && paged_keys {
            h.dm.record_command("sb/browse", false, ms(started), CommandTally::default());
            return Err(CommandError::new(
                "BAD_ARGS",
                "`ref`/`depth`/`maxRefs` (hierarchical) and `cursor`/`max` (paged) are mutually exclusive",
            ));
        }
        if hierarchical_keys && body.get("ref").is_none() {
            h.dm.record_command("sb/browse", false, ms(started), CommandTally::default());
            return Err(CommandError::new(
                "BAD_ARGS",
                "`depth`/`maxRefs` are hierarchical-mode arguments and require `ref`",
            ));
        }
        if body.get("ref").is_some() {
            let result = self.browse_hierarchical(&h, body).await;
            let (ok, browsed) = match &result {
                Ok(Some(v)) => (true, v.get("refCount").and_then(Value::as_u64).unwrap_or(0)),
                _ => (false, 0),
            };
            h.dm.record_command(
                "sb/browse",
                ok,
                ms(started),
                CommandTally {
                    browsed_tags: browsed,
                    ..CommandTally::default()
                },
            );
            return result;
        }
        let cursor = body
            .get("cursor")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let max = body
            .get("max")
            .and_then(|v| v.as_u64())
            .unwrap_or(200)
            .clamp(1, 1000) as usize;

        let result: std::result::Result<Value, CommandError> =
            if matches!(h.cfg.mode, DeviceMode::Push) {
                browse_push_layout(&h, cursor.as_deref(), max)
            } else {
                let (tx, rx) = oneshot::channel();
                h.control
                    .send(DeviceControl::Browse {
                        cursor,
                        max,
                        reply: tx,
                    })
                    .await
                    .map_err(|_| device_unavailable())?;
                match rx.await {
                    Ok(Ok(page)) => Ok(browse_page_json(&h, page)),
                    Ok(Err(BrowseError::Unsupported)) => Err(CommandError::new(
                        "BROWSE_UNSUPPORTED",
                        "device has no tag-list service",
                    )),
                    Ok(Err(BrowseError::Failed(e))) => Err(CommandError::new("BROWSE_FAILED", e)),
                    Err(_) => Err(device_unavailable()),
                }
            };

        let (ok, browsed) = match &result {
            Ok(v) => (
                true,
                v.get("tags").and_then(|t| t.as_array()).map_or(0, Vec::len) as u64,
            ),
            Err(_) => (false, 0),
        };
        h.dm.record_command(
            "sb/browse",
            ok,
            ms(started),
            CommandTally {
                browsed_tags: browsed,
                ..CommandTally::default()
            },
        );
        result.map(Some)
    }

    /// The `treeBrowser` panel mode of `sb/browse` (§7.5): `ref` names a node in the **same**
    /// inventory the paged mode serves — the device tag list (poll) or the configured assembly
    /// layout (push). `"root"` is the device node, whose `contains` refs are the inventory (bounded
    /// by `maxRefs`); a tag/field id is a known leaf (`"refs": []`); an unknown ref is `BAD_ARGS`.
    /// `depth` and `maxRefs` are clamped to 1..4 / 1..1000 (the same convention as the paged `max`);
    /// the tag inventory is flat, so a deeper `depth` finds no grandchildren — it is still validated
    /// and echoed.
    ///
    /// Poll mode collects the whole tag list by following the backend's cursors, so this is the one
    /// browse form whose termination depends on the backend. Two guards make that termination the
    /// adapter's own property rather than the device's: a cursor that does not advance past the one
    /// already followed, and a walk that exceeds [`MAX_BROWSE_PAGES`], are both `BROWSE_FAILED`;
    /// so is a cursor that is not a number, which no backend of this adapter issues. They are
    /// defence in depth over the protocol crate's own ascending-order check — they also bound a
    /// misbehaving non-CIP backend — and they turn "the handler never returns" into a typed error.
    async fn browse_hierarchical(&self, h: &DeviceHandle, body: &Value) -> Reply {
        let Some(ref_id) = body
            .get("ref")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
        else {
            return Err(CommandError::new(
                "BAD_ARGS",
                "`ref` must be a non-empty string",
            ));
        };
        let depth = body
            .get("depth")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, 4);
        let max_refs = body
            .get("maxRefs")
            .and_then(Value::as_u64)
            .unwrap_or(200)
            .clamp(1, 1000) as usize;

        // One inventory source per mode — the same one the paged form serves. Each entry:
        // (nodeId, name, dataType, extra fields).
        let entries: Vec<(String, String, Value, serde_json::Map<String, Value>)> =
            if matches!(h.cfg.mode, DeviceMode::Push) {
                let mut out = Vec::new();
                if let Some(io) = h.cfg.io.as_ref() {
                    for f in &io.input.signals {
                        out.push(hier_entry(f, io.assemblies.input, "input"));
                    }
                    if let Some(o) = io.output.as_ref() {
                        for f in &o.signals {
                            out.push(hier_entry(f, io.assemblies.output, "output"));
                        }
                    }
                }
                out
            } else {
                // Collect the whole tag list through the same control channel the paged mode uses,
                // following its cursors — one source, both browse modes.
                let configured: std::collections::HashSet<String> =
                    h.cfg.signals().map(|s| s.tag_path.clone()).collect();
                let mut out = Vec::new();
                let mut cursor: Option<String> = None;
                // Anti-loop guards on a walk this adapter drives to completion (the paged form
                // returns after one page; this one keeps asking until the device says it is done).
                // `prev_start` is the last resume point followed, `pages` the request count.
                let mut prev_start: u64 = 0;
                let mut pages: usize = 0;
                loop {
                    pages += 1;
                    if pages > MAX_BROWSE_PAGES {
                        return Err(CommandError::new(
                            "BROWSE_FAILED",
                            "browse exceeded the page cap without completing",
                        ));
                    }
                    let (tx, rx) = oneshot::channel();
                    h.control
                        .send(DeviceControl::Browse {
                            cursor: cursor.clone(),
                            max: 1000,
                            reply: tx,
                        })
                        .await
                        .map_err(|_| device_unavailable())?;
                    let page = match rx.await {
                        Ok(Ok(page)) => page,
                        Ok(Err(BrowseError::Unsupported)) => {
                            return Err(CommandError::new(
                                "BROWSE_UNSUPPORTED",
                                "device has no tag-list service",
                            ));
                        }
                        Ok(Err(BrowseError::Failed(e))) => {
                            return Err(CommandError::new("BROWSE_FAILED", e))
                        }
                        Err(_) => return Err(device_unavailable()),
                    };
                    for t in &page.tags {
                        let mut extra = serde_json::Map::new();
                        extra.insert("configured".into(), json!(configured.contains(&t.name)));
                        extra.insert(
                            "supported".into(),
                            json!(tag_supported(&t.type_name, t.array_dim)),
                        );
                        if let Some(dim) = t.array_dim {
                            extra.insert("arrayDim".into(), json!(dim));
                        }
                        out.push((t.name.clone(), t.name.clone(), json!(t.type_name), extra));
                    }
                    if let Some(next) = &page.next_cursor {
                        let n: u64 = next.parse().map_err(|_| {
                            CommandError::new(
                                "BROWSE_FAILED",
                                format!("device returned a non-numeric browse cursor `{next}`"),
                            )
                        })?;
                        if n <= prev_start {
                            return Err(CommandError::new(
                                "BROWSE_FAILED",
                                "browse cursor did not advance",
                            ));
                        }
                        prev_start = n;
                        cursor = Some(next.clone());
                    } else {
                        break;
                    }
                }
                out
            };

        if ref_id == "root" {
            let truncated = entries.len() > max_refs;
            let refs: Vec<Value> = entries
                .into_iter()
                .take(max_refs)
                .map(|(id, name, data_type, extra)| {
                    let mut target = serde_json::Map::new();
                    target.insert("nodeId".into(), json!(id));
                    target.insert("name".into(), json!(name));
                    target.insert("nodeClass".into(), json!("signal"));
                    target.insert("dataType".into(), data_type);
                    target.extend(extra);
                    json!({ "referenceType": "contains", "target": Value::Object(target) })
                })
                .collect();
            let ref_count = refs.len();
            return Ok(Some(json!({
                "id": h.cfg.id,
                "mode": "hierarchical",
                "root": { "nodeId": "root", "name": h.cfg.id, "nodeClass": "device",
                          "dataType": Value::Null, "refs": refs },
                "refCount": ref_count,
                "depth": depth,
                "truncated": truncated
            })));
        }

        let Some((id, name, data_type, extra)) =
            entries.into_iter().find(|(id, _, _, _)| id == ref_id)
        else {
            return Err(CommandError::new(
                "BAD_ARGS",
                format!("unknown browse ref `{ref_id}`"),
            ));
        };
        let mut root = serde_json::Map::new();
        root.insert("nodeId".into(), json!(id));
        root.insert("name".into(), json!(name));
        root.insert("nodeClass".into(), json!("signal"));
        root.insert("dataType".into(), data_type);
        root.extend(extra);
        root.insert("refs".into(), json!([]));
        Ok(Some(json!({
            "id": h.cfg.id,
            "mode": "hierarchical",
            "root": Value::Object(root),
            "refCount": 0,
            "depth": depth,
            "truncated": false
        })))
    }

    // ---------------------------------------------------------------------------------------------
    // sb/pause + sb/resume (§7.4) — idempotent {paused, changed}, both modes
    // ---------------------------------------------------------------------------------------------
    async fn pause(&self, addressed: Option<&str>, _body: &Value, by: Option<String>) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Pause { by, reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let changed = rx.await.map_err(|_| device_unavailable())?;
        h.dm.record_command("sb/pause", true, ms(started), CommandTally::default());
        Ok(Some(
            json!({ "id": h.cfg.id, "paused": true, "changed": changed }),
        ))
    }

    async fn resume(&self, addressed: Option<&str>, _body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Resume { reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let changed = rx.await.map_err(|_| device_unavailable())?;
        h.dm.record_command("sb/resume", true, ms(started), CommandTally::default());
        Ok(Some(
            json!({ "id": h.cfg.id, "paused": false, "changed": changed }),
        ))
    }

    // ---------------------------------------------------------------------------------------------
    // reconnect (§7.5)
    // ---------------------------------------------------------------------------------------------
    async fn reconnect(&self, addressed: Option<&str>, _body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Reconnect { reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let result = rx.await.map_err(|_| device_unavailable())?;
        match result {
            Ok(()) => {
                h.dm.record_command("reconnect", true, ms(started), CommandTally::default());
                Ok(Some(json!({ "id": h.cfg.id, "connected": true })))
            }
            Err(e) => {
                h.dm.record_command("reconnect", false, ms(started), CommandTally::default());
                Err(CommandError::new("RECONNECT_FAILED", e))
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // repoll (§7.5) — poll only, refused on push (BAD_ARGS) and while paused (PAUSED)
    // ---------------------------------------------------------------------------------------------
    async fn repoll(&self, addressed: Option<&str>, _body: &Value) -> Reply {
        let h = self.resolve(addressed)?;
        let started = Instant::now();
        if matches!(h.cfg.mode, DeviceMode::Push) {
            h.dm.record_command("repoll", false, ms(started), CommandTally::default());
            return Err(CommandError::new(
                "BAD_ARGS",
                "push instance - data arrives cyclically",
            ));
        }
        if h.health.paused.load(Ordering::Relaxed) {
            h.dm.record_command("repoll", false, ms(started), CommandTally::default());
            return Err(CommandError::new(
                "PAUSED",
                "instance is paused - resume first",
            ));
        }
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Repoll { reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        match rx.await.map_err(|_| device_unavailable())? {
            Ok(polled) => {
                h.dm.record_command("repoll", true, ms(started), CommandTally::default());
                Ok(Some(json!({ "id": h.cfg.id, "polled": polled })))
            }
            Err(e) if e.contains("paused") => {
                h.dm.record_command("repoll", false, ms(started), CommandTally::default());
                Err(CommandError::new("PAUSED", e))
            }
            Err(e) => {
                h.dm.record_command("repoll", false, ms(started), CommandTally::default());
                Err(CommandError::new("DEVICE_UNAVAILABLE", e))
            }
        }
    }
}

// =================================================================================================
// Helpers
// =================================================================================================

fn ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn device_unavailable() -> CommandError {
    CommandError::new("DEVICE_UNAVAILABLE", "device task is unavailable")
}

/// The §5 quality token for a read entry.
fn quality_str(q: Quality) -> &'static str {
    match q {
        Quality::Good => "GOOD",
        Quality::Bad => "BAD",
        Quality::Uncertain => "UNCERTAIN",
    }
}

/// A BAD read entry with the given native code (§7.2 unresolved / no-data).
fn bad_read(id: &str, raw: &str) -> Value {
    json!({ "signal": { "id": id }, "value": Value::Null, "quality": "BAD", "qualityRaw": raw })
}

/// A short label for an unresolved ref (for the BAD entry / audit).
fn ref_label(r: &Value) -> String {
    if let Some(n) = r.get("name").and_then(|v| v.as_str()) {
        n.to_string()
    } else if let Some(t) = r.get("tagPath").and_then(|v| v.as_str()) {
        t.to_string()
    } else if let (Some(a), Some(o), Some(t)) = (
        r.get("assembly").and_then(|v| v.as_u64()),
        r.get("offset").and_then(|v| v.as_u64()),
        r.get("type").and_then(|v| v.as_str()),
    ) {
        format!("a{a}/{o}/{t}")
    } else {
        "<invalid ref>".to_string()
    }
}

/// Parse a `type` token (`"real"`, `"dint"`, …) to an [`EipType`] via the same lowercase mapping the
/// config uses.
fn parse_eip_type(s: &str) -> Option<EipType> {
    serde_json::from_value(Value::String(s.to_string())).ok()
}

/// Why a poll signal-ref did not resolve to a [`SignalSpec`].
///
/// The two outcomes are different facts and get different answers. A ref that simply names nothing
/// this device can address is a **per-entry** result — a BAD `UNRESOLVED_REF` read, a failed write —
/// because the rest of the batch is still serviceable. A ref whose `arrayCount` is outside the wire
/// bound is a **malformed argument**, and the whole command is refused with `BAD_ARGS` rather than
/// answered: the truncating `as u32` this replaces turned `2^32 + 1` into a one-element read
/// answered GOOD, and `2^32` into a zero-element read whose reply the device may not frame at all —
/// a bad command argument poisoning the session (D-EIP-33).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PollRefError {
    /// The ref names nothing addressable — a per-entry BAD/unresolved outcome, carrying the label.
    Unresolved(String),
    /// The ref is malformed — the whole command is `BAD_ARGS`, carrying the message.
    BadArgs(String),
}

/// Resolve a poll `sb/read`/`sb/write` signal-ref (§7.2): a friendly `{"name"}` → the configured
/// signal; an explicit `{"tagPath","type","arrayCount"?}` → a synthesized [`SignalSpec`]. See
/// [`PollRefError`] for the two failure shapes.
fn resolve_poll_ref(
    cfg: &DeviceConfig,
    r: &Value,
) -> std::result::Result<SignalSpec, PollRefError> {
    if let Some(name) = r.get("name").and_then(|v| v.as_str()) {
        return cfg
            .signals()
            .find(|s| s.name == name)
            .cloned()
            .ok_or_else(|| PollRefError::Unresolved(name.to_string()));
    }
    if let Some(tag) = r.get("tagPath").and_then(|v| v.as_str()) {
        let ty = r
            .get("type")
            .and_then(|v| v.as_str())
            .and_then(parse_eip_type);
        let array_count = match r.get("arrayCount").filter(|v| !v.is_null()) {
            None => None,
            // An explicit ref never reaches config validation, so the SAME bound is applied here —
            // an unreadable or out-of-range count is refused, never narrowed and never quietly
            // dropped into a scalar read (D-EIP-33). 65 535 is the wire limit: the CIP Read Tag
            // element count is a `u16`.
            Some(v) => match v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| (1..=MAX_ARRAY_COUNT).contains(n))
            {
                Some(n) => Some(n),
                None => {
                    return Err(PollRefError::BadArgs(format!(
                        "`arrayCount` must be an integer in 1..={MAX_ARRAY_COUNT} (got {v})"
                    )))
                }
            },
        };
        return match ty {
            Some(eip_type) => Ok(SignalSpec {
                name: tag.to_string(),
                tag_path: tag.to_string(),
                eip_type,
                array_count,
                scale: None,
                offset: None,
                deadband: crate::config::DeadbandSpec::default(),
            }),
            None => Err(PollRefError::Unresolved(tag.to_string())),
        };
    }
    Err(PollRefError::Unresolved(ref_label(r)))
}

/// Resolve a push `sb/read` ref against the **configured input layout only** (§7.2): a friendly
/// `{"name"}` or an explicit `{"assembly","offset","type","bit"?}` that must match a declared input
/// field. Returns `(signal_id, address)`.
fn resolve_push_read_ref(
    io: &IoConfig,
    conn: &crate::device::ConnectionConfig,
    r: &Value,
) -> Option<(String, Value)> {
    let assembly = io.assemblies.input;
    if let Some(name) = r.get("name").and_then(|v| v.as_str()) {
        let f = io.input.signals.iter().find(|f| f.name == name)?;
        return Some((f.signal_id(assembly), f.address_json(assembly, conn)));
    }
    let ref_asm = r.get("assembly").and_then(|v| v.as_u64())? as u16;
    if ref_asm != assembly {
        return None;
    }
    let off = r.get("offset").and_then(|v| v.as_u64())? as usize;
    let ty = r
        .get("type")
        .and_then(|v| v.as_str())
        .and_then(parse_eip_type)?;
    let bit = r.get("bit").and_then(|v| v.as_u64()).map(|b| b as u8);
    let f = io
        .input
        .signals
        .iter()
        .find(|f| f.offset == off && f.eip_type == ty && f.bit == bit)?;
    Some((f.signal_id(assembly), f.address_json(assembly, conn)))
}

/// Resolve a push `sb/write` ref to an OUTPUT field (§7.3). Input fields are never writable —
/// resolving one is `Err((label, "input field"))`; an unknown ref is `Err((label, "unresolved ref"))`.
#[allow(clippy::type_complexity)]
fn resolve_push_write_ref(
    io: &IoConfig,
    r: &Value,
) -> std::result::Result<(String, IoFieldSpec), (String, String)> {
    let out_asm = io.assemblies.output;
    let in_asm = io.assemblies.input;
    if let Some(name) = r.get("name").and_then(|v| v.as_str()) {
        if let Some(out) = io.output.as_ref() {
            if let Some(f) = out.signals.iter().find(|f| f.name == name) {
                return Ok((f.signal_id(out_asm), f.clone()));
            }
        }
        if io.input.signals.iter().any(|f| f.name == name) {
            return Err((name.to_string(), "input field".to_string()));
        }
        return Err((name.to_string(), "unresolved ref".to_string()));
    }
    let asm = r.get("assembly").and_then(|v| v.as_u64()).map(|n| n as u16);
    let off = r.get("offset").and_then(|v| v.as_u64()).map(|n| n as usize);
    let ty = r
        .get("type")
        .and_then(|v| v.as_str())
        .and_then(parse_eip_type);
    let bit = r.get("bit").and_then(|v| v.as_u64()).map(|b| b as u8);
    let (Some(asm), Some(off), Some(ty)) = (asm, off, ty) else {
        return Err((ref_label(r), "unresolved ref".to_string()));
    };
    if asm == in_asm {
        return Err((
            format!("a{in_asm}/{off}/{}", ty.wire()),
            "input field".to_string(),
        ));
    }
    if let Some(out) = io.output.as_ref() {
        if let Some(f) = out
            .signals
            .iter()
            .find(|f| f.offset == off && f.eip_type == ty && f.bit == bit)
        {
            return Ok((f.signal_id(out_asm), f.clone()));
        }
    }
    Err((
        format!("a{asm}/{off}/{}", ty.wire()),
        "unresolved ref".to_string(),
    ))
}

/// One `sb/signals` push entry.
fn field_signal(
    f: &IoFieldSpec,
    assembly: u16,
    direction: &str,
    mode: &str,
    cfg: &DeviceConfig,
    conn: &crate::device::ConnectionConfig,
) -> Value {
    let id = f.signal_id(assembly);
    let writable = cfg.writes.permits(&id);
    let mut v = json!({
        "name": f.name,
        "id": id,
        "address": f.address_json(assembly, conn),
        "direction": direction,
        "publishMode": mode,
        "writable": writable,
    });
    if let Some(db) = f.deadband.as_ref() {
        v["deadband"] = deadband_json(db);
    }
    v
}

/// The deadband as a `{type, value}` object (§4.4).
fn deadband_json(db: &crate::config::DeadbandSpec) -> Value {
    use crate::config::DeadbandKind;
    let kind = match db.kind {
        DeadbandKind::None => "none",
        DeadbandKind::Absolute => "absolute",
        DeadbandKind::Percent => "percent",
    };
    json!({ "type": kind, "value": db.value })
}

/// The `sb/browse` reply for a poll page (§7.5): each tag with `configured`/`supported` flags.
fn browse_page_json(h: &DeviceHandle, page: BrowsePage) -> Value {
    let configured: std::collections::HashSet<&str> =
        h.cfg.signals().map(|s| s.tag_path.as_str()).collect();
    let tags: Vec<Value> = page
        .tags
        .iter()
        .map(|t| {
            let mut v = json!({
                "name": t.name,
                "type": t.type_name,
                "configured": configured.contains(t.name.as_str()),
                "supported": tag_supported(&t.type_name, t.array_dim),
            });
            if let Some(dim) = t.array_dim {
                v["arrayDim"] = json!(dim);
            }
            v
        })
        .collect();
    let mut out = json!({ "id": h.cfg.id, "tags": tags });
    if let Some(cursor) = page.next_cursor {
        out["cursor"] = json!(cursor);
    }
    out
}

/// The `sb/browse` reply for a push instance (§7.5): the configured assembly layout (input + output
/// fields), no device round-trip — paged with the same `cursor`/`max` contract as the poll form, so
/// one client loop walks either mode.
///
/// The cursor is the 0-based index into the flat field list (inputs in declaration order, then
/// outputs). That list is the parsed configuration, so it is stable for the life of the generation
/// and an index is a faithful resume point; a configuration change replaces the instance, which
/// ends the walk with `NO_SUCH_INSTANCE` rather than serving a page from a different layout.
/// The reply carries `cursor` only while entries remain, so a walk terminates on its absence.
///
/// # Errors
/// `BAD_ARGS` when the cursor is not one this form issued — the command layer owns this cursor
/// format (no device is consulted), so it can say so precisely instead of resuming from the top and
/// silently re-serving the whole layout.
fn browse_push_layout(
    h: &DeviceHandle,
    cursor: Option<&str>,
    max: usize,
) -> std::result::Result<Value, CommandError> {
    let start = parse_push_browse_cursor(cursor)?;
    let mut all = Vec::new();
    if let Some(io) = h.cfg.io.as_ref() {
        for f in &io.input.signals {
            all.push(layout_tag(f, io.assemblies.input, "input"));
        }
        if let Some(out) = io.output.as_ref() {
            for f in &out.signals {
                all.push(layout_tag(f, io.assemblies.output, "output"));
            }
        }
    }
    let total = all.len();
    let tags: Vec<Value> = all.into_iter().skip(start).take(max.max(1)).collect();
    let end = start.saturating_add(tags.len());
    let mut out = json!({ "id": h.cfg.id, "tags": tags });
    if end < total {
        out["cursor"] = json!(end.to_string());
    }
    Ok(out)
}

/// The resume index for a push `sb/browse` page: no cursor ⇒ the start of the layout, else the
/// decimal index a previous page returned. Anything else is a caller error — never a silent restart
/// at 0, which would duplicate the whole layout in the middle of a walk.
fn parse_push_browse_cursor(cursor: Option<&str>) -> std::result::Result<usize, CommandError> {
    match cursor {
        None => Ok(0),
        Some(c) => c.trim().parse::<usize>().map_err(|_| {
            CommandError::new(
                "BAD_ARGS",
                format!("invalid browse cursor `{c}` (expected the numeric cursor from the previous page)"),
            )
        }),
    }
}

/// A hierarchical-browse inventory entry for one configured push I/O field (§7.5):
/// `(nodeId, name, dataType, extra)`.
fn hier_entry(
    f: &IoFieldSpec,
    assembly: u16,
    direction: &str,
) -> (String, String, Value, serde_json::Map<String, Value>) {
    let mut extra = serde_json::Map::new();
    extra.insert("direction".into(), json!(direction));
    extra.insert("configured".into(), json!(true));
    (
        f.signal_id(assembly),
        f.name.clone(),
        json!(f.eip_type.wire()),
        extra,
    )
}

fn layout_tag(f: &IoFieldSpec, assembly: u16, direction: &str) -> Value {
    json!({
        "name": f.name,
        "id": f.signal_id(assembly),
        "type": f.eip_type.wire(),
        "direction": direction,
        "configured": true,
        "supported": true,
    })
}

/// Whether a browsed tag can be configured as a signal and decoded per §5.1 — the `supported` flag
/// both `sb/browse` arms publish (§7.5). It is the **type name AND the shape**, because a name alone
/// answers only half the question: `array_dim` is the dimensionality the symbol type declares
/// (`SymbolType::dims()`, 0–3, carried through as [`BrowsedTag::array_dim`]) — **not** an element
/// count — and `> 1` is a multi-dimensional tag, which has no configuration representation
/// (`arrayCount` is a single integer). That is what §7.5's "multi-dim report `false`" means; without
/// the shape half, such a tag advertised itself `supported: true` alongside its own `arrayDim: 2`.
///
/// A one-dimensional `BOOL` stays **supported**: `bool` + `arrayCount` is a configurable signal,
/// accepted and labelled experimental — see [`crate::config::BOOL_ARRAY_EXPERIMENTAL`].
///
/// Deliberately NOT the crate's `SymbolType::is_value_supported`, which requires `dims() == 0` and
/// would mark every supported 1-D array unsupported.
fn tag_supported(type_name: &str, array_dim: Option<u32>) -> bool {
    array_dim.unwrap_or(0) <= 1 && type_supported(type_name)
}

/// Whether a browsed CIP type name is decodable per §5.1 (an elementary type). Structures / STRING /
/// SSTRING / unknown codes are `false`. The shape half of the question is [`tag_supported`]'s.
fn type_supported(type_name: &str) -> bool {
    matches!(
        type_name,
        "BOOL"
            | "SINT"
            | "USINT"
            | "INT"
            | "UINT"
            | "DINT"
            | "UDINT"
            | "LINT"
            | "ULINT"
            | "REAL"
            | "LREAL"
    )
}

/// Normalize an `sb/write` body to a list of `{ref…, value}` entries: a `writes` array, or a single
/// object carrying `value` (§2.2). `Err(BAD_ARGS)` when neither form is present.
fn write_entries(body: &Value) -> std::result::Result<Vec<Value>, CommandError> {
    if let Some(arr) = body.get("writes").and_then(|v| v.as_array()) {
        return Ok(arr.clone());
    }
    if body.get("value").is_some() {
        return Ok(vec![body.clone()]);
    }
    Err(CommandError::new(
        "BAD_ARGS",
        "expected a `writes` array or a single write object with `value`",
    ))
}

#[cfg(test)]
mod tests {
    //! §12.3 command surface: every verb happy path + error codes + single-instance default; the
    //! allow-list refusal proven to happen BEFORE any device I/O; confirmed/push writes; poll-live vs
    //! push-snapshot reads; repoll refusals; browse mapping; the catalog. A mock device task services
    //! the control channel and RECORDS every write that reaches it — no PLC, no socket.
    //!
    //! Every `Commander` here is built over a real [`DeviceRegistry`], the same one the supervisor
    //! feeds, so the routing assertions exercise the live-lookup path (D-EIP-28) rather than a
    //! startup snapshot.
    use super::*;
    use std::sync::Mutex;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::app::{apply_pause, Health, LinkState};
    use crate::config::GlobalConfig;
    use crate::device::{BrowsedTag, InputSnapshot};
    use crate::lifecycle::DeviceRuntime;
    use crate::testutil::{device_metrics, RecordingEvents};

    fn dev(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).unwrap()
    }

    /// A registry entry for a routing-only handle: no tasks, an unused token — the registry is the
    /// routing view under test, not the supervision one.
    fn runtime(handle: DeviceHandle) -> DeviceRuntime {
        DeviceRuntime {
            raw: json!({ "id": handle.cfg.id }),
            handle,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
        }
    }

    /// A live registry holding `handles` in order, with the default global published.
    fn registry_of(handles: Vec<DeviceHandle>) -> Arc<DeviceRegistry> {
        let registry = Arc::new(DeviceRegistry::default());
        registry.set_global(Arc::new(GlobalConfig::default()));
        for h in handles {
            registry.insert(runtime(h));
        }
        registry
    }

    /// A `Commander` over a live registry holding `handles`.
    fn commander_of(handles: Vec<DeviceHandle>) -> Commander {
        Commander::new(registry_of(handles))
    }

    fn poll_device() -> DeviceConfig {
        dev(json!({
            "id": "filler-plc",
            "adapter": "sim",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [ { "id": "fast", "signals": [
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" },
                { "name": "fill-setpoint", "tagPath": "FILL_SETPOINT", "type": "real" }
            ] } ],
            "writes": { "allow": ["FILL_SETPOINT"] }
        }))
    }

    fn push_device() -> DeviceConfig {
        dev(json!({
            "id": "palletizer-io",
            "adapter": "sim",
            "mode": "push",
            "connection": { "endpoint": "opener:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "udint" } ] },
                "output": { "sizeBytes": 8, "signals": [
                    { "name": "fill-setpoint", "offset": 0, "type": "real" } ] }
            },
            "writes": { "allow": ["a150/0/real"] }
        }))
    }

    #[derive(Clone)]
    enum BrowseKind {
        Tags(Vec<(&'static str, &'static str)>),
        /// One page of `(name, type_name, array_dim)` — the dimensionality a real symbol type
        /// declares (`SymbolType::dims()`), so the `supported` rule can be pinned on shape as well
        /// as name (§7.5).
        DimTags(Vec<(&'static str, &'static str, Option<u32>)>),
        /// A page carrying an array-dim tag and a next-cursor (§7.5 paging). The cursor is the
        /// constant `"42"`, so a walk that follows it revisits the same page — a device that pages
        /// in a circle.
        Paged,
        /// A tag set served the way a real backend pages it: the cursor is the symbol instance to
        /// resume from, a page carries at most `min(max, <device page size>)` records — the device
        /// picks its own page size, which is why the hierarchical walk has to follow cursors at all
        /// — and a truncated page resumes after its last record.
        PagedSet(Vec<(&'static str, &'static str)>, usize),
        /// A backend whose cursors advance forever — every page reports one more record and a
        /// strictly larger cursor, so only the page cap ends the walk.
        EndlessAdvancing,
        /// A backend that hands back a cursor the adapter never issued (not a number).
        NonNumericCursor,
        Unsupported,
        /// A mid-browse link failure ⇒ BROWSE_FAILED.
        Failed,
    }

    #[derive(Clone)]
    struct MockOpts {
        write_ok: bool,
        reconnect_ok: bool,
        read_ok: bool,
        repoll_ok: bool,
        browse: BrowseKind,
        snapshot: Option<InputSnapshot>,
    }

    impl Default for MockOpts {
        fn default() -> Self {
            Self {
                write_ok: true,
                reconnect_ok: true,
                read_ok: true,
                repoll_ok: true,
                browse: BrowseKind::Tags(vec![]),
                snapshot: None,
            }
        }
    }

    struct Harness {
        commander: Arc<Commander>,
        /// The registry the commander routes over — tests mutate it to model a generation swap.
        registry: Arc<DeviceRegistry>,
        /// Every write that REACHED the device (`(id, value)`) — empty proves the allow-list refused
        /// before any device I/O.
        writes: Arc<Mutex<Vec<(String, Value)>>>,
        events: Arc<RecordingEvents>,
        health: Arc<Health>,
        _task: tokio::task::JoinHandle<()>,
    }

    /// Build a single-device commander whose control channel is served by a mock device task.
    fn harness(cfg: DeviceConfig, opts: MockOpts) -> Harness {
        let (tx, mut rx) = mpsc::channel::<DeviceControl>(16);
        let health = Arc::new(Health::default());
        health.set_link(LinkState::Online);
        let (_svc, dm) = device_metrics(cfg.clone(), Arc::clone(&health));
        let events_rec = Arc::new(RecordingEvents::default());
        let events: Arc<dyn EventSink> = events_rec.clone();
        let writes = Arc::new(Mutex::new(Vec::new()));

        let t_cfg = cfg.clone();
        let t_health = Arc::clone(&health);
        let t_dm = Arc::clone(&dm);
        let t_events = events.clone();
        let t_writes = Arc::clone(&writes);
        let task = tokio::spawn(async move {
            while let Some(ctrl) = rx.recv().await {
                match ctrl {
                    DeviceControl::Write(req) => {
                        t_writes
                            .lock()
                            .unwrap()
                            .push((req.signal.tag_path.clone(), req.value.clone()));
                        let _ = req.ack.send(if opts.write_ok {
                            Ok(())
                        } else {
                            Err("write rejected".into())
                        });
                    }
                    DeviceControl::WriteOutput {
                        field,
                        value,
                        reply,
                    } => {
                        t_writes
                            .lock()
                            .unwrap()
                            .push((field.name.clone(), value.clone()));
                        let _ = reply.send(if opts.write_ok {
                            Ok(())
                        } else {
                            Err("staging failed".into())
                        });
                    }
                    DeviceControl::ReadNow { specs, reply } => {
                        if opts.read_ok {
                            let readings = specs
                                .iter()
                                .map(|s| Reading {
                                    signal_id: s.tag_path.clone(),
                                    name: Some(s.name.clone()),
                                    value: json!(42.0),
                                    quality: Quality::Good,
                                    quality_raw: Some("0x00".into()),
                                    observed_type: Some("REAL".into()),
                                })
                                .collect();
                            let _ = reply.send(Ok(readings));
                        } else {
                            let _ = reply.send(Err("link error".into()));
                        }
                    }
                    DeviceControl::Snapshot { reply } => {
                        let _ = reply.send(opts.snapshot.clone());
                    }
                    DeviceControl::Pause { by, reply } => {
                        let c = apply_pause(
                            &t_cfg,
                            &t_health,
                            &t_dm,
                            t_events.as_ref(),
                            true,
                            by.as_deref(),
                        )
                        .await;
                        let _ = reply.send(c);
                    }
                    DeviceControl::Resume { reply } => {
                        let c =
                            apply_pause(&t_cfg, &t_health, &t_dm, t_events.as_ref(), false, None)
                                .await;
                        let _ = reply.send(c);
                    }
                    DeviceControl::Reconnect { reply } => {
                        let _ = reply.send(if opts.reconnect_ok {
                            Ok(())
                        } else {
                            Err("no route to host".into())
                        });
                    }
                    DeviceControl::Repoll { reply } => {
                        let _ = reply.send(if opts.repoll_ok {
                            Ok(7)
                        } else {
                            Err("link error".into())
                        });
                    }
                    DeviceControl::Browse { cursor, max, reply } => match &opts.browse {
                        BrowseKind::Unsupported => {
                            let _ = reply.send(Err(BrowseError::Unsupported));
                        }
                        BrowseKind::Failed => {
                            let _ = reply
                                .send(Err(BrowseError::Failed("mid-browse link error".into())));
                        }
                        BrowseKind::PagedSet(all, page) => {
                            // The §7.3 backend contract, mirrored: the cursor is the symbol instance
                            // to resume from and no cursor means instance **0**, the bottom of the
                            // instance space (`None` ⇒ 0), the page carries at most `min(max, page)`
                            // records, and a truncated page's cursor follows its LAST RETURNED
                            // record — so no record between the cut and the end of the device page
                            // is skipped. This mock numbers its own symbols from 1, so a walk that
                            // starts at 0 simply returns all of them.
                            let start: u32 = match cursor.as_deref() {
                                None => 0,
                                Some(c) => c.trim().parse().unwrap_or_else(|_| {
                                    panic!("the adapter must not send a non-numeric cursor: `{c}`")
                                }),
                            };
                            let remaining: Vec<BrowsedTag> = all
                                .iter()
                                .enumerate()
                                .map(|(i, (n, ty))| BrowsedTag {
                                    name: (*n).to_string(),
                                    type_name: (*ty).to_string(),
                                    array_dim: None,
                                    instance_id: i as u32 + 1,
                                })
                                .filter(|t| t.instance_id >= start)
                                .collect();
                            let total = remaining.len();
                            let limit = max.max(1).min(*page);
                            let tags: Vec<BrowsedTag> = remaining.into_iter().take(limit).collect();
                            let next = if tags.len() < total {
                                tags.last().map(|t| (t.instance_id + 1).to_string())
                            } else {
                                None
                            };
                            let _ = reply.send(Ok(BrowsePage {
                                tags,
                                next_cursor: next,
                            }));
                        }
                        BrowseKind::EndlessAdvancing => {
                            // Each page advances (so the non-advancing guard never fires) and never
                            // ends: only the page cap can stop the walk.
                            let start: u32 =
                                cursor.as_deref().and_then(|c| c.parse().ok()).unwrap_or(1);
                            let tags = vec![BrowsedTag {
                                name: format!("TAG_{start}"),
                                type_name: "DINT".to_string(),
                                array_dim: None,
                                instance_id: start,
                            }];
                            let _ = reply.send(Ok(BrowsePage {
                                tags,
                                next_cursor: Some((start + 1).to_string()),
                            }));
                        }
                        BrowseKind::NonNumericCursor => {
                            let _ = reply.send(Ok(BrowsePage {
                                tags: Vec::new(),
                                next_cursor: Some("not-a-number".into()),
                            }));
                        }
                        BrowseKind::Paged => {
                            // An array tag + a next-cursor exercise the arrayDim + cursor reply
                            // keys. `REAL[8]` is ONE-dimensional: `array_dim` is the symbol type's
                            // dimensionality, not its element count.
                            let tags = vec![BrowsedTag {
                                name: "ZONE_TEMPS".to_string(),
                                type_name: "REAL".to_string(),
                                array_dim: Some(1),
                                instance_id: 1,
                            }];
                            let _ = reply.send(Ok(BrowsePage {
                                tags,
                                next_cursor: Some("42".into()),
                            }));
                        }
                        BrowseKind::DimTags(t) => {
                            // One page of `(name, type, dims)` — the shape both browse arms read the
                            // `supported` flag out of (§7.5).
                            let tags = t
                                .iter()
                                .enumerate()
                                .map(|(i, (n, ty, dims))| BrowsedTag {
                                    name: (*n).to_string(),
                                    type_name: (*ty).to_string(),
                                    array_dim: *dims,
                                    instance_id: i as u32 + 1,
                                })
                                .collect();
                            let _ = reply.send(Ok(BrowsePage {
                                tags,
                                next_cursor: None,
                            }));
                        }
                        BrowseKind::Tags(t) => {
                            let tags = t
                                .iter()
                                .enumerate()
                                .map(|(i, (n, ty))| BrowsedTag {
                                    name: (*n).to_string(),
                                    type_name: (*ty).to_string(),
                                    array_dim: None,
                                    instance_id: i as u32 + 1,
                                })
                                .collect();
                            let _ = reply.send(Ok(BrowsePage {
                                tags,
                                next_cursor: None,
                            }));
                        }
                    },
                }
            }
        });

        let handle = DeviceHandle {
            cfg,
            control: tx,
            health: Arc::clone(&health),
            dm,
            events,
        };
        let registry = registry_of(vec![handle]);
        let commander = Arc::new(Commander::new(Arc::clone(&registry)));
        Harness {
            commander,
            registry,
            writes,
            events: events_rec,
            health,
            _task: task,
        }
    }

    fn ok(reply: Reply) -> Value {
        reply.expect("command succeeded").expect("a result object")
    }
    fn err_code(reply: Reply) -> String {
        reply.expect_err("command failed").code
    }

    // --- routing / single-instance default (D-EIP-13) ---------------------------------------------

    #[tokio::test]
    async fn instance_defaults_to_the_sole_device_and_unknown_or_missing_ids_error() {
        // Single device: the request need not address an instance.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.status(None, &json!({})).await);
        assert_eq!(out["id"], json!("filler-plc"));
        // An unknown addressed instance is NO_SUCH_INSTANCE.
        assert_eq!(
            err_code(h.commander.status(Some("nope"), &json!({})).await),
            "NO_SUCH_INSTANCE"
        );

        // Two devices: an unaddressed request is BAD_ARGS.
        let multi = two_device_commander();
        assert_eq!(err_code(multi.status(None, &json!({})).await), "BAD_ARGS");
    }

    // --- SOUTHBOUND §2.2 addressed-instance routing (D-U28 / D-SC-4 / D-EIP-26) ------------------

    /// A device handle with no live device task — enough for routing/`sb/status` assertions.
    fn bare_handle(cfg: DeviceConfig) -> DeviceHandle {
        let (tx, _rx) = mpsc::channel(1);
        let health = Arc::new(Health::default());
        let (_m, dm) = device_metrics(cfg.clone(), Arc::clone(&health));
        let events: Arc<dyn EventSink> = Arc::new(RecordingEvents::default());
        DeviceHandle {
            cfg,
            control: tx,
            health,
            dm,
            events,
        }
    }

    /// A second poll device, `second`.
    fn second_device() -> DeviceConfig {
        let mut b = poll_device();
        b.id = "second".into();
        b
    }

    /// Two poll devices: `filler-plc` + `second`.
    fn two_device_commander() -> Commander {
        commander_of(vec![
            bare_handle(poll_device()),
            bare_handle(second_device()),
        ])
    }

    #[tokio::test]
    async fn the_addressed_instance_routes_the_command() {
        let multi = two_device_commander();
        // The library resolves the addressing (topic token, else `body.instance`) and hands it to
        // the handler; it routes even with two devices configured and an empty body.
        assert_eq!(
            ok(multi.status(Some("second"), &json!({})).await)["id"],
            json!("second")
        );
        // An addressed instance this adapter does not serve is NO_SUCH_INSTANCE.
        assert_eq!(
            err_code(multi.status(Some("ghost"), &json!({})).await),
            "NO_SUCH_INSTANCE"
        );
        // An addressed instance never falls back to "the only device".
        let single = harness(poll_device(), MockOpts::default());
        assert_eq!(
            err_code(single.commander.status(Some("ghost"), &json!({})).await),
            "NO_SUCH_INSTANCE"
        );
    }

    #[tokio::test]
    async fn an_unaddressed_request_takes_the_configured_default() {
        // ≥ 2 devices: the request must address one (D-EIP-13).
        let multi = two_device_commander();
        assert_eq!(err_code(multi.status(None, &json!({})).await), "BAD_ARGS");
        // Exactly one device: the sole configured device answers.
        let single = harness(poll_device(), MockOpts::default());
        assert_eq!(
            ok(single.commander.status(None, &json!({})).await)["id"],
            json!("filler-plc")
        );
    }

    /// The describe availability `register_all` and the configuration-change path both apply
    /// (D-EIP-25). `available` is the clearing state, which is what lets an all-push adapter that
    /// gains a poll instance get the verb back.
    #[test]
    fn repoll_availability_rule() {
        let (state, reason) = repoll_availability(true);
        assert_eq!(state, AVAILABILITY_UNSUPPORTED);
        assert!(reason.is_some_and(|r| r.contains("push-mode")));

        let (state, reason) = repoll_availability(false);
        assert_eq!(state, AVAILABILITY_AVAILABLE);
        assert_eq!(reason, None);
    }

    // --- routing over the LIVE registry across a generation swap (D-EIP-28) -----------------------

    /// Routing follows the registry, not a startup snapshot: an instance a configuration change
    /// stopped is `NO_SUCH_INSTANCE`, and one it starts routes as soon as it is inserted. Against a
    /// `Commander` holding its own startup map, the second assertion cannot fail and the third
    /// cannot pass.
    ///
    /// The whole `resolve` matrix runs over the registry's targeted accessors, so every outcome —
    /// addressed hit, addressed miss, and the three unaddressed ones — is asserted here through
    /// them.
    #[tokio::test]
    async fn resolve_follows_the_live_registry() {
        let registry = registry_of(vec![
            bare_handle(poll_device()),
            bare_handle(second_device()),
        ]);
        let commander = Commander::new(Arc::clone(&registry));
        assert_eq!(
            ok(commander.status(Some("second"), &json!({})).await)["id"],
            json!("second")
        );
        // Several running: an unaddressed request has to name one.
        assert_eq!(
            err_code(commander.status(None, &json!({})).await),
            "BAD_ARGS"
        );

        // The configuration no longer runs `second`.
        registry.remove("second").expect("second was running");
        assert_eq!(
            err_code(commander.status(Some("second"), &json!({})).await),
            "NO_SUCH_INSTANCE"
        );
        // …which makes the survivor the sole instance, so it answers unaddressed requests.
        assert_eq!(
            ok(commander.status(None, &json!({})).await)["id"],
            json!("filler-plc")
        );

        // Nothing running: the truthful answer, not a request to address an instance.
        registry.take_all();
        assert_eq!(
            err_code(commander.status(None, &json!({})).await),
            "DEVICE_UNAVAILABLE"
        );

        // A configuration change starts it again — same registrations, routable immediately.
        registry.insert(runtime(bare_handle(second_device())));
        assert_eq!(
            ok(commander.status(Some("second"), &json!({})).await)["id"],
            json!("second")
        );
    }

    /// The single-instance default is computed from the live count, so removing one of two devices
    /// makes the survivor answer unaddressed requests — and adding one takes the default away.
    #[tokio::test]
    async fn single_instance_default_tracks_the_live_count() {
        let registry = registry_of(vec![
            bare_handle(poll_device()),
            bare_handle(second_device()),
        ]);
        let commander = Commander::new(Arc::clone(&registry));
        assert_eq!(
            err_code(commander.status(None, &json!({})).await),
            "BAD_ARGS"
        );

        registry.remove("second").expect("second was running");
        assert_eq!(
            ok(commander.status(None, &json!({})).await)["id"],
            json!("filler-plc"),
            "the sole survivor answers an unaddressed request"
        );

        registry.insert(runtime(bare_handle(second_device())));
        assert_eq!(
            err_code(commander.status(None, &json!({})).await),
            "BAD_ARGS"
        );
    }

    /// The window a configuration change that restarts every instance opens: for the length of the
    /// stop stage the registry is empty. An unaddressed request then gets the truth — no device is
    /// running — rather than being told to address an instance that would only answer
    /// `NO_SUCH_INSTANCE`.
    #[tokio::test]
    async fn an_unaddressed_request_with_nothing_running_is_device_unavailable() {
        let registry = registry_of(vec![bare_handle(poll_device())]);
        let commander = Commander::new(Arc::clone(&registry));
        assert_eq!(
            ok(commander.status(None, &json!({})).await)["id"],
            json!("filler-plc")
        );

        registry.take_all();
        let err = commander
            .status(None, &json!({}))
            .await
            .expect_err("nothing is running");
        assert_eq!(err.code, "DEVICE_UNAVAILABLE");
        assert!(
            err.message.contains("no device is running"),
            "the message states what is actually wrong: {}",
            err.message
        );
        // Addressing an instance in that window is still `NO_SUCH_INSTANCE`, which is why asking the
        // caller to address one would be useless advice.
        assert_eq!(
            err_code(commander.status(Some("filler-plc"), &json!({})).await),
            "NO_SUCH_INSTANCE"
        );
    }

    /// `sb/signals` resolves its cadence/publish mode against the registry's global, so the reply
    /// reflects the generation the poll engine is running — not the one captured at startup.
    #[tokio::test]
    async fn sb_signals_reads_the_swapped_global() {
        let h = harness(poll_device(), MockOpts::default());
        let poll_ms = |out: &Value| out["signals"][0]["pollIntervalMs"].as_u64().unwrap();
        let before = ok(h.commander.signals(None, &json!({})).await);
        assert_eq!(poll_ms(&before), 5_000, "the built-in default");
        assert_eq!(before["signals"][0]["publishMode"], json!("onChange"));

        h.registry.set_global(Arc::new(
            GlobalConfig::from_value(&json!({
                "defaults": { "pollIntervalMs": 250, "publishMode": "always" }
            }))
            .unwrap(),
        ));

        let after = ok(h.commander.signals(None, &json!({})).await);
        assert_eq!(poll_ms(&after), 250, "the swapped global's cadence");
        assert_eq!(after["signals"][0]["publishMode"], json!("always"));

        // Push instances resolve their publish mode from the same live global.
        let hp = harness(push_device(), MockOpts::default());
        assert_eq!(
            ok(hp.commander.signals(None, &json!({})).await)["signals"][0]["publishMode"],
            json!("onChange")
        );
        hp.registry.set_global(Arc::new(
            GlobalConfig::from_value(&json!({ "defaults": { "publishMode": "always" } })).unwrap(),
        ));
        assert_eq!(
            ok(hp.commander.signals(None, &json!({})).await)["signals"][0]["publishMode"],
            json!("always")
        );
    }

    // --- sb/status ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn status_reports_connected_state_paused_and_a_counter_snapshot() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.status(None, &json!({})).await);
        assert_eq!(out["connected"], json!(true));
        assert_eq!(out["state"], json!("ONLINE"));
        assert_eq!(out["paused"], json!(false));
        assert_eq!(out["adapter"], json!("sim"));
        assert!(out["metrics"].get("read").is_some() && out["metrics"].get("write").is_some());

        // A push instance's status additionally carries the `io` object (§7.1).
        let hp = harness(push_device(), MockOpts::default());
        let out = ok(hp.commander.status(None, &json!({})).await);
        assert_eq!(out["mode"], json!("push"));
        assert!(out["io"].get("framesConsumed").is_some());
    }

    // --- sb/write: allow-list BEFORE any device I/O (the security guarantee) -----------------------

    #[tokio::test]
    async fn write_allow_list_refusal_happens_before_any_device_io() {
        let h = harness(poll_device(), MockOpts::default());
        // LINE_SPEED is NOT in writes.allow — the sole entry is refused ⇒ WRITE_NOT_ALLOWED.
        let code = err_code(
            h.commander
                .write(None, &json!({ "name": "line-speed", "value": 12.0 }))
                .await,
        );
        assert_eq!(code, "WRITE_NOT_ALLOWED");
        // THE GUARANTEE: no write ever reached the device task.
        assert!(
            h.writes.lock().unwrap().is_empty(),
            "a refused write must not reach device I/O"
        );
        // The refusal is still audited on evt (§6.3).
        assert!(h.events.has("write-audit"));
        let ctx = h.events.last_ctx("write-audit").unwrap();
        assert_eq!(ctx["ok"], json!(false));
        assert_eq!(ctx["signalId"], json!("LINE_SPEED"));
    }

    #[tokio::test]
    async fn a_confirmed_allowed_write_reaches_the_device_and_acks() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h
            .commander
            .write(
                None,
                &json!({ "writes": [ { "name": "fill-setpoint", "value": 55.5 } ] }),
            )
            .await);
        assert_eq!(out["written"], json!(1));
        assert_eq!(out["results"][0]["ok"], json!(true));
        // It reached the device (allow-listed), and is audited Info.
        let writes = h.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "FILL_SETPOINT");
        assert!(h.events.has("write-audit"));
    }

    #[tokio::test]
    async fn a_push_write_targets_the_output_assembly_and_is_applied_next_frame() {
        let h = harness(push_device(), MockOpts::default());
        // a150/0/real is allow-listed; the friendly name resolves to it.
        let out = ok(h
            .commander
            .write(None, &json!({ "name": "fill-setpoint", "value": 55.5 }))
            .await);
        assert_eq!(out["written"], json!(1));
        assert_eq!(out["results"][0]["ok"], json!(true));
        assert_eq!(
            out["results"][0]["applied"],
            json!("next-frame"),
            "push write confirmation honesty"
        );
        assert_eq!(
            h.writes.lock().unwrap().len(),
            1,
            "it reached the output assembly"
        );

        // An INPUT field is never writable (§7.3), even by explicit ref.
        let out = ok(h
            .commander
            .write(
                None,
                &json!({ "assembly": 100, "offset": 0, "type": "udint", "value": 1 }),
            )
            .await);
        assert_eq!(out["results"][0]["ok"], json!(false));
        assert_eq!(out["results"][0]["error"], json!("input field"));
    }

    // --- sb/read: poll live vs push snapshot ------------------------------------------------------

    #[tokio::test]
    async fn read_poll_is_a_live_read_and_unresolved_refs_come_back_bad() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h
            .commander
            .read(
                None,
                &json!({ "signals": [ { "name": "line-speed" }, { "name": "ghost" } ] }),
            )
            .await);
        let reads = out["reads"].as_array().unwrap();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0]["value"], json!(42.0), "the live mock read");
        assert_eq!(reads[0]["quality"], json!("GOOD"));
        assert_eq!(reads[1]["quality"], json!("BAD"));
        assert_eq!(reads[1]["qualityRaw"], json!("UNRESOLVED_REF"));
    }

    #[tokio::test]
    async fn read_push_answers_from_the_last_input_snapshot() {
        // A preset snapshot for the configured input field a100/0/udint.
        let snapshot = InputSnapshot {
            readings: vec![Reading {
                signal_id: "a100/0/udint".into(),
                name: Some("motor-run".into()),
                value: json!(7),
                quality: Quality::Good,
                quality_raw: Some("0x00".into()),
                observed_type: None,
            }],
            received_at: Instant::now(),
            run_mode: true,
        };
        let h = harness(
            push_device(),
            MockOpts {
                snapshot: Some(snapshot),
                ..MockOpts::default()
            },
        );
        let out = ok(h
            .commander
            .read(None, &json!({ "signals": [ { "name": "motor-run" } ] }))
            .await);
        assert_eq!(
            out["reads"][0]["value"],
            json!(7),
            "answered from the snapshot, no round-trip"
        );
        assert_eq!(out["reads"][0]["quality"], json!("GOOD"));

        // No frame yet ⇒ BAD/NO_FRAME (§7.2).
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h
            .commander
            .read(None, &json!({ "signals": [ { "name": "motor-run" } ] }))
            .await);
        assert_eq!(out["reads"][0]["qualityRaw"], json!("NO_FRAME"));
    }

    // --- sb/signals -------------------------------------------------------------------------------

    #[tokio::test]
    async fn signals_is_the_resolved_config_view_with_writable_flags() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.signals(None, &json!({})).await);
        let sigs = out["signals"].as_array().unwrap();
        let setpoint = sigs
            .iter()
            .find(|s| s["id"] == json!("FILL_SETPOINT"))
            .unwrap();
        assert_eq!(setpoint["writable"], json!(true), "allow-listed ⇒ writable");
        let speed = sigs
            .iter()
            .find(|s| s["id"] == json!("LINE_SPEED"))
            .unwrap();
        assert_eq!(speed["writable"], json!(false));
        assert!(speed.get("pollGroup").is_some() && speed.get("pollIntervalMs").is_some());
    }

    /// D-EIP-35: `sb/signals` reports the **observed** wire representation beside the configured
    /// one. It is a device property, so it is absent until the signal has actually been read — an
    /// empty field says "not yet contacted", which is a different fact from "reads as configured"
    /// and must not be papered over by defaulting to the config's type. Once a reply has declared a
    /// type, the field carries it verbatim, including the packed `DWORD` a Logix BOOL array serves.
    #[tokio::test]
    async fn signals_reports_the_observed_wire_representation_once_it_is_known() {
        let h = harness(poll_device(), MockOpts::default());

        let before = ok(h.commander.signals(None, &json!({})).await);
        for s in before["signals"].as_array().unwrap() {
            assert!(
                s.get("observedType").is_none(),
                "no representation is claimed before first contact: {s}"
            );
        }

        // What the poll loop records after a reply (see poll_driver's own test for the wiring).
        h.health.record_observed(&[
            Reading {
                observed_type: Some("DWORD".into()),
                ..crate::testutil::reading("LINE_SPEED", json!(1.0), Quality::Good)
            },
            Reading {
                observed_type: None,
                ..crate::testutil::reading("FILL_SETPOINT", json!(1.0), Quality::Good)
            },
        ]);

        let after = ok(h.commander.signals(None, &json!({})).await);
        let sigs = after["signals"].as_array().unwrap();
        let speed = sigs
            .iter()
            .find(|s| s["id"] == json!("LINE_SPEED"))
            .unwrap();
        assert_eq!(speed["observedType"], json!("DWORD"));
        assert_eq!(
            speed["address"]["type"],
            json!("real"),
            "the configured type is untouched beside it"
        );
        let setpoint = sigs
            .iter()
            .find(|s| s["id"] == json!("FILL_SETPOINT"))
            .unwrap();
        assert!(
            setpoint.get("observedType").is_none(),
            "a signal with no observation is still silent: {setpoint}"
        );
    }

    // --- sb/browse --------------------------------------------------------------------------------

    #[tokio::test]
    async fn browse_pages_tags_for_poll_and_maps_unsupported() {
        // Poll: a page of tags, with configured/supported flags.
        let opts = MockOpts {
            browse: BrowseKind::Tags(vec![("LINE_SPEED", "REAL"), ("RECIPE", "SSTRING")]),
            ..MockOpts::default()
        };
        let h = harness(poll_device(), opts);
        let out = ok(h.commander.browse(None, &json!({})).await);
        let tags = out["tags"].as_array().unwrap();
        assert_eq!(
            tags[0]["configured"],
            json!(true),
            "LINE_SPEED is in config"
        );
        assert_eq!(tags[0]["supported"], json!(true));
        assert_eq!(tags[1]["supported"], json!(false), "SSTRING is undecodable");

        // A device with no tag-list service ⇒ BROWSE_UNSUPPORTED.
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::Unsupported,
                ..MockOpts::default()
            },
        );
        assert_eq!(
            err_code(h.commander.browse(None, &json!({})).await),
            "BROWSE_UNSUPPORTED"
        );

        // Push: the configured assembly layout, no round-trip.
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.browse(None, &json!({})).await);
        assert!(!out["tags"].as_array().unwrap().is_empty());
    }

    /// The paged walk's contract (§7.5): `max` is honoured truthfully and the cursor resumes where
    /// the page stopped, so a client that follows the cursors sees every tag **exactly once**.
    /// Before F7 the first page came back with no cursor at all and the rest of the tag space was
    /// unreachable.
    #[tokio::test]
    async fn browse_paged_walk_enumerates_every_tag_exactly_once() {
        let all = vec![
            ("LINE_SPEED", "REAL"),
            ("FILL_SETPOINT", "REAL"),
            ("RECIPE", "SSTRING"),
            ("ZONE_TEMPS", "REAL"),
            ("MOTOR_RUN", "BOOL"),
        ];
        // The device would serve all five in one page; `max` is what cuts them into three.
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::PagedSet(all.clone(), 100),
                ..MockOpts::default()
            },
        );

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let body = match &cursor {
                Some(c) => json!({ "cursor": c, "max": 2 }),
                None => json!({ "max": 2 }),
            };
            let out = ok(h.commander.browse(None, &body).await);
            pages += 1;
            assert!(pages <= 10, "the walk must terminate");
            let tags = out["tags"].as_array().unwrap();
            assert!(
                tags.len() <= 2,
                "`max` is honoured truthfully: {}",
                tags.len()
            );
            for t in tags {
                seen.push(t["name"].as_str().unwrap().to_string());
            }
            match out.get("cursor") {
                Some(c) => cursor = Some(c.as_str().unwrap().to_string()),
                None => break,
            }
        }

        assert_eq!(pages, 3, "5 tags at max 2 = 3 pages");
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), seen.len(), "no tag is served twice: {seen:?}");
        assert_eq!(
            unique,
            {
                let mut want: Vec<String> = all.iter().map(|(n, _)| (*n).to_string()).collect();
                want.sort_unstable();
                want
            },
            "and none is skipped"
        );
    }

    /// A push instance pages its configured layout with the same `cursor`/`max` contract, and its
    /// cursor is validated: the command layer owns this cursor format, so a corrupt one is
    /// `BAD_ARGS` rather than a silent restart that would re-serve the whole layout mid-walk.
    #[tokio::test]
    async fn browse_push_layout_pages_the_configured_layout_and_validates_its_cursor() {
        let h = harness(push_device(), MockOpts::default());

        // The whole layout is one input + one output field; `max: 1` cuts it in two pages.
        let first = ok(h.commander.browse(None, &json!({ "max": 1 })).await);
        let first_tags = first["tags"].as_array().unwrap();
        assert_eq!(first_tags.len(), 1);
        assert_eq!(first_tags[0]["direction"], json!("input"));
        assert_eq!(
            first["cursor"],
            json!("1"),
            "the resume index of the next field"
        );

        let second = ok(h
            .commander
            .browse(None, &json!({ "cursor": "1", "max": 1 }))
            .await);
        let second_tags = second["tags"].as_array().unwrap();
        assert_eq!(second_tags.len(), 1);
        assert_eq!(second_tags[0]["direction"], json!("output"));
        assert!(
            second.get("cursor").is_none(),
            "the last page ends the walk"
        );
        assert_ne!(first_tags[0]["id"], second_tags[0]["id"], "each field once");

        // An unpaged request still returns the whole layout with no cursor.
        let whole = ok(h.commander.browse(None, &json!({})).await);
        assert_eq!(whole["tags"].as_array().unwrap().len(), 2);
        assert!(whole.get("cursor").is_none());

        // A cursor past the end is an empty final page, not a wrap.
        let past = ok(h.commander.browse(None, &json!({ "cursor": "9" })).await);
        assert_eq!(past["tags"].as_array().unwrap().len(), 0);
        assert!(past.get("cursor").is_none());

        // A cursor this form never issued is refused.
        let err = h
            .commander
            .browse(None, &json!({ "cursor": "banana" }))
            .await
            .expect_err("a corrupt cursor is refused");
        assert_eq!(err.code, "BAD_ARGS");
        assert!(
            err.message.contains("invalid browse cursor"),
            "{}",
            err.message
        );
    }

    /// **`supported` is the type name AND the shape (D-EIP-33), on BOTH arms.** §7.5 promises that
    /// multi-dimensional tags report `supported: false`; a pure name match reported a multi-dim
    /// atomic `supported: true` right next to its own `arrayDim: 2`, telling a console it could
    /// configure a tag the config parser rejects. A 1-D array is the control — it stays supported,
    /// which is why the crate's `SymbolType::is_value_supported` (`dims() == 0`) is deliberately not
    /// used, and that includes a 1-D `BOOL`: `bool` + `arrayCount` is configurable (experimental,
    /// D-EIP-16). The flat and hierarchical arms must agree, so both are pinned here.
    #[tokio::test]
    async fn browse_supported_accounts_for_dimensionality_on_both_arms() {
        // (name, CIP type name, dims) → expected `supported`.
        let rows: Vec<(&'static str, &'static str, Option<u32>, bool)> = vec![
            ("LINE_SPEED", "REAL", None, true),
            ("ZONE_TEMPS", "REAL", Some(1), true),
            ("TEMP_GRID", "REAL", Some(2), false),
            ("CUBE", "DINT", Some(3), false),
            ("MOTOR_RUN", "BOOL", None, true),
            ("ALARMS", "BOOL", Some(1), true),
            ("RECIPE", "SSTRING", None, false),
        ];
        let opts = MockOpts {
            browse: BrowseKind::DimTags(rows.iter().map(|(n, t, d, _)| (*n, *t, *d)).collect()),
            ..MockOpts::default()
        };
        let h = harness(poll_device(), opts);

        // Flat (paged) arm.
        let out = ok(h.commander.browse(None, &json!({})).await);
        let tags = out["tags"].as_array().unwrap();
        assert_eq!(tags.len(), rows.len());
        for (tag, (name, _, dims, want)) in tags.iter().zip(rows.iter()) {
            assert_eq!(
                tag["supported"],
                json!(want),
                "flat: `{name}` with dims {dims:?}"
            );
        }
        assert_eq!(
            tags[2]["arrayDim"],
            json!(2),
            "the multi-dim tag still reports its dimensionality — it just is not supported"
        );

        // Hierarchical arm, over the same inventory: the two must not disagree.
        let out = ok(h.commander.browse(None, &json!({ "ref": "root" })).await);
        let refs = out["root"]["refs"].as_array().unwrap();
        assert_eq!(refs.len(), rows.len());
        for (r, (name, _, dims, want)) in refs.iter().zip(rows.iter()) {
            assert_eq!(
                r["target"]["supported"],
                json!(want),
                "hierarchical: `{name}` with dims {dims:?}"
            );
        }
    }

    #[test]
    fn tag_supported_is_the_name_and_the_shape() {
        assert!(tag_supported("DINT", None) && tag_supported("DINT", Some(1)));
        assert!(!tag_supported("DINT", Some(2)) && !tag_supported("DINT", Some(3)));
        // A 1-D BOOL is configurable (experimental), so browse does not mark it unsupported.
        assert!(tag_supported("BOOL", None) && tag_supported("BOOL", Some(1)));
        assert!(!tag_supported("SSTRING", None) && !tag_supported("STRUCT", Some(1)));
    }

    // --- sb/browse hierarchical (the treeBrowser panel mode) --------------------------------------

    #[tokio::test]
    async fn browse_ref_serves_the_hierarchical_panel_mode_over_the_same_inventory() {
        let opts = MockOpts {
            browse: BrowseKind::Tags(vec![("LINE_SPEED", "REAL"), ("RECIPE", "SSTRING")]),
            ..MockOpts::default()
        };
        let h = harness(poll_device(), opts);

        // "root" answers the device node with one `contains` ref per browsed tag.
        let out = ok(h.commander.browse(None, &json!({ "ref": "root" })).await);
        assert_eq!(out["mode"], json!("hierarchical"));
        assert_eq!(out["root"]["nodeId"], json!("root"));
        assert_eq!(out["root"]["nodeClass"], json!("device"));
        let refs = out["root"]["refs"].as_array().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0]["referenceType"], json!("contains"));
        assert_eq!(refs[0]["target"]["nodeId"], json!("LINE_SPEED"));
        assert_eq!(
            refs[0]["target"]["configured"],
            json!(true),
            "LINE_SPEED is in config"
        );
        assert_eq!(
            refs[1]["target"]["supported"],
            json!(false),
            "SSTRING is undecodable"
        );
        assert_eq!(out["refCount"], json!(2));
        assert_eq!(out["truncated"], json!(false));

        // A known tag ref is a leaf; an unknown ref is BAD_ARGS.
        let out = ok(h
            .commander
            .browse(None, &json!({ "ref": "LINE_SPEED" }))
            .await);
        assert_eq!(out["root"]["nodeClass"], json!("signal"));
        assert_eq!(out["root"]["refs"], json!([]));
        assert_eq!(
            err_code(h.commander.browse(None, &json!({ "ref": "nope" })).await),
            "BAD_ARGS"
        );

        // `depth` clamps to 1..4 and `maxRefs` to 1..1000 (`truncated` reports the cut).
        let out = ok(h
            .commander
            .browse(None, &json!({ "ref": "root", "depth": 99, "maxRefs": 1 }))
            .await);
        assert_eq!(out["depth"], json!(4));
        assert_eq!(out["root"]["refs"].as_array().unwrap().len(), 1);
        assert_eq!(out["truncated"], json!(true));

        // Push: the hierarchical inventory is the configured assembly layout, no round-trip.
        let hp = harness(push_device(), MockOpts::default());
        let out = ok(hp.commander.browse(None, &json!({ "ref": "root" })).await);
        let refs = out["root"]["refs"].as_array().unwrap();
        assert_eq!(refs.len(), 2, "one input + one output field");
        assert_eq!(refs[0]["target"]["direction"], json!("input"));
        let out = ok(hp
            .commander
            .browse(None, &json!({ "ref": "a150/0/real" }))
            .await);
        assert_eq!(out["root"]["nodeClass"], json!("signal"));
    }

    /// The hierarchical walk is the one browse form the adapter drives to completion, so its
    /// termination must not depend on the backend. A device that pages in a circle (this mock
    /// answers the same cursor forever) is `BROWSE_FAILED`, not a handler that never returns —
    /// which is exactly what this test would do before the guard landed.
    #[tokio::test]
    async fn browse_hierarchical_refuses_a_cursor_that_does_not_advance() {
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::Paged,
                ..MockOpts::default()
            },
        );
        let err = h
            .commander
            .browse(None, &json!({ "ref": "root" }))
            .await
            .expect_err("a repeating cursor cannot complete a walk");
        assert_eq!(err.code, "BROWSE_FAILED");
        assert!(err.message.contains("did not advance"), "{}", err.message);
    }

    /// A backend cursor that is not one this adapter's backends issue is refused rather than fed
    /// back to the device.
    #[tokio::test]
    async fn browse_hierarchical_refuses_a_non_numeric_device_cursor() {
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::NonNumericCursor,
                ..MockOpts::default()
            },
        );
        let err = h
            .commander
            .browse(None, &json!({ "ref": "root" }))
            .await
            .expect_err("a non-numeric backend cursor is refused");
        assert_eq!(err.code, "BROWSE_FAILED");
        assert!(
            err.message.contains("non-numeric browse cursor"),
            "{}",
            err.message
        );
    }

    /// The second guard, for a backend whose cursors advance honestly but never end: the walk stops
    /// at [`MAX_BROWSE_PAGES`] with a typed error instead of running forever.
    #[tokio::test]
    async fn browse_hierarchical_stops_at_the_page_cap() {
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::EndlessAdvancing,
                ..MockOpts::default()
            },
        );
        let err = h
            .commander
            .browse(None, &json!({ "ref": "root" }))
            .await
            .expect_err("an endless walk is capped");
        assert_eq!(err.code, "BROWSE_FAILED");
        assert!(err.message.contains("page cap"), "{}", err.message);
    }

    /// A backend that pages legitimately is walked to completion by the hierarchical mode: every
    /// page's records join the one inventory, and the walk ends when the backend stops issuing
    /// cursors.
    #[tokio::test]
    async fn browse_hierarchical_follows_legitimate_cursors_to_completion() {
        let all = vec![
            ("LINE_SPEED", "REAL"),
            ("RECIPE", "SSTRING"),
            ("ZONE_TEMPS", "REAL"),
        ];
        // The device pages two at a time, so the hierarchical walk must follow a cursor to see all
        // three — the `max: 1000` this mode asks for does not stop the device from paging.
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::PagedSet(all, 2),
                ..MockOpts::default()
            },
        );
        let out = ok(h.commander.browse(None, &json!({ "ref": "root" })).await);
        let refs = out["root"]["refs"].as_array().unwrap();
        assert_eq!(refs.len(), 3, "every page's records reached the inventory");
        assert_eq!(out["refCount"], json!(3));
        assert_eq!(out["truncated"], json!(false));
    }

    #[tokio::test]
    async fn browse_rejects_mixed_modes_and_hierarchical_args_without_ref() {
        let h = harness(poll_device(), MockOpts::default());
        // Mixing the paged and hierarchical arg families is BAD_ARGS.
        assert_eq!(
            err_code(
                h.commander
                    .browse(None, &json!({ "ref": "root", "cursor": "1" }))
                    .await
            ),
            "BAD_ARGS"
        );
        assert_eq!(
            err_code(
                h.commander
                    .browse(None, &json!({ "ref": "root", "max": 10 }))
                    .await
            ),
            "BAD_ARGS"
        );
        // `depth`/`maxRefs` without `ref` is BAD_ARGS.
        assert_eq!(
            err_code(h.commander.browse(None, &json!({ "depth": 2 })).await),
            "BAD_ARGS"
        );
        assert_eq!(
            err_code(h.commander.browse(None, &json!({ "maxRefs": 10 })).await),
            "BAD_ARGS"
        );
        // A non-string / empty `ref` is BAD_ARGS.
        assert_eq!(
            err_code(h.commander.browse(None, &json!({ "ref": "" })).await),
            "BAD_ARGS"
        );
    }

    // --- sb/pause / sb/resume + reflection through the mock task -----------------------------------

    #[tokio::test]
    async fn pause_and_resume_are_idempotent_and_reflect_through_the_task() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h
            .commander
            .pause(None, &json!({}), Some("site/op".into()))
            .await);
        assert_eq!(out["paused"], json!(true));
        assert_eq!(out["changed"], json!(true));
        assert!(h.health.paused.load(Ordering::Relaxed));
        assert!(h.events.has("adapter-paused"));

        // Idempotent: pausing again is changed:false.
        let out = ok(h.commander.pause(None, &json!({}), None).await);
        assert_eq!(out["changed"], json!(false));

        let out = ok(h.commander.resume(None, &json!({})).await);
        assert_eq!(out["paused"], json!(false));
        assert_eq!(out["changed"], json!(true));
        assert!(!h.health.paused.load(Ordering::Relaxed));
    }

    // --- reconnect --------------------------------------------------------------------------------

    #[tokio::test]
    async fn reconnect_reports_connected_or_maps_failure() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.reconnect(None, &json!({})).await);
        assert_eq!(out["connected"], json!(true));

        let h = harness(
            poll_device(),
            MockOpts {
                reconnect_ok: false,
                ..MockOpts::default()
            },
        );
        assert_eq!(
            err_code(h.commander.reconnect(None, &json!({})).await),
            "RECONNECT_FAILED"
        );
    }

    // --- repoll: poll-only, refused on push and while paused --------------------------------------

    #[tokio::test]
    async fn repoll_polls_all_groups_but_is_refused_on_push_and_while_paused() {
        // Poll happy path: the mock returns a count.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.repoll(None, &json!({})).await);
        assert_eq!(out["polled"], json!(7));

        // Push instance ⇒ BAD_ARGS.
        let hp = harness(push_device(), MockOpts::default());
        assert_eq!(
            err_code(hp.commander.repoll(None, &json!({})).await),
            "BAD_ARGS"
        );

        // Paused poll instance ⇒ the dedicated PAUSED code (resume first, §7.4.7).
        let h = harness(poll_device(), MockOpts::default());
        let _ = h.commander.pause(None, &json!({}), None).await;
        assert_eq!(
            err_code(h.commander.repoll(None, &json!({})).await),
            "PAUSED"
        );
    }

    // --- the describe catalog: 9 verbs + 3 panels -------------------------------------------------

    #[test]
    fn catalog_advertises_nine_verbs_and_three_panels() {
        // The three edge-console panels, in order, instance-scoped, bound to the right verbs (§7.6).
        let panels = panels();
        assert_eq!(panels.len(), 3);
        let ids: Vec<&str> = panels.iter().map(|p| p["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["overview", "signals", "diagnostics"]);
        for (p, order) in panels.iter().zip([10, 20, 30]) {
            assert_eq!(p["order"], json!(order));
            assert_eq!(p["scope"], json!("instance"));
        }
        assert_eq!(
            panels[1]["verbs"],
            json!(["sb/signals", "sb/read", "sb/write", "repoll"])
        );

        // The renderable-descriptor floor: `summary.rows`, `commandSummary.verbs`, a `signalGrid`
        // naming BOTH `signalsVerb` and `subscriptionsVerb` (→ sb/signals) plus `readVerb`, a
        // hierarchical `treeBrowser` with `browseVerb`/`rootRef`, widget-level `scope: "instance"`
        // on the command-backed widgets — and NO widget advertises a `writeVerb` (the guarded-write
        // console flow does not exist).
        let overview = &panels[0]["widgets"];
        assert!(
            overview[0]["rows"]
                .as_array()
                .is_some_and(|r| !r.is_empty()),
            "summary carries rows"
        );
        assert!(
            overview[1]["verbs"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "commandSummary carries verbs"
        );
        let grid = &panels[1]["widgets"][0];
        assert_eq!(grid["kind"], json!("signalGrid"));
        assert_eq!(grid["scope"], json!("instance"));
        assert_eq!(grid["signalsVerb"], json!("sb/signals"));
        assert_eq!(grid["subscriptionsVerb"], json!("sb/signals"));
        assert_eq!(grid["readVerb"], json!("sb/read"));
        let tree = &panels[2]["widgets"][0];
        assert_eq!(tree["kind"], json!("treeBrowser"));
        assert_eq!(tree["scope"], json!("instance"));
        assert_eq!(tree["mode"], json!("hierarchical"));
        assert_eq!(tree["rootRef"], json!("root"));
        assert_eq!(tree["browseVerb"], json!("sb/browse"));
        for p in &panels {
            for w in p["widgets"].as_array().unwrap() {
                assert!(
                    w.get("writeVerb").is_none(),
                    "no widget advertises writeVerb"
                );
            }
        }

        // The nine verbs `register_all` registers == the `EtherNetIpCommand` verb set (§7, §8.6).
        let expected = [
            "sb/status",
            "sb/read",
            "sb/write",
            "sb/signals",
            "sb/browse",
            "sb/pause",
            "sb/resume",
            "reconnect",
            "repoll",
        ];
        assert_eq!(expected.len(), 9);
        let mut got = crate::metrics::COMMAND_VERBS.to_vec();
        let mut want = expected.to_vec();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "the registered verbs match the metric verb dimension set"
        );
    }

    // --- signal-ref resolution + small helpers (pure, no device) ----------------------------------

    #[test]
    fn resolve_poll_ref_handles_names_explicit_tag_paths_and_misses() {
        let cfg = poll_device();
        // A friendly name resolves to the configured spec.
        assert_eq!(
            resolve_poll_ref(&cfg, &json!({ "name": "line-speed" }))
                .unwrap()
                .tag_path,
            "LINE_SPEED"
        );
        // A name that matches nothing is Err (the label rides the BAD entry).
        assert_eq!(
            resolve_poll_ref(&cfg, &json!({ "name": "ghost" })).unwrap_err(),
            PollRefError::Unresolved("ghost".to_string())
        );
        // An explicit {tagPath,type,arrayCount} synthesizes a spec.
        let s = resolve_poll_ref(
            &cfg,
            &json!({ "tagPath": "ADHOC", "type": "dint", "arrayCount": 4 }),
        )
        .unwrap();
        assert_eq!(s.tag_path, "ADHOC");
        assert_eq!(s.array_count, Some(4));
        // An explicit tagPath with no/invalid type is unresolved.
        assert_eq!(
            resolve_poll_ref(&cfg, &json!({ "tagPath": "NOPE" })).unwrap_err(),
            PollRefError::Unresolved("NOPE".to_string())
        );
        // Neither a name nor a tagPath ⇒ the ref label.
        assert_eq!(
            resolve_poll_ref(&cfg, &json!({ "junk": 1 })).unwrap_err(),
            PollRefError::Unresolved("<invalid ref>".to_string())
        );
    }

    #[test]
    fn resolve_push_read_ref_matches_names_and_explicit_input_fields() {
        let cfg = push_device();
        let io = cfg.io.as_ref().unwrap();
        // By name.
        let (id, _) =
            resolve_push_read_ref(io, &cfg.connection, &json!({ "name": "motor-run" })).unwrap();
        assert_eq!(id, "a100/0/udint");
        // By explicit assembly/offset/type.
        let (id2, _) = resolve_push_read_ref(
            io,
            &cfg.connection,
            &json!({ "assembly": 100, "offset": 0, "type": "udint" }),
        )
        .unwrap();
        assert_eq!(id2, "a100/0/udint");
        // Wrong assembly / unknown field ⇒ None.
        assert!(resolve_push_read_ref(
            io,
            &cfg.connection,
            &json!({ "assembly": 999, "offset": 0, "type": "udint" })
        )
        .is_none());
        assert!(resolve_push_read_ref(
            io,
            &cfg.connection,
            &json!({ "assembly": 100, "offset": 4, "type": "real" })
        )
        .is_none());
    }

    #[test]
    fn resolve_push_write_ref_targets_outputs_and_rejects_inputs() {
        let cfg = push_device();
        let io = cfg.io.as_ref().unwrap();
        // Output field by name.
        assert_eq!(
            resolve_push_write_ref(io, &json!({ "name": "fill-setpoint" }))
                .unwrap()
                .0,
            "a150/0/real"
        );
        // Output field by explicit ref.
        assert_eq!(
            resolve_push_write_ref(io, &json!({ "assembly": 150, "offset": 0, "type": "real" }))
                .unwrap()
                .0,
            "a150/0/real"
        );
        // An input field is never writable — by name and by explicit ref.
        assert_eq!(
            resolve_push_write_ref(io, &json!({ "name": "motor-run" }))
                .unwrap_err()
                .1,
            "input field"
        );
        assert_eq!(
            resolve_push_write_ref(
                io,
                &json!({ "assembly": 100, "offset": 0, "type": "udint" })
            )
            .unwrap_err()
            .1,
            "input field"
        );
        // Unknown refs.
        assert_eq!(
            resolve_push_write_ref(io, &json!({ "name": "ghost" }))
                .unwrap_err()
                .1,
            "unresolved ref"
        );
        assert_eq!(
            resolve_push_write_ref(
                io,
                &json!({ "assembly": 150, "offset": 99, "type": "real" })
            )
            .unwrap_err()
            .1,
            "unresolved ref"
        );
        assert_eq!(
            resolve_push_write_ref(io, &json!({ "junk": 1 }))
                .unwrap_err()
                .1,
            "unresolved ref"
        );
    }

    #[test]
    fn ref_label_prefers_name_then_tag_path_then_assembly_form() {
        assert_eq!(ref_label(&json!({ "name": "a" })), "a");
        assert_eq!(ref_label(&json!({ "tagPath": "T" })), "T");
        assert_eq!(
            ref_label(&json!({ "assembly": 100, "offset": 4, "type": "real" })),
            "a100/4/real"
        );
        assert_eq!(ref_label(&json!({ "nope": 1 })), "<invalid ref>");
    }

    #[test]
    fn small_helpers_cover_their_branches() {
        use crate::config::{DeadbandKind, DeadbandSpec};
        assert_eq!(quality_str(Quality::Good), "GOOD");
        assert_eq!(quality_str(Quality::Bad), "BAD");
        assert_eq!(quality_str(Quality::Uncertain), "UNCERTAIN");
        assert_eq!(
            deadband_json(&DeadbandSpec {
                kind: DeadbandKind::Percent,
                value: 1.5
            })["type"],
            json!("percent")
        );
        assert_eq!(
            deadband_json(&DeadbandSpec {
                kind: DeadbandKind::Absolute,
                value: 2.0
            })["type"],
            json!("absolute")
        );
        assert!(type_supported("DINT") && !type_supported("SSTRING"));
        // write_entries: a `writes` array, a single `value` object, or BAD_ARGS.
        assert_eq!(
            write_entries(&json!({ "writes": [ { "value": 1 } ] }))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(write_entries(&json!({ "value": 1 })).unwrap().len(), 1);
        assert_eq!(write_entries(&json!({})).unwrap_err().code, "BAD_ARGS");
    }

    // --- verb error/edge branches through the mock task -------------------------------------------

    #[tokio::test]
    async fn read_poll_maps_a_device_read_failure_and_reads_by_explicit_tag_path() {
        // An explicit {tagPath,type} ref resolves and reads live.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h
            .commander
            .read(
                None,
                &json!({ "signals": [ { "tagPath": "LINE_SPEED", "type": "real" } ] }),
            )
            .await);
        assert_eq!(out["reads"][0]["value"], json!(42.0));

        // A live read that fails at the device ⇒ READ_FAILED.
        let h = harness(
            poll_device(),
            MockOpts {
                read_ok: false,
                ..MockOpts::default()
            },
        );
        assert_eq!(
            err_code(
                h.commander
                    .read(None, &json!({ "signals": [ { "name": "line-speed" } ] }))
                    .await
            ),
            "READ_FAILED"
        );
    }

    /// **An explicit ref's `arrayCount` is bounded, and out of bounds is `BAD_ARGS` (D-EIP-33).**
    /// The truncating `n as u32` this replaces made `2^32 + 1` a one-element read answered GOOD —
    /// wrong data, confidently labelled — and `2^32` a zero-element read whose reply a device may
    /// not frame, which is a bad *command argument* able to poison the session. Both are refused
    /// before any device I/O, and the session survives: the very next read succeeds.
    #[tokio::test]
    async fn read_poll_refuses_an_out_of_bound_array_count_without_bouncing_the_session() {
        let h = harness(poll_device(), MockOpts::default());
        for n in [4_294_967_297u64, 4_294_967_296, 70_000, 0] {
            let reply = h
                .commander
                .read(
                    None,
                    &json!({ "signals": [
                        { "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": n } ] }),
                )
                .await;
            let e = reply.expect_err("an out-of-bound arrayCount is refused");
            assert_eq!(e.code, "BAD_ARGS", "arrayCount {n}");
            assert!(
                e.message.contains("1..=65535"),
                "the refusal names the bound: {}",
                e.message
            );
        }

        // The refusals were arguments, not link failures: the instance still serves reads.
        let out = ok(h
            .commander
            .read(
                None,
                &json!({ "signals": [ { "tagPath": "LINE_SPEED", "type": "real" } ] }),
            )
            .await);
        assert_eq!(out["reads"][0]["value"], json!(42.0));

        // In bounds, the count survives to the spec; an absent/null one is simply a scalar read.
        let out = ok(h
            .commander
            .read(
                None,
                &json!({ "signals": [
                    { "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 65_535 },
                    { "tagPath": "LINE_SPEED", "type": "real", "arrayCount": null } ] }),
            )
            .await);
        assert_eq!(
            out["reads"][0]["signal"]["address"]["arrayCount"],
            json!(65_535)
        );
        assert!(out["reads"][1]["signal"]["address"]
            .get("arrayCount")
            .is_none());
    }

    /// The same bound guards `sb/write`, which resolves refs through the same function — a malformed
    /// argument refuses the whole batch instead of writing part of it (§7.3).
    #[tokio::test]
    async fn write_poll_refuses_an_out_of_bound_array_count_as_bad_args() {
        let h = harness(poll_device(), MockOpts::default());
        let e = h
            .commander
            .write(
                None,
                &json!({ "writes": [ { "tagPath": "FILL_SETPOINT", "type": "real",
                                       "arrayCount": 0, "value": [1.0] } ] }),
            )
            .await
            .expect_err("an out-of-bound arrayCount is refused");
        assert_eq!(e.code, "BAD_ARGS");
        assert!(h.writes.lock().unwrap().is_empty(), "nothing was written");
    }

    #[tokio::test]
    async fn write_poll_reports_missing_value_failed_and_unresolved_entries() {
        // A missing value + an unresolved ref: both fail, and (since not ALL are allow-list refusals)
        // the call returns 200 with per-entry errors.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h
            .commander
            .write(
                None,
                &json!({ "writes": [
            { "name": "fill-setpoint" },              // allow-listed but no value
            { "name": "ghost", "value": 1 }           // unresolved
        ] }),
            )
            .await);
        assert_eq!(out["written"], json!(0));
        let errs: Vec<&str> = out["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["error"].as_str().unwrap())
            .collect();
        assert!(errs.contains(&"missing value"));
        assert!(errs.contains(&"unresolved ref"));

        // A device-rejected write ⇒ the entry is ok:false with the device error.
        let h = harness(
            poll_device(),
            MockOpts {
                write_ok: false,
                ..MockOpts::default()
            },
        );
        let out = ok(h
            .commander
            .write(None, &json!({ "name": "fill-setpoint", "value": 55.5 }))
            .await);
        assert_eq!(out["results"][0]["ok"], json!(false));
        assert_eq!(out["results"][0]["error"], json!("write rejected"));
    }

    #[tokio::test]
    async fn write_push_reports_missing_value_failed_and_unresolved_entries() {
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h
            .commander
            .write(
                None,
                &json!({ "writes": [
            { "name": "fill-setpoint" },   // allow-listed output, no value
            { "name": "ghost", "value": 1 }
        ] }),
            )
            .await);
        assert_eq!(out["written"], json!(0));

        let h = harness(
            push_device(),
            MockOpts {
                write_ok: false,
                ..MockOpts::default()
            },
        );
        let out = ok(h
            .commander
            .write(None, &json!({ "name": "fill-setpoint", "value": 55.5 }))
            .await);
        assert_eq!(
            out["results"][0]["ok"],
            json!(false),
            "staging failure surfaces per-entry"
        );
    }

    #[tokio::test]
    async fn signals_push_lists_input_and_output_fields_with_direction() {
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.signals(None, &json!({})).await);
        assert_eq!(out["mode"], json!("push"));
        let sigs = out["signals"].as_array().unwrap();
        assert!(sigs.iter().any(|s| s["direction"] == json!("input")));
        assert!(sigs
            .iter()
            .any(|s| s["direction"] == json!("output") && s["writable"] == json!(true)));
    }

    #[tokio::test]
    async fn browse_maps_failed_and_pages_array_dim_and_cursor() {
        // A mid-browse failure ⇒ BROWSE_FAILED.
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::Failed,
                ..MockOpts::default()
            },
        );
        assert_eq!(
            err_code(h.commander.browse(None, &json!({})).await),
            "BROWSE_FAILED"
        );

        // A paged reply carries the array-dim tag and the next-cursor.
        let h = harness(
            poll_device(),
            MockOpts {
                browse: BrowseKind::Paged,
                ..MockOpts::default()
            },
        );
        let out = ok(h
            .commander
            .browse(None, &json!({ "cursor": "1", "max": 50 }))
            .await);
        assert_eq!(out["tags"][0]["arrayDim"], json!(1));
        assert_eq!(out["cursor"], json!("42"));
    }

    #[tokio::test]
    async fn repoll_maps_a_device_failure_to_unavailable() {
        let h = harness(
            poll_device(),
            MockOpts {
                repoll_ok: false,
                ..MockOpts::default()
            },
        );
        assert_eq!(
            err_code(h.commander.repoll(None, &json!({})).await),
            "DEVICE_UNAVAILABLE"
        );
    }
}
