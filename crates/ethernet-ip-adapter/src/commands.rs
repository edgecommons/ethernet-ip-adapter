//! # The southbound command surface (§7) — the nine `sb/*` verbs + the three edge-console panels
//!
//! This module owns the whole `gg.commands()` registration: `sb/status`, `sb/read`, `sb/write`,
//! `sb/signals`, `sb/browse`, `sb/pause`, `sb/resume`, `reconnect`, `repoll` — mode-aware (poll vs
//! push), with **instance routing** (D-EIP-13: `body.instance` optional iff exactly one device) and
//! the §7.1 error codes (`BAD_ARGS`, `NO_SUCH_INSTANCE`, `WRITE_NOT_ALLOWED`, `WRITE_FAILED`,
//! `DEVICE_UNAVAILABLE`, `READ_FAILED`, `RECONNECT_FAILED`, `BROWSE_UNSUPPORTED`, `BROWSE_FAILED`).
//!
//! The inbox handlers never touch the (non-`Sync`) session directly: every session-touching verb is
//! sent to the device's own task as a [`DeviceControl`] and *confirmed* through the reply that rides
//! it. The security-critical guarantee lives here: for `sb/write` the **allow-list check happens
//! BEFORE any device I/O** — a refused entry never becomes a [`DeviceControl::Write`]/`WriteOutput`.
//!
//! Three panels (§7.6) are registered via `commands.register_panel` for the edge-console descriptor
//! surface — `overview`, `signals`, `diagnostics`, each `scope: "instance"` with `order` 10/20/30.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use edgecommons::prelude::{command_handler, CommandError, CommandInbox, Severity};
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::app::{BrowseError, DeviceControl, EventSink, Health, LinkState, WriteRequest};
use crate::config::{DeviceConfig, DeviceMode, EipType, GlobalConfig, IoConfig, IoFieldSpec, SignalSpec};
use crate::device::{BrowsePage, Quality, Reading};
use crate::metrics::{CommandTally, DeviceMetrics};

/// The per-device handles the command surface needs: the config (routing, allow-list, address view),
/// the control channel (session-touching verbs), the shared health (status/paused), the metrics
/// emitter (command counters + status snapshot), and the event sink (`write-audit`, §6.3).
pub struct DeviceHandle {
    pub cfg: DeviceConfig,
    pub control: tokio::sync::mpsc::Sender<DeviceControl>,
    pub health: Arc<Health>,
    pub dm: Arc<DeviceMetrics>,
    pub events: Arc<dyn EventSink>,
}

/// Register all nine `sb/*` verbs (§7) + the three edge-console panels (§7.6) on the inbox.
///
/// # Errors
/// Propagates [`CommandInbox::register`] / [`CommandInbox::register_panel`] failures (a verb/panel
/// name clash or an invalid token).
pub fn register_all(
    commands: &CommandInbox,
    handles: Vec<DeviceHandle>,
    global: Arc<GlobalConfig>,
) -> anyhow::Result<()> {
    let commander = Arc::new(Commander::new(handles, global));

    macro_rules! verb {
        ($name:expr, $method:ident) => {{
            let c = Arc::clone(&commander);
            commands.register(
                $name,
                command_handler(move |req| {
                    let c = Arc::clone(&c);
                    async move { c.$method(&req.body).await }
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
            command_handler(move |req| {
                let c = Arc::clone(&c);
                async move {
                    let by = req.identity.as_ref().map(|i| i.path().to_string());
                    c.pause(&req.body, by).await
                }
            }),
        )?;
    }

    for panel in panels() {
        commands.register_panel(panel)?;
    }
    Ok(())
}

/// The three edge-console panel descriptors (§7.6). Core validates `id`/`title`/uniqueness; the rest
/// is console-interpreted (the PHASE3-DESCRIPTOR-PANELS contract), so the widget kinds and bound
/// verbs ride verbatim. `order` 10/20/30 and `scope: "instance"` per the spec.
#[must_use]
pub fn panels() -> Vec<Value> {
    vec![
        json!({
            "id": "overview", "title": "Overview", "order": 10, "scope": "instance",
            "widgets": [
                { "kind": "summary", "fields": ["connected", "state", "paused", "endpoint"] },
                { "kind": "commandSummary", "actions": ["sb/pause", "sb/resume", "reconnect"] }
            ],
            "verbs": ["sb/status", "sb/pause", "sb/resume", "reconnect"]
        }),
        json!({
            "id": "signals", "title": "Signals", "order": 20, "scope": "instance",
            "widgets": [ { "kind": "signalGrid" } ],
            "verbs": ["sb/signals", "sb/read", "sb/write", "repoll"]
        }),
        json!({
            "id": "diagnostics", "title": "Diagnostics", "order": 30, "scope": "instance",
            "widgets": [ { "kind": "treeBrowser" }, { "kind": "keyValueList" } ],
            "verbs": ["sb/browse", "sb/status"]
        }),
    ]
}

/// The command dispatcher: owns the per-device handles + the config order (for the single-instance
/// default) and the shared global (effective poll/publish resolution for `sb/signals`).
struct Commander {
    devices: HashMap<String, DeviceHandle>,
    ids: Vec<String>,
    global: Arc<GlobalConfig>,
}

type Reply = std::result::Result<Option<Value>, CommandError>;

impl Commander {
    fn new(handles: Vec<DeviceHandle>, global: Arc<GlobalConfig>) -> Self {
        let ids: Vec<String> = handles.iter().map(|h| h.cfg.id.clone()).collect();
        let devices = handles.into_iter().map(|h| (h.cfg.id.clone(), h)).collect();
        Self { devices, ids, global }
    }

    /// Route to the addressed device (D-EIP-13): `body.instance` optional iff exactly one device is
    /// configured; with ≥ 2 a missing/unknown id is `BAD_ARGS`/`NO_SUCH_INSTANCE`.
    fn resolve(&self, body: &Value) -> std::result::Result<&DeviceHandle, CommandError> {
        match body.get("instance").and_then(|v| v.as_str()) {
            Some(id) => self
                .devices
                .get(id)
                .ok_or_else(|| CommandError::new("NO_SUCH_INSTANCE", format!("no configured device `{id}`"))),
            None => {
                if self.ids.len() == 1 {
                    Ok(self.devices.get(&self.ids[0]).expect("one device"))
                } else {
                    Err(CommandError::new(
                        "BAD_ARGS",
                        "field `instance` is required when multiple devices are configured",
                    ))
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // sb/status (§7.1)
    // ---------------------------------------------------------------------------------------------
    async fn status(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let link = h.health.link();
        let connected = link == LinkState::Online;
        let paused = h.health.paused.load(Ordering::Relaxed);
        let state = if paused && connected { "PAUSED" } else { link.as_str() };
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
    async fn read(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let refs = body
            .get("signals")
            .and_then(|v| v.as_array())
            .ok_or_else(|| CommandError::new("BAD_ARGS", "expected a `signals` array"))?;
        let result = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.read_push(h, refs).await
        } else {
            self.read_poll(h, refs).await
        };
        let (ok, served) = match &result {
            Ok((_, n)) => (true, *n),
            Err(_) => (false, 0),
        };
        h.dm.record_command(
            "sb/read",
            ok,
            ms(started),
            CommandTally { read_signals: served, ..CommandTally::default() },
        );
        result.map(|(v, _)| Some(v))
    }

    async fn read_poll(&self, h: &DeviceHandle, refs: &[Value]) -> std::result::Result<(Value, u64), CommandError> {
        // Resolve each ref: a friendly name → the configured spec; an explicit {tagPath,type} → a
        // synthesized spec; anything else → a BAD "UNRESOLVED_REF" entry.
        let mut plan: Vec<std::result::Result<SignalSpec, String>> = Vec::with_capacity(refs.len());
        let mut specs: Vec<SignalSpec> = Vec::new();
        for r in refs {
            match resolve_poll_ref(&h.cfg, r) {
                Ok(spec) => {
                    specs.push(spec.clone());
                    plan.push(Ok(spec));
                }
                Err(label) => plan.push(Err(label)),
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

    async fn read_push(&self, h: &DeviceHandle, refs: &[Value]) -> std::result::Result<(Value, u64), CommandError> {
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
            .map(|s| s.readings.iter().map(|r| (r.signal_id.as_str(), r)).collect())
            .unwrap_or_default();
        let ts = snapshot
            .as_ref()
            .map(|s| iso_ago(s.received_at))
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
    async fn write(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let entries = write_entries(body)?;
        let result = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.write_push(h, &entries).await
        } else {
            self.write_poll(h, &entries).await
        };
        let (ok, attempted, failures) = match &result {
            Ok((_, tally)) => (true, tally.write_signals, tally.write_failures),
            Err(_) => (false, entries.len() as u64, entries.len() as u64),
        };
        h.dm.record_command(
            "sb/write",
            ok,
            ms(started),
            CommandTally { write_signals: attempted, write_failures: failures, ..CommandTally::default() },
        );
        result.map(|(v, _)| Some(v))
    }

    async fn write_poll(&self, h: &DeviceHandle, entries: &[Value]) -> std::result::Result<(Value, CommandTally), CommandError> {
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
                        self.audit(h, &id, false, value.as_ref(), Some("not in writes.allow")).await;
                        results.push(json!({ "signal": id, "ok": false, "error": "not in writes.allow" }));
                        continue;
                    }
                    let Some(value) = value else {
                        failures += 1;
                        self.audit(h, &id, false, None, Some("missing value")).await;
                        results.push(json!({ "signal": id, "ok": false, "error": "missing value" }));
                        continue;
                    };
                    let (tx, rx) = oneshot::channel();
                    h.control
                        .send(DeviceControl::Write(WriteRequest { signal: spec, value: value.clone(), ack: tx }))
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
                            results.push(json!({ "signal": id, "value": value, "ok": false, "error": e }));
                        }
                        Err(_) => return Err(device_unavailable()),
                    }
                }
                Err(label) => {
                    failures += 1;
                    self.audit(h, &label, false, value.as_ref(), Some("unresolved ref")).await;
                    results.push(json!({ "signal": label, "ok": false, "error": "unresolved ref" }));
                }
            }
        }

        // WRITE_NOT_ALLOWED only when EVERY entry was an allow-list refusal (§7.3).
        if attempted > 0 && refused == attempted {
            return Err(CommandError::new("WRITE_NOT_ALLOWED", "no entry is in this instance's writes.allow list"));
        }
        Ok((
            json!({ "id": h.cfg.id, "written": written, "results": results }),
            CommandTally { write_signals: attempted, write_failures: failures, ..CommandTally::default() },
        ))
    }

    async fn write_push(&self, h: &DeviceHandle, entries: &[Value]) -> std::result::Result<(Value, CommandTally), CommandError> {
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
                        self.audit(h, &id, false, value.as_ref(), Some("not in writes.allow")).await;
                        results.push(json!({ "signal": id, "ok": false, "error": "not in writes.allow" }));
                        continue;
                    }
                    let Some(value) = value else {
                        failures += 1;
                        self.audit(h, &id, false, None, Some("missing value")).await;
                        results.push(json!({ "signal": id, "ok": false, "error": "missing value" }));
                        continue;
                    };
                    let (tx, rx) = oneshot::channel();
                    h.control
                        .send(DeviceControl::WriteOutput { field, value: value.clone(), reply: tx })
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
                            results.push(json!({ "signal": id, "value": value, "ok": false, "error": e }));
                        }
                        Err(_) => return Err(device_unavailable()),
                    }
                }
                Err((label, err)) => {
                    failures += 1;
                    self.audit(h, &label, false, value.as_ref(), Some(&err)).await;
                    results.push(json!({ "signal": label, "ok": false, "error": err }));
                }
            }
        }

        if attempted > 0 && refused == attempted {
            return Err(CommandError::new("WRITE_NOT_ALLOWED", "no entry is in this instance's writes.allow list"));
        }
        Ok((
            json!({ "id": h.cfg.id, "written": written, "results": results }),
            CommandTally { write_signals: attempted, write_failures: failures, ..CommandTally::default() },
        ))
    }

    /// The `write-audit` event for one `sb/write` entry (§6.3) — Info on success, Warning on failure
    /// or allow-list refusal.
    async fn audit(&self, h: &DeviceHandle, signal_id: &str, ok: bool, value: Option<&Value>, error: Option<&str>) {
        let severity = if ok { Severity::Info } else { Severity::Warning };
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
        h.events.emit(severity, "write-audit", None, Some(Value::Object(ctx))).await;
    }

    // ---------------------------------------------------------------------------------------------
    // sb/signals (§7.5) — the resolved config view, no device I/O
    // ---------------------------------------------------------------------------------------------
    async fn signals(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let out = if matches!(h.cfg.mode, DeviceMode::Push) {
            self.signals_push(h)
        } else {
            self.signals_poll(h)
        };
        h.dm.record_command("sb/signals", true, ms(started), CommandTally::default());
        Ok(Some(out))
    }

    fn signals_poll(&self, h: &DeviceHandle) -> Value {
        let mut signals = Vec::new();
        for g in &h.cfg.poll_groups {
            let group = g.id.clone().unwrap_or_default();
            let interval = h.cfg.effective_poll_ms(g, &self.global);
            let mode = h.cfg.effective_publish_mode(g, &self.global).as_str();
            for s in &g.signals {
                signals.push(json!({
                    "name": s.name,
                    "id": s.tag_path,
                    "address": s.address_json(&h.cfg.connection),
                    "pollGroup": group,
                    "pollIntervalMs": interval,
                    "publishMode": mode,
                    "writable": h.cfg.writes.permits(&s.tag_path),
                    "deadband": deadband_json(&s.deadband),
                }));
            }
        }
        json!({ "id": h.cfg.id, "mode": "poll", "signals": signals })
    }

    fn signals_push(&self, h: &DeviceHandle) -> Value {
        let mut signals = Vec::new();
        let mode = h
            .cfg
            .defaults
            .publish_mode
            .or(self.global.defaults.publish_mode)
            .unwrap_or(crate::config::PublishMode::OnChange)
            .as_str();
        if let Some(io) = h.cfg.io.as_ref() {
            let in_asm = io.assemblies.input;
            for f in &io.input.signals {
                signals.push(field_signal(f, in_asm, "input", mode, &h.cfg, &h.cfg.connection));
            }
            let out_asm = io.assemblies.output;
            if let Some(out) = io.output.as_ref() {
                for f in &out.signals {
                    signals.push(field_signal(f, out_asm, "output", mode, &h.cfg, &h.cfg.connection));
                }
            }
        }
        json!({ "id": h.cfg.id, "mode": "push", "signals": signals })
    }

    // ---------------------------------------------------------------------------------------------
    // sb/browse (§7.5) — poll = paged list_tags; push = the configured assembly layout
    // ---------------------------------------------------------------------------------------------
    async fn browse(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let cursor = body.get("cursor").and_then(|v| v.as_str()).map(str::to_string);
        let max = body.get("max").and_then(|v| v.as_u64()).unwrap_or(200).clamp(1, 1000) as usize;

        let result: std::result::Result<Value, CommandError> = if matches!(h.cfg.mode, DeviceMode::Push) {
            Ok(browse_push_layout(h))
        } else {
            let (tx, rx) = oneshot::channel();
            h.control
                .send(DeviceControl::Browse { cursor, max, reply: tx })
                .await
                .map_err(|_| device_unavailable())?;
            match rx.await {
                Ok(Ok(page)) => Ok(browse_page_json(h, page)),
                Ok(Err(BrowseError::Unsupported)) => {
                    Err(CommandError::new("BROWSE_UNSUPPORTED", "device has no tag-list service"))
                }
                Ok(Err(BrowseError::Failed(e))) => Err(CommandError::new("BROWSE_FAILED", e)),
                Err(_) => Err(device_unavailable()),
            }
        };

        let (ok, browsed) = match &result {
            Ok(v) => (true, v.get("tags").and_then(|t| t.as_array()).map_or(0, Vec::len) as u64),
            Err(_) => (false, 0),
        };
        h.dm.record_command(
            "sb/browse",
            ok,
            ms(started),
            CommandTally { browsed_tags: browsed, ..CommandTally::default() },
        );
        result.map(Some)
    }

    // ---------------------------------------------------------------------------------------------
    // sb/pause + sb/resume (§7.4) — idempotent {paused, changed}, both modes
    // ---------------------------------------------------------------------------------------------
    async fn pause(&self, body: &Value, by: Option<String>) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Pause { by, reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let changed = rx.await.map_err(|_| device_unavailable())?;
        h.dm.record_command("sb/pause", true, ms(started), CommandTally::default());
        Ok(Some(json!({ "id": h.cfg.id, "paused": true, "changed": changed })))
    }

    async fn resume(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        h.control
            .send(DeviceControl::Resume { reply: tx })
            .await
            .map_err(|_| device_unavailable())?;
        let changed = rx.await.map_err(|_| device_unavailable())?;
        h.dm.record_command("sb/resume", true, ms(started), CommandTally::default());
        Ok(Some(json!({ "id": h.cfg.id, "paused": false, "changed": changed })))
    }

    // ---------------------------------------------------------------------------------------------
    // reconnect (§7.5)
    // ---------------------------------------------------------------------------------------------
    async fn reconnect(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
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
    // repoll (§7.5) — poll only, refused on push and while paused
    // ---------------------------------------------------------------------------------------------
    async fn repoll(&self, body: &Value) -> Reply {
        let h = self.resolve(body)?;
        let started = Instant::now();
        if matches!(h.cfg.mode, DeviceMode::Push) {
            h.dm.record_command("repoll", false, ms(started), CommandTally::default());
            return Err(CommandError::new("BAD_ARGS", "push instance - data arrives cyclically"));
        }
        if h.health.paused.load(Ordering::Relaxed) {
            h.dm.record_command("repoll", false, ms(started), CommandTally::default());
            return Err(CommandError::new("BAD_ARGS", "instance is paused - resume first"));
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
                Err(CommandError::new("BAD_ARGS", e))
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

/// Resolve a poll `sb/read`/`sb/write` signal-ref (§7.2): a friendly `{"name"}` → the configured
/// signal; an explicit `{"tagPath","type","arrayCount"?}` → a synthesized [`SignalSpec`]. `Err` carries
/// the ref label for the BAD/unresolved entry.
fn resolve_poll_ref(cfg: &DeviceConfig, r: &Value) -> std::result::Result<SignalSpec, String> {
    if let Some(name) = r.get("name").and_then(|v| v.as_str()) {
        return cfg.signals().find(|s| s.name == name).cloned().ok_or_else(|| name.to_string());
    }
    if let Some(tag) = r.get("tagPath").and_then(|v| v.as_str()) {
        let ty = r.get("type").and_then(|v| v.as_str()).and_then(parse_eip_type);
        return match ty {
            Some(eip_type) => Ok(SignalSpec {
                name: tag.to_string(),
                tag_path: tag.to_string(),
                eip_type,
                array_count: r.get("arrayCount").and_then(|v| v.as_u64()).map(|n| n as u32),
                scale: None,
                offset: None,
                deadband: crate::config::DeadbandSpec::default(),
            }),
            None => Err(tag.to_string()),
        };
    }
    Err(ref_label(r))
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
    let ty = r.get("type").and_then(|v| v.as_str()).and_then(parse_eip_type)?;
    let bit = r.get("bit").and_then(|v| v.as_u64()).map(|b| b as u8);
    let f = io.input.signals.iter().find(|f| f.offset == off && f.eip_type == ty && f.bit == bit)?;
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
    let ty = r.get("type").and_then(|v| v.as_str()).and_then(parse_eip_type);
    let bit = r.get("bit").and_then(|v| v.as_u64()).map(|b| b as u8);
    let (Some(asm), Some(off), Some(ty)) = (asm, off, ty) else {
        return Err((ref_label(r), "unresolved ref".to_string()));
    };
    if asm == in_asm {
        return Err((format!("a{in_asm}/{off}/{}", ty.wire()), "input field".to_string()));
    }
    if let Some(out) = io.output.as_ref() {
        if let Some(f) = out.signals.iter().find(|f| f.offset == off && f.eip_type == ty && f.bit == bit) {
            return Ok((f.signal_id(out_asm), f.clone()));
        }
    }
    Err((format!("a{asm}/{off}/{}", ty.wire()), "unresolved ref".to_string()))
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
                "supported": type_supported(&t.type_name),
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
/// fields), no device round-trip.
fn browse_push_layout(h: &DeviceHandle) -> Value {
    let mut tags = Vec::new();
    if let Some(io) = h.cfg.io.as_ref() {
        for f in &io.input.signals {
            tags.push(layout_tag(f, io.assemblies.input, "input"));
        }
        if let Some(out) = io.output.as_ref() {
            for f in &out.signals {
                tags.push(layout_tag(f, io.assemblies.output, "output"));
            }
        }
    }
    json!({ "id": h.cfg.id, "tags": tags })
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

/// Whether a browsed CIP type name is decodable per §5.1 (an elementary scalar). Structures / STRING /
/// SSTRING / unknown codes are `false`.
fn type_supported(type_name: &str) -> bool {
    matches!(
        type_name,
        "BOOL" | "SINT" | "USINT" | "INT" | "UINT" | "DINT" | "UDINT" | "LINT" | "ULINT" | "REAL" | "LREAL"
    )
}

/// An RFC-3339 timestamp for a snapshot accepted `ago` before now — the push read `serverTs` (§7.2).
fn iso_ago(received: Instant) -> String {
    let ago = Instant::now().saturating_duration_since(received);
    let dt = time::OffsetDateTime::now_utc() - time::Duration::try_from(ago).unwrap_or(time::Duration::ZERO);
    dt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
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
    Err(CommandError::new("BAD_ARGS", "expected a `writes` array or a single write object with `value`"))
}

#[cfg(test)]
mod tests {
    //! §12.3 command surface: every verb happy path + error codes + single-instance default; the
    //! allow-list refusal proven to happen BEFORE any device I/O; confirmed/push writes; poll-live vs
    //! push-snapshot reads; repoll refusals; browse mapping; the catalog. A mock device task services
    //! the control channel and RECORDS every write that reaches it — no PLC, no socket.
    use super::*;
    use std::sync::Mutex;

    use tokio::sync::mpsc;

    use crate::app::{apply_pause, Health, LinkState};
    use crate::config::GlobalConfig;
    use crate::device::{BrowsedTag, InputSnapshot};
    use crate::testutil::{device_metrics, RecordingEvents};

    fn dev(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).unwrap()
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
        /// A page carrying an array-dim tag and a next-cursor (§7.5 paging).
        Paged,
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
                        t_writes.lock().unwrap().push((req.signal.tag_path.clone(), req.value.clone()));
                        let _ = req.ack.send(if opts.write_ok { Ok(()) } else { Err("write rejected".into()) });
                    }
                    DeviceControl::WriteOutput { field, value, reply } => {
                        t_writes.lock().unwrap().push((field.name.clone(), value.clone()));
                        let _ = reply.send(if opts.write_ok { Ok(()) } else { Err("staging failed".into()) });
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
                        let c = apply_pause(&t_cfg, &t_health, &t_dm, t_events.as_ref(), true, by.as_deref()).await;
                        let _ = reply.send(c);
                    }
                    DeviceControl::Resume { reply } => {
                        let c = apply_pause(&t_cfg, &t_health, &t_dm, t_events.as_ref(), false, None).await;
                        let _ = reply.send(c);
                    }
                    DeviceControl::Reconnect { reply } => {
                        let _ = reply.send(if opts.reconnect_ok { Ok(()) } else { Err("no route to host".into()) });
                    }
                    DeviceControl::Repoll { reply } => {
                        let _ = reply.send(if opts.repoll_ok { Ok(7) } else { Err("link error".into()) });
                    }
                    DeviceControl::Browse { reply, .. } => match &opts.browse {
                        BrowseKind::Unsupported => {
                            let _ = reply.send(Err(BrowseError::Unsupported));
                        }
                        BrowseKind::Failed => {
                            let _ = reply.send(Err(BrowseError::Failed("mid-browse link error".into())));
                        }
                        BrowseKind::Paged => {
                            // An array tag + a next-cursor exercise the arrayDim + cursor reply keys.
                            let tags = vec![BrowsedTag {
                                name: "ZONE_TEMPS".to_string(),
                                type_name: "REAL".to_string(),
                                array_dim: Some(8),
                                instance_id: 1,
                            }];
                            let _ = reply.send(Ok(BrowsePage { tags, next_cursor: Some("42".into()) }));
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
                            let _ = reply.send(Ok(BrowsePage { tags, next_cursor: None }));
                        }
                    },
                }
            }
        });

        let handle = DeviceHandle { cfg, control: tx, health: Arc::clone(&health), dm, events };
        let commander = Arc::new(Commander::new(vec![handle], Arc::new(GlobalConfig::default())));
        Harness { commander, writes, events: events_rec, health, _task: task }
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
        // Single device: `instance` may be omitted.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.status(&json!({})).await);
        assert_eq!(out["id"], json!("filler-plc"));
        // An unknown id is NO_SUCH_INSTANCE.
        assert_eq!(err_code(h.commander.status(&json!({ "instance": "nope" })).await), "NO_SUCH_INSTANCE");

        // Two devices: a missing `instance` is BAD_ARGS.
        let mk = |cfg: DeviceConfig| {
            let (tx, _rx) = mpsc::channel(1);
            let health = Arc::new(Health::default());
            let (_m, dm) = device_metrics(cfg.clone(), Arc::clone(&health));
            let events: Arc<dyn EventSink> = Arc::new(RecordingEvents::default());
            DeviceHandle { cfg, control: tx, health, dm, events }
        };
        let mut b = poll_device();
        b.id = "second".into();
        let multi = Commander::new(vec![mk(poll_device()), mk(b)], Arc::new(GlobalConfig::default()));
        assert_eq!(err_code(multi.status(&json!({})).await), "BAD_ARGS");
    }

    // --- sb/status ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn status_reports_connected_state_paused_and_a_counter_snapshot() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.status(&json!({})).await);
        assert_eq!(out["connected"], json!(true));
        assert_eq!(out["state"], json!("ONLINE"));
        assert_eq!(out["paused"], json!(false));
        assert_eq!(out["adapter"], json!("sim"));
        assert!(out["metrics"].get("read").is_some() && out["metrics"].get("write").is_some());

        // A push instance's status additionally carries the `io` object (§7.1).
        let hp = harness(push_device(), MockOpts::default());
        let out = ok(hp.commander.status(&json!({})).await);
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
                .write(&json!({ "name": "line-speed", "value": 12.0 }))
                .await,
        );
        assert_eq!(code, "WRITE_NOT_ALLOWED");
        // THE GUARANTEE: no write ever reached the device task.
        assert!(h.writes.lock().unwrap().is_empty(), "a refused write must not reach device I/O");
        // The refusal is still audited on evt (§6.3).
        assert!(h.events.has("write-audit"));
        let ctx = h.events.last_ctx("write-audit").unwrap();
        assert_eq!(ctx["ok"], json!(false));
        assert_eq!(ctx["signalId"], json!("LINE_SPEED"));
    }

    #[tokio::test]
    async fn a_confirmed_allowed_write_reaches_the_device_and_acks() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(
            h.commander
                .write(&json!({ "writes": [ { "name": "fill-setpoint", "value": 55.5 } ] }))
                .await,
        );
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
        let out = ok(
            h.commander
                .write(&json!({ "name": "fill-setpoint", "value": 55.5 }))
                .await,
        );
        assert_eq!(out["written"], json!(1));
        assert_eq!(out["results"][0]["ok"], json!(true));
        assert_eq!(out["results"][0]["applied"], json!("next-frame"), "push write confirmation honesty");
        assert_eq!(h.writes.lock().unwrap().len(), 1, "it reached the output assembly");

        // An INPUT field is never writable (§7.3), even by explicit ref.
        let out = ok(
            h.commander
                .write(&json!({ "assembly": 100, "offset": 0, "type": "udint", "value": 1 }))
                .await,
        );
        assert_eq!(out["results"][0]["ok"], json!(false));
        assert_eq!(out["results"][0]["error"], json!("input field"));
    }

    // --- sb/read: poll live vs push snapshot ------------------------------------------------------

    #[tokio::test]
    async fn read_poll_is_a_live_read_and_unresolved_refs_come_back_bad() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(
            h.commander
                .read(&json!({ "signals": [ { "name": "line-speed" }, { "name": "ghost" } ] }))
                .await,
        );
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
            }],
            received_at: Instant::now(),
            run_mode: true,
        };
        let h = harness(push_device(), MockOpts { snapshot: Some(snapshot), ..MockOpts::default() });
        let out = ok(h.commander.read(&json!({ "signals": [ { "name": "motor-run" } ] })).await);
        assert_eq!(out["reads"][0]["value"], json!(7), "answered from the snapshot, no round-trip");
        assert_eq!(out["reads"][0]["quality"], json!("GOOD"));

        // No frame yet ⇒ BAD/NO_FRAME (§7.2).
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.read(&json!({ "signals": [ { "name": "motor-run" } ] })).await);
        assert_eq!(out["reads"][0]["qualityRaw"], json!("NO_FRAME"));
    }

    // --- sb/signals -------------------------------------------------------------------------------

    #[tokio::test]
    async fn signals_is_the_resolved_config_view_with_writable_flags() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.signals(&json!({})).await);
        let sigs = out["signals"].as_array().unwrap();
        let setpoint = sigs.iter().find(|s| s["id"] == json!("FILL_SETPOINT")).unwrap();
        assert_eq!(setpoint["writable"], json!(true), "allow-listed ⇒ writable");
        let speed = sigs.iter().find(|s| s["id"] == json!("LINE_SPEED")).unwrap();
        assert_eq!(speed["writable"], json!(false));
        assert!(speed.get("pollGroup").is_some() && speed.get("pollIntervalMs").is_some());
    }

    // --- sb/browse --------------------------------------------------------------------------------

    #[tokio::test]
    async fn browse_pages_tags_for_poll_and_maps_unsupported() {
        // Poll: a page of tags, with configured/supported flags.
        let opts = MockOpts { browse: BrowseKind::Tags(vec![("LINE_SPEED", "REAL"), ("RECIPE", "SSTRING")]), ..MockOpts::default() };
        let h = harness(poll_device(), opts);
        let out = ok(h.commander.browse(&json!({})).await);
        let tags = out["tags"].as_array().unwrap();
        assert_eq!(tags[0]["configured"], json!(true), "LINE_SPEED is in config");
        assert_eq!(tags[0]["supported"], json!(true));
        assert_eq!(tags[1]["supported"], json!(false), "SSTRING is undecodable");

        // A device with no tag-list service ⇒ BROWSE_UNSUPPORTED.
        let h = harness(poll_device(), MockOpts { browse: BrowseKind::Unsupported, ..MockOpts::default() });
        assert_eq!(err_code(h.commander.browse(&json!({})).await), "BROWSE_UNSUPPORTED");

        // Push: the configured assembly layout, no round-trip.
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.browse(&json!({})).await);
        assert!(!out["tags"].as_array().unwrap().is_empty());
    }

    // --- sb/pause / sb/resume + reflection through the mock task -----------------------------------

    #[tokio::test]
    async fn pause_and_resume_are_idempotent_and_reflect_through_the_task() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.pause(&json!({}), Some("site/op".into())).await);
        assert_eq!(out["paused"], json!(true));
        assert_eq!(out["changed"], json!(true));
        assert!(h.health.paused.load(Ordering::Relaxed));
        assert!(h.events.has("adapter-paused"));

        // Idempotent: pausing again is changed:false.
        let out = ok(h.commander.pause(&json!({}), None).await);
        assert_eq!(out["changed"], json!(false));

        let out = ok(h.commander.resume(&json!({})).await);
        assert_eq!(out["paused"], json!(false));
        assert_eq!(out["changed"], json!(true));
        assert!(!h.health.paused.load(Ordering::Relaxed));
    }

    // --- reconnect --------------------------------------------------------------------------------

    #[tokio::test]
    async fn reconnect_reports_connected_or_maps_failure() {
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.reconnect(&json!({})).await);
        assert_eq!(out["connected"], json!(true));

        let h = harness(poll_device(), MockOpts { reconnect_ok: false, ..MockOpts::default() });
        assert_eq!(err_code(h.commander.reconnect(&json!({})).await), "RECONNECT_FAILED");
    }

    // --- repoll: poll-only, refused on push and while paused --------------------------------------

    #[tokio::test]
    async fn repoll_polls_all_groups_but_is_refused_on_push_and_while_paused() {
        // Poll happy path: the mock returns a count.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.repoll(&json!({})).await);
        assert_eq!(out["polled"], json!(7));

        // Push instance ⇒ BAD_ARGS.
        let hp = harness(push_device(), MockOpts::default());
        assert_eq!(err_code(hp.commander.repoll(&json!({})).await), "BAD_ARGS");

        // Paused poll instance ⇒ BAD_ARGS (resume first, §7.4.7).
        let h = harness(poll_device(), MockOpts::default());
        let _ = h.commander.pause(&json!({}), None).await;
        assert_eq!(err_code(h.commander.repoll(&json!({})).await), "BAD_ARGS");
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
        assert_eq!(panels[1]["verbs"], json!(["sb/signals", "sb/read", "sb/write", "repoll"]));

        // The nine verbs `register_all` registers == the `EtherNetIpCommand` verb set (§7, §8.6).
        let expected = [
            "sb/status", "sb/read", "sb/write", "sb/signals", "sb/browse", "sb/pause", "sb/resume",
            "reconnect", "repoll",
        ];
        assert_eq!(expected.len(), 9);
        let mut got = crate::metrics::COMMAND_VERBS.to_vec();
        let mut want = expected.to_vec();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "the registered verbs match the metric verb dimension set");
    }

    // --- signal-ref resolution + small helpers (pure, no device) ----------------------------------

    #[test]
    fn resolve_poll_ref_handles_names_explicit_tag_paths_and_misses() {
        let cfg = poll_device();
        // A friendly name resolves to the configured spec.
        assert_eq!(resolve_poll_ref(&cfg, &json!({ "name": "line-speed" })).unwrap().tag_path, "LINE_SPEED");
        // A name that matches nothing is Err (the label rides the BAD entry).
        assert_eq!(resolve_poll_ref(&cfg, &json!({ "name": "ghost" })).unwrap_err(), "ghost");
        // An explicit {tagPath,type,arrayCount} synthesizes a spec.
        let s = resolve_poll_ref(&cfg, &json!({ "tagPath": "ADHOC", "type": "dint", "arrayCount": 4 })).unwrap();
        assert_eq!(s.tag_path, "ADHOC");
        assert_eq!(s.array_count, Some(4));
        // An explicit tagPath with no/invalid type is unresolved.
        assert_eq!(resolve_poll_ref(&cfg, &json!({ "tagPath": "NOPE" })).unwrap_err(), "NOPE");
        // Neither a name nor a tagPath ⇒ the ref label.
        assert_eq!(resolve_poll_ref(&cfg, &json!({ "junk": 1 })).unwrap_err(), "<invalid ref>");
    }

    #[test]
    fn resolve_push_read_ref_matches_names_and_explicit_input_fields() {
        let cfg = push_device();
        let io = cfg.io.as_ref().unwrap();
        // By name.
        let (id, _) = resolve_push_read_ref(io, &cfg.connection, &json!({ "name": "motor-run" })).unwrap();
        assert_eq!(id, "a100/0/udint");
        // By explicit assembly/offset/type.
        let (id2, _) = resolve_push_read_ref(io, &cfg.connection, &json!({ "assembly": 100, "offset": 0, "type": "udint" })).unwrap();
        assert_eq!(id2, "a100/0/udint");
        // Wrong assembly / unknown field ⇒ None.
        assert!(resolve_push_read_ref(io, &cfg.connection, &json!({ "assembly": 999, "offset": 0, "type": "udint" })).is_none());
        assert!(resolve_push_read_ref(io, &cfg.connection, &json!({ "assembly": 100, "offset": 4, "type": "real" })).is_none());
    }

    #[test]
    fn resolve_push_write_ref_targets_outputs_and_rejects_inputs() {
        let cfg = push_device();
        let io = cfg.io.as_ref().unwrap();
        // Output field by name.
        assert_eq!(resolve_push_write_ref(io, &json!({ "name": "fill-setpoint" })).unwrap().0, "a150/0/real");
        // Output field by explicit ref.
        assert_eq!(resolve_push_write_ref(io, &json!({ "assembly": 150, "offset": 0, "type": "real" })).unwrap().0, "a150/0/real");
        // An input field is never writable — by name and by explicit ref.
        assert_eq!(resolve_push_write_ref(io, &json!({ "name": "motor-run" })).unwrap_err().1, "input field");
        assert_eq!(resolve_push_write_ref(io, &json!({ "assembly": 100, "offset": 0, "type": "udint" })).unwrap_err().1, "input field");
        // Unknown refs.
        assert_eq!(resolve_push_write_ref(io, &json!({ "name": "ghost" })).unwrap_err().1, "unresolved ref");
        assert_eq!(resolve_push_write_ref(io, &json!({ "assembly": 150, "offset": 99, "type": "real" })).unwrap_err().1, "unresolved ref");
        assert_eq!(resolve_push_write_ref(io, &json!({ "junk": 1 })).unwrap_err().1, "unresolved ref");
    }

    #[test]
    fn ref_label_prefers_name_then_tag_path_then_assembly_form() {
        assert_eq!(ref_label(&json!({ "name": "a" })), "a");
        assert_eq!(ref_label(&json!({ "tagPath": "T" })), "T");
        assert_eq!(ref_label(&json!({ "assembly": 100, "offset": 4, "type": "real" })), "a100/4/real");
        assert_eq!(ref_label(&json!({ "nope": 1 })), "<invalid ref>");
    }

    #[test]
    fn small_helpers_cover_their_branches() {
        use crate::config::{DeadbandKind, DeadbandSpec};
        assert_eq!(quality_str(Quality::Good), "GOOD");
        assert_eq!(quality_str(Quality::Bad), "BAD");
        assert_eq!(quality_str(Quality::Uncertain), "UNCERTAIN");
        assert_eq!(deadband_json(&DeadbandSpec { kind: DeadbandKind::Percent, value: 1.5 })["type"], json!("percent"));
        assert_eq!(deadband_json(&DeadbandSpec { kind: DeadbandKind::Absolute, value: 2.0 })["type"], json!("absolute"));
        assert!(type_supported("DINT") && !type_supported("SSTRING"));
        // write_entries: a `writes` array, a single `value` object, or BAD_ARGS.
        assert_eq!(write_entries(&json!({ "writes": [ { "value": 1 } ] })).unwrap().len(), 1);
        assert_eq!(write_entries(&json!({ "value": 1 })).unwrap().len(), 1);
        assert_eq!(write_entries(&json!({})).unwrap_err().code, "BAD_ARGS");
    }

    // --- verb error/edge branches through the mock task -------------------------------------------

    #[tokio::test]
    async fn read_poll_maps_a_device_read_failure_and_reads_by_explicit_tag_path() {
        // An explicit {tagPath,type} ref resolves and reads live.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.read(&json!({ "signals": [ { "tagPath": "LINE_SPEED", "type": "real" } ] })).await);
        assert_eq!(out["reads"][0]["value"], json!(42.0));

        // A live read that fails at the device ⇒ READ_FAILED.
        let h = harness(poll_device(), MockOpts { read_ok: false, ..MockOpts::default() });
        assert_eq!(err_code(h.commander.read(&json!({ "signals": [ { "name": "line-speed" } ] })).await), "READ_FAILED");
    }

    #[tokio::test]
    async fn write_poll_reports_missing_value_failed_and_unresolved_entries() {
        // A missing value + an unresolved ref: both fail, and (since not ALL are allow-list refusals)
        // the call returns 200 with per-entry errors.
        let h = harness(poll_device(), MockOpts::default());
        let out = ok(h.commander.write(&json!({ "writes": [
            { "name": "fill-setpoint" },              // allow-listed but no value
            { "name": "ghost", "value": 1 }           // unresolved
        ] })).await);
        assert_eq!(out["written"], json!(0));
        let errs: Vec<&str> = out["results"].as_array().unwrap().iter().map(|r| r["error"].as_str().unwrap()).collect();
        assert!(errs.contains(&"missing value"));
        assert!(errs.contains(&"unresolved ref"));

        // A device-rejected write ⇒ the entry is ok:false with the device error.
        let h = harness(poll_device(), MockOpts { write_ok: false, ..MockOpts::default() });
        let out = ok(h.commander.write(&json!({ "name": "fill-setpoint", "value": 55.5 })).await);
        assert_eq!(out["results"][0]["ok"], json!(false));
        assert_eq!(out["results"][0]["error"], json!("write rejected"));
    }

    #[tokio::test]
    async fn write_push_reports_missing_value_failed_and_unresolved_entries() {
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.write(&json!({ "writes": [
            { "name": "fill-setpoint" },   // allow-listed output, no value
            { "name": "ghost", "value": 1 }
        ] })).await);
        assert_eq!(out["written"], json!(0));

        let h = harness(push_device(), MockOpts { write_ok: false, ..MockOpts::default() });
        let out = ok(h.commander.write(&json!({ "name": "fill-setpoint", "value": 55.5 })).await);
        assert_eq!(out["results"][0]["ok"], json!(false), "staging failure surfaces per-entry");
    }

    #[tokio::test]
    async fn signals_push_lists_input_and_output_fields_with_direction() {
        let h = harness(push_device(), MockOpts::default());
        let out = ok(h.commander.signals(&json!({})).await);
        assert_eq!(out["mode"], json!("push"));
        let sigs = out["signals"].as_array().unwrap();
        assert!(sigs.iter().any(|s| s["direction"] == json!("input")));
        assert!(sigs.iter().any(|s| s["direction"] == json!("output") && s["writable"] == json!(true)));
    }

    #[tokio::test]
    async fn browse_maps_failed_and_pages_array_dim_and_cursor() {
        // A mid-browse failure ⇒ BROWSE_FAILED.
        let h = harness(poll_device(), MockOpts { browse: BrowseKind::Failed, ..MockOpts::default() });
        assert_eq!(err_code(h.commander.browse(&json!({})).await), "BROWSE_FAILED");

        // A paged reply carries the array-dim tag and the next-cursor.
        let h = harness(poll_device(), MockOpts { browse: BrowseKind::Paged, ..MockOpts::default() });
        let out = ok(h.commander.browse(&json!({ "cursor": "1", "max": 50 })).await);
        assert_eq!(out["tags"][0]["arrayDim"], json!(8));
        assert_eq!(out["cursor"], json!("42"));
    }

    #[tokio::test]
    async fn repoll_maps_a_device_failure_to_unavailable() {
        let h = harness(poll_device(), MockOpts { repoll_ok: false, ..MockOpts::default() });
        assert_eq!(err_code(h.commander.repoll(&json!({})).await), "DEVICE_UNAVAILABLE");
    }
}
