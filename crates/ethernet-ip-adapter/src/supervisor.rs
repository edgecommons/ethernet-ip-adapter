//! # The supervisor loop drivers (§3.2, §10.2) — the live-infra seam (excluded from coverage, §12.2)
//!
//! This module is a **thin driver seam**: it wires the already-unit-tested pieces (the [`crate::app`]
//! backoff math, connectivity token, `apply_pause`, `serve_control_disconnected`, `connect_reason`,
//! the [`crate::poll`] / [`crate::push`] gating engines, the [`crate::metrics`] recorder) onto a live
//! [`EdgeCommons`] runtime, a live [`DeviceBackend`] connection, and the `data()` publish facade — then
//! runs the connect → poll/consume → reconnect loops. Everything here `.await`s a socket, a broker, or
//! a spawned task, so it cannot run without live infrastructure; it carries **no branching that is not
//! driven by that I/O** (the reconnect-ladder decisions are validated by the live cpppo/OpENer
//! integration suites (§11) and the S9 deployed regression, exactly as `file-replicator` validates its
//! `dest/*/client.rs` seams). The pure decisions it composes are tested in their home modules.
//!
//! The same rule governs the two lifecycle seams it hosts: [`App`] holds the live
//! [`crate::lifecycle::DeviceRegistry`] and cancellation root but delegates every teardown decision
//! to `lifecycle.rs`, and [`RuntimeLauncher`] is the production body of
//! [`crate::reload::DeviceLauncher`] — the facade/metric/task construction an instance needs, with no
//! decision of its own. What to launch, stop, or keep is decided in `reload.rs`, in the gate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use edgecommons::prelude::*;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::app::{
    connect_reason, rand01, serve_control_disconnected, Backoff, DeviceControl, DisconnectedWait,
    EventSink, Health, LinkState,
};
use crate::config::{DeviceConfig, DeviceMode, GlobalConfig};
use crate::device::DeviceBackend;
use crate::lifecycle::{DeviceRegistry, DeviceRuntime};
use crate::metrics::DeviceMetrics;
use crate::reload::{DeviceLauncher, PriorGeneration, ReloadCoordinator};
use crate::sim::SimBackend;

pub struct App {
    /// The startup configuration snapshot — the generation the first instances bind to. A reload
    /// replaces it (in the coordinator's prior slot); this field stays the startup document, which
    /// is all `start_instances` needs.
    config: Arc<Config>,
    metrics: Arc<dyn MetricService>,
    global: Arc<GlobalConfig>,
    /// The startup instance set as `(parsed config, raw subtree)`, deduped first-wins by
    /// [`crate::reload::parse_instances`] — the same list a reload plans against.
    devices: Vec<(DeviceConfig, Value)>,
    /// The live per-instance registry (§10.3): the ONE source of truth for the connectivity
    /// provider, the command surface, the configuration transaction, and the shutdown drain.
    registry: Arc<DeviceRegistry>,
    /// The app-wide cancellation root. Every instance runs under a child of it, so one `cancel()`
    /// reaches every device task, and each instance can still be stopped on its own — which is what
    /// a configuration change does to the instances it replaces (§10.4).
    root: CancellationToken,
    /// Flipped once the startup launch loop has published every surface. A reload arriving before
    /// then is rejected with `STARTING` rather than diffing against a half-populated registry.
    started: Arc<AtomicBool>,
    /// The ONE construction path for an instance runtime — startup and every reload go through it,
    /// which is what makes skip-bad, facade binding, and metric definition provably identical.
    launcher: Arc<RuntimeLauncher>,
}

impl App {
    /// Parse the component configuration, build the live registry, and install the single
    /// configuration-application coordinator (§10.4, D-EIP-28).
    ///
    /// # Errors
    /// A malformed `component.global`, zero valid instances, or a coordinator that is somehow
    /// already installed (a programming error — core allows exactly one).
    pub fn new(gg: &Arc<EdgeCommons>) -> anyhow::Result<Self> {
        let config = gg.config();
        let metrics = gg.metrics();

        let global = Arc::new(
            GlobalConfig::from_value(config.global())
                .map_err(|e| anyhow::anyhow!("invalid component.global: {e}"))?,
        );

        // The SAME instance-set rule a configuration change applies (`reload::parse_instances`):
        // declaration order, duplicate ids first-wins, id-less entries invisible, malformed entries
        // skipped with a warning. Startup deduping differently from the plan would leave a surplus
        // runtime the reload could never stop (§10.4).
        let (devices, skipped) = crate::reload::parse_instances(&config.raw);
        for (id, e) in &skipped {
            tracing::warn!("skipping malformed device `{id}`: {e}");
        }
        anyhow::ensure!(
            !devices.is_empty(),
            "no valid devices in component.instances[]"
        );

        let registry = Arc::new(DeviceRegistry::default());
        registry.set_global(Arc::clone(&global));
        let root = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let launcher = Arc::new(RuntimeLauncher {
            gg: Arc::downgrade(gg),
            creds: gg.credentials(),
            root: root.clone(),
        });

        // Configuration changes apply as ONE transaction over the live instance set: core prepares
        // and commits this coordinator BEFORE it publishes a candidate snapshot, so a rejected
        // candidate leaves the running generation untouched. Core allows exactly one coordinator —
        // a second registration is a programming error, so it fails startup loudly rather than
        // leaving the component running with a silently inert reload path.
        let coordinator = Arc::new(ReloadCoordinator::new(
            Arc::clone(&launcher) as Arc<dyn DeviceLauncher>,
            Arc::clone(&registry),
            root.clone(),
            Arc::clone(&started),
            PriorGeneration::of(&config, &global),
        ));
        gg.add_config_apply_listener(coordinator)
            .map_err(|e| anyhow::anyhow!("config apply listener: {e}"))?;

        Ok(Self {
            config,
            metrics,
            global,
            devices,
            registry,
            root,
            started,
            launcher,
        })
    }

    pub async fn run(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        let budget = crate::lifecycle::stop_budget(&self.global.timeouts);

        // Startup is fallible while instances are ALREADY running (facade minting, command
        // registration), so its error takes the same bounded teardown as a signalled shutdown before
        // it propagates: a failed start must not leave device tasks polling and publishing with
        // their sessions unclosed (§10.3, D-EIP-27).
        crate::lifecycle::stop_on_startup_error(
            self.start_instances(gg),
            &self.registry,
            &self.root,
            budget,
        )
        .await?;

        gg.shutdown_signal().await;
        tracing::info!("shutdown signal received; stopping device tasks");
        let report = crate::lifecycle::shutdown_all(&self.registry, &self.root, budget).await;
        tracing::info!(
            joined = report.joined,
            aborted = report.aborted,
            budget_ms = budget.as_millis() as u64,
            "device teardown complete"
        );
        self.metrics.flush_metrics().await.ok();
        Ok(())
    }

    /// Launch every configured instance into the registry, then publish the two surfaces that read
    /// it (the connectivity provider and the `sb/*` command surface) and open the reload gate.
    ///
    /// Fallible, and deliberately *only* fallible: whatever it has already launched is live by the
    /// time it can fail, so its `Err` is routed through
    /// [`crate::lifecycle::stop_on_startup_error`] rather than returned to the caller directly.
    fn start_instances(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        for (device, raw) in &self.devices {
            // The same call a configuration change makes — one construction path, one behavior.
            let runtime = self
                .launcher
                .launch(device, raw, &self.global, &self.config)?;
            self.registry.insert(runtime);
        }

        // ONE provider, TWO surfaces: the library pushes this sample into the `state` keepalive's
        // `instances[]` every tick, and returns the same sample from the built-in `status` verb. It
        // reads the registry, so it reports what is actually running — across every generation, with
        // no re-registration.
        let reg = Arc::clone(&self.registry);
        let provider: Arc<InstanceConnectivityProvider> = Arc::new(move || reg.connectivity());
        gg.set_instance_connectivity_provider(Some(provider));

        // The full southbound command surface (§7): all nine `sb/*` verbs + the three edge-console
        // panels, mode-aware, with instance routing and the §7.1 error codes. Registered ONCE, over
        // the registry, so routing follows the live instance set instead of a startup snapshot.
        if let Some(commands) = gg.commands() {
            crate::commands::register_all(&commands, Arc::clone(&self.registry))?;
        }

        // Every surface now reads the live registry: a configuration change may be applied against
        // it. Before this point a reload is refused with `STARTING` (§10.4).
        self.started.store(true, Ordering::Release);
        Ok(())
    }
}

/// The production [`DeviceLauncher`]: the one place an instance runtime is built and started.
///
/// Startup calls it per configured device; a configuration commit calls it for every added or
/// changed instance, and a rollback calls it to restore the prior set — always against an explicit
/// configuration snapshot, so the facades, the UNS identity, and the metric identity of an instance
/// are exactly the ones its generation declared.
struct RuntimeLauncher {
    /// **Weak** on purpose: core holds the coordinator, the coordinator holds this launcher. A
    /// strong reference here would be an `Arc` cycle through the runtime and would suppress the RAII
    /// teardown (unsubscribes, `STOPPED` state) that dropping `gg` in `main` performs. A failed
    /// upgrade means the runtime is going away — the launch is refused.
    gg: Weak<EdgeCommons>,
    /// The credentials vault, when the component declares a `credentials` section — the source of TLS
    /// cert/key/CA material for `mode: tls` connections (CIP Security Phase 1). `None` otherwise.
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
    /// The app root: every instance's token is a child of it, so shutdown reaches every generation.
    root: CancellationToken,
}

impl DeviceLauncher for RuntimeLauncher {
    fn launch(
        &self,
        cfg: &DeviceConfig,
        raw: &Value,
        global: &Arc<GlobalConfig>,
        snapshot: &Arc<Config>,
    ) -> anyhow::Result<DeviceRuntime> {
        let gg = self
            .gg
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("the runtime is shutting down"))?;

        // Facades bound to THIS snapshot, not to whatever core's current snapshot happens to be:
        // during a commit the candidate has not been published yet, and the instance must already
        // mint its topics and stamp its identity from the configuration it is being started for.
        let instance = gg.instance_from_config_snapshot(&cfg.id, Arc::clone(snapshot))?;

        // Allow-list entries matching no configured tag are warned, not rejected (§4.4) — on every
        // launch, so a reload reports them exactly as startup does.
        for ghost in cfg.unmatched_allow_entries() {
            tracing::warn!(
                instance = %cfg.id, tag_path = %ghost,
                "writes.allow entry matches no configured tagPath (kept for sb/write-by-ref)"
            );
        }

        let cancel = self.root.child_token();

        // One control channel per device. The command inbox cannot touch the session directly —
        // the session lives in the device's own task and is not `Sync` — so every session-touching
        // verb is *sent* to that task as a [`DeviceControl`], which serializes it against the
        // poll/push loop.
        let (control_tx, control_rx) = tokio::sync::mpsc::channel::<DeviceControl>(16);

        let health = Arc::new(Health::default());

        // The full §8 metric set for this device, dimensioned BY INSTANCE (a fleet view can show one
        // device down without averaging it away): the mandatory `southbound_health` plus the six
        // `EtherNetIp*` families, defined up front and emitted on the `metricsIntervalSecs` cadence +
        // connect/disconnect/pause/resume/push-up/lost transitions. `define_metric` replaces by name,
        // so defining them again for a relaunched instance is idempotent.
        let dm = Arc::new(DeviceMetrics::new(
            gg.metrics(),
            Arc::clone(snapshot),
            cfg.clone(),
            global,
            Arc::clone(&health),
        ));
        dm.define_all();

        let events: Arc<dyn EventSink> = Arc::new(FacadeEventSink(instance.events()));

        // The routing view the command surface reads (routing, allow-list, status snapshot) and the
        // connectivity provider samples.
        let handle = crate::commands::DeviceHandle {
            cfg: cfg.clone(),
            control: control_tx.clone(),
            health: Arc::clone(&health),
            dm: Arc::clone(&dm),
            events: Arc::clone(&events),
        };

        // The supervision view: every spawned task's join handle, so shutdown (and a reload that
        // replaces this instance) can actually wait for the session close instead of discarding it.
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // CIP Security Phase 2b: a per-instance cert-lifecycle task for a TLS poll device watches
        // the vault for a rotated client cert / trust store and cert-expiry threshold crossings,
        // reconnecting so the fresh material takes effect without a restart (§4.2).
        let tls_poll = !matches!(cfg.mode, DeviceMode::Push)
            && crate::eip::tls::SecurityConfig::from_connection(&cfg.connection)
                .ok()
                .flatten()
                .is_some_and(|s| s.is_tls());
        if tls_poll {
            tasks.push(tokio::spawn(security_lifecycle_inner(
                cfg.clone(),
                self.creds.clone(),
                control_tx,
                Arc::clone(&events),
                Arc::clone(&dm),
                Some(Arc::clone(&health)),
                cancel.clone(),
            )));
        }

        tasks.push(tokio::spawn(run_device(
            cfg.clone(),
            Arc::clone(global),
            instance.data(),
            events,
            dm,
            health,
            control_rx,
            self.creds.clone(),
            cancel.clone(),
        )));

        Ok(DeviceRuntime {
            handle,
            raw: raw.clone(),
            cancel,
            tasks,
        })
    }

    fn component_events(&self) -> Arc<dyn EventSink> {
        match self.gg.upgrade() {
            Some(gg) => Arc::new(FacadeEventSink(gg.events())),
            // Shutting down: swallow the event rather than fail a commit over it.
            None => Arc::new(DroppedEvents),
        }
    }

    fn set_repoll_availability(&self, all_push: bool) {
        let Some(gg) = self.gg.upgrade() else {
            return;
        };
        let Some(commands) = gg.commands() else {
            return;
        };
        let (state, reason) = crate::commands::repoll_availability(all_push);
        if let Err(e) = commands.set_command_availability("repoll", state, reason) {
            tracing::warn!(error = %e, "could not update the repoll verb's availability");
        }
    }
}

/// The event sink of a runtime that is already gone — every emit is a no-op. Only reachable when the
/// `EdgeCommons` runtime dropped between a commit's launch stage and its event, i.e. at process exit.
struct DroppedEvents;

#[async_trait::async_trait]
impl EventSink for DroppedEvents {
    async fn emit(&self, _: Severity, _: &str, _: Option<String>, _: Option<serde_json::Value>) {}
    async fn raise_alarm(&self, _: Severity, _: &str, _: Option<String>, _: Option<serde_json::Value>) {}
    async fn clear_alarm(&self, _: Severity, _: &str, _: Option<serde_json::Value>) {}
}

/// Production [`EventSink`] over the `events()` facade. Errors are best-effort (a failed publish must
/// not stall the loop) — matching the template's `let _ = events…` behavior.
pub struct FacadeEventSink(pub EventsFacade);

#[async_trait::async_trait]
impl EventSink for FacadeEventSink {
    async fn emit(&self, severity: Severity, event_type: &str, message: Option<String>, context: Option<serde_json::Value>) {
        let _ = self.0.emit(severity, event_type.to_string(), message, context).await;
    }
    async fn raise_alarm(&self, severity: Severity, event_type: &str, message: Option<String>, context: Option<serde_json::Value>) {
        let _ = self.0.raise_alarm(severity, event_type.to_string(), message, context).await;
    }
    async fn clear_alarm(&self, severity: Severity, event_type: &str, context: Option<serde_json::Value>) {
        let _ = self.0.clear_alarm(severity, event_type.to_string(), context).await;
    }
}

/// One device's lifecycle: connect, poll, publish, reconnect — now also servicing the device's
/// [`DeviceControl`] channel so every `sb/*` verb serializes with the engine loop (§7).
///
/// The connect loop and the poll loop are nested on purpose. A read failure that breaks the link
/// drops out of the poll loop and back into connect — which is the only place that knows how to
/// back off. An explicit `reconnect` short-circuits the backoff; `pause`/`resume` are serviced in
/// both the loop and the backoff wait, so they take effect whether the device is up or reconnecting.
///
/// `cancel` is this instance's child of the app root token (§10.3): every wait selects on it, and
/// the driver closes the session before returning, so a teardown reaches the wire (UnRegisterSession
/// / ForwardClose) instead of dropping the socket. A cancelled exit raises no alarm, emits no event,
/// and never backs off — the link did not fail, the instance was stopped.
#[allow(clippy::too_many_arguments)]
async fn run_device(
    cfg: DeviceConfig,
    global: Arc<GlobalConfig>,
    data: DataFacade,
    events: Arc<dyn EventSink>,
    dm: Arc<DeviceMetrics>,
    health: Arc<Health>,
    mut control: tokio::sync::mpsc::Receiver<DeviceControl>,
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
    cancel: CancellationToken,
) {
    let backend: Box<dyn DeviceBackend> = match cfg.adapter.as_str() {
        // The in-process simulator — `cargo run` works with no PLC / no OpENer (the runnable configs
        // select this; it stands in for both poll reads and class-1 push frames).
        "sim" => Box::new(SimBackend),
        // The real EtherNet/IP backend over the owned `enip` stack (poll + push). Selected against a
        // live cpppo / ControlLogix / OpENer target; the on-container validation is slice S7. The
        // credentials vault (when present) sources TLS material for `mode: tls` connections.
        "ethernet-ip" => {
            Box::new(crate::eip::EipBackend::new(global.timeouts.clone()).credentials(creds))
        }
        other => {
            tracing::error!(instance = %cfg.id, adapter = %other, "unknown adapter");
            return;
        }
    };
    let backoff = Backoff::from_timeouts(&global.timeouts);
    let connect_timeout = Duration::from_millis(global.timeouts.connect_ms.max(1));
    let keepalive_ms = global.health_thresholds.keepalive_probe_interval_ms;
    // Whether this instance runs over TLS (CIP Security Phase 1) — drives the handshake-failure
    // metric/event on the connect path.
    let tls_instance = crate::eip::tls::SecurityConfig::from_connection(&cfg.connection)
        .ok()
        .flatten()
        .is_some_and(|s| s.is_tls());

    // Push (class-1 implicit I/O) has its own connect → consume → reconnect loop over the
    // `PushSession` seam; it never enters the poll loop (a push device has no poll groups).
    if matches!(cfg.mode, DeviceMode::Push) {
        run_push(
            &cfg,
            &global,
            backend.as_ref(),
            &data,
            events.as_ref(),
            &dm,
            &health,
            backoff,
            connect_timeout,
            &mut control,
            &cancel,
        )
        .await;
        return;
    }

    let mut attempt: u32 = 0;
    // A pending explicit-`reconnect` reply: fulfilled after the *next* connect attempt resolves.
    let mut pending_reconnect: Option<tokio::sync::oneshot::Sender<std::result::Result<(), String>>> =
        None;

    loop {
        // Connect within the configured deadline (§4.1 connectMs).
        dm.on_connect_attempt();
        let started = Instant::now();
        // No session is open yet, so a cancel here has nothing to close: drop the connect future and
        // leave (the enip connect is itself deadline-bounded; the half-open socket dies with RAII).
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            o = tokio::time::timeout(connect_timeout, backend.connect(&cfg.connection)) => o,
        };

        match outcome {
            Ok(Ok(session)) => {
                attempt = 0;
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                dm.on_connected(latency_ms, Instant::now());
                // Capture the negotiated security posture for the sb/status/state surface (§3.4), and
                // clear any prior handshake-failing state.
                let security = session.security();
                health.set_security(security.clone());
                // Phase 2b: surface the connected cert's days-to-expiry as a gauge immediately, even
                // before the lifecycle task's first re-read (§4.2).
                if let Some(days) = security.as_ref().and_then(|s| s.client_cert_expiry_days) {
                    dm.set_cert_expiry_days(days);
                }
                health
                    .tls_handshake_failing
                    .store(false, Ordering::Relaxed);
                health.set_link(LinkState::Online);
                // A transition: flush southbound_health + connection immediately (§8.7).
                dm.emit_now().await;
                let mut connected_ctx = json!({ "instance": cfg.id, "adapter": backend.kind() });
                if let Some(sec) = &security {
                    connected_ctx["security"] = json!(if sec.tls { "tls" } else { "plaintext" });
                    if !sec.peer_verified && sec.tls {
                        // A no-verify TLS session is a loud, commissioning/debug posture (§3.3).
                        events
                            .emit(
                                Severity::Warning,
                                "tls-peer-unverified",
                                Some(format!(
                                    "connected to {} over TLS WITHOUT peer verification (verifyPeer:false)",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                    }
                }
                events
                    .emit(
                        Severity::Info,
                        "device-connected",
                        Some(format!("connected to {}", cfg.connection.endpoint)),
                        Some(connected_ctx),
                    )
                    .await;
                // A raised alarm is cleared by the SAME wire type, so the pair rides one channel.
                events
                    .clear_alarm(Severity::Critical, "device-unreachable", None)
                    .await;
                // An explicit reconnect that asked for this connect: it succeeded.
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Ok(()));
                }

                let exit = crate::poll_driver::poll_until_disconnected(
                    &cfg,
                    &global,
                    session,
                    &data,
                    &dm,
                    &health,
                    backend.kind(),
                    &mut control,
                    events.as_ref(),
                    keepalive_ms,
                    &cancel,
                )
                .await;

                dm.on_connection_dropped(Instant::now());
                health.set_security(None);
                match exit {
                    // The driver already closed the session on its way out — nothing to reconnect.
                    crate::poll_driver::PollExit::Stopped => return,
                    crate::poll_driver::PollExit::LinkLost => {
                        health.set_link(LinkState::Backoff);
                        health.reconnects.fetch_add(1, Ordering::Relaxed);
                        dm.emit_now().await;
                        events
                            .raise_alarm(
                                Severity::Critical,
                                "device-unreachable",
                                Some(format!("lost the link to {}", cfg.connection.endpoint)),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                        let wait = backoff.delay(attempt, rand01());
                        match serve_control_disconnected(
                            &mut control, &cfg, &health, &dm, events.as_ref(), wait, &cancel,
                        )
                        .await
                        {
                            DisconnectedWait::Stopped => return,
                            DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                            DisconnectedWait::Elapsed => {}
                        }
                        attempt = attempt.saturating_add(1);
                    }
                    // An explicit reconnect: no alarm, no backoff — straight back to connect, carrying
                    // the reply to fulfill after the next connect resolves (§7.5).
                    crate::poll_driver::PollExit::Reconnect(reply) => {
                        health.set_link(LinkState::Connecting);
                        pending_reconnect = Some(reply);
                    }
                }
            }

            // Connect failed (Err) or timed out (Elapsed). A permanent failure will fail identically
            // forever, so back off to the ceiling immediately.
            other => {
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let reason = connect_reason(&other, connect_timeout);
                // An explicit reconnect that asked for this connect: it failed → RECONNECT_FAILED.
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Err(reason.clone()));
                }
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                // A permanent connect failure on a TLS instance is a cert/suite/protocol handshake
                // failure (a transient TCP hiccup or pre-handshake IO is not) — count it and fire the
                // `tls-handshake-failed` event on the transition into failing (§3.4).
                if tls_instance && permanent {
                    dm.on_tls_handshake_failure();
                    dm.emit_now().await;
                    if !health.tls_handshake_failing.swap(true, Ordering::Relaxed) {
                        events
                            .emit(
                                Severity::Warning,
                                "tls-handshake-failed",
                                Some(format!("TLS handshake to {} failed: {reason}", cfg.connection.endpoint)),
                                Some(json!({ "instance": cfg.id, "security": "tls" })),
                            )
                            .await;
                    }
                }
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "connect failed"
                );
                attempt = attempt.saturating_add(1);
                match serve_control_disconnected(
                    &mut control, &cfg, &health, &dm, events.as_ref(), wait, &cancel,
                )
                .await
                {
                    DisconnectedWait::Stopped => return,
                    DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                    DisconnectedWait::Elapsed => {}
                }
            }
        }
    }
}

/// The CIP Security Phase-2b cert-lifecycle driver (§4.2/§4.3) — the thin live-infra seam over the
/// pure [`crate::eip::rotation`] logic. On the `reloadIntervalSecs` cadence it re-reads the vault's
/// current TLS material, and:
///
/// * on a **rotation** (the client cert and/or a trust-store CA changed) it bumps `certReloads`, emits
///   `cert-rotated`, and sends a `reconnect` so the next handshake uses the fresh material (the connect
///   path always rebuilds the `ClientConfig` from the latest vault contents);
/// * on the transition into **near-expiry** (`renewBeforeDays`) it emits `cert-expiring`, and into
///   **expired** it emits `cert-expired`;
/// * every tick it refreshes the `certExpiryDays` gauge.
///
/// It never blocks polling: a vault-read error is logged and the loop continues on the current
/// material (offline-first). All decisions are made by [`crate::eip::rotation::CertWatcher`]; this
/// driver only performs the I/O.
/// The lifecycle body (Phase 2b rotation/expiry + Phase 2c EST enroll/renew), parameterized on an
/// optional shared [`crate::app::Health`] so the EST state can be surfaced on `sb/status.security.est`.
///
/// `cancel` ends the task at the tick boundary (§10.3). A cancel landing **mid-EST-exchange** (itself
/// bounded at 20 s) is deliberately not selected against; that task is instead reaped by
/// [`crate::lifecycle::stop_tasks`]'s abort at the end of the teardown budget. That is safe: the EST
/// client holds no device session, its vault write is atomic in the credential service, and
/// enrollment is idempotent — an interrupted exchange simply re-enrolls on the next start.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn security_lifecycle_inner(
    cfg: DeviceConfig,
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
    control: tokio::sync::mpsc::Sender<crate::app::DeviceControl>,
    events: Arc<dyn EventSink>,
    dm: Arc<crate::metrics::DeviceMetrics>,
    health: Option<Arc<crate::app::Health>>,
    cancel: CancellationToken,
) {
    use crate::eip::est::{enroll_once, next_renew_rfc3339, EstDecision, EstScheduler, EstStatus};
    use crate::eip::rotation::{read_reload_state, CertWatcher, WatchAction};
    use crate::eip::tls::{SecurityConfig, DEFAULT_RELOAD_INTERVAL_SECS, DEFAULT_RENEW_BEFORE_DAYS};

    let Some(sec) = SecurityConfig::from_connection(&cfg.connection)
        .ok()
        .flatten()
        .filter(SecurityConfig::is_tls)
    else {
        return;
    };
    let interval_secs = sec.reload_interval_secs.unwrap_or(DEFAULT_RELOAD_INTERVAL_SECS);

    // CIP Security Phase 2c: EST enrollment/renewal (off unless `est.enabled`).
    let est = sec.est_enabled().cloned();
    let est_renew_days = est.as_ref().map_or(DEFAULT_RENEW_BEFORE_DAYS, |e| e.renew_before_days(&sec));
    let est_backoff = est.as_ref().map_or(Duration::from_secs(3600), |e| e.retry_backoff());
    // A generous fixed deadline for the whole EST exchange (connect + handshake + request/reply); EST
    // is a background provisioning step, never on the polling hot path.
    let connect_timeout = Duration::from_secs(20);
    let mut est_last_attempt: Option<Instant> = None;
    if let (Some(e), Some(h)) = (&est, &health) {
        h.set_est(Some(EstStatus {
            enabled: true,
            server: e.server.clone(),
            ..EstStatus::default()
        }));
    }

    // With EST disabled and rotation-watching disabled, there is nothing to do.
    if interval_secs == 0 && est.is_none() {
        // Rotation is then picked up only on a natural reconnect (the connect path rebuilds anyway).
        return;
    }
    // When only EST is on but the reload watcher is disabled, still tick (default cadence) to enroll.
    let tick_secs = if interval_secs == 0 { DEFAULT_RELOAD_INTERVAL_SECS } else { interval_secs };
    let renew_before_days = sec
        .client
        .as_ref()
        .and_then(|c| c.renew_before_days)
        .map_or(DEFAULT_RENEW_BEFORE_DAYS, i64::from);

    let mut watcher = CertWatcher::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(tick_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let now = time::OffsetDateTime::now_utc();

        // ---- Phase 2c: EST enrollment/renewal, BEFORE the rotation re-read so a fresh enrollment's
        // vault write is observed by the watcher this same tick (⇒ Rotated ⇒ reconnect). ----
        if let Some(e) = &est {
            // The current cert's days-to-expiry drives the enroll decision (None ⇒ initial enroll).
            let current_days = read_reload_state(&sec, creds.as_ref(), now)
                .ok()
                .and_then(|s| s.client.map(|c| c.expiry_days))
                .filter(|d| *d != i64::MAX);
            let since = est_last_attempt.map(|t| t.elapsed());
            if let EstDecision::Enroll { reenroll } =
                EstScheduler::decide(current_days, est_renew_days, since, est_backoff)
            {
                est_last_attempt = Some(Instant::now());
                match enroll_once(e, &sec, creds.as_ref(), reenroll, connect_timeout).await {
                    Ok(out) => {
                        dm.on_est_enrollment(true);
                        let next_renew =
                            next_renew_rfc3339(out.not_after.as_deref(), est_renew_days);
                        if let Some(h) = &health {
                            let prev = h.est().unwrap_or_default();
                            h.set_est(Some(EstStatus {
                                enabled: true,
                                server: e.server.clone(),
                                last_enroll: now
                                    .format(&time::format_description::well_known::Rfc3339)
                                    .ok(),
                                next_renew,
                                last_error: None,
                                enrollments: prev.enrollments + 1,
                                failures: prev.failures,
                            }));
                        }
                        events
                            .emit(
                                Severity::Info,
                                "cert-enrolled",
                                Some(format!(
                                    "EST {} succeeded for {} — wrote the new certificate to `{}`",
                                    if reenroll { "re-enrollment" } else { "enrollment" },
                                    cfg.connection.endpoint,
                                    out.written_to
                                )),
                                Some(json!({
                                    "instance": cfg.id, "security": "tls",
                                    "serial": out.serial, "notAfter": out.not_after,
                                    "reenroll": reenroll
                                })),
                            )
                            .await;
                    }
                    Err(err) => {
                        dm.on_est_enrollment(false);
                        if let Some(h) = &health {
                            let prev = h.est().unwrap_or_default();
                            h.set_est(Some(EstStatus {
                                enabled: true,
                                server: e.server.clone(),
                                last_enroll: prev.last_enroll,
                                next_renew: prev.next_renew,
                                last_error: Some(err.clone()),
                                enrollments: prev.enrollments,
                                failures: prev.failures + 1,
                            }));
                        }
                        events
                            .emit(
                                Severity::Warning,
                                "cert-enroll-failed",
                                Some(format!(
                                    "EST enrollment for {} failed: {err} — keeping the current \
                                     certificate; will retry",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id, "security": "tls" })),
                            )
                            .await;
                    }
                }
            }
        }

        // ---- Phase 2b: rotation / expiry watch (also picks up a fresh EST enrollment's vault write). ----
        let state = match read_reload_state(&sec, creds.as_ref(), now) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(instance = %cfg.id, error = %e, "cert-lifecycle re-read failed (ignored)");
                continue;
            }
        };
        let outcome = watcher.observe(&state, renew_before_days);
        if let Some(days) = outcome.expiry_days {
            dm.set_cert_expiry_days(days);
        }
        for action in outcome.actions {
            match action {
                WatchAction::Rotated { serial, not_after } => {
                    dm.on_cert_reload();
                    events
                        .emit(
                            Severity::Info,
                            "cert-rotated",
                            Some(format!(
                                "client certificate / trust store rotated for {} — reconnecting to \
                                 apply the new material",
                                cfg.connection.endpoint
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls",
                                "serial": serial, "notAfter": not_after
                            })),
                        )
                        .await;
                    // Trigger a graceful reconnect (the reply is not needed here).
                    let (reply, _rx) = tokio::sync::oneshot::channel();
                    if control
                        .send(crate::app::DeviceControl::Reconnect { reply })
                        .await
                        .is_err()
                    {
                        // The device task ended — nothing left to serve.
                        return;
                    }
                }
                WatchAction::Expiring { days, not_after } => {
                    events
                        .emit(
                            Severity::Warning,
                            "cert-expiring",
                            Some(format!(
                                "adapter client certificate expires in {days} day(s) — rotate it \
                                 (e.g. ec-secrets) before it lapses"
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls",
                                "daysRemaining": days, "notAfter": not_after
                            })),
                        )
                        .await;
                }
                WatchAction::Expired { days, not_after } => {
                    events
                        .emit(
                            Severity::Warning,
                            "cert-expired",
                            Some(format!(
                                "adapter client certificate EXPIRED {} day(s) ago — TLS connects will \
                                 fail until it is rotated",
                                -days
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls", "notAfter": not_after
                            })),
                        )
                        .await;
                }
            }
        }
    }
}

/// One push device's lifecycle: open the class-1 connection, consume the [`crate::device::IoUpdate`]
/// stream through the push engine ([`crate::push_driver::consume_push`]) — servicing the control
/// channel — and reconnect on loss with the same backoff ladder as poll (§10.2).
#[allow(clippy::too_many_arguments)]
async fn run_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    backend: &dyn DeviceBackend,
    data: &DataFacade,
    events: &dyn EventSink,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    backoff: Backoff,
    connect_timeout: Duration,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    cancel: &CancellationToken,
) {
    let Some(io) = cfg.io.clone() else {
        tracing::error!(instance = %cfg.id, "push device has no io block");
        return;
    };
    let mut attempt: u32 = 0;
    let mut pending_reconnect: Option<tokio::sync::oneshot::Sender<std::result::Result<(), String>>> =
        None;

    loop {
        health.set_link(LinkState::Connecting);
        dm.on_connect_attempt();
        let started = Instant::now();
        // No class-1 connection is open yet, so a cancel here has nothing to ForwardClose.
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            o = tokio::time::timeout(connect_timeout, backend.open_push(&cfg.connection, &io)) => o,
        };
        match outcome {
            Ok(Ok(mut session)) => {
                attempt = 0;
                // The class-1 ForwardOpen succeeded (§8.8 forwardOpens; §8.2 sessionConnected).
                dm.on_forward_open(true);
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                dm.on_connected(latency_ms, Instant::now());
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Ok(()));
                }

                let exit = crate::push_driver::consume_push(
                    cfg,
                    global,
                    session.as_mut(),
                    data,
                    events,
                    dm,
                    health,
                    backend.kind(),
                    control,
                    cancel,
                )
                .await;
                // Unconditional, and therefore also the teardown path: ForwardClose + the class-1
                // socket release happen before this task returns.
                session.close().await;

                dm.on_connection_dropped(Instant::now());
                match exit {
                    crate::push_driver::PushExit::Stopped => return,
                    crate::push_driver::PushExit::LinkLost => {
                        health.set_link(LinkState::Backoff);
                        health.reconnects.fetch_add(1, Ordering::Relaxed);
                        dm.emit_now().await;
                        events
                            .raise_alarm(
                                Severity::Critical,
                                "device-unreachable",
                                Some(format!("lost the class-1 link to {}", cfg.connection.endpoint)),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                        let wait = backoff.delay(attempt, rand01());
                        match serve_control_disconnected(
                            control, cfg, health, dm, events, wait, cancel,
                        )
                        .await
                        {
                            DisconnectedWait::Stopped => return,
                            DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                            DisconnectedWait::Elapsed => {}
                        }
                        attempt = attempt.saturating_add(1);
                    }
                    crate::push_driver::PushExit::Reconnect(reply) => {
                        health.set_link(LinkState::Connecting);
                        // The class-1 connection just closed and a fresh ForwardOpen follows, so the
                        // §8.8 stack-counter baselines belong to a connection that no longer exists:
                        // rebase them, and with them the per-connection latches, so a redirect that is
                        // refused again on the new connection re-reports (D-ENIP-17). Deliberately NOT
                        // `on_io_lost` — a requested reconnect is not a watchdog timeout.
                        dm.on_io_link_replaced();
                        pending_reconnect = Some(reply);
                    }
                }
            }
            other => {
                // The ForwardOpen was refused / timed out (§8.8 forwardOpenFailures; §8.2 connectFailures).
                dm.on_forward_open(false);
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let reason = connect_reason(&other, connect_timeout);
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Err(reason.clone()));
                }
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "push open failed"
                );
                attempt = attempt.saturating_add(1);
                match serve_control_disconnected(control, cfg, health, dm, events, wait, cancel)
                    .await
                {
                    DisconnectedWait::Stopped => return,
                    DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                    DisconnectedWait::Elapsed => {}
                }
            }
        }
    }
}
