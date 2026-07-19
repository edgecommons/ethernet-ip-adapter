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

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::*;
use serde_json::json;

use crate::app::{
    connect_reason, connectivity_of, rand01, serve_control_disconnected, Backoff, DeviceControl,
    EventSink, Health, LinkState,
};
use crate::config::{DeviceConfig, DeviceMode, GlobalConfig};
use crate::device::DeviceBackend;
use crate::metrics::DeviceMetrics;
use crate::sim::SimBackend;

pub struct App {
    config: Arc<Config>,
    metrics: Arc<dyn MetricService>,
    global: Arc<GlobalConfig>,
    devices: Vec<DeviceConfig>,
    /// The credentials vault, when the component declares a `credentials` section — the source of TLS
    /// cert/key/CA material for `mode: tls` connections (CIP Security Phase 1). `None` otherwise.
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
}

struct ConfigListener;

#[async_trait::async_trait]
impl ConfigurationChangeListener for ConfigListener {
    async fn on_configuration_change(&self, config: Arc<Config>) -> bool {
        tracing::info!(identity = %config.identity().path(), "configuration changed");
        true
    }
}

impl App {
    pub fn new(gg: &EdgeCommons) -> anyhow::Result<Self> {
        gg.add_config_change_listener(Arc::new(ConfigListener));

        let config = gg.config();
        let metrics = gg.metrics();

        let global = GlobalConfig::from_value(config.global())
            .map_err(|e| anyhow::anyhow!("invalid component.global: {e}"))?;

        let mut devices = Vec::new();
        for id in config.instance_ids() {
            let Some(value) = config.instance(&id) else {
                continue;
            };
            match DeviceConfig::from_value(value) {
                Ok(device) => {
                    // Allow-list entries matching no configured tag are warned, not rejected (§4.4).
                    for ghost in device.unmatched_allow_entries() {
                        tracing::warn!(
                            instance = %device.id, tag_path = %ghost,
                            "writes.allow entry matches no configured tagPath (kept for sb/write-by-ref)"
                        );
                    }
                    devices.push(device);
                }
                Err(e) => tracing::warn!("skipping malformed device `{id}`: {e}"),
            }
        }
        anyhow::ensure!(
            !devices.is_empty(),
            "no valid devices in component.instances[]"
        );

        Ok(Self {
            config,
            metrics,
            global: Arc::new(global),
            devices,
            creds: gg.credentials(),
        })
    }

    pub async fn run(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        // One control channel per device. The command inbox cannot touch the session directly — the
        // session lives in the device's own task and is not `Sync` — so every session-touching verb is
        // *sent* to that task as a [`DeviceControl`], which serializes it against the poll/push loop.
        let mut controls: HashMap<String, tokio::sync::mpsc::Sender<DeviceControl>> = HashMap::new();
        // Each device's config/health/metrics, shared with the command surface (routing, allow-list,
        // status snapshot) and — for health — the connectivity provider.
        let mut handles: Vec<crate::commands::DeviceHandle> = Vec::new();
        let mut reported: Vec<(DeviceConfig, Arc<Health>)> = Vec::new();

        for device in &self.devices {
            let instance = gg.instance(&device.id)?;

            let (control_tx, control_rx) = tokio::sync::mpsc::channel::<DeviceControl>(16);
            controls.insert(device.id.clone(), control_tx.clone());

            let health = Arc::new(Health::default());
            reported.push((device.clone(), Arc::clone(&health)));

            // The full §8 metric set for this device, dimensioned BY INSTANCE (a fleet view can show
            // one device down without averaging it away): the mandatory `southbound_health` plus the
            // six `EtherNetIp*` families, pre-defined at startup and emitted on the
            // `metricsIntervalSecs` cadence + connect/disconnect/pause/resume/push-up/lost transitions.
            let dm = Arc::new(DeviceMetrics::new(
                Arc::clone(&self.metrics),
                Arc::clone(&self.config),
                device.clone(),
                &self.global,
                Arc::clone(&health),
            ));
            dm.define_all();

            let events: Arc<dyn EventSink> = Arc::new(FacadeEventSink(instance.events()));

            handles.push(crate::commands::DeviceHandle {
                cfg: device.clone(),
                control: control_tx.clone(),
                health: Arc::clone(&health),
                dm: Arc::clone(&dm),
                events: Arc::clone(&events),
            });

            // CIP Security Phase 2b: a per-instance cert-lifecycle task for a TLS poll device watches
            // the vault for a rotated client cert / trust store and cert-expiry threshold crossings,
            // reconnecting so the fresh material takes effect without a restart (§4.2).
            let tls_poll = !matches!(device.mode, DeviceMode::Push)
                && crate::eip::tls::SecurityConfig::from_connection(&device.connection)
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.is_tls());
            if tls_poll {
                tokio::spawn(security_lifecycle(
                    device.clone(),
                    self.creds.clone(),
                    control_tx,
                    Arc::clone(&events),
                    Arc::clone(&dm),
                ));
            }

            tokio::spawn(run_device(
                device.clone(),
                Arc::clone(&self.global),
                instance.data(),
                events,
                dm,
                health,
                control_rx,
                self.creds.clone(),
            ));
        }

        // ONE provider, TWO surfaces: the library pushes this sample into the `state` keepalive's
        // `instances[]` every tick, and returns the same sample from the built-in `status` verb.
        let provider: Arc<InstanceConnectivityProvider> = Arc::new(move || {
            reported
                .iter()
                .map(|(cfg, health)| connectivity_of(cfg, health))
                .collect()
        });
        gg.set_instance_connectivity_provider(Some(provider));

        // The full southbound command surface (§7): all nine `sb/*` verbs + the three edge-console
        // panels, mode-aware, with instance routing and the §7.1 error codes.
        if let Some(commands) = gg.commands() {
            crate::commands::register_all(&commands, handles, Arc::clone(&self.global))?;
        }

        gg.shutdown_signal().await;
        tracing::info!("shutdown signal received");
        self.metrics.flush_metrics().await.ok();
        Ok(())
    }
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
        let outcome = tokio::time::timeout(connect_timeout, backend.connect(&cfg.connection)).await;

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
                )
                .await;

                dm.on_connection_dropped(Instant::now());
                health.set_security(None);
                match exit {
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
                        if let Some(reply) =
                            serve_control_disconnected(&mut control, &cfg, &health, &dm, events.as_ref(), wait).await
                        {
                            pending_reconnect = Some(reply);
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
                if let Some(reply) =
                    serve_control_disconnected(&mut control, &cfg, &health, &dm, events.as_ref(), wait).await
                {
                    pending_reconnect = Some(reply);
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
async fn security_lifecycle(
    cfg: DeviceConfig,
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
    control: tokio::sync::mpsc::Sender<crate::app::DeviceControl>,
    events: Arc<dyn EventSink>,
    dm: Arc<crate::metrics::DeviceMetrics>,
) {
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
    if interval_secs == 0 {
        // Rotation is then picked up only on a natural reconnect (the connect path rebuilds anyway).
        return;
    }
    let renew_before_days = sec
        .client
        .as_ref()
        .and_then(|c| c.renew_before_days)
        .map_or(DEFAULT_RENEW_BEFORE_DAYS, i64::from);

    let mut watcher = CertWatcher::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let now = time::OffsetDateTime::now_utc();
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
        let outcome =
            tokio::time::timeout(connect_timeout, backend.open_push(&cfg.connection, &io)).await;
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
                )
                .await;
                session.close().await;

                dm.on_connection_dropped(Instant::now());
                match exit {
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
                        if let Some(reply) =
                            serve_control_disconnected(control, cfg, health, dm, events, wait).await
                        {
                            pending_reconnect = Some(reply);
                        }
                        attempt = attempt.saturating_add(1);
                    }
                    crate::push_driver::PushExit::Reconnect(reply) => {
                        health.set_link(LinkState::Connecting);
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
                if let Some(reply) =
                    serve_control_disconnected(control, cfg, health, dm, events, wait).await
                {
                    pending_reconnect = Some(reply);
                }
            }
        }
    }
}
