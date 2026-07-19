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
                control: control_tx,
                health: Arc::clone(&health),
                dm: Arc::clone(&dm),
                events: Arc::clone(&events),
            });

            tokio::spawn(run_device(
                device.clone(),
                Arc::clone(&self.global),
                instance.data(),
                events,
                dm,
                health,
                control_rx,
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
async fn run_device(
    cfg: DeviceConfig,
    global: Arc<GlobalConfig>,
    data: DataFacade,
    events: Arc<dyn EventSink>,
    dm: Arc<DeviceMetrics>,
    health: Arc<Health>,
    mut control: tokio::sync::mpsc::Receiver<DeviceControl>,
) {
    let backend: Box<dyn DeviceBackend> = match cfg.adapter.as_str() {
        // The in-process simulator — `cargo run` works with no PLC / no OpENer (the runnable configs
        // select this; it stands in for both poll reads and class-1 push frames).
        "sim" => Box::new(SimBackend),
        // The real EtherNet/IP backend over the owned `enip` stack (poll + push). Selected against a
        // live cpppo / ControlLogix / OpENer target; the on-container validation is slice S7.
        "ethernet-ip" => Box::new(crate::eip::EipBackend::new(global.timeouts.clone())),
        other => {
            tracing::error!(instance = %cfg.id, adapter = %other, "unknown adapter");
            return;
        }
    };
    let backoff = Backoff::from_timeouts(&global.timeouts);
    let connect_timeout = Duration::from_millis(global.timeouts.connect_ms.max(1));
    let keepalive_ms = global.health_thresholds.keepalive_probe_interval_ms;

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
                health.set_link(LinkState::Online);
                // A transition: flush southbound_health + connection immediately (§8.7).
                dm.emit_now().await;
                events
                    .emit(
                        Severity::Info,
                        "device-connected",
                        Some(format!("connected to {}", cfg.connection.endpoint)),
                        Some(json!({ "instance": cfg.id, "adapter": backend.kind() })),
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
