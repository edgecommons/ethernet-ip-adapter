//! # The supervisor — connect, poll, publish, reconnect
//!
//! An **adapter** connects to devices, reads signals, and publishes them onto the UNS in the shape
//! the rest of the fleet expects — so a consumer can chart a CIP tag and an OPC UA node without
//! knowing either protocol.
//!
//! ```text
//!   connect ──► poll each group on its own cadence ──► publish SouthboundSignalUpdate ──► health
//!      ▲                                                                                    │
//!      └──────────────────── reconnect with backoff ◄──────────────────────────────────────┘
//! ```
//!
//! One task per device (one `component.instances[]` entry): a device is one PLC / CIP endpoint, and
//! its connection lifecycle is its own.
//!
//! ## What this slice (S2) covers
//!
//! The supervisor now drives the typed [`crate::config`] model: one task per device, one
//! `tokio` ticker per poll group at its resolved cadence, publishing every polled sample through
//! the `data()` facade. Deadband/change gating and batching (S4), the full metric families (S5),
//! and the `sb/*` command family + pause/resume (S6) plug into the seams left here; this slice
//! keeps the connectivity provider, the allow-listed `sb/write`, the events, and the single
//! `southbound_health` metric working against the new config.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::*;
use serde_json::json;

use crate::config::{DeviceConfig, GlobalConfig, SignalSpec};
use crate::device::DeviceBackend;
use crate::metrics::DeviceMetrics;
use crate::sim::SimBackend;

/// Reconnect backoff. Exponential with full jitter and a cap — so a site whose PLC reboots does
/// not get every adapter in the plant reconnecting in lockstep on the same second.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub base_ms: u64,
    pub max_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base_ms: 1_000,
            max_ms: 60_000,
        }
    }
}

impl Backoff {
    /// The backoff from the configured reconnect window (§4.1).
    #[must_use]
    pub fn from_timeouts(t: &crate::config::Timeouts) -> Self {
        Self {
            base_ms: t.reconnect_backoff_min_ms.max(1),
            max_ms: t.reconnect_backoff_max_ms.max(1),
        }
    }

    #[must_use]
    pub fn delay(&self, attempt: u32, rand01: f64) -> Duration {
        let exp = self.base_ms.saturating_mul(1_u64 << attempt.min(20));
        let cap = exp.min(self.max_ms);
        Duration::from_millis((rand01.clamp(0.0, 1.0) * cap as f64) as u64)
    }
}

/// This adapter's **own vocabulary** for a link's condition — what it reports as
/// `InstanceConnectivity::state`. A boolean cannot tell "still trying" from "backing off after a
/// failure"; an operator needs to, so the richer token exists alongside the normalized flag.
/// (The `PAUSED` token from §9.2 lands with pause/resume in slice S6.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LinkState {
    /// Connecting for the first time; nothing has failed yet.
    #[default]
    Connecting = 0,
    /// The session is up and being polled.
    Online = 1,
    /// The link failed; reconnecting with backoff.
    Backoff = 2,
}

impl LinkState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "CONNECTING",
            Self::Online => "ONLINE",
            Self::Backoff => "BACKOFF",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Online,
            2 => Self::Backoff,
            _ => Self::Connecting,
        }
    }
}

/// The `southbound_health` measures, per instance (SOUTHBOUND.md §5), plus the link condition the
/// connectivity provider reports **and** the engine counters slice S5 wires into the full
/// `EtherNetIp*` metric families (§8). The engines ([`crate::poll`] / [`crate::push`]) produce these;
/// this slice keeps only the single `southbound_health` metric emitting — S5 consumes the rest.
#[derive(Default)]
pub struct Health {
    /// 1 = connected, 0 = down.
    pub connection_state: AtomicU64,
    /// The [`LinkState`], as a `u8`. Read it through [`Health::link`].
    link: AtomicU8,
    pub poll_latency_ms: AtomicU64,
    pub read_errors: AtomicU64,
    /// Failed confirmed writes over the interval (`southbound_health.writeErrors`, §8.1). Bumped by
    /// the poll write path; consumed (swap-reset) by the metrics emitter.
    pub write_errors: AtomicU64,
    pub reconnects: AtomicU64,
    pub signals_published: AtomicU64,
    /// 1 = this instance is paused (§7.4 / §8.1 `paused` gauge). Owned here so the connectivity
    /// token, the `paused` attribute, and the gauge all derive from one source (§9.2). S6 sets it;
    /// it reads `false` until then.
    pub paused: std::sync::atomic::AtomicBool,

    // ---- engine counters (consumed by the S5 metric families; §8) ----
    /// Publish latency of the last `data.publish().await`, ms (§6.2).
    // SLICE S5: EtherNetIpPublish.publishLatencyMs / southbound_health.publishLatencyMs.
    #[allow(dead_code)]
    pub publish_latency_ms: AtomicU64,
    /// Poll cycles run (per group tick).
    // SLICE S5: EtherNetIpPoll.pollCycles.
    #[allow(dead_code)]
    pub poll_cycles: AtomicU64,
    /// Consumed class-1 frames (push).
    // SLICE S5: EtherNetIpIo.framesConsumed.
    #[allow(dead_code)]
    pub frames_consumed: AtomicU64,
    /// Samples read GOOD.
    // SLICE S5: EtherNetIpPoll.samplesGood.
    #[allow(dead_code)]
    pub samples_good: AtomicU64,
    /// Samples read BAD (a per-signal failure, published not swallowed).
    // SLICE S5: EtherNetIpPoll.samplesBad.
    #[allow(dead_code)]
    pub samples_bad: AtomicU64,
    /// Samples that decoded but scaled non-finite (§5.4) — neither GOOD nor BAD.
    // SLICE S5: EtherNetIpPoll.samplesUncertain.
    #[allow(dead_code)]
    pub samples_uncertain: AtomicU64,
    /// Samples that passed the onChange gate (published because they changed).
    // SLICE S5: EtherNetIpPublish.samplesChanged.
    #[allow(dead_code)]
    pub samples_changed: AtomicU64,
    /// Samples gated out (deadband / sampleMs floor).
    // SLICE S5: EtherNetIpPublish.samplesSuppressed.
    #[allow(dead_code)]
    pub samples_suppressed: AtomicU64,
    /// Poll cycles that overran their interval.
    // SLICE S5: EtherNetIpPoll.overruns.
    #[allow(dead_code)]
    pub overruns: AtomicU64,
    /// Signals currently stale (no GOOD read within `staleSignalSecs`), as of the last emit.
    // SLICE S5: EtherNetIpInventory.staleSignals.
    #[allow(dead_code)]
    pub stale_signals: AtomicU64,
}

impl Health {
    /// Record the link's condition. The metric's boolean and the reported state token move
    /// **together**, so the health dot and the label a console shows can never disagree.
    pub fn set_link(&self, state: LinkState) {
        self.link.store(state as u8, Ordering::Relaxed);
        self.connection_state
            .store(u64::from(state == LinkState::Online), Ordering::Relaxed);
    }

    #[must_use]
    pub fn link(&self) -> LinkState {
        LinkState::from_u8(self.link.load(Ordering::Relaxed))
    }
}

/// One device's connectivity sample, for the instance-connectivity provider registered in
/// [`App::run`].
///
/// * `connected` is the **normalized** flag — always present, so a console renders a health dot for
///   this adapter without knowing anything about its protocol.
/// * `state` is *this adapter's* vocabulary ([`LinkState`]) for the richer condition.
/// * `attributes` is the **open** bag: the backend, the connection mode, and the routing slot.
#[must_use]
pub fn connectivity_of(cfg: &DeviceConfig, health: &Health) -> InstanceConnectivity {
    let link = health.link();
    let mut attributes = serde_json::Map::new();
    attributes.insert("adapter".to_string(), json!(cfg.adapter));
    attributes.insert(
        "connectionMode".to_string(),
        json!(cfg.connection.connection_mode()),
    );
    if let Some(slot) = cfg.connection.slot {
        attributes.insert("slot".to_string(), json!(slot));
    }

    InstanceConnectivity::new(
        &cfg.id,
        link == LinkState::Online,
        Some(cfg.connection.endpoint.clone()),
    )
    .with_state(link.as_str())
    .with_attributes(attributes)
}

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
        // One write channel per device. The command handler cannot touch the session directly —
        // the session lives in the device's own task and is not `Sync` — so a write is *sent* to
        // that task, which serializes it against the poll loop.
        let mut writers: HashMap<String, tokio::sync::mpsc::Sender<WriteRequest>> = HashMap::new();
        // Each device's health, shared with its task: the task writes it, the connectivity provider
        // below reads it.
        let mut reported: Vec<(DeviceConfig, Arc<Health>)> = Vec::new();

        for device in &self.devices {
            let instance = gg.instance(&device.id)?;

            let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteRequest>(16);
            writers.insert(device.id.clone(), write_tx);

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

            tokio::spawn(run_device(
                device.clone(),
                Arc::clone(&self.global),
                instance.data(),
                instance.events(),
                dm,
                health,
                write_rx,
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

        // The southbound command surface. The full `sb/*` family + pause/resume land in slice S6;
        // this slice keeps the allow-listed, confirmed `sb/write`.
        if let Some(commands) = gg.commands() {
            let devices: HashMap<String, DeviceConfig> =
                self.devices.iter().map(|d| (d.id.clone(), d.clone())).collect();

            commands.register(
                "sb/write",
                command_handler(move |request| {
                    let devices = devices.clone();
                    let writers = writers.clone();
                    async move {
                        let instance = request
                            .body
                            .get("instance")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| CommandError::new("BAD_ARGS", "expected `instance`"))?;
                        let signal_id = request
                            .body
                            .get("signalId")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| CommandError::new("BAD_ARGS", "expected `signalId`"))?;
                        let value = request
                            .body
                            .get("value")
                            .ok_or_else(|| CommandError::new("BAD_ARGS", "expected `value`"))?;

                        let cfg = devices
                            .get(instance)
                            .ok_or_else(|| CommandError::new("NO_SUCH_INSTANCE", instance))?;

                        // THE ALLOW-LIST, checked here before the write ever reaches the device — an
                        // adapter that writes whatever it is asked to is a control-system
                        // vulnerability. Matched on the stable signal.id (the tag path).
                        if !cfg.writes.permits(signal_id) {
                            return Err(CommandError::new(
                                "WRITE_NOT_ALLOWED",
                                format!(
                                    "`{signal_id}` is not in this instance's writes.allow list"
                                ),
                            ));
                        }

                        // Resolve the tag path to its configured signal (the codec needs the type).
                        // SLICE S6: explicit-ref writes to unconfigured tags are added with the full
                        // sb/write body; here only configured signals are writable.
                        let spec = cfg.find_signal(signal_id).cloned().ok_or_else(|| {
                            CommandError::new(
                                "WRITE_FAILED",
                                format!("`{signal_id}` is not a configured signal"),
                            )
                        })?;

                        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                        let tx = writers
                            .get(instance)
                            .ok_or_else(|| CommandError::new("NO_SUCH_INSTANCE", instance))?;
                        tx.send(WriteRequest {
                            signal: spec,
                            value: value.clone(),
                            ack: ack_tx,
                        })
                        .await
                        .map_err(|_| {
                            CommandError::new("DEVICE_UNAVAILABLE", "device task is gone")
                        })?;

                        // A write is CONFIRMED: the reply is the device's answer, not "we sent it".
                        match ack_rx.await {
                            Ok(Ok(())) => Ok(Some(json!({ "written": signal_id }))),
                            Ok(Err(e)) => Err(CommandError::new("WRITE_FAILED", e)),
                            Err(_) => Err(CommandError::new("DEVICE_UNAVAILABLE", "no answer")),
                        }
                    }
                }),
            )?;
        }

        gg.shutdown_signal().await;
        tracing::info!("shutdown signal received");
        self.metrics.flush_metrics().await.ok();
        Ok(())
    }
}

/// A write, on its way from the command inbox to the device's own task. Carries the resolved
/// [`SignalSpec`] (the codec needs the type to build the CIP value — §3.3).
pub struct WriteRequest {
    pub signal: SignalSpec,
    pub value: serde_json::Value,
    /// The device's answer. A write is confirmed, not fire-and-forget.
    pub ack: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

/// One device's lifecycle: connect, poll, publish, reconnect.
///
/// The connect loop and the poll loop are nested on purpose. A read failure that breaks the link
/// drops out of the poll loop and back into connect — which is the only place that knows how to
/// back off.
async fn run_device(
    cfg: DeviceConfig,
    global: Arc<GlobalConfig>,
    data: DataFacade,
    events: EventsFacade,
    dm: Arc<DeviceMetrics>,
    health: Arc<Health>,
    mut writes: tokio::sync::mpsc::Receiver<WriteRequest>,
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

    // Push (class-1 implicit I/O) has its own connect → consume → reconnect loop over the
    // `PushSession` seam; it never enters the poll loop (a push device has no poll groups).
    if matches!(cfg.mode, crate::config::DeviceMode::Push) {
        run_push(
            &cfg,
            &global,
            backend.as_ref(),
            &data,
            &events,
            &dm,
            &health,
            backoff,
            connect_timeout,
        )
        .await;
        return;
    }

    let mut attempt: u32 = 0;

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
                let _ = events
                    .emit(
                        Severity::Info,
                        "device-connected",
                        Some(format!("connected to {}", cfg.connection.endpoint)),
                        Some(json!({ "instance": cfg.id, "adapter": backend.kind() })),
                    )
                    .await;
                // A raised alarm is cleared by the SAME wire type, so the pair rides one channel.
                let _ = events
                    .clear_alarm(Severity::Critical, "device-unreachable", None)
                    .await;

                crate::poll::poll_until_disconnected(
                    &cfg,
                    &global,
                    session,
                    &data,
                    &dm,
                    &health,
                    backend.kind(),
                    &mut writes,
                )
                .await;

                dm.on_connection_dropped(Instant::now());
                health.set_link(LinkState::Backoff);
                health.reconnects.fetch_add(1, Ordering::Relaxed);
                dm.emit_now().await;
                let _ = events
                    .raise_alarm(
                        Severity::Critical,
                        "device-unreachable",
                        Some(format!("lost the link to {}", cfg.connection.endpoint)),
                        Some(json!({ "instance": cfg.id })),
                    )
                    .await;
            }

            // Connect failed (Err) or timed out (Elapsed). A permanent failure will fail identically
            // forever, so back off to the ceiling immediately.
            other => {
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                let reason = match &other {
                    Ok(Err(e)) => e.to_string(),
                    _ => format!("connect timed out after {} ms", connect_timeout.as_millis()),
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "connect failed"
                );
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// One push device's lifecycle: open the class-1 connection, consume the [`IoUpdate`] stream through
/// the push engine ([`crate::push::consume_push`]), and reconnect on loss with the same backoff
/// ladder as poll (§10.2).
#[allow(clippy::too_many_arguments)]
async fn run_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    backend: &dyn DeviceBackend,
    data: &DataFacade,
    events: &EventsFacade,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    backoff: Backoff,
    connect_timeout: Duration,
) {
    let Some(io) = cfg.io.clone() else {
        tracing::error!(instance = %cfg.id, "push device has no io block");
        return;
    };
    let mut attempt: u32 = 0;

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
                crate::push::consume_push(
                    cfg,
                    global,
                    session.as_mut(),
                    data,
                    events,
                    dm,
                    health,
                    backend.kind(),
                )
                .await;
                session.close().await;

                dm.on_connection_dropped(Instant::now());
                health.set_link(LinkState::Backoff);
                health.reconnects.fetch_add(1, Ordering::Relaxed);
                dm.emit_now().await;
                let _ = events
                    .raise_alarm(
                        Severity::Critical,
                        "device-unreachable",
                        Some(format!("lost the class-1 link to {}", cfg.connection.endpoint)),
                        Some(json!({ "instance": cfg.id })),
                    )
                    .await;
            }
            other => {
                // The ForwardOpen was refused / timed out (§8.8 forwardOpenFailures; §8.2 connectFailures).
                dm.on_forward_open(false);
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                let reason = match &other {
                    Ok(Err(e)) => e.to_string(),
                    _ => format!("open_push timed out after {} ms", connect_timeout.as_millis()),
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "push open failed"
                );
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(wait).await;
            }
        }
    }
}

fn rand01() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let n = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    (n % 1_000_000) as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device(value: serde_json::Value) -> DeviceConfig {
        DeviceConfig::from_value(&value).unwrap()
    }

    fn a_device() -> DeviceConfig {
        device(json!({
            "id": "plc-1",
            "adapter": "ethernet-ip",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [ { "signals": [
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" }
            ] } ]
        }))
    }

    #[test]
    fn reconnect_backoff_is_exponential_capped_and_jittered() {
        let b = Backoff {
            base_ms: 1_000,
            max_ms: 10_000,
        };
        assert_eq!(b.delay(0, 1.0).as_millis(), 1_000);
        assert_eq!(b.delay(2, 1.0).as_millis(), 4_000);
        assert_eq!(b.delay(20, 1.0).as_millis(), 10_000, "capped");
        // Jitter: the delay is a point in the window, not its edge.
        assert_eq!(b.delay(2, 0.5).as_millis(), 2_000);
        assert_eq!(b.delay(2, 0.0).as_millis(), 0);
    }

    #[test]
    fn backoff_takes_the_configured_window() {
        let g = GlobalConfig::from_value(&json!({
            "timeouts": { "reconnectBackoffMinMs": 250, "reconnectBackoffMaxMs": 5000 }
        }))
        .unwrap();
        let b = Backoff::from_timeouts(&g.timeouts);
        assert_eq!(b.base_ms, 250);
        assert_eq!(b.max_ms, 5_000);
    }

    #[test]
    fn every_device_reports_its_own_connectivity() {
        let cfg = a_device();
        let health = Health::default();

        // Before the first connect: not reachable, and the token says why — CONNECTING, not BACKOFF.
        let c = connectivity_of(&cfg, &health);
        assert_eq!(c.instance, "plc-1");
        assert!(!c.connected);
        assert_eq!(c.state.as_deref(), Some("CONNECTING"));
        assert_eq!(c.detail.as_deref(), Some("127.0.0.1:44818"));
        assert_eq!(c.attributes["adapter"], json!("ethernet-ip"));
        assert_eq!(c.attributes["connectionMode"], json!("unconnected"));
        assert_eq!(c.attributes["slot"], json!(0));

        health.set_link(LinkState::Online);
        let c = connectivity_of(&cfg, &health);
        assert!(c.connected, "the normalized flag every console reads");
        assert_eq!(c.state.as_deref(), Some("ONLINE"));

        health.set_link(LinkState::Backoff);
        assert!(!connectivity_of(&cfg, &health).connected);
    }

    #[test]
    fn the_normalized_flag_and_the_health_metric_cannot_disagree() {
        let health = Health::default();
        health.set_link(LinkState::Online);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 1);
        health.set_link(LinkState::Backoff);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 0);
    }
}
