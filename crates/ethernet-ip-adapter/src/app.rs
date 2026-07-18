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
use crate::device::{DeviceBackend, Quality, Reading};
use crate::sim::SimBackend;

/// The metric every southbound adapter emits (SOUTHBOUND.md §5). The full `EtherNetIp*` families
/// land in slice S5.
const HEALTH_METRIC: &str = "southbound_health";

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
/// connectivity provider reports.
#[derive(Default)]
pub struct Health {
    /// 1 = connected, 0 = down.
    pub connection_state: AtomicU64,
    /// The [`LinkState`], as a `u8`. Read it through [`Health::link`].
    link: AtomicU8,
    pub poll_latency_ms: AtomicU64,
    pub read_errors: AtomicU64,
    pub reconnects: AtomicU64,
    pub signals_published: AtomicU64,
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

            // The health metric is dimensioned BY INSTANCE, so a fleet view can show one device
            // down without averaging it away against the others.
            self.metrics.define_metric(
                MetricBuilder::create(HEALTH_METRIC)
                    .with_config(&self.config)
                    .add_measure("connectionState", "Count", 1)
                    .add_measure("pollLatencyMs", "Milliseconds", 1)
                    .add_measure("readErrors", "Count", 60)
                    .add_measure("reconnects", "Count", 60)
                    .add_measure("signalsPublished", "Count", 60)
                    .add_dimension("instance", &device.id)
                    .build(),
            );

            let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteRequest>(16);
            writers.insert(device.id.clone(), write_tx);

            let health = Arc::new(Health::default());
            reported.push((device.clone(), Arc::clone(&health)));

            tokio::spawn(run_device(
                device.clone(),
                Arc::clone(&self.global),
                instance.data(),
                instance.events(),
                Arc::clone(&self.metrics),
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
    metrics: Arc<dyn MetricService>,
    health: Arc<Health>,
    mut writes: tokio::sync::mpsc::Receiver<WriteRequest>,
) {
    let backend: Box<dyn DeviceBackend> = match cfg.adapter.as_str() {
        "sim" => Box::new(SimBackend),
        // SLICE S3: the real `EipBackend` (built on the owned `enip` protocol crate) lands in slice
        // S3. Until then the simulator stands in for `ethernet-ip` so a bare deploy runs end-to-end
        // without a PLC.
        "ethernet-ip" => Box::new(SimBackend),
        other => {
            tracing::error!(instance = %cfg.id, adapter = %other, "unknown adapter");
            return;
        }
    };
    let backoff = Backoff::from_timeouts(&global.timeouts);
    let connect_timeout = Duration::from_millis(global.timeouts.connect_ms.max(1));
    let mut attempt: u32 = 0;

    loop {
        // Connect within the configured deadline (§4.1 connectMs).
        let outcome = tokio::time::timeout(connect_timeout, backend.connect(&cfg.connection)).await;

        match outcome {
            Ok(Ok(session)) => {
                attempt = 0;
                health.set_link(LinkState::Online);
                emit_health(&metrics, &health).await;
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

                poll_until_disconnected(
                    &cfg,
                    &global,
                    session,
                    &data,
                    &metrics,
                    &health,
                    backend.kind(),
                    &mut writes,
                )
                .await;

                health.set_link(LinkState::Backoff);
                health.reconnects.fetch_add(1, Ordering::Relaxed);
                emit_health(&metrics, &health).await;
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

/// Poll each group on its own cadence and publish, until the link breaks.
///
/// A single task owns the session (it is not `Sync`), so all poll groups and the write channel are
/// serialized here. Each group carries its own deadline; the loop sleeps until the earliest one,
/// polls that group, and re-arms it — a per-group [`tokio::time::interval`] without racing N
/// tickers in a static `select!`.
#[allow(clippy::too_many_arguments)]
async fn poll_until_disconnected(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    mut session: Box<dyn crate::device::DeviceSession>,
    data: &DataFacade,
    metrics: &Arc<dyn MetricService>,
    health: &Arc<Health>,
    adapter: &str,
    writes: &mut tokio::sync::mpsc::Receiver<WriteRequest>,
) {
    let intervals: Vec<Duration> = cfg
        .poll_groups
        .iter()
        .map(|g| Duration::from_millis(cfg.effective_poll_ms(g, global).max(1)))
        .collect();
    let mut deadlines: Vec<Instant> = intervals.iter().map(|d| Instant::now() + *d).collect();
    let mut since_health = Instant::now();

    loop {
        // Earliest group deadline.
        let mut idx = 0;
        let mut due = deadlines[0];
        for (i, d) in deadlines.iter().enumerate() {
            if *d < due {
                due = *d;
                idx = i;
            }
        }
        let wait = due.saturating_duration_since(Instant::now());

        tokio::select! {
            biased;

            // A write shares this one task, so it can never race a read on the same connection.
            Some(req) = writes.recv() => {
                let result = session
                    .write_signal(&req.signal, &req.value)
                    .await
                    .map_err(|e| e.to_string());
                if let Err(e) = &result {
                    tracing::warn!(instance = %cfg.id, tag_path = %req.signal.tag_path, error = %e, "write failed");
                }
                let _ = req.ack.send(result);
                continue;
            }

            _ = tokio::time::sleep(wait) => {}
        }

        // Re-arm this group (guard against catch-up storms if a cycle overran).
        deadlines[idx] = (deadlines[idx] + intervals[idx]).max(Instant::now());

        let group = &cfg.poll_groups[idx];
        let started = Instant::now();
        let readings = match session.read_signals(&group.signals).await {
            Ok(r) => r,
            Err(e) => {
                // The link is gone (transient) or misconfigured (permanent). Either way, leave the
                // poll loop so the connect loop can back off.
                tracing::warn!(instance = %cfg.id, error = %e, transient = e.is_transient(), "read failed; reconnecting");
                health.read_errors.fetch_add(1, Ordering::Relaxed);
                session.close().await;
                return;
            }
        };
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        health.poll_latency_ms.store(latency, Ordering::Relaxed);

        // SLICE S4: deadband/change gating and batchMs coalescing plug in here — this slice
        // publishes every polled sample.
        let by_id: HashMap<&str, &Reading> =
            readings.iter().map(|r| (r.signal_id.as_str(), r)).collect();
        for spec in &group.signals {
            if let Some(reading) = by_id.get(spec.tag_path.as_str()) {
                publish_reading(spec, reading, data, cfg, adapter, health).await;
            }
        }

        if since_health.elapsed() >= Duration::from_secs(60) {
            emit_health(metrics, health).await;
            since_health = Instant::now();
        }
    }
}

/// Publish one reading as a `SouthboundSignalUpdate`. The `data()` facade builds the body, mints the
/// topic (channel = the config `name`, §5.3), and stamps identity — none of the three is
/// hand-built. `signal.id` is the tag path (D-EIP-9).
async fn publish_reading(
    spec: &SignalSpec,
    reading: &Reading,
    data: &DataFacade,
    cfg: &DeviceConfig,
    adapter: &str,
    health: &Health,
) {
    let quality = match reading.quality {
        Quality::Good => edgecommons::facades::Quality::Good,
        Quality::Bad => edgecommons::facades::Quality::Bad,
        Quality::Uncertain => edgecommons::facades::Quality::Uncertain,
    };
    let mut sample = Sample::with_quality(reading.value.clone(), quality);
    if let Some(raw) = &reading.quality_raw {
        sample = sample.quality_raw(raw);
    }

    let update = data
        .signal(&spec.tag_path)
        .name(&spec.name)
        .address(spec.address_json(&cfg.connection))
        .device_parts(adapter, &cfg.id, &cfg.connection.endpoint)
        .signal_path(&spec.name)
        .sample(sample)
        .build();

    if let Err(e) = data.publish(update).await {
        tracing::warn!(instance = %cfg.id, tag_path = %spec.tag_path, error = %e, "publish failed");
    } else {
        health.signals_published.fetch_add(1, Ordering::Relaxed);
    }
}

async fn emit_health(metrics: &Arc<dyn MetricService>, health: &Arc<Health>) {
    let mut v = HashMap::new();
    v.insert(
        "connectionState".to_string(),
        health.connection_state.load(Ordering::Relaxed) as f64,
    );
    v.insert(
        "pollLatencyMs".to_string(),
        health.poll_latency_ms.load(Ordering::Relaxed) as f64,
    );
    v.insert(
        "readErrors".to_string(),
        health.read_errors.swap(0, Ordering::Relaxed) as f64,
    );
    v.insert(
        "reconnects".to_string(),
        health.reconnects.swap(0, Ordering::Relaxed) as f64,
    );
    v.insert(
        "signalsPublished".to_string(),
        health.signals_published.swap(0, Ordering::Relaxed) as f64,
    );
    if let Err(e) = metrics.emit_metric(HEALTH_METRIC, v).await {
        tracing::warn!(error = %e, "health metric emit failed");
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
