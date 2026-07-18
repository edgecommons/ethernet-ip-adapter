//! # EthernetIpAdapter — a southbound protocol adapter
//!
//! An **adapter** connects to devices, reads signals, and publishes them onto the UNS in the
//! shape the rest of the fleet expects — so that a consumer can chart a Modbus register and an
//! OPC UA node without knowing either protocol.
//!
//! ```text
//!   connect ──► poll ──► publish SouthboundSignalUpdate ──► report health
//!      ▲                                                         │
//!      └──────────── reconnect with backoff ◄────────────────────┘
//! ```
//!
//! One task per instance: an instance is one device, and its connection lifecycle is its own.
//!
//! ## The contract you are implementing (docs/SOUTHBOUND.md)
//!
//! * Publish `SouthboundSignalUpdate` on the `data` class, **via the `data()` facade** — never
//!   hand-build the body and never hand-write the topic. The facade constructs
//!   `{device, signal, samples}`, mints `ecv1/{device}/{component}/{instance}/data/{signal}`, and
//!   stamps identity. A hand-rolled topic is a topic that will disagree with the envelope.
//! * **Quality on every sample**, normalized to `GOOD | BAD | UNCERTAIN`, with the native code in
//!   `qualityRaw`.
//! * Emit **`southbound_health`**, dimensioned by instance, so an operator can see a link go down
//!   without reading logs.
//! * Report **per-instance connectivity** ([`connectivity_of`]), so the fleet sees which devices
//!   this adapter is actually talking to — pushed on every `state` keepalive and returned by the
//!   built-in `status` verb, from one provider.
//! * Serve **read/write commands** — and allow-list the writes. An adapter that will write any
//!   address it is asked to is a control-system vulnerability, not a feature.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use edgecommons::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::device::{DeviceBackend, DeviceSession, Quality, SimBackend};

/// The metric every southbound adapter emits (SOUTHBOUND.md §5).
const HEALTH_METRIC: &str = "southbound_health";

/// One device == one entry of `component.instances[]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceConfig {
    /// The instance id. It is the `{instance}` token of this device's UNS topics, so it must be a
    /// valid UNS token (lower-kebab).
    pub id: String,
    /// Which backend to use. Matches [`crate::device::DeviceBackend::kind`].
    #[serde(default = "default_adapter")]
    pub adapter: String,
    pub connection: crate::device::ConnectionConfig,
    /// How often to read, in milliseconds.
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    /// Writes are **allow-listed by stable `signal.id`**. An empty list means this adapter is
    /// read-only, which is the correct default for anything touching a control system.
    #[serde(default)]
    pub writes: Writes,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Writes {
    /// Signal ids this adapter is permitted to write. Nothing else is writable, whatever the
    /// command asks for.
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Writes {
    #[must_use]
    pub fn permits(&self, signal_id: &str) -> bool {
        self.allow.iter().any(|s| s == signal_id)
    }
}

fn default_adapter() -> String {
    "sim".into()
}
fn default_poll_ms() -> u64 {
    5_000
}

/// Reconnect backoff. Exponential with full jitter and a cap — so a site whose PLC reboots does
/// not get every adapter in the plant reconnecting in lockstep on the same second.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub base_ms: u64,
    pub max_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { base_ms: 1_000, max_ms: 60_000 }
    }
}

impl Backoff {
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
/// * `attributes` is the **open** bag: domain data only this adapter understands (here, which
///   backend the device speaks), carried without touching the two fields above that every consumer
///   relies on.
#[must_use]
pub fn connectivity_of(cfg: &DeviceConfig, health: &Health) -> InstanceConnectivity {
    let link = health.link();
    let mut attributes = serde_json::Map::new();
    attributes.insert("adapter".to_string(), json!(cfg.adapter));

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

        let mut devices = Vec::new();
        for id in config.instance_ids() {
            match config
                .instance(&id)
                .ok_or_else(|| anyhow::anyhow!("no config"))
                .and_then(|v| Ok(serde_json::from_value::<DeviceConfig>(v.clone())?))
            {
                Ok(d) => devices.push(d),
                Err(e) => tracing::warn!("skipping malformed device `{id}`: {e}"),
            }
        }
        anyhow::ensure!(!devices.is_empty(), "no valid devices in component.instances[]");

        Ok(Self { config, metrics, devices })
    }

    pub async fn run(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        // One write channel per device. The command handler cannot touch the session directly —
        // the session lives in the device's own task and is not `Sync` — so a write is *sent* to
        // that task, which serializes it against the poll loop. This is why an adapter is one
        // task per device rather than a shared connection pool.
        let mut writers: HashMap<String, tokio::sync::mpsc::Sender<WriteRequest>> = HashMap::new();
        // Each device's health, shared with its task: the task writes it, the connectivity
        // provider below reads it.
        let mut reported: Vec<(DeviceConfig, Arc<Health>)> = Vec::new();

        for device in &self.devices {
            // Per-instance facades: `data()` mints this device's topics and stamps its identity.
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
                instance.data(),
                instance.events(),
                Arc::clone(&self.metrics),
                health,
                write_rx,
            ));
        }

        // ONE provider, TWO surfaces: the library pushes this sample into the `state` keepalive's
        // `instances[]` every tick, and returns the very same sample from the built-in `status`
        // command verb when a console asks for it. Whoever watches and whoever asks cannot get
        // different answers. Keep it cheap — it is sampled on the keepalive interval.
        //
        // Reporting one entry per device is the whole point of the adapter archetype: the fleet
        // sees which of THIS component's devices are reachable, without minting a UNS instance per
        // connection.
        let provider: Arc<InstanceConnectivityProvider> = Arc::new(move || {
            reported.iter().map(|(cfg, health)| connectivity_of(cfg, health)).collect()
        });
        gg.set_instance_connectivity_provider(Some(provider));

        // The southbound command surface. `ping` / `reload-config` / `get-configuration` are
        // already live — the library registered them before we ran. These are the adapter's own.
        if let Some(commands) = gg.commands() {
            let devices: HashMap<String, DeviceConfig> =
                self.devices.iter().map(|d| (d.id.clone(), d.clone())).collect();

            commands.register(
                "sb/write",
                command_handler(move |request| {
                    let devices = devices.clone();
                    let writers = writers.clone();
                    async move {
                        // Scope rides an `instance` body field rather than a topic segment, so one
                        // inbox serves every device this adapter owns.
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

                        // THE ALLOW-LIST. Checked here, before the write ever reaches the device.
                        // An adapter that writes whatever it is asked to is a control-system
                        // vulnerability, and "the caller was authorized" is not this component's
                        // judgement to make.
                        if !cfg.writes.permits(signal_id) {
                            return Err(CommandError::new(
                                "WRITE_NOT_ALLOWED",
                                format!(
                                    "`{signal_id}` is not in this instance's writes.allow list"
                                ),
                            ));
                        }

                        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                        let tx = writers
                            .get(instance)
                            .ok_or_else(|| CommandError::new("NO_SUCH_INSTANCE", instance))?;
                        tx.send(WriteRequest {
                            signal_id: signal_id.to_string(),
                            value: value.clone(),
                            ack: ack_tx,
                        })
                        .await
                        .map_err(|_| CommandError::new("DEVICE_UNAVAILABLE", "device task is gone"))?;

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

/// A write, on its way from the command inbox to the device's own task.
pub struct WriteRequest {
    pub signal_id: String,
    pub value: serde_json::Value,
    /// The device's answer. A write is confirmed, not fire-and-forget.
    pub ack: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

/// One device's lifecycle: connect, poll, publish, reconnect.
///
/// The connect loop and the poll loop are nested on purpose. A read failure that breaks the link
/// drops out of the poll loop and back into connect — which is the only place that knows how to
/// back off. Retrying a read on a dead socket forever is the classic adapter bug.
async fn run_device(
    cfg: DeviceConfig,
    data: DataFacade,
    events: EventsFacade,
    metrics: Arc<dyn MetricService>,
    health: Arc<Health>,
    mut writes: tokio::sync::mpsc::Receiver<WriteRequest>,
) {
    let backend: Box<dyn DeviceBackend> = match cfg.adapter.as_str() {
        "sim" => Box::new(SimBackend),
        other => {
            tracing::error!(instance = %cfg.id, adapter = %other, "unknown adapter");
            return;
        }
    };
    let backoff = Backoff::default();
    let mut attempt: u32 = 0;

    loop {
        match backend.connect(&cfg.connection).await {
            Ok(session) => {
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
                // A raised alarm is cleared by the SAME wire type, so the pair rides one channel
                // and a consumer can match them.
                let _ = events.clear_alarm(Severity::Critical, "device-unreachable", None).await;

                poll_until_disconnected(
                    &cfg, session, &data, &metrics, &health, backend.kind(), &mut writes,
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

            // A permanent failure will fail identically forever, so back off to the ceiling
            // immediately rather than hammering a device that is never going to answer.
            Err(e) => {
                health.set_link(LinkState::Backoff);
                let permanent = !e.is_transient();
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                tracing::warn!(
                    instance = %cfg.id, error = %e, permanent,
                    wait_ms = wait.as_millis() as u64, "connect failed"
                );
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// Read on the poll interval and publish, until the link breaks.
async fn poll_until_disconnected(
    cfg: &DeviceConfig,
    mut session: Box<dyn DeviceSession>,
    data: &DataFacade,
    metrics: &Arc<dyn MetricService>,
    health: &Arc<Health>,
    adapter: &str,
    writes: &mut tokio::sync::mpsc::Receiver<WriteRequest>,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.poll_interval_ms));
    let mut since_health = Instant::now();

    loop {
        // Poll and write share this one task, so a write can never race a read on the same
        // connection — most device protocols are a single request/response channel and would
        // interleave into nonsense if two tasks talked at once.
        tokio::select! {
            Some(req) = writes.recv() => {
                let result = session
                    .write_signal(&req.signal_id, &req.value)
                    .await
                    .map_err(|e| e.to_string());
                if let Err(e) = &result {
                    tracing::warn!(instance = %cfg.id, signal = %req.signal_id, error = %e, "write failed");
                }
                // The command handler is waiting on this: a write is confirmed, not assumed.
                let _ = req.ack.send(result);
                continue;
            }
            _ = ticker.tick() => {}
        }

        let started = Instant::now();
        let readings = match session.read_signals().await {
            Ok(r) => r,
            Err(e) if e.is_transient() => {
                // The link is gone. Leave the poll loop so the connect loop can back off.
                tracing::warn!(instance = %cfg.id, error = %e, "read failed; reconnecting");
                health.read_errors.fetch_add(1, Ordering::Relaxed);
                session.close().await;
                return;
            }
            Err(e) => {
                tracing::error!(instance = %cfg.id, error = %e, "permanent read failure");
                health.read_errors.fetch_add(1, Ordering::Relaxed);
                session.close().await;
                return;
            }
        };
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        health.poll_latency_ms.store(latency, Ordering::Relaxed);

        for r in readings {
            // The data() facade builds the SouthboundSignalUpdate body, mints the topic, and
            // stamps identity. Do not hand-build any of the three.
            let quality = match r.quality {
                Quality::Good => edgecommons::facades::Quality::Good,
                Quality::Bad => edgecommons::facades::Quality::Bad,
                Quality::Uncertain => edgecommons::facades::Quality::Uncertain,
            };
            let mut sample = Sample::with_quality(r.value.clone(), quality);
            if let Some(raw) = &r.quality_raw {
                sample = sample.quality_raw(raw);
            }

            let mut signal = data.signal(&r.signal_id);
            if let Some(name) = &r.name {
                signal = signal.name(name);
            }
            let update = signal
                .device_parts(adapter, &cfg.id, &cfg.connection.endpoint)
                .sample(sample)
                .build();

            if let Err(e) = data.publish(update).await {
                tracing::warn!(instance = %cfg.id, signal = %r.signal_id, error = %e, "publish failed");
            } else {
                health.signals_published.fetch_add(1, Ordering::Relaxed);
            }
        }

        if since_health.elapsed() >= Duration::from_secs(60) {
            emit_health(metrics, health).await;
            since_health = Instant::now();
        }
    }
}

async fn emit_health(metrics: &Arc<dyn MetricService>, health: &Arc<Health>) {
    let mut v = HashMap::new();
    v.insert("connectionState".to_string(), health.connection_state.load(Ordering::Relaxed) as f64);
    v.insert("pollLatencyMs".to_string(), health.poll_latency_ms.load(Ordering::Relaxed) as f64);
    v.insert("readErrors".to_string(), health.read_errors.swap(0, Ordering::Relaxed) as f64);
    v.insert("reconnects".to_string(), health.reconnects.swap(0, Ordering::Relaxed) as f64);
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
    let n = std::collections::hash_map::RandomState::new().build_hasher().finish();
    (n % 1_000_000) as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_parses_from_its_instance_config() {
        let d: DeviceConfig = serde_json::from_value(json!({
            "id": "plc-1",
            "adapter": "sim",
            "connection": { "endpoint": "sim://plc-1", "unitId": 3 },
            "pollIntervalMs": 1000,
            "writes": { "allow": ["setpoint-1"] }
        }))
        .unwrap();

        assert_eq!(d.id, "plc-1");
        assert_eq!(d.poll_interval_ms, 1_000);
        // `connection` is deliberately open: every protocol needs different keys.
        assert_eq!(d.connection.extra["unitId"], 3);
    }

    #[test]
    fn an_adapter_is_read_only_until_a_write_is_allow_listed() {
        // The default must be read-only. An adapter that writes any address it is asked to is a
        // control-system vulnerability, not a convenience.
        let d: DeviceConfig = serde_json::from_value(json!({
            "id": "plc-1",
            "connection": { "endpoint": "sim://plc-1" }
        }))
        .unwrap();
        assert!(!d.writes.permits("setpoint-1"), "nothing is writable by default");

        let w = Writes { allow: vec!["setpoint-1".into()] };
        assert!(w.permits("setpoint-1"));
        assert!(!w.permits("setpoint-2"), "only the listed signal, not its neighbours");
    }

    #[test]
    fn reconnect_backoff_is_exponential_capped_and_jittered() {
        let b = Backoff { base_ms: 1_000, max_ms: 10_000 };
        assert_eq!(b.delay(0, 1.0).as_millis(), 1_000);
        assert_eq!(b.delay(2, 1.0).as_millis(), 4_000);
        assert_eq!(b.delay(20, 1.0).as_millis(), 10_000, "capped");
        // Jitter: the delay is a point in the window, not its edge — so a plant full of adapters
        // does not reconnect in lockstep when a PLC reboots.
        assert_eq!(b.delay(2, 0.5).as_millis(), 2_000);
        assert_eq!(b.delay(2, 0.0).as_millis(), 0);
    }

    #[test]
    fn an_unknown_config_key_is_rejected_rather_than_ignored() {
        let bad = serde_json::from_value::<DeviceConfig>(json!({
            "id": "plc-1",
            "connection": { "endpoint": "x" },
            "pollIntervalMS": 1000
        }));
        assert!(bad.is_err(), "a typo'd key is a mistake, not a no-op");
    }

    #[test]
    fn every_device_reports_its_own_connectivity() {
        let cfg: DeviceConfig = serde_json::from_value(json!({
            "id": "plc-1",
            "adapter": "sim",
            "connection": { "endpoint": "sim://plc-1" }
        }))
        .unwrap();
        let health = Health::default();

        // Before the first connect: not reachable, and the adapter's own token says why it is not
        // yet — CONNECTING is not BACKOFF, and the boolean alone could not tell them apart.
        let c = connectivity_of(&cfg, &health);
        assert_eq!(c.instance, "plc-1");
        assert!(!c.connected);
        assert_eq!(c.state.as_deref(), Some("CONNECTING"));
        assert_eq!(c.detail.as_deref(), Some("sim://plc-1"), "the endpoint, for a human");
        assert_eq!(c.attributes["adapter"], json!("sim"), "the open bag carries domain data");

        health.set_link(LinkState::Online);
        let c = connectivity_of(&cfg, &health);
        assert!(c.connected, "the normalized flag every console reads");
        assert_eq!(c.state.as_deref(), Some("ONLINE"));

        health.set_link(LinkState::Backoff);
        assert!(!connectivity_of(&cfg, &health).connected);
    }

    #[test]
    fn the_normalized_flag_and_the_health_metric_cannot_disagree() {
        // Both move through set_link, so the metric an operator charts and the connectivity a
        // console renders are the same fact.
        let health = Health::default();
        health.set_link(LinkState::Online);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 1);
        health.set_link(LinkState::Backoff);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 0);
    }
}
