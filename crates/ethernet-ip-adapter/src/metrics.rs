//! # Operational metrics (§8) — the mandatory `southbound_health` + the six `EtherNetIp*` families
//!
//! Every southbound adapter emits the shared [`HEALTH`] metric (SOUTHBOUND §5). This adapter adds
//! six protocol families (§8.2–§8.8), each defined at startup like the reference adapters and
//! emitted on the `metricsIntervalSecs` cadence from a per-device [`DeviceMetrics`] emitter, plus an
//! immediate flush on connect / disconnect / pause / resume / push-up / push-lost transitions
//! (`emit_metric_now`, §8.7).
//!
//! ## The Total/Interval convention (D-EIP-12, §8)
//!
//! Every **counter** is a measure PAIR: `<name>Total` (monotonic since component start) and
//! `<name>Interval` (since the previous emit of that family; **reset on emit**). **Gauges**
//! (`connectionState`, `sessionConnected`, `paused`, `batchSize`, latencies, inventory sizes) and
//! interval **sums** (`pollDurationMs`, `publishLatencyMs`, `commandLatencyMs`, `connectedDurationMs`)
//! are single measures. See [`Pair`].
//!
//! ## Dimensions are low-cardinality ONLY (§8)
//!
//! `instance`, `pollGroup`, `result` (`success`|`error`), `verb` (the closed §8.6 set), `publishMode`
//! (`onChange`|`always`), `connectionMode` (`connected`|`unconnected`). **Never** signal names,
//! addresses, endpoints, or error text — those are unbounded and would shred a fleet dashboard.
//! (`coreName`/`category`/`component` are injected by [`MetricBuilder::build`].)
//!
//! ## Why re-define before each emit
//!
//! The core `MetricService` store is keyed by metric *name*, so one family name (e.g. `EtherNetIpPoll`)
//! cannot hold several dimension combinations at once. Like the shipped `file-replicator`, this module
//! **re-defines** the family with the combo's dimensions immediately before emitting it — so each
//! (family × dimension) combination emits with its own dimensions. All combinations are ALSO
//! pre-defined once at startup ([`DeviceMetrics::define_all`]) so the set is fixed and discoverable.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use edgecommons::prelude::{Config, MetricBuilder, MetricService};

use crate::app::Health;
use crate::config::{DeviceConfig, DeviceMode, GlobalConfig, PublishMode};

/// The mandatory shared southbound metric (SOUTHBOUND §5 + the §8.1 `paused`/`publishLatencyMs`/
/// `staleSignals` extensions).
pub const HEALTH: &str = "southbound_health";
/// §8.2 — the CIP session / connect lifecycle.
pub const CONNECTION: &str = "EtherNetIpConnection";
/// §8.3 — config-derived poll inventory gauges.
pub const INVENTORY: &str = "EtherNetIpInventory";
/// §8.4 — the poll-cycle counters.
pub const POLL: &str = "EtherNetIpPoll";
/// §8.5 — the publish path.
pub const PUBLISH: &str = "EtherNetIpPublish";
/// §8.6 — the `sb/*` command surface (fed by S6; defined here).
pub const COMMAND: &str = "EtherNetIpCommand";
/// §8.8 — class-1 implicit I/O (push instances only).
pub const IO: &str = "EtherNetIpIo";

/// A `result` dimension value: the operation succeeded.
pub const RESULT_SUCCESS: &str = "success";
/// A `result` dimension value: the operation failed.
pub const RESULT_ERROR: &str = "error";
const RESULTS: [&str; 2] = [RESULT_SUCCESS, RESULT_ERROR];

/// The closed `verb` dimension set for [`COMMAND`] (§8.6). 9 verbs × 2 results, pre-defined like the
/// Modbus reference's `COMMAND_VERBS`.
pub const COMMAND_VERBS: [&str; 9] = [
    "sb/status", "sb/read", "sb/write", "sb/signals", "sb/browse", "sb/pause", "sb/resume",
    "reconnect", "repoll",
];

const UNIT_COUNT: &str = "Count";
const UNIT_MS: &str = "Milliseconds";

/// The per-verb tallies [`DeviceMetrics::record_command`] adds to a command's `(verb, result)` row
/// (§8.6). Measures irrelevant to a verb stay 0.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandTally {
    /// `sb/read` entries served.
    pub read_signals: u64,
    /// `sb/write` entries attempted.
    pub write_signals: u64,
    /// `sb/write` entries that failed (incl. allow-list refusals).
    pub write_failures: u64,
    /// `sb/browse` tags returned.
    pub browsed_tags: u64,
}

// ===================================================================================
// The definition schema (§8) — the executable parity contract's data source
// ===================================================================================

/// One measure in a [`FamilyDef`]: its name, unit, and storage resolution, exactly as §8 lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasureDef {
    pub name: String,
    pub unit: String,
    pub res: u32,
}

/// One metric family's full definition: its name, its dimension keys, and its measures (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyDef {
    pub name: String,
    pub dimensions: Vec<String>,
    pub measures: Vec<MeasureDef>,
}

fn m(name: &str, unit: &str, res: u32) -> MeasureDef {
    MeasureDef { name: name.to_string(), unit: unit.to_string(), res }
}

/// A `<prefix>Total` + `<prefix>Interval` counter pair (both `Count`, resolution 60).
fn pair(prefix: &str) -> Vec<MeasureDef> {
    vec![
        m(&format!("{prefix}Total"), UNIT_COUNT, 60),
        m(&format!("{prefix}Interval"), UNIT_COUNT, 60),
    ]
}

fn dims(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|s| (*s).to_string()).collect()
}

/// The **complete** §8 definition set — every family, every measure, every dimension key. This is the
/// single source the startup pre-definition and the §12.3 parity test both read; the test asserts it
/// equals an independent literal transcription of §8, so a dropped or renamed measure fails the build.
#[must_use]
pub fn family_defs() -> Vec<FamilyDef> {
    let mut out = Vec::new();

    // §8.1 southbound_health — dims: instance. All single measures (no Total/Interval pairs).
    out.push(FamilyDef {
        name: HEALTH.to_string(),
        dimensions: dims(&["instance"]),
        measures: vec![
            m("connectionState", UNIT_COUNT, 1),
            m("paused", UNIT_COUNT, 1),
            m("pollLatencyMs", UNIT_MS, 1),
            m("publishLatencyMs", UNIT_MS, 1),
            m("readErrors", UNIT_COUNT, 60),
            m("writeErrors", UNIT_COUNT, 60),
            m("staleSignals", UNIT_COUNT, 60),
            m("reconnects", UNIT_COUNT, 60),
        ],
    });

    // §8.2 EtherNetIpConnection — dims: instance, connectionMode.
    let mut conn = vec![m("sessionConnected", UNIT_COUNT, 1)];
    conn.extend(pair("connectAttempts"));
    conn.extend(pair("connectFailures"));
    conn.extend(pair("connectionDrops"));
    conn.extend(pair("reconnects"));
    conn.extend(pair("tlsHandshakeFailures"));
    conn.push(m("connectLatencyMs", UNIT_MS, 60));
    conn.push(m("connectedDurationMs", UNIT_MS, 60));
    out.push(FamilyDef { name: CONNECTION.to_string(), dimensions: dims(&["instance", "connectionMode"]), measures: conn });

    // §8.3 EtherNetIpInventory — dims: instance, pollGroup. Config-derived gauges.
    out.push(FamilyDef {
        name: INVENTORY.to_string(),
        dimensions: dims(&["instance", "pollGroup"]),
        measures: vec![
            m("configuredSignals", UNIT_COUNT, 60),
            m("arraySignals", UNIT_COUNT, 60),
            m("writableSignals", UNIT_COUNT, 60),
            m("configuredPollIntervalMs", UNIT_MS, 60),
            m("requestsPerCycle", UNIT_COUNT, 60),
        ],
    });

    // §8.4 EtherNetIpPoll — dims: instance, pollGroup, result.
    let mut poll = Vec::new();
    poll.extend(pair("pollCycles"));
    poll.push(m("pollDurationMs", UNIT_MS, 60));
    poll.extend(pair("tagReads"));
    poll.extend(pair("tagReadErrors"));
    poll.extend(pair("samplesGood"));
    poll.extend(pair("samplesBad"));
    poll.extend(pair("samplesUncertain"));
    poll.extend(pair("samplesChanged"));
    poll.extend(pair("samplesSuppressed"));
    poll.extend(pair("pollOverruns"));
    out.push(FamilyDef { name: POLL.to_string(), dimensions: dims(&["instance", "pollGroup", "result"]), measures: poll });

    // §8.5 EtherNetIpPublish — dims: instance, publishMode.
    let mut publish = Vec::new();
    publish.extend(pair("dataMessagesPublished"));
    publish.extend(pair("samplesPublished"));
    publish.extend(pair("publishFailures"));
    publish.extend(pair("batchFlushes"));
    publish.push(m("batchSize", UNIT_COUNT, 60));
    publish.push(m("publishLatencyMs", UNIT_MS, 60));
    out.push(FamilyDef { name: PUBLISH.to_string(), dimensions: dims(&["instance", "publishMode"]), measures: publish });

    // §8.6 EtherNetIpCommand — dims: instance, verb, result.
    let mut command = Vec::new();
    command.extend(pair("commandRequests"));
    command.extend(pair("commandErrors"));
    command.push(m("commandLatencyMs", UNIT_MS, 60));
    command.extend(pair("readSignals"));
    command.extend(pair("writeSignals"));
    command.extend(pair("writeFailures"));
    command.extend(pair("browsedTags"));
    command.extend(pair("pauseRequests"));
    command.extend(pair("resumeRequests"));
    command.extend(pair("reconnectRequests"));
    command.extend(pair("repollRequests"));
    out.push(FamilyDef { name: COMMAND.to_string(), dimensions: dims(&["instance", "verb", "result"]), measures: command });

    // §8.8 EtherNetIpIo — dims: instance (push only).
    let mut io = vec![m("ioConnectionState", UNIT_COUNT, 1)];
    io.extend(pair("forwardOpens"));
    io.extend(pair("forwardOpenFailures"));
    io.extend(pair("framesConsumed"));
    io.extend(pair("framesProduced"));
    io.extend(pair("staleFramesDropped"));
    io.extend(pair("sequenceGaps"));
    io.extend(pair("sizeMismatchDropped"));
    io.extend(pair("malformedFrames"));
    io.extend(pair("ioTimeouts"));
    io.extend(pair("produceOverruns"));
    io.push(m("interFrameMs", UNIT_MS, 1));
    io.push(m("runMode", UNIT_COUNT, 1));
    out.push(FamilyDef { name: IO.to_string(), dimensions: dims(&["instance"]), measures: io });

    out
}

fn family_def(name: &str) -> FamilyDef {
    family_defs()
        .into_iter()
        .find(|f| f.name == name)
        .expect("family_defs covers every family name used by the emitter")
}

// ===================================================================================
// Counter state
// ===================================================================================

/// A `<name>Total` (monotonic) + `<name>Interval` (reset on emit) counter pair (§8 convention).
#[derive(Debug, Default, Clone, Copy)]
struct Pair {
    total: f64,
    interval: f64,
}

impl Pair {
    fn add(&mut self, v: f64) {
        self.total += v;
        self.interval += v;
    }

    /// Write both measures into `out` and **reset the interval** (the emit convention).
    fn drain_into(&mut self, out: &mut HashMap<String, f64>, prefix: &str) {
        out.insert(format!("{prefix}Total"), self.total);
        out.insert(format!("{prefix}Interval"), self.interval);
        self.interval = 0.0;
    }
}

#[derive(Default)]
struct ConnCounters {
    session_connected: bool,
    ever_connected: bool,
    connect_attempts: Pair,
    connect_failures: Pair,
    connection_drops: Pair,
    reconnects: Pair,
    /// TLS handshake failures on a `mode: tls` connection (CIP Security Phase 1, §3.4).
    tls_handshake_failures: Pair,
    connect_latency_ms: f64,
    connected_accrued_ms: f64,
    connected_since: Option<Instant>,
}

impl ConnCounters {
    fn accrue(&mut self, now: Instant) {
        if let Some(since) = self.connected_since {
            self.connected_accrued_ms += now.saturating_duration_since(since).as_secs_f64() * 1000.0;
            self.connected_since = Some(now);
        }
    }

    fn drain(&mut self, now: Instant) -> HashMap<String, f64> {
        self.accrue(now);
        let mut v = HashMap::new();
        v.insert("sessionConnected".to_string(), f64::from(u8::from(self.session_connected)));
        self.connect_attempts.drain_into(&mut v, "connectAttempts");
        self.connect_failures.drain_into(&mut v, "connectFailures");
        self.connection_drops.drain_into(&mut v, "connectionDrops");
        self.reconnects.drain_into(&mut v, "reconnects");
        self.tls_handshake_failures.drain_into(&mut v, "tlsHandshakeFailures");
        v.insert("connectLatencyMs".to_string(), self.connect_latency_ms);
        v.insert("connectedDurationMs".to_string(), self.connected_accrued_ms);
        self.connected_accrued_ms = 0.0;
        v
    }
}

#[derive(Default)]
struct PollCounters {
    poll_cycles: Pair,
    poll_duration_ms: f64,
    tag_reads: Pair,
    tag_read_errors: Pair,
    samples_good: Pair,
    samples_bad: Pair,
    samples_uncertain: Pair,
    samples_changed: Pair,
    samples_suppressed: Pair,
    poll_overruns: Pair,
}

impl PollCounters {
    fn drain(&mut self) -> HashMap<String, f64> {
        let mut v = HashMap::new();
        self.poll_cycles.drain_into(&mut v, "pollCycles");
        v.insert("pollDurationMs".to_string(), self.poll_duration_ms);
        self.poll_duration_ms = 0.0;
        self.tag_reads.drain_into(&mut v, "tagReads");
        self.tag_read_errors.drain_into(&mut v, "tagReadErrors");
        self.samples_good.drain_into(&mut v, "samplesGood");
        self.samples_bad.drain_into(&mut v, "samplesBad");
        self.samples_uncertain.drain_into(&mut v, "samplesUncertain");
        self.samples_changed.drain_into(&mut v, "samplesChanged");
        self.samples_suppressed.drain_into(&mut v, "samplesSuppressed");
        self.poll_overruns.drain_into(&mut v, "pollOverruns");
        v
    }
}

#[derive(Default)]
struct PubCounters {
    data_messages: Pair,
    samples: Pair,
    failures: Pair,
    batch_flushes: Pair,
    batch_size: f64,
    publish_latency_ms: f64,
}

impl PubCounters {
    fn drain(&mut self) -> HashMap<String, f64> {
        let mut v = HashMap::new();
        self.data_messages.drain_into(&mut v, "dataMessagesPublished");
        self.samples.drain_into(&mut v, "samplesPublished");
        self.failures.drain_into(&mut v, "publishFailures");
        self.batch_flushes.drain_into(&mut v, "batchFlushes");
        v.insert("batchSize".to_string(), self.batch_size);
        v.insert("publishLatencyMs".to_string(), self.publish_latency_ms);
        self.publish_latency_ms = 0.0;
        v
    }
}

#[derive(Default)]
struct CmdCounters {
    command_requests: Pair,
    command_errors: Pair,
    command_latency_ms: f64,
    read_signals: Pair,
    write_signals: Pair,
    write_failures: Pair,
    browsed_tags: Pair,
    pause_requests: Pair,
    resume_requests: Pair,
    reconnect_requests: Pair,
    repoll_requests: Pair,
}

impl CmdCounters {
    fn drain(&mut self) -> HashMap<String, f64> {
        let mut v = HashMap::new();
        self.command_requests.drain_into(&mut v, "commandRequests");
        self.command_errors.drain_into(&mut v, "commandErrors");
        v.insert("commandLatencyMs".to_string(), self.command_latency_ms);
        self.command_latency_ms = 0.0;
        self.read_signals.drain_into(&mut v, "readSignals");
        self.write_signals.drain_into(&mut v, "writeSignals");
        self.write_failures.drain_into(&mut v, "writeFailures");
        self.browsed_tags.drain_into(&mut v, "browsedTags");
        self.pause_requests.drain_into(&mut v, "pauseRequests");
        self.resume_requests.drain_into(&mut v, "resumeRequests");
        self.reconnect_requests.drain_into(&mut v, "reconnectRequests");
        self.repoll_requests.drain_into(&mut v, "repollRequests");
        v
    }
}

#[derive(Default)]
struct IoCounters {
    io_connection_state: bool,
    forward_opens: Pair,
    forward_open_failures: Pair,
    frames_consumed: Pair,
    frames_produced: Pair,
    stale_frames_dropped: Pair,
    sequence_gaps: Pair,
    size_mismatch_dropped: Pair,
    malformed_frames: Pair,
    io_timeouts: Pair,
    produce_overruns: Pair,
    inter_frame_ms: f64,
    run_mode: bool,
    last_seq: Option<u16>,
    last_frame_at: Option<Instant>,
    /// Last absolute values read from the class-1 stack counters (§8.8), so a cumulative snapshot is
    /// folded into the Total/Interval pairs as a delta. Reset on a lost link (counters belong to one
    /// ForwardOpen), so a fresh connection's counts accrue from 0.
    last_stats_frames_produced: u64,
    last_stats_stale: u64,
    last_stats_size_mismatch: u64,
    last_stats_malformed: u64,
    last_stats_produce_overruns: u64,
    /// Negotiated APIs from the ForwardOpen reply (ms), surfaced by `sb/status` (§7.1).
    o2t_api_ms: u32,
    t2o_api_ms: u32,
}

impl IoCounters {
    fn drain(&mut self) -> HashMap<String, f64> {
        let mut v = HashMap::new();
        v.insert("ioConnectionState".to_string(), f64::from(u8::from(self.io_connection_state)));
        self.forward_opens.drain_into(&mut v, "forwardOpens");
        self.forward_open_failures.drain_into(&mut v, "forwardOpenFailures");
        self.frames_consumed.drain_into(&mut v, "framesConsumed");
        self.frames_produced.drain_into(&mut v, "framesProduced");
        self.stale_frames_dropped.drain_into(&mut v, "staleFramesDropped");
        self.sequence_gaps.drain_into(&mut v, "sequenceGaps");
        self.size_mismatch_dropped.drain_into(&mut v, "sizeMismatchDropped");
        self.malformed_frames.drain_into(&mut v, "malformedFrames");
        self.io_timeouts.drain_into(&mut v, "ioTimeouts");
        self.produce_overruns.drain_into(&mut v, "produceOverruns");
        v.insert("interFrameMs".to_string(), self.inter_frame_ms);
        v.insert("runMode".to_string(), f64::from(u8::from(self.run_mode)));
        v
    }
}

/// One poll group's static inventory row (§8.3), computed once from config.
struct InventoryRow {
    group: String,
    configured_signals: f64,
    array_signals: f64,
    writable_signals: f64,
    poll_interval_ms: f64,
    requests_per_cycle: f64,
}

#[derive(Default)]
struct Inner {
    conn: ConnCounters,
    poll: BTreeMap<(String, &'static str), PollCounters>,
    publish: BTreeMap<&'static str, PubCounters>,
    command: BTreeMap<(&'static str, &'static str), CmdCounters>,
    io: IoCounters,
}

/// A per-device operational-metrics emitter (§8). Owns the counter state for one device's six
/// `EtherNetIp*` families and emits them — plus the shared [`HEALTH`] metric — on the
/// `metricsIntervalSecs` cadence and on transitions.
pub struct DeviceMetrics {
    svc: Arc<dyn MetricService>,
    config: Arc<Config>,
    device: DeviceConfig,
    is_push: bool,
    /// The `publishMode` dimension values this device emits (poll: the modes across its groups; push:
    /// its single resolved mode).
    publish_modes: Vec<&'static str>,
    inventory: Vec<InventoryRow>,
    health: Arc<Health>,
    /// The O→T run/idle we produce (push output.run, default true) — the `run` field of the status
    /// `io` view (§7.1). `false`/irrelevant for poll devices.
    produced_run: bool,
    inner: Mutex<Inner>,
}

fn mode_token(m: PublishMode) -> &'static str {
    m.as_str()
}

impl DeviceMetrics {
    /// Build the emitter for one device, pre-populating every counter combination (§8): connection,
    /// per-group inventory + poll (poll devices), per-mode publish, the full command matrix, and IO
    /// (push devices).
    #[must_use]
    pub fn new(
        svc: Arc<dyn MetricService>,
        config: Arc<Config>,
        device: DeviceConfig,
        global: &GlobalConfig,
        health: Arc<Health>,
    ) -> Self {
        let is_push = matches!(device.mode, DeviceMode::Push);

        // publishMode dimension values.
        let publish_modes: Vec<&'static str> = if is_push {
            let m = device
                .defaults
                .publish_mode
                .or(global.defaults.publish_mode)
                .unwrap_or(PublishMode::OnChange);
            vec![mode_token(m)]
        } else {
            let mut set: Vec<&'static str> = Vec::new();
            for g in &device.poll_groups {
                let tok = mode_token(device.effective_publish_mode(g, global));
                if !set.contains(&tok) {
                    set.push(tok);
                }
            }
            if set.is_empty() {
                set.push(mode_token(PublishMode::OnChange));
            }
            set
        };

        // Inventory rows (poll devices only): config-derived gauges (§8.3).
        let mut inventory = Vec::new();
        for g in &device.poll_groups {
            let group = g
                .id
                .clone()
                .unwrap_or_else(|| "group".to_string());
            let configured = g.signals.len();
            let arrays = g.signals.iter().filter(|s| s.array_count.is_some()).count();
            let writable = g
                .signals
                .iter()
                .filter(|s| device.writes.permits(&s.tag_path))
                .count();
            inventory.push(InventoryRow {
                group,
                configured_signals: configured as f64,
                array_signals: arrays as f64,
                writable_signals: writable as f64,
                poll_interval_ms: device.effective_poll_ms(g, global) as f64,
                // D-EIP-15: one CIP request per signal per cycle (no MSP batching) → makes the cost visible.
                requests_per_cycle: configured as f64,
            });
        }

        // Pre-populate the counter maps so the combination set is fixed at startup.
        let mut inner = Inner::default();
        for row in &inventory {
            for result in RESULTS {
                inner.poll.entry((row.group.clone(), result)).or_default();
            }
        }
        for mode in &publish_modes {
            inner.publish.entry(*mode).or_default();
        }
        for verb in COMMAND_VERBS {
            for result in RESULTS {
                inner.command.entry((verb, result)).or_default();
            }
        }

        let produced_run = device
            .io
            .as_ref()
            .and_then(|io| io.output.as_ref())
            .is_none_or(|o| o.run);

        Self {
            svc,
            config,
            device,
            is_push,
            publish_modes,
            inventory,
            health,
            produced_run,
            inner: Mutex::new(inner),
        }
    }

    fn instance(&self) -> &str {
        &self.device.id
    }

    fn connection_mode(&self) -> &'static str {
        self.device.connection.connection_mode()
    }

    // ---- recording (called from the engines / supervisor; all synchronous) ----

    /// A connect attempt is about to be made (poll `connect` / push `open_push`).
    pub fn on_connect_attempt(&self) {
        self.inner.lock().unwrap().conn.connect_attempts.add(1.0);
    }

    /// The connect attempt succeeded. `latency_ms` is the connect round-trip; a re-establishment
    /// (after a previous drop) also bumps `reconnects`.
    pub fn on_connected(&self, latency_ms: u64, now: Instant) {
        let mut inner = self.inner.lock().unwrap();
        let c = &mut inner.conn;
        c.session_connected = true;
        c.connect_latency_ms = latency_ms as f64;
        c.connected_since = Some(now);
        if c.ever_connected {
            c.reconnects.add(1.0);
        }
        c.ever_connected = true;
    }

    /// The connect attempt failed (unreachable / refused / timeout).
    pub fn on_connect_failure(&self) {
        self.inner.lock().unwrap().conn.connect_failures.add(1.0);
    }

    /// A TLS handshake failed on a `mode: tls` connection (CIP Security Phase 1, §3.4). Distinct from
    /// `on_connect_failure` (which also fires) so a fleet view can single out cert/suite failures.
    pub fn on_tls_handshake_failure(&self) {
        self.inner.lock().unwrap().conn.tls_handshake_failures.add(1.0);
    }

    /// An established session was lost (poll loop exited / push `Lost`).
    pub fn on_connection_dropped(&self, now: Instant) {
        let mut inner = self.inner.lock().unwrap();
        let c = &mut inner.conn;
        c.accrue(now);
        c.connected_since = None;
        c.session_connected = false;
        c.connection_drops.add(1.0);
    }

    /// Record one completed poll cycle for `(group, result)` (§8.4). The per-sample counts are the
    /// deltas of the shared [`Health`] counters across the cycle (see [`crate::poll`]).
    #[allow(clippy::too_many_arguments)]
    pub fn record_poll_cycle(
        &self,
        group: &str,
        result: &'static str,
        duration_ms: u64,
        tag_reads: u64,
        overran: bool,
        good: u64,
        bad: u64,
        uncertain: u64,
        changed: u64,
        suppressed: u64,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let c = inner.poll.entry((group.to_string(), result)).or_default();
        c.poll_cycles.add(1.0);
        c.poll_duration_ms += duration_ms as f64;
        c.tag_reads.add(tag_reads as f64);
        // A BAD read is a failed CIP read: it is both a bad sample and a tag-read error (§8.4).
        c.tag_read_errors.add(bad as f64);
        c.samples_good.add(good as f64);
        c.samples_bad.add(bad as f64);
        c.samples_uncertain.add(uncertain as f64);
        c.samples_changed.add(changed as f64);
        c.samples_suppressed.add(suppressed as f64);
        if overran {
            c.poll_overruns.add(1.0);
        }
    }

    /// Record one `data` publish for `publish_mode` (§8.5). `from_batch` marks a coalescing-window
    /// flush (which also sets `batchSize`); `ok=false` marks a publish failure.
    pub fn record_publish(
        &self,
        publish_mode: &'static str,
        samples: u64,
        from_batch: bool,
        latency_ms: u64,
        ok: bool,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let c = inner.publish.entry(publish_mode).or_default();
        c.data_messages.add(1.0);
        if ok {
            c.samples.add(samples as f64);
            c.publish_latency_ms += latency_ms as f64;
        } else {
            c.failures.add(1.0);
        }
        if from_batch {
            c.batch_flushes.add(1.0);
            c.batch_size = samples as f64;
        }
    }

    /// A class-1 ForwardOpen outcome (push, §8.8).
    pub fn on_forward_open(&self, ok: bool) {
        let mut inner = self.inner.lock().unwrap();
        if ok {
            inner.io.forward_opens.add(1.0);
        } else {
            inner.io.forward_open_failures.add(1.0);
        }
    }

    /// The class-1 connection came up (first accepted frame, §8.8); records the negotiated APIs from
    /// the ForwardOpen reply for `sb/status` (§7.1).
    pub fn on_io_up(&self, o2t_api_ms: u32, t2o_api_ms: u32) {
        let mut inner = self.inner.lock().unwrap();
        inner.io.io_connection_state = true;
        inner.io.o2t_api_ms = o2t_api_ms;
        inner.io.t2o_api_ms = t2o_api_ms;
    }

    /// Record one `sb/*` command outcome for the `(verb, result)` combo (§8.6): the request, its
    /// latency, an error (when `!ok`), and the per-verb tallies. The pause/resume/reconnect/repoll
    /// request counters are bumped from `verb` so each verb's row carries its own counter (§8.6).
    pub fn record_command(&self, verb: &'static str, ok: bool, latency_ms: u64, tally: CommandTally) {
        let result = if ok { RESULT_SUCCESS } else { RESULT_ERROR };
        let mut inner = self.inner.lock().unwrap();
        let c = inner.command.entry((verb, result)).or_default();
        c.command_requests.add(1.0);
        c.command_latency_ms += latency_ms as f64;
        if !ok {
            c.command_errors.add(1.0);
        }
        c.read_signals.add(tally.read_signals as f64);
        c.write_signals.add(tally.write_signals as f64);
        c.write_failures.add(tally.write_failures as f64);
        c.browsed_tags.add(tally.browsed_tags as f64);
        match verb {
            "sb/pause" => c.pause_requests.add(1.0),
            "sb/resume" => c.resume_requests.add(1.0),
            "reconnect" => c.reconnect_requests.add(1.0),
            "repoll" => c.repoll_requests.add(1.0),
            _ => {}
        }
    }

    /// The `sb/status` counter snapshot (§7.1): `{ read, write, readErrors }`, each `{interval, total}`.
    /// `read` is CIP reads (poll `tagReads`) or accepted frames (push `framesConsumed`); `write` is
    /// `sb/write` entries attempted; `readErrors` is `tagReadErrors` (poll) or IO timeouts (push).
    #[must_use]
    pub fn counters_view(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        let pair = |p: &Pair| serde_json::json!({ "interval": p.interval, "total": p.total });
        let (read, read_errors) = if self.is_push {
            (pair(&inner.io.frames_consumed), pair(&inner.io.io_timeouts))
        } else {
            let mut reads = Pair::default();
            let mut errs = Pair::default();
            for c in inner.poll.values() {
                reads.total += c.tag_reads.total;
                reads.interval += c.tag_reads.interval;
                errs.total += c.tag_read_errors.total;
                errs.interval += c.tag_read_errors.interval;
            }
            (pair(&reads), pair(&errs))
        };
        let mut writes = Pair::default();
        for c in inner.command.values() {
            writes.total += c.write_signals.total;
            writes.interval += c.write_signals.interval;
        }
        serde_json::json!({ "read": read, "write": pair(&writes), "readErrors": read_errors })
    }

    /// The `sb/status` `security` object (CIP Security Phase 1, DESIGN-cip-security.md §3.4). A
    /// plaintext instance reports `{ "mode": "plaintext" }` (so a console can render the posture
    /// column unconditionally); a `mode: tls` instance reports the negotiated TLS facts (when the
    /// session is up) plus the `handshakeFailures` counter pair.
    #[must_use]
    pub fn security_view(&self) -> serde_json::Value {
        let hs = {
            let inner = self.inner.lock().unwrap();
            let p = &inner.conn.tls_handshake_failures;
            serde_json::json!({ "interval": p.interval, "total": p.total })
        };
        let is_tls = crate::eip::tls::SecurityConfig::from_connection(&self.device.connection)
            .ok()
            .flatten()
            .is_some_and(|s| s.is_tls());
        let sec = self.health.security();
        let mut out = serde_json::Map::new();
        out.insert(
            "mode".into(),
            serde_json::json!(if is_tls { "tls" } else { "plaintext" }),
        );
        if is_tls {
            if let Some(st) = &sec {
                out.insert("tlsVersion".into(), serde_json::json!(st.tls_version));
                out.insert("cipherSuite".into(), serde_json::json!(st.cipher_suite));
                out.insert("peerVerified".into(), serde_json::json!(st.peer_verified));
                out.insert("peer".into(), serde_json::json!(st.peer));
                out.insert(
                    "clientCertNotAfter".into(),
                    serde_json::json!(st.client_cert_not_after),
                );
            }
            out.insert("handshakeFailures".into(), hs);
        }
        // Phase 2a: the target's decoded CIP Security posture (both modes), when it was read on
        // connect. `targetSupportsCipSecurity` is present whenever a posture read was attempted (i.e.
        // the session is up); `target` carries the decoded objects only when the device implements
        // them. A generic CIP device / cpppo reports `targetSupportsCipSecurity: false`.
        if let Some(st) = &sec {
            out.insert(
                "targetSupportsCipSecurity".into(),
                serde_json::json!(st.target.is_some()),
            );
            if let Some(t) = &st.target {
                out.insert("target".into(), security_target_view(t));
            }
        }
        serde_json::Value::Object(out)
    }

    /// The push `sb/status` `io` object (§7.1): negotiated APIs, run/peerRun, and the §8.8 counters.
    #[must_use]
    pub fn io_view(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        let io = &inner.io;
        let pair = |p: &Pair| serde_json::json!({ "interval": p.interval, "total": p.total });
        serde_json::json!({
            "o2tApiMs": io.o2t_api_ms,
            "t2oApiMs": io.t2o_api_ms,
            "run": self.produced_run,
            "peerRun": io.run_mode,
            "framesConsumed": pair(&io.frames_consumed),
            "staleDropped": pair(&io.stale_frames_dropped),
            "sequenceGaps": pair(&io.sequence_gaps),
        })
    }

    /// One accepted T→O frame (push, §8.8): counts the frame, infers a sequence gap from a forward
    /// jump, and records the lived inter-arrival (`interFrameMs`) + run/idle state.
    pub fn record_frame_consumed(&self, sequence: u16, received_at: Instant, run_mode: bool) {
        let mut inner = self.inner.lock().unwrap();
        let io = &mut inner.io;
        io.frames_consumed.add(1.0);
        io.run_mode = run_mode;
        if let Some(last) = io.last_seq {
            let gap = sequence.wrapping_sub(last);
            if gap > 1 {
                io.sequence_gaps.add(f64::from(gap - 1));
            }
        }
        io.last_seq = Some(sequence);
        if let Some(prev) = io.last_frame_at {
            io.inter_frame_ms = received_at.saturating_duration_since(prev).as_secs_f64() * 1000.0;
        }
        io.last_frame_at = Some(received_at);
    }

    /// Fold a cumulative class-1 stack-counter snapshot (§8.8) into the `EtherNetIpIo` drop/produce
    /// pairs. The snapshot is cumulative-since-ForwardOpen, so we add the delta against the last read;
    /// a decrease (a reconnect reset the stack counters) folds the new absolute value in from 0. This
    /// is what makes `framesProduced` / `staleFramesDropped` / `sizeMismatchDropped` / `malformedFrames`
    /// / `produceOverruns` read REAL values (the S5-flagged gap), rather than 0.
    pub fn record_io_stats(&self, s: crate::device::IoLinkStats) {
        fn feed(pair: &mut Pair, last: &mut u64, cur: u64) {
            let delta = if cur >= *last { cur - *last } else { cur };
            pair.add(delta as f64);
            *last = cur;
        }
        let mut inner = self.inner.lock().unwrap();
        let io = &mut inner.io;
        feed(&mut io.frames_produced, &mut io.last_stats_frames_produced, s.frames_produced);
        feed(&mut io.stale_frames_dropped, &mut io.last_stats_stale, s.stale_frames);
        feed(&mut io.size_mismatch_dropped, &mut io.last_stats_size_mismatch, s.size_mismatch);
        feed(&mut io.malformed_frames, &mut io.last_stats_malformed, s.malformed_frames);
        feed(&mut io.produce_overruns, &mut io.last_stats_produce_overruns, s.produce_overruns);
    }

    /// The class-1 connection was lost (watchdog / peer close, §8.8): a watchdog expiry is an
    /// `ioTimeouts` event.
    pub fn on_io_lost(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.io.io_connection_state = false;
        inner.io.io_timeouts.add(1.0);
        inner.io.last_seq = None;
        inner.io.last_frame_at = None;
        // The next connection's stack counters restart at 0; drop our deltas' baselines so they fold
        // in from 0 rather than going negative.
        inner.io.last_stats_frames_produced = 0;
        inner.io.last_stats_stale = 0;
        inner.io.last_stats_size_mismatch = 0;
        inner.io.last_stats_malformed = 0;
        inner.io.last_stats_produce_overruns = 0;
    }

    // ---- definition + emission ----

    /// Pre-define every family × dimension combination this device emits (§8, startup). All are also
    /// re-defined immediately before each emit (the name-keyed-store workaround).
    pub fn define_all(&self) {
        // southbound_health.
        self.define(HEALTH, &[("instance", self.instance())]);
        // Connection (both modes).
        self.define(CONNECTION, &[("instance", self.instance()), ("connectionMode", self.connection_mode())]);
        // Publish (per mode) + Command (per verb×result) — both poll and push.
        for mode in &self.publish_modes {
            self.define(PUBLISH, &[("instance", self.instance()), ("publishMode", mode)]);
        }
        for verb in COMMAND_VERBS {
            for result in RESULTS {
                self.define(COMMAND, &[("instance", self.instance()), ("verb", verb), ("result", result)]);
            }
        }
        if self.is_push {
            self.define(IO, &[("instance", self.instance())]);
        } else {
            for row in &self.inventory {
                self.define(INVENTORY, &[("instance", self.instance()), ("pollGroup", &row.group)]);
                for result in RESULTS {
                    self.define(POLL, &[("instance", self.instance()), ("pollGroup", &row.group), ("result", result)]);
                }
            }
        }
    }

    /// Build + register one family combo's metric definition.
    fn define(&self, name: &str, dimensions: &[(&str, &str)]) {
        let def = family_def(name);
        let mut b = MetricBuilder::create(name).with_config(&self.config);
        for measure in &def.measures {
            b = b.add_measure(measure.name.clone(), measure.unit.clone(), measure.res);
        }
        for (k, v) in dimensions {
            b = b.add_dimension(*k, *v);
        }
        self.svc.define_metric(b.build());
    }

    /// Re-define (with the combo's dimensions) then emit one family combo.
    async fn emit_combo(&self, name: &str, dimensions: &[(&str, &str)], values: HashMap<String, f64>, now: bool) {
        self.define(name, dimensions);
        let res = if now {
            self.svc.emit_metric_now(name, values).await
        } else {
            self.svc.emit_metric(name, values).await
        };
        if let Err(e) = res {
            tracing::warn!(metric = %name, instance = %self.instance(), error = %e, "metric emit failed");
        }
    }

    /// The full periodic emit (every `metricsIntervalSecs`, §8.7): all families for this device's mode.
    pub async fn emit_periodic(&self) {
        self.emit_health(false).await;
        self.emit_connection(false).await;
        self.emit_publish().await;
        self.emit_command().await;
        if self.is_push {
            self.emit_io(false).await;
        } else {
            self.emit_inventory().await;
            self.emit_poll().await;
        }
    }

    /// The immediate transition emit (`emit_metric_now`, §8.7): the mandatory `southbound_health` plus
    /// the connection/IO gauges whose state just changed.
    pub async fn emit_now(&self) {
        self.emit_health(true).await;
        self.emit_connection(true).await;
        if self.is_push {
            self.emit_io(true).await;
        }
    }

    async fn emit_health(&self, now: bool) {
        // Gauges from the shared Health; interval counters swap-reset here (§8.1).
        let mut v = HashMap::new();
        v.insert("connectionState".to_string(), self.health.connection_state.load(Ordering::Relaxed) as f64);
        v.insert("paused".to_string(), f64::from(u8::from(self.health.paused.load(Ordering::Relaxed))));
        v.insert("pollLatencyMs".to_string(), self.health.poll_latency_ms.load(Ordering::Relaxed) as f64);
        v.insert("publishLatencyMs".to_string(), self.health.publish_latency_ms.load(Ordering::Relaxed) as f64);
        v.insert("readErrors".to_string(), self.health.read_errors.swap(0, Ordering::Relaxed) as f64);
        v.insert("writeErrors".to_string(), self.health.write_errors.swap(0, Ordering::Relaxed) as f64);
        v.insert("staleSignals".to_string(), self.health.stale_signals.load(Ordering::Relaxed) as f64);
        v.insert("reconnects".to_string(), self.health.reconnects.swap(0, Ordering::Relaxed) as f64);
        self.emit_combo(HEALTH, &[("instance", self.instance())], v, now).await;
    }

    async fn emit_connection(&self, now: bool) {
        let values = self.inner.lock().unwrap().conn.drain(Instant::now());
        self.emit_combo(
            CONNECTION,
            &[("instance", self.instance()), ("connectionMode", self.connection_mode())],
            values,
            now,
        )
        .await;
    }

    async fn emit_inventory(&self) {
        for row in &self.inventory {
            let mut v = HashMap::new();
            v.insert("configuredSignals".to_string(), row.configured_signals);
            v.insert("arraySignals".to_string(), row.array_signals);
            v.insert("writableSignals".to_string(), row.writable_signals);
            v.insert("configuredPollIntervalMs".to_string(), row.poll_interval_ms);
            v.insert("requestsPerCycle".to_string(), row.requests_per_cycle);
            self.emit_combo(INVENTORY, &[("instance", self.instance()), ("pollGroup", &row.group)], v, false).await;
        }
    }

    async fn emit_poll(&self) {
        let rows: Vec<(String, &'static str, HashMap<String, f64>)> = {
            let mut inner = self.inner.lock().unwrap();
            inner
                .poll
                .iter_mut()
                .map(|((g, r), c)| (g.clone(), *r, c.drain()))
                .collect()
        };
        for (group, result, values) in rows {
            self.emit_combo(POLL, &[("instance", self.instance()), ("pollGroup", &group), ("result", result)], values, false).await;
        }
    }

    async fn emit_publish(&self) {
        let rows: Vec<(&'static str, HashMap<String, f64>)> = {
            let mut inner = self.inner.lock().unwrap();
            inner.publish.iter_mut().map(|(m, c)| (*m, c.drain())).collect()
        };
        for (mode, values) in rows {
            self.emit_combo(PUBLISH, &[("instance", self.instance()), ("publishMode", mode)], values, false).await;
        }
    }

    async fn emit_command(&self) {
        let rows: Vec<(&'static str, &'static str, HashMap<String, f64>)> = {
            let mut inner = self.inner.lock().unwrap();
            inner.command.iter_mut().map(|((verb, result), c)| (*verb, *result, c.drain())).collect()
        };
        for (verb, result, values) in rows {
            self.emit_combo(COMMAND, &[("instance", self.instance()), ("verb", verb), ("result", result)], values, false).await;
        }
    }

    async fn emit_io(&self, now: bool) {
        let values = self.inner.lock().unwrap().io.drain();
        self.emit_combo(IO, &[("instance", self.instance())], values, now).await;
    }
}

/// Render a target CIP Security posture (Phase 2a, DESIGN-cip-security.md §4.1) into the
/// `sb/status.security.target` JSON. Arrays are always present (possibly empty); scalar fields are
/// included only when decoded (a device need not expose every attribute). `pullModel` mirrors the
/// certificate object's pull capability for a console's quick posture read.
#[must_use]
fn security_target_view(t: &crate::device::TargetSecurityPosture) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    if let Some(state) = &t.state {
        out.insert("state".into(), serde_json::json!(state));
    }
    out.insert("profiles".into(), serde_json::json!(t.profiles));
    out.insert(
        "allowedCipherSuites".into(),
        serde_json::json!(t.allowed_cipher_suites),
    );
    out.insert(
        "availableCipherSuites".into(),
        serde_json::json!(t.available_cipher_suites),
    );
    if let Some(v) = t.verify_client {
        out.insert("verifyClient".into(), serde_json::json!(v));
    }
    if let Some(v) = t.send_certificate_chain {
        out.insert("sendCertificateChain".into(), serde_json::json!(v));
    }
    if let Some(v) = t.check_expiration {
        out.insert("checkExpiration".into(), serde_json::json!(v));
    }
    if let Some(cert) = &t.certificate {
        if let Some(v) = cert.pull_supported {
            out.insert("pullModel".into(), serde_json::json!(v));
        }
        let mut c = serde_json::Map::new();
        if let Some(v) = cert.push_supported {
            c.insert("pushSupported".into(), serde_json::json!(v));
        }
        if let Some(v) = cert.pull_supported {
            c.insert("pullSupported".into(), serde_json::json!(v));
        }
        if let Some(v) = &cert.name {
            c.insert("name".into(), serde_json::json!(v));
        }
        if let Some(v) = &cert.state {
            c.insert("state".into(), serde_json::json!(v));
        }
        if let Some(v) = &cert.encoding {
            c.insert("encoding".into(), serde_json::json!(v));
        }
        out.insert("certificate".into(), serde_json::Value::Object(c));
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests {
    //! §12.3 metrics tests: the parity contract (definition set matches §8 EXACTLY), Total/Interval
    //! semantics, and per-mode family selection. No PLC / no network.
    use super::*;
    use async_trait::async_trait;
    use edgecommons::prelude::{Config, Metric};
    use serde_json::json;
    use std::collections::BTreeSet;

    /// A capturing [`MetricService`]: records every definition (keyed by its dimension set, so combos
    /// do not collapse) and every emit, so a test can introspect exactly what the emitter produced.
    #[derive(Default)]
    struct RecordingMetrics {
        defined: Mutex<Vec<Metric>>,
        emitted: Mutex<Vec<(String, HashMap<String, f64>)>>,
    }

    impl RecordingMetrics {
        /// The most recent emit of `name`, or `None`.
        fn last(&self, name: &str) -> Option<HashMap<String, f64>> {
            self.emitted.lock().unwrap().iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.clone())
        }
    }

    #[async_trait]
    impl MetricService for RecordingMetrics {
        fn define_metric(&self, metric: Metric) {
            self.defined.lock().unwrap().push(metric);
        }
        fn is_metric_defined(&self, name: &str) -> bool {
            self.defined.lock().unwrap().iter().any(|m| m.get_name() == name)
        }
        async fn emit_metric(&self, name: &str, values: HashMap<String, f64>) -> edgecommons::Result<()> {
            self.emitted.lock().unwrap().push((name.to_string(), values));
            Ok(())
        }
        async fn emit_metric_now(&self, name: &str, values: HashMap<String, f64>) -> edgecommons::Result<()> {
            self.emitted.lock().unwrap().push((name.to_string(), values));
            Ok(())
        }
        async fn flush_metrics(&self) -> edgecommons::Result<()> {
            Ok(())
        }
        async fn shutdown(&self) {}
    }

    fn config() -> Arc<Config> {
        Arc::new(
            Config::from_value(
                "com.example.EthernetIpAdapter",
                "thing-1",
                json!({ "metricEmission": { "target": "log", "namespace": "test" } }),
            )
            .unwrap(),
        )
    }

    fn poll_device() -> DeviceConfig {
        DeviceConfig::from_value(&json!({
            "id": "filler-plc",
            "adapter": "sim",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [
                { "id": "fast", "signals": [
                    { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" },
                    { "name": "zone-temps", "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 8 } ] },
                { "id": "slow", "publishMode": "always", "signals": [
                    { "name": "fill-setpoint", "tagPath": "FILL_SETPOINT", "type": "real" } ] }
            ],
            "writes": { "allow": ["FILL_SETPOINT"] }
        }))
        .unwrap()
    }

    fn push_device() -> DeviceConfig {
        DeviceConfig::from_value(&json!({
            "id": "palletizer-io",
            "adapter": "sim",
            "mode": "push",
            "connection": { "endpoint": "opener:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "config": 151, "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "sampleMs": 0, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "bool", "bit": 0 } ] }
            }
        }))
        .unwrap()
    }

    fn dm(device: DeviceConfig) -> (Arc<RecordingMetrics>, DeviceMetrics) {
        let svc = Arc::new(RecordingMetrics::default());
        let global = GlobalConfig::default();
        let health = Arc::new(Health::default());
        let m = DeviceMetrics::new(svc.clone(), config(), device, &global, health);
        (svc, m)
    }

    /// Only the adapter's own (low-cardinality) dimension keys — strip the builder-injected
    /// `category`/`coreName`/`component`.
    fn custom_dims(metric: &Metric) -> BTreeSet<String> {
        metric
            .get_dimensions()
            .keys()
            .filter(|k| !matches!(k.as_str(), "category" | "coreName" | "component"))
            .cloned()
            .collect()
    }

    // -------------------------------------------------------------------------------------------
    // THE PARITY CONTRACT (§12.3): the definition set matches §8 EXACTLY — no missing, no extra.
    // The expected table below is an INDEPENDENT literal transcription of DESIGN §8; if the code's
    // `family_defs()` (or a wired measure) is renamed/dropped/added, this test fails.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn definition_set_matches_design_section_8_exactly() {
        // (family, dims, [(measure, unit, res)]) — verbatim from §8.
        let c = |n: &str| (n.to_string(), "Count".to_string(), 60u32);
        let cp = |n: &str| vec![c(&format!("{n}Total")), c(&format!("{n}Interval"))];
        let g = |n: &str, u: &str, r: u32| (n.to_string(), u.to_string(), r);

        // (family name, dimension keys, [(measure, unit, res)]).
        type ExpectedFamily = (&'static str, Vec<&'static str>, Vec<(String, String, u32)>);
        let mut expected: Vec<ExpectedFamily> = Vec::new();

        expected.push((HEALTH, vec!["instance"], vec![
            g("connectionState", "Count", 1), g("paused", "Count", 1),
            g("pollLatencyMs", "Milliseconds", 1), g("publishLatencyMs", "Milliseconds", 1),
            g("readErrors", "Count", 60), g("writeErrors", "Count", 60),
            g("staleSignals", "Count", 60), g("reconnects", "Count", 60),
        ]));

        let mut conn = vec![g("sessionConnected", "Count", 1)];
        for p in ["connectAttempts", "connectFailures", "connectionDrops", "reconnects", "tlsHandshakeFailures"] { conn.extend(cp(p)); }
        conn.push(g("connectLatencyMs", "Milliseconds", 60));
        conn.push(g("connectedDurationMs", "Milliseconds", 60));
        expected.push((CONNECTION, vec!["instance", "connectionMode"], conn));

        expected.push((INVENTORY, vec!["instance", "pollGroup"], vec![
            g("configuredSignals", "Count", 60), g("arraySignals", "Count", 60),
            g("writableSignals", "Count", 60), g("configuredPollIntervalMs", "Milliseconds", 60),
            g("requestsPerCycle", "Count", 60),
        ]));

        let mut poll = Vec::new();
        poll.extend(cp("pollCycles"));
        poll.push(g("pollDurationMs", "Milliseconds", 60));
        for p in ["tagReads", "tagReadErrors", "samplesGood", "samplesBad", "samplesUncertain",
                  "samplesChanged", "samplesSuppressed", "pollOverruns"] { poll.extend(cp(p)); }
        expected.push((POLL, vec!["instance", "pollGroup", "result"], poll));

        let mut publish = Vec::new();
        for p in ["dataMessagesPublished", "samplesPublished", "publishFailures", "batchFlushes"] { publish.extend(cp(p)); }
        publish.push(g("batchSize", "Count", 60));
        publish.push(g("publishLatencyMs", "Milliseconds", 60));
        expected.push((PUBLISH, vec!["instance", "publishMode"], publish));

        let mut command = Vec::new();
        command.extend(cp("commandRequests"));
        command.extend(cp("commandErrors"));
        command.push(g("commandLatencyMs", "Milliseconds", 60));
        for p in ["readSignals", "writeSignals", "writeFailures", "browsedTags", "pauseRequests",
                  "resumeRequests", "reconnectRequests", "repollRequests"] { command.extend(cp(p)); }
        expected.push((COMMAND, vec!["instance", "verb", "result"], command));

        let mut io = vec![g("ioConnectionState", "Count", 1)];
        for p in ["forwardOpens", "forwardOpenFailures", "framesConsumed", "framesProduced",
                  "staleFramesDropped", "sequenceGaps", "sizeMismatchDropped", "malformedFrames",
                  "ioTimeouts", "produceOverruns"] { io.extend(cp(p)); }
        io.push(g("interFrameMs", "Milliseconds", 1));
        io.push(g("runMode", "Count", 1));
        expected.push((IO, vec!["instance"], io));

        let actual = family_defs();
        assert_eq!(actual.len(), expected.len(), "exactly seven families (§8)");

        for (name, dims, measures) in expected {
            let fam = actual.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("family {name} defined"));

            let want_dims: Vec<String> = dims.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(fam.dimensions, want_dims, "{name} dimension keys match §8 exactly");

            // Measure sets match exactly — no missing, no extra — with the right unit + resolution.
            let want: BTreeSet<(String, String, u32)> =
                measures.iter().map(|(n, u, r)| (n.clone(), u.clone(), *r)).collect();
            let got: BTreeSet<(String, String, u32)> =
                fam.measures.iter().map(|m| (m.name.clone(), m.unit.clone(), m.res)).collect();
            assert_eq!(got, want, "{name} measure set (name/unit/res) matches §8 exactly");
            assert_eq!(fam.measures.len(), measures.len(), "{name}: no duplicate measures");
        }
    }

    /// The startup pre-definition (`define_all`) actually emits the §8 schema through the core
    /// builder: measure names + custom dimension keys survive round-trip into a real `Metric`.
    #[test]
    fn define_all_registers_families_with_low_cardinality_dims_only() {
        let (svc, m) = dm(poll_device());
        m.define_all();
        let defined = svc.defined.lock().unwrap();

        // Every custom dimension across every defined metric is from the low-cardinality allow-set.
        let allowed: BTreeSet<&str> =
            ["instance", "connectionMode", "pollGroup", "result", "verb", "publishMode"].into_iter().collect();
        for metric in defined.iter() {
            for dim in custom_dims(metric) {
                assert!(allowed.contains(dim.as_str()), "dimension `{dim}` on {} is low-cardinality", metric.get_name());
            }
        }

        // A poll device defines the poll families and NOT EtherNetIpIo.
        let names: BTreeSet<&str> = defined.iter().map(Metric::get_name).collect();
        for f in [HEALTH, CONNECTION, INVENTORY, POLL, PUBLISH, COMMAND] {
            assert!(names.contains(f), "poll device defines {f}");
        }
        assert!(!names.contains(IO), "poll device does not define EtherNetIpIo");

        // southbound_health carries the `paused` gauge (§8.1 extension).
        let health = defined.iter().find(|x| x.get_name() == HEALTH).unwrap();
        assert!(health.get_measure("paused").is_some(), "southbound_health has the paused gauge");
    }

    #[test]
    fn push_device_defines_io_and_not_the_poll_families() {
        let (svc, m) = dm(push_device());
        m.define_all();
        let defined = svc.defined.lock().unwrap();
        let names: BTreeSet<&str> = defined.iter().map(Metric::get_name).collect();

        assert!(names.contains(IO), "push device defines EtherNetIpIo");
        for f in [HEALTH, CONNECTION, PUBLISH, COMMAND] {
            assert!(names.contains(f), "push device defines {f}");
        }
        assert!(!names.contains(POLL), "push device does not define EtherNetIpPoll");
        assert!(!names.contains(INVENTORY), "push device does not define EtherNetIpInventory");
    }

    /// Total accumulates; Interval resets on each emit (§8 convention).
    #[test]
    fn total_accumulates_while_interval_resets_each_emit() {
        let mut p = Pair::default();
        p.add(3.0);
        let mut a = HashMap::new();
        p.drain_into(&mut a, "x");
        assert_eq!(a["xTotal"], 3.0);
        assert_eq!(a["xInterval"], 3.0);

        // A second emit with no activity: interval reset to 0, total unchanged.
        let mut b = HashMap::new();
        p.drain_into(&mut b, "x");
        assert_eq!(b["xTotal"], 3.0, "total is monotonic");
        assert_eq!(b["xInterval"], 0.0, "interval reset after the previous emit");

        // More activity accrues on both again.
        p.add(2.0);
        let mut c = HashMap::new();
        p.drain_into(&mut c, "x");
        assert_eq!(c["xTotal"], 5.0);
        assert_eq!(c["xInterval"], 2.0);
    }

    /// End-to-end Total/Interval reset through a real emit: a recorded poll cycle shows up on the
    /// first `EtherNetIpPoll` emit, then the interval is 0 on the next while the total holds.
    #[tokio::test]
    async fn poll_interval_resets_after_emit_but_total_persists() {
        let (svc, m) = dm(poll_device());
        // Two GOOD samples, one changed, on group "fast", a success cycle.
        m.record_poll_cycle("fast", RESULT_SUCCESS, 12, 2, false, 2, 0, 0, 1, 0);

        m.emit_poll().await;
        m.emit_poll().await;

        let emitted = svc.emitted.lock().unwrap();
        let fast_success: Vec<&HashMap<String, f64>> = emitted
            .iter()
            .filter(|(n, _)| n == POLL)
            .map(|(_, v)| v)
            .collect();
        // Two emits × (2 groups × 2 results) rows.
        let firsts: Vec<&&HashMap<String, f64>> =
            fast_success.iter().filter(|v| (v["samplesGoodTotal"] - 2.0).abs() < f64::EPSILON).collect();
        assert!(!firsts.is_empty(), "the recorded cycle emitted its totals");

        // Collect the two emits for the (fast, success) row by their pollCyclesTotal==1.
        let mut cycles_interval = Vec::new();
        for v in fast_success.iter().filter(|v| (v["pollCyclesTotal"] - 1.0).abs() < f64::EPSILON) {
            cycles_interval.push(v["pollCyclesInterval"]);
        }
        assert_eq!(cycles_interval.len(), 2, "the (fast,success) row emitted twice");
        assert!(cycles_interval.contains(&1.0), "first emit reports the interval");
        assert!(cycles_interval.contains(&0.0), "second emit's interval reset while total stayed 1");
    }

    /// The class-1 stack counters fold into `EtherNetIpIo` as deltas of a cumulative snapshot, and a
    /// lost link re-bases them so a reconnect's counts accrue from 0 (the S5-flagged real-stats gap).
    #[tokio::test]
    async fn io_stack_stats_fold_into_ethernetip_io_as_deltas() {
        use crate::device::IoLinkStats;
        let (svc, m) = dm(push_device());

        // First cumulative snapshot after a ForwardOpen.
        m.record_io_stats(IoLinkStats {
            frames_produced: 10,
            stale_frames: 2,
            size_mismatch: 1,
            malformed_frames: 0,
            produce_overruns: 3,
            sequence_gaps: 9, // sequenceGaps is fed from frame deltas, not this path — must not double-count
        });
        m.emit_io(false).await;
        // A second snapshot: counters advanced (cumulative).
        m.record_io_stats(IoLinkStats {
            frames_produced: 25,
            stale_frames: 2,
            size_mismatch: 4,
            malformed_frames: 1,
            produce_overruns: 3,
            sequence_gaps: 20,
        });
        m.emit_io(false).await;

        // Snapshot the two IO emits as owned maps (drop the guard before any further await).
        let io_emits: Vec<HashMap<String, f64>> = {
            let emitted = svc.emitted.lock().unwrap();
            emitted.iter().filter(|(n, _)| n == IO).map(|(_, v)| v.clone()).collect()
        };
        assert_eq!(io_emits.len(), 2, "two EtherNetIpIo emits");

        // First emit: totals reflect the first snapshot's absolute values.
        assert_eq!(io_emits[0]["framesProducedTotal"], 10.0);
        assert_eq!(io_emits[0]["framesProducedInterval"], 10.0);
        assert_eq!(io_emits[0]["produceOverrunsTotal"], 3.0);

        // Second emit: Total is the new absolute (delta added); Interval is just the delta.
        assert_eq!(io_emits[1]["framesProducedTotal"], 25.0, "10 + (25-10)");
        assert_eq!(io_emits[1]["framesProducedInterval"], 15.0, "delta only");
        assert_eq!(io_emits[1]["sizeMismatchDroppedTotal"], 4.0);
        assert_eq!(io_emits[1]["sizeMismatchDroppedInterval"], 3.0);
        assert_eq!(io_emits[1]["malformedFramesInterval"], 1.0);
        assert_eq!(io_emits[1]["staleFramesDroppedInterval"], 0.0, "unchanged since last read");
        assert_eq!(io_emits[1]["produceOverrunsInterval"], 0.0, "unchanged");

        // sequenceGaps on the IO family is fed from frame deltas (record_frame_consumed), NOT the
        // stats path — record_io_stats must not touch it, so it stays 0 here.
        assert_eq!(io_emits[1]["sequenceGapsTotal"], 0.0, "record_io_stats does not feed sequenceGaps");

        // A lost link rebases the deltas: after on_io_lost, a fresh connection's cumulative snapshot
        // (restarting at low numbers) folds in from 0 rather than going negative.
        m.on_io_lost();
        m.record_io_stats(IoLinkStats { frames_produced: 5, ..Default::default() });
        m.emit_io(false).await;
        let last = {
            let emitted = svc.emitted.lock().unwrap();
            emitted.iter().rev().find(|(n, _)| n == IO).map(|(_, v)| v.clone()).unwrap()
        };
        assert_eq!(last["framesProducedInterval"], 5.0, "reconnect counts fold in from 0");
        assert_eq!(last["framesProducedTotal"], 30.0, "total stays monotonic across the reconnect");
    }

    #[tokio::test]
    async fn health_emit_includes_the_paused_gauge_and_reads_health() {
        let (svc, m) = dm(poll_device());
        m.health.connection_state.store(1, Ordering::Relaxed);
        m.health.read_errors.store(4, Ordering::Relaxed);
        m.emit_health(false).await;

        let emitted = svc.emitted.lock().unwrap();
        let (_, v) = emitted.iter().find(|(n, _)| n == HEALTH).expect("health emitted");
        assert_eq!(v["connectionState"], 1.0);
        assert_eq!(v["readErrors"], 4.0);
        assert_eq!(v["paused"], 0.0, "paused reads false until S6 sets it");
        assert!(v.contains_key("publishLatencyMs") && v.contains_key("staleSignals"));
        // readErrors is an interval counter: it swap-resets, so a re-read is 0.
        assert_eq!(m.health.read_errors.load(Ordering::Relaxed), 0);
    }

    /// The connection lifecycle counters (§8.2): a first connect sets `sessionConnected` and does NOT
    /// bump `reconnects`; a drop + reconnect does, and `connectedDurationMs` accrues while up and
    /// resets on emit. Drives `on_connect_attempt`/`on_connected`/`on_connect_failure`/
    /// `on_connection_dropped` + `ConnCounters::accrue`/`drain`.
    #[tokio::test]
    async fn connection_lifecycle_counts_attempts_reconnects_and_up_duration() {
        let (svc, m) = dm(poll_device());
        let t0 = Instant::now();
        m.on_connect_attempt();
        m.on_connect_failure(); // one failed attempt
        m.on_connect_attempt();
        m.on_connected(12, t0); // first success: no reconnect
        m.emit_connection(false).await;

        let first = svc.last("EtherNetIpConnection").expect("connection emitted");
        assert_eq!(first["sessionConnected"], 1.0);
        assert_eq!(first["connectAttemptsTotal"], 2.0);
        assert_eq!(first["connectFailuresTotal"], 1.0);
        assert_eq!(first["reconnectsInterval"], 0.0, "the first connect is not a reconnect");
        assert_eq!(first["connectLatencyMs"], 12.0);

        // A drop then a re-established connection: reconnects bumps, sessionConnected flips off then on.
        m.on_connection_dropped(t0 + std::time::Duration::from_millis(500));
        let dropped = { let mut i = m.inner.lock().unwrap(); i.conn.drain(Instant::now()) };
        assert_eq!(dropped["sessionConnected"], 0.0);
        assert_eq!(dropped["connectionDropsInterval"], 1.0);
        assert!(dropped["connectedDurationMs"] > 0.0, "up-duration accrued while connected");

        m.on_connect_attempt();
        m.on_connected(5, Instant::now()); // ever_connected ⇒ a reconnect
        m.emit_connection(false).await;
        let re = svc.last("EtherNetIpConnection").unwrap();
        assert_eq!(re["reconnectsInterval"], 1.0, "the re-establishment is a reconnect");
    }

    /// `record_publish` (§8.5): a batch flush sets `batchSize` + `batchFlushes`; a failure bumps
    /// `publishFailures` and does not add samples. An overrun poll cycle bumps `pollOverruns`.
    #[tokio::test]
    async fn publish_and_poll_recording_cover_batch_failure_and_overrun() {
        let (svc, m) = dm(poll_device());
        m.record_publish("onChange", 3, true, 7, true); // a batch flush of 3 samples
        m.record_publish("onChange", 1, false, 0, false); // a failed publish
        m.emit_publish().await;
        let p = svc
            .emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == PUBLISH)
            .map(|(_, v)| v.clone())
            .find(|v| v["dataMessagesPublishedTotal"] == 2.0)
            .expect("onChange publish row");
        assert_eq!(p["samplesPublishedTotal"], 3.0, "only the ok publish added samples");
        assert_eq!(p["publishFailuresTotal"], 1.0);
        assert_eq!(p["batchFlushesTotal"], 1.0);
        assert_eq!(p["batchSize"], 3.0);

        m.record_poll_cycle("fast", RESULT_SUCCESS, 900, 2, true, 2, 0, 0, 0, 0); // overran
        m.emit_poll().await;
        let poll_row = svc
            .emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == POLL)
            .map(|(_, v)| v.clone())
            .find(|v| v["pollOverrunsTotal"] == 1.0);
        assert!(poll_row.is_some(), "an overran cycle bumps pollOverruns");
    }

    /// The full periodic emit for a POLL device (§8.7) publishes every poll family; `emit_now` flushes
    /// the transition subset. Drives `emit_periodic`/`emit_now`/`emit_inventory`/`emit_command`.
    #[tokio::test]
    async fn periodic_emit_publishes_every_poll_family() {
        let (svc, m) = dm(poll_device());
        m.record_command("sb/status", true, 2, CommandTally::default());
        m.emit_periodic().await;
        let names: std::collections::BTreeSet<String> =
            svc.emitted.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
        for f in [HEALTH, CONNECTION, INVENTORY, POLL, PUBLISH, COMMAND] {
            assert!(names.contains(f), "periodic emit includes {f}");
        }
        assert!(!names.contains(IO), "a poll device never emits EtherNetIpIo");

        // A poll device's inventory row carries the config-derived gauges (§8.3).
        let inv = svc.last(INVENTORY).expect("inventory emitted");
        assert!(inv.contains_key("configuredSignals") && inv.contains_key("requestsPerCycle"));

        // emit_now flushes just health + connection (poll has no IO).
        let (svc2, m2) = dm(poll_device());
        m2.emit_now().await;
        let now_names: std::collections::BTreeSet<String> =
            svc2.emitted.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
        assert!(now_names.contains(HEALTH) && now_names.contains(CONNECTION));
        assert!(!now_names.contains(POLL), "the transition emit is not the full periodic set");
    }

    /// The push IO lifecycle (§8.8): `on_forward_open`, `on_io_up`, `record_frame_consumed` (sequence
    /// gap + inter-frame), the periodic IO emit, and the `sb/status` `io`/counter views.
    #[tokio::test]
    async fn push_io_recording_and_status_views() {
        let (svc, m) = dm(push_device());
        m.on_forward_open(true);
        m.on_forward_open(false);
        m.on_io_up(100, 100);
        let base = Instant::now();
        m.record_frame_consumed(1, base, true);
        // A forward jump 1 → 4 is two missed frames (sequenceGaps += 2).
        m.record_frame_consumed(4, base + std::time::Duration::from_millis(30), true);
        m.emit_periodic().await;

        let names: std::collections::BTreeSet<String> =
            svc.emitted.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
        assert!(names.contains(IO), "a push device emits EtherNetIpIo");
        assert!(!names.contains(POLL) && !names.contains(INVENTORY), "no poll families on push");

        let io = svc.last(IO).unwrap();
        assert_eq!(io["ioConnectionState"], 1.0);
        assert_eq!(io["forwardOpensTotal"], 1.0);
        assert_eq!(io["forwardOpenFailuresTotal"], 1.0);
        assert_eq!(io["framesConsumedTotal"], 2.0);
        assert_eq!(io["sequenceGapsTotal"], 2.0, "1→4 is two missed frames");
        assert_eq!(io["runMode"], 1.0);
        assert!(io["interFrameMs"] > 0.0, "the lived inter-arrival is recorded");

        // The push status counter + io views (§7.1).
        let counters = m.counters_view();
        assert!(counters["read"]["total"].as_f64().unwrap() >= 2.0, "read = accepted frames");
        let iov = m.io_view();
        assert_eq!(iov["o2tApiMs"], 100);
        assert_eq!(iov["peerRun"], true);
        assert!(iov.get("framesConsumed").is_some());
    }

    /// The poll `sb/status` counter view (§7.1) sums `tagReads`/`tagReadErrors` across groups and
    /// `writeSignals` across the command matrix.
    #[test]
    fn poll_counters_view_sums_reads_and_writes() {
        let (_svc, m) = dm(poll_device());
        m.record_poll_cycle("fast", RESULT_SUCCESS, 5, 2, false, 2, 1, 0, 0, 0); // 2 reads, 1 bad
        m.record_command("sb/write", true, 1, CommandTally { write_signals: 1, ..CommandTally::default() });
        let v = m.counters_view();
        assert_eq!(v["read"]["total"], 2.0);
        assert_eq!(v["readErrors"]["total"], 1.0, "a BAD read is a tagReadError");
        assert_eq!(v["write"]["total"], 1.0);
    }

    // --- Phase 2a: sb/status.security target posture rendering ---

    /// Build a `DeviceMetrics` whose session security has been set to `sec` (Phase 2a).
    fn dm_with_security(
        device: DeviceConfig,
        sec: Option<crate::device::SecurityStatus>,
    ) -> DeviceMetrics {
        let svc = Arc::new(RecordingMetrics::default());
        let global = GlobalConfig::default();
        let health = Arc::new(Health::default());
        health.set_security(sec);
        DeviceMetrics::new(svc, config(), device, &global, health)
    }

    #[test]
    fn security_view_plaintext_no_session_is_bare() {
        // No security block, no posture read ⇒ `{ "mode": "plaintext" }` (backward compatible).
        let (_svc, m) = dm(poll_device());
        let v = m.security_view();
        assert_eq!(v["mode"], "plaintext");
        assert!(v.get("targetSupportsCipSecurity").is_none());
        assert!(v.get("target").is_none());
    }

    #[test]
    fn security_view_reports_target_unavailable_for_generic_device() {
        // A posture read happened but the device has no CIP Security objects.
        let sec = crate::device::SecurityStatus { tls: false, target: None, ..Default::default() };
        let m = dm_with_security(poll_device(), Some(sec));
        let v = m.security_view();
        assert_eq!(v["mode"], "plaintext");
        assert_eq!(v["targetSupportsCipSecurity"], false);
        assert!(v.get("target").is_none());
    }

    #[test]
    fn security_view_renders_decoded_target_posture() {
        use crate::device::{SecurityStatus, TargetCertificateSummary, TargetSecurityPosture};
        let target = TargetSecurityPosture {
            state: Some("Configured".to_string()),
            profiles: vec!["EtherNet/IP Confidentiality".to_string()],
            allowed_cipher_suites: vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string()],
            available_cipher_suites: vec![
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                "0xC023".to_string(),
            ],
            verify_client: Some(true),
            send_certificate_chain: Some(true),
            check_expiration: Some(false),
            certificate: Some(TargetCertificateSummary {
                push_supported: Some(true),
                pull_supported: Some(false),
                name: Some("Device".to_string()),
                state: Some("Verified".to_string()),
                encoding: Some("PEM".to_string()),
            }),
        };
        let sec = SecurityStatus { tls: false, target: Some(target), ..Default::default() };
        let m = dm_with_security(poll_device(), Some(sec));
        let v = m.security_view();
        assert_eq!(v["targetSupportsCipSecurity"], true);
        let t = &v["target"];
        assert_eq!(t["state"], "Configured");
        assert_eq!(t["profiles"][0], "EtherNet/IP Confidentiality");
        assert_eq!(t["allowedCipherSuites"][0], "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(t["availableCipherSuites"].as_array().unwrap().len(), 2);
        assert_eq!(t["verifyClient"], true);
        assert_eq!(t["checkExpiration"], false);
        assert_eq!(t["pullModel"], false);
        assert_eq!(t["certificate"]["pushSupported"], true);
        assert_eq!(t["certificate"]["name"], "Device");
        assert_eq!(t["certificate"]["encoding"], "PEM");
    }

    #[test]
    fn security_target_view_arrays_always_present() {
        // An empty posture still renders the array keys (a console can bind unconditionally).
        let t = crate::device::TargetSecurityPosture::default();
        let v = security_target_view(&t);
        assert!(v["profiles"].is_array());
        assert!(v["allowedCipherSuites"].is_array());
        assert!(v["availableCipherSuites"].is_array());
        assert!(v.get("state").is_none());
        assert!(v.get("certificate").is_none());
    }
}
