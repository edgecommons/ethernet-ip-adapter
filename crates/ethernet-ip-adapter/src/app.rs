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

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

use edgecommons::prelude::*;
use serde_json::{json, Value};

use crate::config::{DeviceConfig, IoFieldSpec, SignalSpec};
use crate::device::{InputSnapshot, Reading};
use crate::metrics::DeviceMetrics;

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
///
/// The §9.2 `PAUSED` token is **derived**, not a variant here: it is stored separately (the
/// [`Health::paused`] `AtomicBool`) so a link break while paused still reports `BACKOFF` +
/// `attributes.paused: true`, and re-establishment returns to `PAUSED` (not `ONLINE`).
/// [`connectivity_of`] renders the token: `PAUSED` iff paused AND the session is up, else this link
/// state.
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
    /// 1 = this instance is paused (§7.4). Owned here so the connectivity token, the `paused`
    /// attribute, and the `sb/status` reply all derive from one source (§9.2). S6 sets it; it
    /// reads `false` until then.
    pub paused: std::sync::atomic::AtomicBool,
    /// The negotiated TLS security posture of the current session (CIP Security Phase 1,
    /// DESIGN-cip-security.md §3.4), or `None` when down / plaintext. Set on connect, cleared on drop;
    /// read by the `sb/status` `security` object. Owned here so the status, keepalive, and metric all
    /// derive from one source.
    pub security: std::sync::Mutex<Option<crate::device::SecurityStatus>>,
    /// 1 = the instance is currently in a TLS-handshake-failing state (§3.4). Drives the transition
    /// edge for the `tls-handshake-failed` event (fired on the transition into failing, not per retry).
    pub tls_handshake_failing: std::sync::atomic::AtomicBool,
    /// The EST enrollment lifecycle state (CIP Security Phase 2c, DESIGN-cip-security.md §4.3), or
    /// `None` when EST is not enabled for this instance. Updated by the `security_lifecycle` driver;
    /// read by the `sb/status` `security.est` object. One source for the status surface.
    pub est: std::sync::Mutex<Option<crate::eip::est::EstStatus>>,
    /// **The observed wire representation of each signal** (D-EIP-35), `signal id → declared CIP
    /// type name`, as of that signal's last reply. Written by the poll loop from
    /// [`Reading::observed_type`]; read by `sb/signals` as `observedType`.
    ///
    /// It lives here because this is the per-instance state the command surface already shares with
    /// the device task, and `sb/signals` answers **without device I/O** (§7.5) — routing it through
    /// the control channel would turn a config view into a verb that can report
    /// `DEVICE_UNAVAILABLE`. A signal with no entry has not been read yet, which is exactly the
    /// "absent until first contact" the field promises. Entries are keyed by the stable signal id
    /// and last written wins, so a re-programmed device corrects the surface on its next reply.
    pub observed_types: std::sync::Mutex<std::collections::HashMap<String, String>>,

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

    /// Store the negotiated security posture of a freshly-established session (CIP Security §3.4).
    pub fn set_security(&self, security: Option<crate::device::SecurityStatus>) {
        *self.security.lock().unwrap() = security;
    }

    /// The current session's security posture, if any (read by the `sb/status` `security` object).
    #[must_use]
    pub fn security(&self) -> Option<crate::device::SecurityStatus> {
        self.security.lock().unwrap().clone()
    }

    /// Store the EST enrollment state (CIP Security Phase 2c §4.3), read by `sb/status.security.est`.
    pub fn set_est(&self, est: Option<crate::eip::est::EstStatus>) {
        *self.est.lock().unwrap() = est;
    }

    /// The current EST enrollment state, if EST is enabled for this instance.
    #[must_use]
    pub fn est(&self) -> Option<crate::eip::est::EstStatus> {
        self.est.lock().unwrap().clone()
    }

    /// Record the wire representation each of these readings was served in (D-EIP-35). Readings
    /// that carry no declaration (a failed read, a push field) leave the previous observation
    /// standing — the surface reports the last thing the device actually said, not a gap punched in
    /// it by one timeout.
    pub fn record_observed(&self, readings: &[Reading]) {
        if readings.iter().all(|r| r.observed_type.is_none()) {
            return;
        }
        let Ok(mut map) = self.observed_types.lock() else {
            return;
        };
        for r in readings {
            if let Some(ty) = &r.observed_type {
                map.insert(r.signal_id.clone(), ty.clone());
            }
        }
    }

    /// The wire type `signal_id` was last observed to declare, or `None` before first contact.
    #[must_use]
    pub fn observed_type(&self, signal_id: &str) -> Option<String> {
        self.observed_types.lock().ok()?.get(signal_id).cloned()
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
    let paused = health.paused.load(Ordering::Relaxed);
    let connected = link == LinkState::Online;

    let mut attributes = serde_json::Map::new();
    attributes.insert("adapter".to_string(), json!(cfg.adapter));
    attributes.insert("mode".to_string(), json!(cfg.mode.as_str()));
    // A push instance's connection is class-1 implicit I/O, not explicit messaging (§9.1).
    let connection_mode = if matches!(cfg.mode, crate::config::DeviceMode::Push) {
        "class1-io"
    } else {
        cfg.connection.connection_mode()
    };
    attributes.insert("connectionMode".to_string(), json!(connection_mode));
    // The §7.4 reflection attribute: it derives from the SAME AtomicBool as the token and the gauge,
    // so no two surfaces can disagree (§9.2).
    attributes.insert("paused".to_string(), json!(paused));
    // CIP Security posture (§3.4): "tls" when the instance is configured for TLS, else "plaintext",
    // beside connectionMode so a console can render the posture unconditionally.
    let security_mode = crate::eip::tls::SecurityConfig::from_connection(&cfg.connection)
        .ok()
        .flatten()
        .is_some_and(|s| s.is_tls());
    attributes.insert(
        "security".to_string(),
        json!(if security_mode { "tls" } else { "plaintext" }),
    );
    // Phase 2a (§4.1): reflect whether the connected target implements the CIP Security objects, so a
    // fleet consumer watching `state` sees the posture without an `sb/status` round-trip. Present only
    // once a session posture has been read (both modes).
    if let Some(sec) = health.security() {
        attributes.insert("targetCipSecurity".to_string(), json!(sec.target.is_some()));
    }
    if let Some(slot) = cfg.connection.slot {
        attributes.insert("slot".to_string(), json!(slot));
    }

    // The token: PAUSED whenever the instance is paused AND the session is up; otherwise the raw link
    // state (so a break while paused reports BACKOFF, `connected` staying truthful). §9.2.
    let state_token = if paused && connected {
        "PAUSED"
    } else {
        link.as_str()
    };

    InstanceConnectivity::new(&cfg.id, connected, Some(cfg.connection.endpoint.clone()))
        .with_state(state_token)
        .with_attributes(attributes)
}

/// A write, on its way from the command inbox to the device's own task. Carries the resolved
/// [`SignalSpec`] (the codec needs the type to build the CIP value — §3.3).
pub struct WriteRequest {
    pub signal: SignalSpec,
    pub value: Value,
    /// The device's answer. A write is confirmed, not fire-and-forget.
    pub ack: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

/// One message on a device's **control channel** (§7). Every `sb/*` verb that must touch the session
/// or serialize with the engine loop is delivered as one of these, so the command inbox never touches
/// the (non-`Sync`) session directly — the device's own task services them one at a time, in line with
/// its poll/push loop. The reply riding each variant is what makes reads/writes/reconnect *confirmed*.
pub enum DeviceControl {
    /// Poll: a confirmed, allow-listed write of one signal (`sb/write`, §7.3).
    Write(WriteRequest),
    /// Poll: live-read these already-resolved specs now (`sb/read`, §7.2). Serializes with the loop and
    /// works while paused.
    ReadNow {
        specs: Vec<SignalSpec>,
        reply: tokio::sync::oneshot::Sender<std::result::Result<Vec<Reading>, String>>,
    },
    /// Push: the latest input snapshot (`sb/read`, §7.2). Answered even while paused; `None` ⇒ no frame
    /// yet / link down.
    Snapshot {
        reply: tokio::sync::oneshot::Sender<Option<InputSnapshot>>,
    },
    /// Push: stage one output-assembly field into the O→T producer buffer (`sb/write`, applied
    /// next-frame, §7.3).
    WriteOutput {
        field: IoFieldSpec,
        value: Value,
        reply: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Pause telemetry production (`sb/pause`, §7.4). `by` is the requester identity path. Reply =
    /// whether the state changed (idempotent).
    Pause {
        by: Option<String>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Resume telemetry production (`sb/resume`, §7.4). Reply = whether the state changed.
    Resume {
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Drop + re-establish, one bounded attempt (`reconnect`, §7.5). Reply `Ok(())` ⇒ connected,
    /// `Err` ⇒ failed (RECONNECT_FAILED).
    Reconnect {
        reply: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Poll only: force an immediate poll of ALL groups (`repoll`, §7.5). Reply = signals read, or
    /// `Err` when refused (paused).
    Repoll {
        reply: tokio::sync::oneshot::Sender<std::result::Result<u64, String>>,
    },
    /// Poll: one page of CIP tag discovery (`sb/browse`, §7.5) — needs the session's `list_tags`.
    Browse {
        cursor: Option<String>,
        max: usize,
        reply: tokio::sync::oneshot::Sender<
            std::result::Result<crate::device::BrowsePage, BrowseError>,
        >,
    },
}

/// Why a `sb/browse` could not answer (§7.5, §7.1): the device has no tag-list service
/// (`BROWSE_UNSUPPORTED`) or the browse failed / the device was unavailable (`BROWSE_FAILED`).
pub enum BrowseError {
    /// The device does not implement CIP tag discovery.
    Unsupported,
    /// A mid-browse failure (link error, or the task was disconnected).
    Failed(String),
}

/// The `evt`-surface sink the pause/resume + write-audit reflection publishes through (§6.3). Abstracted
/// behind a trait so the reflection logic is unit-testable without a live messaging inbox — production
/// is [`FacadeEventSink`] over the `events()` facade; tests use a recording double.
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Emit a one-shot event (§6.3).
    async fn emit(
        &self,
        severity: Severity,
        event_type: &str,
        message: Option<String>,
        context: Option<Value>,
    );
    /// Raise a stateful alarm (§6.3 `device-unreachable`).
    async fn raise_alarm(
        &self,
        severity: Severity,
        event_type: &str,
        message: Option<String>,
        context: Option<Value>,
    );
    /// Clear a stateful alarm (rides the same severity/channel as the raise).
    async fn clear_alarm(&self, severity: Severity, event_type: &str, context: Option<Value>);
}

/// Move **both** pause-reflection surfaces together, in one place (§9, §6.3) — so the
/// connectivity token/attribute and the `adapter-paused/resumed` event can never disagree:
///
/// 1. the shared [`Health::paused`] flag (which the connectivity provider reads for the `PAUSED` token
///    + `paused` attribute — pull-based, so flipping it is enough);
/// 2. the `adapter-paused` (Warning) / `adapter-resumed` (Info) `evt`.
///
/// The transition also flushes `southbound_health` immediately (`emit_metric_now`, §8.7) so the
/// gauges are current at the pause boundary.
///
/// Idempotent: pausing an already-paused instance changes nothing and returns `false` (never an error).
pub async fn apply_pause(
    cfg: &DeviceConfig,
    health: &Health,
    dm: &DeviceMetrics,
    events: &dyn EventSink,
    paused: bool,
    by: Option<&str>,
) -> bool {
    let was = health.paused.swap(paused, Ordering::Relaxed);
    if was == paused {
        return false;
    }
    // Flush the health gauges at the transition boundary (§8.7).
    dm.emit_now().await;
    if paused {
        let mut ctx = serde_json::Map::new();
        ctx.insert("instance".to_string(), json!(cfg.id));
        if let Some(by) = by {
            ctx.insert("by".to_string(), json!(by));
        }
        events
            .emit(
                Severity::Warning,
                "adapter-paused",
                Some("telemetry production paused".to_string()),
                Some(Value::Object(ctx)),
            )
            .await;
    } else {
        events
            .emit(
                Severity::Info,
                "adapter-resumed",
                Some("telemetry production resumed".to_string()),
                Some(json!({ "instance": cfg.id })),
            )
            .await;
    }
    true
}

/// The human-readable reason a connect attempt failed (for the reconnect reply + the log).
pub(crate) fn connect_reason(
    outcome: &std::result::Result<crate::device::Result<impl Sized>, tokio::time::error::Elapsed>,
    connect_timeout: Duration,
) -> String {
    match outcome {
        Ok(Err(e)) => e.to_string(),
        _ => format!("connect timed out after {} ms", connect_timeout.as_millis()),
    }
}

/// Why a disconnected-wait ended (§10.3).
pub(crate) enum DisconnectedWait {
    /// The wait elapsed (the backoff is over) — reconnect now.
    Elapsed,
    /// An explicit `reconnect` arrived — reconnect immediately, fulfil this reply after.
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
    /// The instance was cancelled (shutdown / a configuration-driven stop) or the control channel
    /// closed — leave the connect loop without reconnecting and **without an alarm**.
    Stopped,
}

/// Service the device's [`DeviceControl`] channel while the session is **down** (backing off or
/// between an explicit reconnect and the next connect), for up to `wait`. Pause/resume take effect
/// (they only need the shared flag + metric + event); the I/O verbs answer "disconnected" (the
/// command handler maps that to `DEVICE_UNAVAILABLE`/`NO_FRAME`); a `reconnect` returns its reply so
/// the caller reconnects *now* (cutting the backoff short).
///
/// The `cancel` arm is `biased`-first: a teardown must not wait out a backoff window that can be a
/// full minute. A closed control channel means the same thing — the owning task is being taken down
/// — so it returns [`DisconnectedWait::Stopped`] immediately rather than sleeping out the wait.
/// Verbs still queued at that point die with the channel and their callers get `DEVICE_UNAVAILABLE`.
///
/// **Clock:** the deadline is a [`tokio::time::Instant`], the same clock the `sleep` inside the loop
/// runs on — so a verb serviced mid-backoff resumes the *remaining* wait rather than restarting it.
/// (Measuring the deadline on the system clock while sleeping on the runtime's is identical in
/// production, where the two advance together, but under a paused clock every serviced verb would
/// re-arm the full window.)
pub(crate) async fn serve_control_disconnected(
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    cfg: &DeviceConfig,
    health: &Health,
    dm: &DeviceMetrics,
    events: &dyn EventSink,
    wait: Duration,
    cancel: &tokio_util::sync::CancellationToken,
) -> DisconnectedWait {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return DisconnectedWait::Elapsed;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return DisconnectedWait::Stopped,
            ctrl = control.recv() => {
                match ctrl {
                    None => {
                        tracing::info!(instance = %cfg.id, "control channel closed; stopping");
                        return DisconnectedWait::Stopped;
                    }
                    Some(DeviceControl::Reconnect { reply }) => return DisconnectedWait::Reconnect(reply),
                    Some(DeviceControl::Pause { by, reply }) => {
                        let changed = apply_pause(cfg, health, dm, events, true, by.as_deref()).await;
                        let _ = reply.send(changed);
                    }
                    Some(DeviceControl::Resume { reply }) => {
                        let changed = apply_pause(cfg, health, dm, events, false, None).await;
                        let _ = reply.send(changed);
                    }
                    Some(DeviceControl::Snapshot { reply }) => {
                        let _ = reply.send(None);
                    }
                    Some(DeviceControl::ReadNow { reply, .. }) => {
                        let _ = reply.send(Err("device is disconnected".to_string()));
                    }
                    Some(DeviceControl::Write(req)) => {
                        let _ = req.ack.send(Err("device is disconnected".to_string()));
                    }
                    Some(DeviceControl::WriteOutput { reply, .. }) => {
                        let _ = reply.send(Err("device is disconnected".to_string()));
                    }
                    Some(DeviceControl::Repoll { reply }) => {
                        let _ = reply.send(Err("device is disconnected".to_string()));
                    }
                    Some(DeviceControl::Browse { reply, .. }) => {
                        let _ = reply.send(Err(BrowseError::Failed("device is disconnected".to_string())));
                    }
                }
            }
            () = tokio::time::sleep(remaining) => return DisconnectedWait::Elapsed,
        }
    }
}

/// The full-jitter fraction for the next backoff wait — a sample in `[0, 1)` that
/// [`Backoff::delay`] scales by the rung's cap (§10.2).
///
/// Under test the fraction can be **pinned** ([`crate::testutil::JitterGuard`]), which is what makes
/// a ladder assertion an equality on the wait instead of a probability: with full jitter a rung that
/// climbed to the ceiling still lands under a low bound a large fraction of the time, so a one-sided
/// `wait ≤ base_ms` assertion would wave a lost `attempt` reset through most runs.
pub(crate) fn rand01() -> f64 {
    #[cfg(test)]
    if let Some(pinned) = crate::testutil::pinned_jitter() {
        return pinned;
    }
    use std::hash::{BuildHasher, Hasher};
    let n = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    (n % 1_000_000) as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;
    use serde_json::json;
    use std::sync::Arc;

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

    /// D-SC-7: the state token reaches the **published** keepalive element, not just the struct —
    /// `ONLINE` while polling and `PAUSED` while deliberately quiet, beside the normalized flag.
    #[test]
    fn the_published_keepalive_element_carries_the_state_token() {
        let cfg = a_device();
        let health = Health::default();
        health.set_link(LinkState::Online);

        let element = connectivity_of(&cfg, &health).to_json();
        assert_eq!(element["instance"], json!("plc-1"));
        assert_eq!(element["connected"], json!(true));
        assert_eq!(element["state"], json!("ONLINE"));
        assert_eq!(element["detail"], json!("127.0.0.1:44818"));

        health.paused.store(true, Ordering::Relaxed);
        let element = connectivity_of(&cfg, &health).to_json();
        assert_eq!(
            element["state"],
            json!("PAUSED"),
            "a paused instance is not silently stale"
        );
        assert_eq!(
            element["connected"],
            json!(true),
            "connectivity stays truthful beside it"
        );
        assert_eq!(element["attributes"]["paused"], json!(true));
    }

    #[test]
    fn state_attributes_reflect_target_cip_security_posture() {
        let cfg = a_device();
        let health = Health::default();
        // No posture read yet ⇒ no targetCipSecurity attribute.
        assert!(connectivity_of(&cfg, &health)
            .attributes
            .get("targetCipSecurity")
            .is_none());

        // A session that read a target posture ⇒ targetCipSecurity: true.
        health.set_security(Some(crate::device::SecurityStatus {
            target: Some(crate::device::TargetSecurityPosture::default()),
            ..Default::default()
        }));
        assert_eq!(
            connectivity_of(&cfg, &health).attributes["targetCipSecurity"],
            json!(true)
        );

        // A generic device (posture read, no objects) ⇒ targetCipSecurity: false.
        health.set_security(Some(crate::device::SecurityStatus::default()));
        assert_eq!(
            connectivity_of(&cfg, &health).attributes["targetCipSecurity"],
            json!(false)
        );
    }

    /// D-EIP-35: the observed representation is remembered per signal and, crucially, **not
    /// forgotten** by a reading that carries no declaration. A timeout or a CIP refusal produces no
    /// reply to read a type code from; punching a hole in the surface for it would make
    /// `observedType` flicker on every dropped poll, when the last thing the device actually said is
    /// still the best answer available.
    #[test]
    fn the_observed_representation_is_remembered_and_survives_a_reply_less_reading() {
        let health = Health::default();
        assert_eq!(
            health.observed_type("ALARMS"),
            None,
            "absent until first contact"
        );

        let observed = |id: &str, ty: Option<&str>| Reading {
            signal_id: id.to_string(),
            name: None,
            value: json!(null),
            quality: crate::device::Quality::Good,
            quality_raw: None,
            observed_type: ty.map(str::to_string),
        };

        health.record_observed(&[observed("ALARMS", Some("DWORD")), observed("SPEED", None)]);
        assert_eq!(health.observed_type("ALARMS").as_deref(), Some("DWORD"));
        assert_eq!(
            health.observed_type("SPEED"),
            None,
            "a reading with no declaration records nothing"
        );

        // A failed read leaves the prior observation standing…
        health.record_observed(&[observed("ALARMS", None)]);
        assert_eq!(health.observed_type("ALARMS").as_deref(), Some("DWORD"));
        // …and a device that starts answering differently corrects it on its next reply.
        health.record_observed(&[observed("ALARMS", Some("BOOL"))]);
        assert_eq!(health.observed_type("ALARMS").as_deref(), Some("BOOL"));
    }

    #[test]
    fn the_normalized_flag_and_the_health_metric_cannot_disagree() {
        let health = Health::default();
        health.set_link(LinkState::Online);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 1);
        health.set_link(LinkState::Backoff);
        assert_eq!(health.connection_state.load(Ordering::Relaxed), 0);
    }

    fn a_push_device() -> DeviceConfig {
        device(json!({
            "id": "io-1",
            "adapter": "sim",
            "mode": "push",
            "connection": { "endpoint": "opener:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "udint" } ] }
            }
        }))
    }

    /// §9.2: a link break WHILE paused reports BACKOFF (not PAUSED) with `paused: true`, and
    /// re-establishment returns to PAUSED — `connected` always telling the truth.
    #[test]
    fn paused_token_derives_from_flag_and_link_together() {
        let cfg = a_device();
        let health = Health::default();
        health.paused.store(true, Ordering::Relaxed);

        health.set_link(LinkState::Online);
        let c = connectivity_of(&cfg, &health);
        assert_eq!(
            c.state.as_deref(),
            Some("PAUSED"),
            "paused + online = PAUSED"
        );
        assert_eq!(c.attributes["paused"], json!(true));
        assert!(c.connected);

        health.set_link(LinkState::Backoff);
        let c = connectivity_of(&cfg, &health);
        assert_eq!(
            c.state.as_deref(),
            Some("BACKOFF"),
            "a break while paused reports BACKOFF"
        );
        assert_eq!(c.attributes["paused"], json!(true), "still marked paused");
        assert!(!c.connected);
    }

    /// The pause-reflection surfaces move together, in ONE test (§9, §6.3): the connectivity
    /// token + `paused` attribute and the `adapter-paused` event — with `southbound_health`
    /// flushed at the transition — and resume flips them back. Idempotent (`changed: false`).
    async fn pause_reflection_case(cfg: DeviceConfig) {
        let health = Arc::new(Health::default());
        health.set_link(LinkState::Online);
        let (metrics, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::clone(&health));
        let events = crate::testutil::RecordingEvents::default();

        // Before: ONLINE + gauge 0 + no event.
        assert_eq!(
            connectivity_of(&cfg, &health).state.as_deref(),
            Some("ONLINE")
        );

        let changed = apply_pause(&cfg, &health, &dm, &events, true, Some("site/op")).await;
        assert!(changed, "the first pause changes state");

        // 1. connectivity surface.
        let c = connectivity_of(&cfg, &health);
        assert_eq!(c.state.as_deref(), Some("PAUSED"));
        assert_eq!(c.attributes["paused"], json!(true));
        assert!(c.connected, "connected stays truthful while paused");
        // 2. the transition flushes southbound_health immediately (no paused measure — the eight
        // SOUTHBOUND §5 measures only).
        let h = metrics
            .last("southbound_health")
            .expect("health emitted on the pause transition");
        assert!(
            !h.contains_key("paused"),
            "southbound_health carries no paused extension measure"
        );
        // 3. the event (with the requester identity path).
        assert!(events.has("adapter-paused"));
        assert_eq!(
            events.last_ctx("adapter-paused").unwrap()["by"],
            json!("site/op")
        );

        // Idempotent: pausing again changes nothing and emits no new event.
        assert!(!apply_pause(&cfg, &health, &dm, &events, true, None).await);
        assert_eq!(
            events.count("adapter-paused"),
            1,
            "idempotent pause emits no second event"
        );

        // Resume flips the surfaces back.
        assert!(apply_pause(&cfg, &health, &dm, &events, false, None).await);
        assert_eq!(
            connectivity_of(&cfg, &health).state.as_deref(),
            Some("ONLINE")
        );
        assert_eq!(
            connectivity_of(&cfg, &health).attributes["paused"],
            json!(false)
        );
        assert!(events.has("adapter-resumed"));
    }

    #[tokio::test]
    async fn pause_reflection_moves_the_surfaces_poll() {
        pause_reflection_case(a_device()).await;
    }

    #[tokio::test]
    async fn pause_reflection_moves_the_surfaces_push() {
        pause_reflection_case(a_push_device()).await;
    }

    #[test]
    fn default_backoff_is_one_second_to_a_minute() {
        let b = Backoff::default();
        assert_eq!(b.base_ms, 1_000);
        assert_eq!(b.max_ms, 60_000);
    }

    #[test]
    fn rand01_is_a_unit_interval_fraction() {
        for _ in 0..64 {
            let r = rand01();
            assert!((0.0..1.0).contains(&r), "rand01 out of [0,1): {r}");
        }
    }

    #[test]
    fn connect_reason_renders_the_error_or_a_timeout() {
        // The Ok(Err(..)) arm carries the device error text.
        let outcome: std::result::Result<crate::device::Result<()>, tokio::time::error::Elapsed> =
            Ok(Err(crate::device::DeviceError::Permanent(anyhow::anyhow!(
                "no route to host"
            ))));
        let reason = connect_reason(&outcome, Duration::from_millis(500));
        assert!(reason.contains("no route to host"));

        // The Elapsed arm renders the timeout deadline.
        let elapsed = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
                    .await
                    .unwrap_err()
            });
        let outcome: std::result::Result<crate::device::Result<()>, tokio::time::error::Elapsed> =
            Err(elapsed);
        let reason = connect_reason(&outcome, Duration::from_millis(750));
        assert!(reason.contains("timed out") && reason.contains("750"));
    }

    /// While the session is down, `serve_control_disconnected` still services the control channel:
    /// pause/resume take effect (they need only the shared flag + metric + event), the I/O verbs answer
    /// "disconnected", and a `reconnect` returns its reply so the caller reconnects immediately.
    #[tokio::test]
    async fn serve_control_disconnected_services_pause_io_verbs_and_reconnect() {
        use tokio::sync::oneshot;
        let cfg = a_device();
        let health = Health::default();
        let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::new(Health::default()));
        let events = crate::testutil::RecordingEvents::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DeviceControl>(16);

        // A pause + one of every I/O verb + a final reconnect, all buffered before we serve.
        let (p_tx, p_rx) = oneshot::channel();
        tx.send(DeviceControl::Pause {
            by: Some("op".into()),
            reply: p_tx,
        })
        .await
        .unwrap();
        let (r_tx, r_rx) = oneshot::channel();
        tx.send(DeviceControl::ReadNow {
            specs: vec![],
            reply: r_tx,
        })
        .await
        .unwrap();
        let (s_tx, s_rx) = oneshot::channel();
        tx.send(DeviceControl::Snapshot { reply: s_tx })
            .await
            .unwrap();
        let (rp_tx, rp_rx) = oneshot::channel();
        tx.send(DeviceControl::Repoll { reply: rp_tx })
            .await
            .unwrap();
        let (b_tx, b_rx) = oneshot::channel();
        tx.send(DeviceControl::Browse {
            cursor: None,
            max: 10,
            reply: b_tx,
        })
        .await
        .unwrap();
        let spec = cfg.signals().next().unwrap().clone();
        let (w_tx, w_rx) = oneshot::channel();
        tx.send(DeviceControl::Write(WriteRequest {
            signal: spec,
            value: json!(1.0),
            ack: w_tx,
        }))
        .await
        .unwrap();
        let field = a_push_device().io.as_ref().unwrap().input.signals[0].clone();
        let (wo_tx, wo_rx) = oneshot::channel();
        tx.send(DeviceControl::WriteOutput {
            field,
            value: json!(1),
            reply: wo_tx,
        })
        .await
        .unwrap();
        let (res_tx, res_rx) = oneshot::channel();
        tx.send(DeviceControl::Resume { reply: res_tx })
            .await
            .unwrap();
        let (rc_tx, _rc_rx) = oneshot::channel();
        tx.send(DeviceControl::Reconnect { reply: rc_tx })
            .await
            .unwrap();

        let returned = serve_control_disconnected(
            &mut rx,
            &cfg,
            &health,
            &dm,
            &events,
            Duration::from_secs(5),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;

        assert!(
            matches!(returned, DisconnectedWait::Reconnect(_)),
            "a buffered reconnect is returned so the caller reconnects now"
        );
        assert!(p_rx.await.unwrap(), "pause took effect while disconnected");
        assert!(events.has("adapter-paused"));
        assert!(r_rx.await.unwrap().is_err(), "a read answers disconnected");
        assert!(s_rx.await.unwrap().is_none(), "a snapshot answers None");
        assert!(
            rp_rx.await.unwrap().is_err(),
            "a repoll answers disconnected"
        );
        assert!(
            b_rx.await.unwrap().is_err(),
            "a browse answers disconnected"
        );
        assert!(w_rx.await.unwrap().is_err(), "a write answers disconnected");
        assert!(
            wo_rx.await.unwrap().is_err(),
            "a push write answers disconnected"
        );
        assert!(res_rx.await.unwrap(), "resume took effect");
        // Pause then resume both ran while disconnected: the flag ends cleared, both events fired.
        assert!(
            !health.paused.load(Ordering::Relaxed),
            "resume cleared the shared flag"
        );
        assert!(events.has("adapter-resumed"));
    }

    /// With no message pending, `serve_control_disconnected` reports `Elapsed` once the wait is over.
    #[tokio::test(start_paused = true)]
    async fn serve_control_disconnected_times_out_to_none() {
        let cfg = a_device();
        let health = Health::default();
        let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::new(Health::default()));
        let events = crate::testutil::RecordingEvents::default();
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<DeviceControl>(4);
        let returned = serve_control_disconnected(
            &mut rx,
            &cfg,
            &health,
            &dm,
            &events,
            Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(returned, DisconnectedWait::Elapsed),
            "the backoff wait elapsed with no control message"
        );
    }

    /// §10.3: a teardown that lands mid-backoff must not wait out the window — a device sitting on a
    /// minute-long backoff ceiling would otherwise wedge shutdown for that whole minute.
    #[tokio::test(start_paused = true)]
    async fn serve_control_disconnected_returns_stopped_on_cancel() {
        let cfg = a_device();
        let health = Health::default();
        let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::new(Health::default()));
        let events = crate::testutil::RecordingEvents::default();
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<DeviceControl>(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();

        let started = tokio::time::Instant::now();
        let returned = serve_control_disconnected(
            &mut rx,
            &cfg,
            &health,
            &dm,
            &events,
            Duration::from_secs(60),
            &cancel,
        )
        .await;

        assert!(matches!(returned, DisconnectedWait::Stopped));
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "a cancelled instance leaves the backoff immediately, not after the window"
        );
        assert!(
            !events.has("device-unreachable"),
            "a stop raises no alarm here"
        );
    }

    /// A closed control channel means the owning task is going away, so it stops immediately rather
    /// than sleeping out the remaining backoff.
    #[tokio::test(start_paused = true)]
    async fn serve_control_disconnected_channel_close_is_stopped_not_a_full_sleep() {
        let cfg = a_device();
        let health = Health::default();
        let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::new(Health::default()));
        let events = crate::testutil::RecordingEvents::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DeviceControl>(4);
        drop(tx);

        let started = tokio::time::Instant::now();
        let returned = serve_control_disconnected(
            &mut rx,
            &cfg,
            &health,
            &dm,
            &events,
            Duration::from_secs(30),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;

        assert!(matches!(returned, DisconnectedWait::Stopped));
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "the remaining wait is not slept out"
        );
    }
}
