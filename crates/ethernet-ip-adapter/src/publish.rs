//! # The publish path + the shared publish-gate primitives (§6.1, §6.2)
//!
//! Both engines — poll ([`crate::poll`]) and push ([`crate::push`]) — feed the *same* publish path
//! here: [`publish`] assembles a `SouthboundSignalUpdate` through the `data()` facade builder and
//! measures the publish latency. Neither engine ever hand-builds a topic or a body — the facade mints
//! the topic (channel = the config `name`, §5.3), stamps identity, and defaults `serverTs` to now
//! when a sample leaves it unset (§6.2).
//!
//! This module also owns the **mode-agnostic gate primitives** both engines share:
//!
//! * [`should_publish`] — the deadband / `publishMode` gate (a BAD/UNCERTAIN sample always passes;
//!   `always` publishes every sample; `onChange` compares against the last published value with the
//!   configured deadband — none / absolute / percent, arrays "any element exceeds", non-numeric "any
//!   change"). §4.4 / §6.2.
//! * [`Batcher`] — the per-signal `batchMs` coalescing window (0 ⇒ publish per cycle; > 0 ⇒ buffer
//!   and flush on window close, one `samples[]` per flush). §6.2.
//! * [`SignalState`] — the per-signal running state (onChange baseline, staleness `last_good`, the
//!   `sampleMs` floor `last_eligible`, and the batcher).
//! * [`is_stale`] / [`cycle_overran`] — the staleness and overrun predicates the engines account
//!   against `staleSignalSecs` (§8.1) and the poll interval (§3.2).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, Sample, SignalUpdate};
use serde_json::Value;

use crate::config::{DeadbandKind, DeadbandSpec, PublishMode};
use crate::device::Quality;

/// The `device` block parts stamped into every `SouthboundSignalUpdate` (§5.2). Borrowed so both
/// engines pass slices of their `DeviceConfig` without cloning per publish.
pub(crate) struct DeviceParts<'a> {
    pub adapter: &'a str,
    pub instance: &'a str,
    pub endpoint: &'a str,
}

/// Map the seam's [`Quality`] to the facade quality (the wire enum). One place, so a new variant is a
/// compile error in exactly one spot.
#[must_use]
pub(crate) fn facade_quality(q: Quality) -> edgecommons::facades::Quality {
    match q {
        Quality::Good => edgecommons::facades::Quality::Good,
        Quality::Bad => edgecommons::facades::Quality::Bad,
        Quality::Uncertain => edgecommons::facades::Quality::Uncertain,
    }
}

/// Build one [`Sample`] from a seam reading's parts. `server_ts` is set explicitly for the older
/// samples of a coalesced batch (so a batch preserves per-read arrival times, §6.2) and left `None`
/// for the immediate/newest case (the facade then stamps "now"). `sourceTs` is never emitted
/// (D-EIP-11).
#[must_use]
pub(crate) fn sample_of(
    value: Value,
    quality: Quality,
    quality_raw: Option<&str>,
    server_ts: Option<String>,
) -> Sample {
    let mut s = Sample::with_quality(value, facade_quality(quality));
    if let Some(raw) = quality_raw {
        s = s.quality_raw(raw);
    }
    if let Some(ts) = server_ts {
        s = s.server_ts(ts);
    }
    s
}

/// Assemble the `SouthboundSignalUpdate` for a batch of samples (§6.2). Exposed (not just used by
/// [`publish`]) so the wire-shape test can assert the body the adapter hands the facade
/// field-by-field, for both id forms.
#[must_use]
pub(crate) fn build_update(
    stable_id: &str,
    name: &str,
    address: Value,
    device: &DeviceParts<'_>,
    samples: Vec<Sample>,
) -> SignalUpdate {
    // signal.id = the stable id (poll: tagPath D-EIP-9; push: a<inst>/<off>/<type> D-EIP-18);
    // channel = the config name (§5.3); the raw id rides only in the body.
    SignalUpdate::builder()
        .signal_id(stable_id)
        .name(name)
        .address(address)
        .device_parts(device.adapter, device.instance, device.endpoint)
        .signal_path(name)
        .samples(samples)
        .build()
}

/// The single publish call both engines use (§6.1): assemble the update and publish it, returning the
/// result and the **publish latency** — the wall time of the `data.publish().await` (§6.2, recorded
/// into `southbound_health.publishLatencyMs` / `EtherNetIpPublish.publishLatencyMs`).
pub(crate) async fn publish(
    data: &DataFacade,
    stable_id: &str,
    name: &str,
    address: Value,
    device: &DeviceParts<'_>,
    samples: Vec<Sample>,
) -> (std::result::Result<(), String>, Duration) {
    let update = build_update(stable_id, name, address, device, samples);
    let start = Instant::now();
    let res = data.publish(update).await;
    let latency = start.elapsed();
    (res.map_err(|e| e.to_string()), latency)
}

// =====================================================================================
// The publish gate (§4.4 / §6.2) — shared by both engines, mode-agnostic and pure.
// =====================================================================================

/// Whether a sample should be published now, per §6.2.
///
/// * A non-GOOD sample (BAD read, or push IDLE/UNCERTAIN) **always passes** — a failure is
///   information, and silence is indistinguishable from "not changing".
/// * `publishMode: always` publishes every sample.
/// * `publishMode: onChange` publishes only when the value changed past the deadband relative to the
///   last published value (`prev`): the first sample (no `prev`) always passes; thereafter
///   none/absolute/percent per [`DeadbandSpec`], arrays "any element exceeds", non-numeric "any
///   change".
#[must_use]
pub(crate) fn should_publish(
    prev: Option<&Value>,
    value: &Value,
    quality: Quality,
    mode: PublishMode,
    deadband: &DeadbandSpec,
) -> bool {
    if quality != Quality::Good {
        return true;
    }
    if mode == PublishMode::Always {
        return true;
    }
    match prev {
        None => true,
        Some(p) => value_changed(p, value, deadband),
    }
}

/// Whether `new` differs from `prev` past the deadband. Arrays: differing length ⇒ changed; else "any
/// element exceeds". Non-numeric (bool / string / type change) ⇒ any inequality.
#[must_use]
fn value_changed(prev: &Value, new: &Value, deadband: &DeadbandSpec) -> bool {
    match (prev, new) {
        (Value::Array(p), Value::Array(n)) => {
            if p.len() != n.len() {
                return true;
            }
            p.iter().zip(n).any(|(a, b)| element_changed(a, b, deadband))
        }
        _ => element_changed(prev, new, deadband),
    }
}

/// One element (or scalar): numeric ⇒ deadband comparison; otherwise any inequality.
#[must_use]
fn element_changed(prev: &Value, new: &Value, deadband: &DeadbandSpec) -> bool {
    match (prev.as_f64(), new.as_f64()) {
        (Some(old), Some(new)) => scalar_exceeds(old, new, deadband),
        _ => prev != new,
    }
}

/// The numeric deadband comparison (§4.4): none ⇒ any change; absolute ⇒ `|new-old| ≥ value`;
/// percent ⇒ `|new-old| ≥ |old| · value/100` (relative to the old value; a zero threshold degrades
/// to "any change").
#[must_use]
fn scalar_exceeds(old: f64, new: f64, deadband: &DeadbandSpec) -> bool {
    let delta = (new - old).abs();
    match deadband.kind {
        DeadbandKind::None => new != old,
        DeadbandKind::Absolute => delta >= deadband.value,
        DeadbandKind::Percent => {
            let threshold = old.abs() * deadband.value / 100.0;
            if threshold == 0.0 {
                new != old
            } else {
                delta >= threshold
            }
        }
    }
}

// =====================================================================================
// Batching (§6.2) + per-signal running state.
// =====================================================================================

/// The per-signal `batchMs` coalescing window (§6.2). With `batch_ms == 0` a passing sample publishes
/// immediately (one sample per cycle); with `batch_ms > 0` samples buffer into a window opened by the
/// first buffered sample and flush together when it closes.
#[derive(Default)]
pub(crate) struct Batcher {
    buffer: Vec<Sample>,
    window_open: Option<Instant>,
}

impl Batcher {
    /// Add a passing sample. Returns `Some(samples)` to publish **now** when `batch_ms == 0`; else
    /// buffers it (opening the window on the first) and returns `None` — [`Self::take_due`] flushes it
    /// once the window closes.
    pub(crate) fn add(&mut self, sample: Sample, now: Instant, batch_ms: u64) -> Option<Vec<Sample>> {
        if batch_ms == 0 {
            return Some(vec![sample]);
        }
        if self.window_open.is_none() {
            self.window_open = Some(now);
        }
        self.buffer.push(sample);
        None
    }

    /// Drain the buffer iff a window is open and `batch_ms` has elapsed since it opened.
    pub(crate) fn take_due(&mut self, now: Instant, batch_ms: u64) -> Option<Vec<Sample>> {
        match self.window_open {
            Some(opened)
                if !self.buffer.is_empty()
                    && now.saturating_duration_since(opened) >= Duration::from_millis(batch_ms) =>
            {
                self.window_open = None;
                Some(std::mem::take(&mut self.buffer))
            }
            _ => None,
        }
    }

    /// When the open window will next be due (for the loop's wake computation), or `None` if idle.
    #[must_use]
    pub(crate) fn next_deadline(&self, batch_ms: u64) -> Option<Instant> {
        self.window_open.map(|t| t + Duration::from_millis(batch_ms))
    }
}

/// One signal's running publish state: the onChange baseline (last published value), the last GOOD
/// read time (staleness), the last publish-eligible time (the push `sampleMs` floor), and the batch
/// window.
#[derive(Default)]
pub(crate) struct SignalState {
    /// Last published value — the onChange comparison baseline.
    pub baseline: Option<Value>,
    /// Last GOOD read (for staleness accounting, §8.1).
    pub last_good: Option<Instant>,
    /// Last publish-eligible time (the `sampleMs` floor gate; push only, §4.6).
    pub last_eligible: Option<Instant>,
    /// The `batchMs` coalescing window.
    pub batcher: Batcher,
}

/// One assembled publish: a stable `signal.id` and the samples to ride one `SouthboundSignalUpdate`.
/// The engine hands these back to the run loop, which resolves the id to its spec/field, builds the
/// address, and calls [`publish`].
pub(crate) struct Publish {
    pub signal_id: String,
    pub samples: Vec<Sample>,
}

/// The per-signal running state, shared by both engines (poll and push). Holds one [`SignalState`]
/// per stable `signal.id` plus the engine's start (the staleness reference for never-read signals).
/// The mode-specific gating (a poll group vs a consumed frame) lives in [`crate::poll`] /
/// [`crate::push`]; the batch bookkeeping, flush scheduling, and staleness accounting live here so
/// both engines behave identically.
pub(crate) struct Engine {
    pub state: HashMap<String, SignalState>,
    pub start: Instant,
}

impl Engine {
    #[must_use]
    pub(crate) fn new(start: Instant) -> Self {
        Self {
            state: HashMap::new(),
            start,
        }
    }

    /// Every batch window that has closed by `now`, drained into one [`Publish`] each.
    pub(crate) fn take_due(&mut self, batch_ms: u64, now: Instant) -> Vec<Publish> {
        let mut out = Vec::new();
        for (id, st) in &mut self.state {
            if let Some(samples) = st.batcher.take_due(now, batch_ms) {
                out.push(Publish {
                    signal_id: id.clone(),
                    samples,
                });
            }
        }
        out
    }

    /// The earliest open batch window's close time (for the run loop's wake), or `None`.
    #[must_use]
    pub(crate) fn next_batch_deadline(&self, batch_ms: u64) -> Option<Instant> {
        self.state
            .values()
            .filter_map(|s| s.batcher.next_deadline(batch_ms))
            .min()
    }

    /// How many of `ids` are stale (§8.1) — no GOOD read for at least `stale_secs`, counting a
    /// never-read signal from the engine's start.
    #[must_use]
    pub(crate) fn count_stale<'a>(
        &self,
        ids: impl Iterator<Item = &'a str>,
        stale_secs: u64,
        now: Instant,
    ) -> u64 {
        ids.filter(|id| {
            let last_good = self.state.get(*id).and_then(|s| s.last_good);
            is_stale(last_good, self.start, now, stale_secs)
        })
        .count() as u64
    }
}

/// Whether a signal is stale (§8.1): no GOOD read for at least `stale_secs`. `since` is the engine's
/// start (so a signal that has *never* read GOOD becomes stale `stale_secs` after start, not at t=0).
#[must_use]
pub(crate) fn is_stale(
    last_good: Option<Instant>,
    since: Instant,
    now: Instant,
    stale_secs: u64,
) -> bool {
    let base = last_good.unwrap_or(since);
    now.saturating_duration_since(base).as_secs() >= stale_secs
}

/// Whether a poll cycle overran its own interval (took longer than the group's cadence, §3.2 — the
/// scanner cannot keep up).
#[must_use]
pub(crate) fn cycle_overran(elapsed: Duration, interval: Duration) -> bool {
    elapsed > interval
}

/// The current wall-clock time as an RFC-3339 string — the explicit `serverTs` stamped on the older
/// samples of a coalesced batch so the batch preserves per-read arrival times (§6.2).
#[must_use]
pub(crate) fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn db(kind: DeadbandKind, value: f64) -> DeadbandSpec {
        DeadbandSpec { kind, value }
    }

    // ---- should_publish: publishMode + BAD-passes-gate ----

    #[test]
    fn always_mode_publishes_every_sample_including_unchanged() {
        let none = db(DeadbandKind::None, 0.0);
        // Same value twice: onChange would suppress the second, `always` publishes both.
        assert!(should_publish(
            Some(&json!(10.0)),
            &json!(10.0),
            Quality::Good,
            PublishMode::Always,
            &none
        ));
    }

    #[test]
    fn on_change_suppresses_an_unchanged_good_sample() {
        let none = db(DeadbandKind::None, 0.0);
        assert!(!should_publish(
            Some(&json!(10.0)),
            &json!(10.0),
            Quality::Good,
            PublishMode::OnChange,
            &none
        ));
    }

    #[test]
    fn a_bad_sample_always_passes_the_gate_even_unchanged() {
        // A failure is information: BAD passes even in onChange with no change (§6.2).
        let none = db(DeadbandKind::None, 0.0);
        assert!(should_publish(
            Some(&json!(10.0)),
            &json!(null),
            Quality::Bad,
            PublishMode::OnChange,
            &none
        ));
        // An IDLE (UNCERTAIN) push sample likewise still publishes.
        assert!(should_publish(
            Some(&json!(10.0)),
            &json!(10.0),
            Quality::Uncertain,
            PublishMode::OnChange,
            &none
        ));
    }

    #[test]
    fn the_first_onchange_sample_always_publishes() {
        let abs = db(DeadbandKind::Absolute, 100.0);
        assert!(should_publish(
            None,
            &json!(1.0),
            Quality::Good,
            PublishMode::OnChange,
            &abs
        ));
    }

    // ---- deadband: none / absolute / percent ----

    #[test]
    fn deadband_none_republishes_any_change_but_not_equality() {
        let none = db(DeadbandKind::None, 0.0);
        assert!(value_changed(&json!(10.0), &json!(10.001), &none));
        assert!(!value_changed(&json!(10.0), &json!(10.0), &none));
    }

    #[test]
    fn deadband_absolute_gates_below_the_threshold() {
        let abs = db(DeadbandKind::Absolute, 0.5);
        assert!(!value_changed(&json!(10.0), &json!(10.4), &abs), "0.4 < 0.5 suppressed");
        assert!(value_changed(&json!(10.0), &json!(10.5), &abs), "0.5 >= 0.5 passes");
    }

    #[test]
    fn deadband_percent_is_relative_to_the_old_value() {
        let pct = db(DeadbandKind::Percent, 1.0); // 1%
        // old=100 → 1% threshold = 1.0.
        assert!(!value_changed(&json!(100.0), &json!(100.9), &pct), "0.9 < 1.0 suppressed");
        assert!(value_changed(&json!(100.0), &json!(101.0), &pct), "1.0 >= 1.0 passes");
        // old=0 → zero threshold degrades to any-change.
        assert!(value_changed(&json!(0.0), &json!(0.001), &pct));
    }

    // ---- non-numeric + arrays ----

    #[test]
    fn non_numeric_uses_any_change() {
        let abs = db(DeadbandKind::Absolute, 1000.0); // huge threshold, irrelevant for bools
        assert!(value_changed(&json!(true), &json!(false), &abs));
        assert!(!value_changed(&json!(true), &json!(true), &abs));
    }

    #[test]
    fn array_passes_when_any_element_exceeds() {
        let abs = db(DeadbandKind::Absolute, 0.5);
        // Only the 3rd element moves past 0.5.
        let prev = json!([1.0, 2.0, 3.0]);
        assert!(value_changed(&prev, &json!([1.1, 2.1, 3.6]), &abs), "3rd exceeds");
        assert!(
            !value_changed(&prev, &json!([1.1, 2.1, 3.1]), &abs),
            "no element moves >= 0.5"
        );
        // Length change ⇒ always changed.
        assert!(value_changed(&prev, &json!([1.0, 2.0]), &abs));
    }

    // ---- Batcher ----

    #[test]
    fn batcher_with_zero_window_publishes_immediately() {
        let mut b = Batcher::default();
        let now = Instant::now();
        let out = b.add(sample_of(json!(1), Quality::Good, Some("0x00"), None), now, 0);
        assert_eq!(out.map(|v| v.len()), Some(1));
        assert!(b.next_deadline(0).is_none());
    }

    #[test]
    fn batcher_buffers_then_flushes_on_window_close() {
        let mut b = Batcher::default();
        let t0 = Instant::now();
        assert!(b.add(sample_of(json!(1), Quality::Good, None, Some("t0".into())), t0, 100).is_none());
        let t1 = t0 + Duration::from_millis(40);
        assert!(b.add(sample_of(json!(2), Quality::Good, None, Some("t1".into())), t1, 100).is_none());
        // Not yet due at t0+50.
        assert!(b.take_due(t0 + Duration::from_millis(50), 100).is_none());
        // Due at t0+100: both buffered samples ride one flush, in arrival order.
        let flush = b.take_due(t0 + Duration::from_millis(100), 100).expect("a due flush");
        assert_eq!(flush.len(), 2);
        assert_eq!(flush[0].value, Some(json!(1)));
        assert_eq!(flush[1].value, Some(json!(2)));
        // Window is closed after the flush.
        assert!(b.take_due(t0 + Duration::from_millis(300), 100).is_none());
    }

    // ---- staleness + overrun ----

    #[test]
    fn staleness_counts_from_last_good_or_start() {
        let start = Instant::now();
        // Never GOOD: stale once stale_secs elapse from start.
        assert!(!is_stale(None, start, start + Duration::from_secs(59), 60));
        assert!(is_stale(None, start, start + Duration::from_secs(60), 60));
        // A recent GOOD read resets the clock.
        let good = start + Duration::from_secs(100);
        assert!(!is_stale(Some(good), start, good + Duration::from_secs(30), 60));
        assert!(is_stale(Some(good), start, good + Duration::from_secs(60), 60));
    }

    #[test]
    fn overrun_is_a_cycle_longer_than_its_interval() {
        assert!(cycle_overran(Duration::from_millis(600), Duration::from_millis(500)));
        assert!(!cycle_overran(Duration::from_millis(400), Duration::from_millis(500)));
    }

    #[test]
    fn now_iso_is_rfc3339() {
        let ts = now_iso();
        // Round-trips as RFC-3339 (has a date/time separator and a zone).
        assert!(ts.contains('T'), "unexpected timestamp: {ts}");
        assert!(
            time::OffsetDateTime::parse(&ts, &time::format_description::well_known::Rfc3339).is_ok()
        );
    }
}
