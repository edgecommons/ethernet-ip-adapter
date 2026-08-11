//! # The poll engine (§3.2, §4, §6) — scheduled explicit-messaging reads → gated publishes
//!
//! One task per poll-mode device drives [`poll_until_disconnected`]: each [`crate::config::PollGroup`]
//! runs on its own resolved cadence (`pollIntervalMs`); each tick reads the group's signals through
//! the [`DeviceSession`] seam; every reading passes the shared deadband / `publishMode` gate
//! ([`publish::should_publish`]) and the `batchMs` coalescing window ([`publish::Batcher`]); and what
//! survives is published through the mode-agnostic [`publish`] path. A per-signal failure rides as a
//! BAD sample (never swallowed); a connection-level failure leaves the loop so the supervisor
//! ([`crate::app`]) can reconnect.
//!
//! The gating/batching/staleness bookkeeping is factored into a shared [`publish::Engine`]; this
//! module owns the *poll-specific* decisions — per-group scheduling, resolving a group's readings
//! against the config, and driving the writes/keepalive-free select loop the S2 template established.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::app::Health;
use crate::config::{PollGroup, PublishMode};
use crate::device::{Quality, Reading};
use crate::publish::{self, Engine, Publish};

// The per-cycle `SampleSnapshot` (the shared-counter deltas), the scheduled read → gate → batch →
// publish select-loop (`poll_until_disconnected`), and the `repoll` / publish glue live in
// [`crate::poll_driver`], which drives them against the session/publisher/event seams under its own
// paused-clock tests; the pure gating/counting/overrun logic below is what the unit tests here drive.

/// Gate + count + batch one group's readings (§4.4, §6.2). Returns the samples to publish **now**
/// (batchMs == 0); anything buffered flushes later via [`Engine::take_due`]. Bumps the S5 counters on
/// `health`. `server_ts` is the capture-time stamp the driver took when the group's read completed
/// (the four-slot timestamp model) — every sample carries it explicitly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_group(
    engine: &mut Engine,
    group: &PollGroup,
    mode: PublishMode,
    batch_ms: u64,
    readings: &[Reading],
    now: Instant,
    server_ts: &str,
    health: &Health,
) -> Vec<Publish> {
    // Match readings to specs by stable id — a backend may reorder, and one dead tag must not shift
    // the others.
    let by_id: std::collections::HashMap<&str, &Reading> =
        readings.iter().map(|r| (r.signal_id.as_str(), r)).collect();

    let mut out = Vec::new();
    for spec in &group.signals {
        let Some(reading) = by_id.get(spec.tag_path.as_str()) else {
            continue;
        };
        let good = reading.quality == Quality::Good;
        let st = engine.state.entry(spec.tag_path.clone()).or_default();

        match reading.quality {
            Quality::Good => {
                health.samples_good.fetch_add(1, Ordering::Relaxed);
                st.last_good = Some(now);
            }
            // A BAD read is a per-signal failure, published not swallowed. It counts as both a bad
            // sample (§8.4) and a signal-read failure (§8.1 readErrors). UNCERTAIN is neither GOOD nor
            // BAD (non-finite scale) — its own tally (§8.4 samplesUncertain).
            Quality::Bad => {
                health.samples_bad.fetch_add(1, Ordering::Relaxed);
                health.read_errors.fetch_add(1, Ordering::Relaxed);
            }
            Quality::Uncertain => {
                health.samples_uncertain.fetch_add(1, Ordering::Relaxed);
            }
        }

        if !publish::gate_passes(st, &reading.value, reading.quality, mode, &spec.deadband) {
            health.samples_suppressed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if good {
            if mode == PublishMode::OnChange {
                health.samples_changed.fetch_add(1, Ordering::Relaxed);
            }
            // The onChange baseline is the last *published* value, so this one is only PENDING
            // until its publish is confirmed — `Engine::settle` promotes it then, and drops it if
            // the publish failed so the same reading gates in again (D-EIP-32).
            st.pending = Some(reading.value.clone());
        }

        // Every sample carries the explicit capture-time serverTs (read completion, §6.2) — never
        // the facade's at-publish default, which would drift under batchMs coalescing.
        let sample = publish::sample_of(
            reading.value.clone(),
            reading.quality,
            reading.quality_raw.as_deref(),
            Some(server_ts.to_string()),
        );
        if let Some(samples) = st.batcher.add(sample, now, batch_ms) {
            out.push(Publish {
                signal_id: spec.tag_path.clone(),
                samples,
            });
        }
    }
    out
}

/// Count one poll cycle and flag an overrun (a cycle that ran longer than its own interval, §3.2).
pub(crate) fn record_cycle(elapsed: Duration, interval: Duration, health: &Health) {
    health.poll_cycles.fetch_add(1, Ordering::Relaxed);
    if publish::cycle_overran(elapsed, interval) {
        health.overruns.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    //! Poll-engine gating/batching/stale/overrun — driven with canned [`Reading`]s and a scripted
    //! mock [`DeviceSession`], no socket / no enip (§12.3).
    use super::*;
    use crate::config::{DeviceConfig, SignalSpec};
    use crate::device::{BrowsePage, DeviceError, DeviceSession, Result as DevResult};
    use async_trait::async_trait;
    use serde_json::{json, Value};

    /// The injected capture-time stamp (read completion) every test passes to [`process_group`].
    const TS: &str = "2026-07-18T12:00:00Z";

    fn dev(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).unwrap()
    }

    fn reading(id: &str, value: Value, quality: Quality) -> Reading {
        Reading {
            signal_id: id.to_string(),
            name: Some(id.to_string()),
            value,
            quality,
            quality_raw: Some(
                if quality == Quality::Good {
                    "0x00"
                } else {
                    "0x04 path segment error"
                }
                .to_string(),
            ),
            observed_type: None,
        }
    }

    /// A scripted [`DeviceSession`]: returns a preset `Vec<Reading>` per `read_signals` call, in order
    /// (repeating the last once exhausted). Proves the engine works over the seam with no PLC.
    struct ScriptedSession {
        script: Vec<Vec<Reading>>,
        calls: usize,
    }

    impl ScriptedSession {
        fn new(script: Vec<Vec<Reading>>) -> Self {
            Self { script, calls: 0 }
        }
    }

    #[async_trait]
    impl DeviceSession for ScriptedSession {
        async fn read_signals(&mut self, _signals: &[SignalSpec]) -> DevResult<Vec<Reading>> {
            let i = self.calls.min(self.script.len().saturating_sub(1));
            self.calls += 1;
            Ok(self.script[i].clone())
        }
        async fn write_signal(&mut self, _s: &SignalSpec, _v: &Value) -> DevResult<()> {
            Ok(())
        }
        async fn browse(&mut self, _c: Option<String>, _m: usize) -> DevResult<BrowsePage> {
            Err(DeviceError::Unsupported("scripted"))
        }
        async fn probe(&mut self) -> DevResult<()> {
            Ok(())
        }
    }

    fn one_signal_device(deadband: Value, publish_mode: &str) -> DeviceConfig {
        dev(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "publishMode": publish_mode, "signals": [
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real", "deadband": deadband }
            ] } ]
        }))
    }

    #[tokio::test]
    async fn deadband_absolute_onchange_via_a_scripted_session_publishes_fewer_than_polls() {
        let d = one_signal_device(json!({ "type": "absolute", "value": 0.5 }), "onChange");
        let group = &d.poll_groups[0];
        let mut session: Box<dyn DeviceSession> = Box::new(ScriptedSession::new(vec![
            vec![reading("LINE_SPEED", json!(10.0), Quality::Good)], // first ⇒ publish
            vec![reading("LINE_SPEED", json!(10.2), Quality::Good)], // +0.2 < 0.5 ⇒ suppress
            vec![reading("LINE_SPEED", json!(11.0), Quality::Good)], // +0.8 ≥ 0.5 ⇒ publish
        ]));
        let health = Health::default();
        let mut engine = Engine::new(Instant::now());

        let mut published = 0usize;
        for _ in 0..3 {
            let r = session.read_signals(&group.signals).await.unwrap();
            published += process_group(
                &mut engine,
                group,
                PublishMode::OnChange,
                0,
                &r,
                Instant::now(),
                TS,
                &health,
            )
            .len();
        }
        assert_eq!(
            published, 2,
            "fewer publishes than polls: the within-band read is suppressed"
        );
        assert_eq!(health.samples_good.load(Ordering::Relaxed), 3);
        assert_eq!(health.samples_suppressed.load(Ordering::Relaxed), 1);
        assert_eq!(health.samples_changed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn deadband_percent_and_none() {
        // percent 1%: baseline 100 → threshold 1.0.
        let d = one_signal_device(json!({ "type": "percent", "value": 1.0 }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(100.0), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(100.9), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            0,
            "0.9 < 1% suppressed"
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(101.5), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1,
            "1.5 ≥ 1% publishes"
        );

        // none: any change republishes.
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let mut e = Engine::new(Instant::now());
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(1.0), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(1.0), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            0,
            "no change"
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", json!(1.1), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
    }

    #[test]
    fn always_mode_publishes_every_poll_and_non_numeric_uses_any_change() {
        // always: even unchanged republishes.
        let d = one_signal_device(json!({ "type": "none" }), "always");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                process_group(
                    &mut e,
                    g,
                    PublishMode::Always,
                    0,
                    &[reading("LINE_SPEED", json!(5.0), Quality::Good)],
                    now,
                    TS,
                    &h
                )
                .len(),
                1
            );
        }
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 0);

        // non-numeric (a dint used as a flag, string values here): any change.
        let d = dev(json!({
            "id": "p", "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [ { "name": "state", "tagPath": "STATE", "type": "dint" } ] } ]
        }));
        let g = &d.poll_groups[0];
        let mut e = Engine::new(Instant::now());
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("STATE", json!("RUN"), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("STATE", json!("RUN"), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            0
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("STATE", json!("STOP"), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
    }

    #[test]
    fn array_any_element_exceeds_gates_the_whole_signal() {
        let d = dev(json!({
            "id": "p", "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "zone-temps", "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 3,
                  "deadband": { "type": "absolute", "value": 0.5 } }
            ] } ]
        }));
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("ZONE_TEMPS", json!([1.0, 2.0, 3.0]), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        // No element moves ≥ 0.5 ⇒ suppressed.
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("ZONE_TEMPS", json!([1.1, 2.1, 3.1]), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            0
        );
        // The 2nd element moves ≥ 0.5 ⇒ publishes.
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("ZONE_TEMPS", json!([1.1, 2.7, 3.1]), Quality::Good)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_bad_read_always_passes_the_gate_and_is_not_swallowed() {
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        // Two consecutive identical BAD reads: both publish (a failure is information), none suppressed.
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", Value::Null, Quality::Bad)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", Value::Null, Quality::Bad)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(h.samples_bad.load(Ordering::Relaxed), 2);
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_uncertain_reading_is_tallied_and_always_passes_the_gate() {
        // A non-finite-after-scale value comes back UNCERTAIN (§5.4): counted in samplesUncertain,
        // neither GOOD nor BAD, and it always publishes (silence would hide it).
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", Value::Null, Quality::Uncertain)],
                now,
                TS,
                &h
            )
            .len(),
            1,
        );
        assert_eq!(
            process_group(
                &mut e,
                g,
                PublishMode::OnChange,
                0,
                &[reading("LINE_SPEED", Value::Null, Quality::Uncertain)],
                now,
                TS,
                &h
            )
            .len(),
            1
        );
        assert_eq!(h.samples_uncertain.load(Ordering::Relaxed), 2);
        assert_eq!(h.samples_good.load(Ordering::Relaxed), 0);
        assert_eq!(h.samples_bad.load(Ordering::Relaxed), 0);
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn batch_window_buffers_reads_then_flushes_one_update() {
        let d = one_signal_device(json!({ "type": "none" }), "always");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);

        // batchMs=100: two reads buffer (no immediate publish).
        assert!(process_group(
            &mut e,
            g,
            PublishMode::Always,
            100,
            &[reading("LINE_SPEED", json!(10.0), Quality::Good)],
            t0,
            TS,
            &h
        )
        .is_empty());
        assert!(process_group(
            &mut e,
            g,
            PublishMode::Always,
            100,
            &[reading("LINE_SPEED", json!(11.0), Quality::Good)],
            t0 + Duration::from_millis(40),
            TS,
            &h
        )
        .is_empty());
        // Not due at t0+50.
        assert!(e.take_due(100, t0 + Duration::from_millis(50)).is_empty());
        // Due at t0+100: both samples ride one update, in read order, each with an explicit serverTs.
        let flush = e.take_due(100, t0 + Duration::from_millis(100));
        assert_eq!(flush.len(), 1);
        assert_eq!(flush[0].samples.len(), 2);
        assert_eq!(flush[0].samples[0].value, Some(json!(10.0)));
        assert_eq!(
            flush[0].samples[0].server_ts.as_deref(),
            Some(TS),
            "batched samples carry the explicit capture-time serverTs"
        );
        assert!(
            flush[0].samples[0].source_ts.is_none(),
            "sourceTs is never emitted"
        );
    }

    /// D-EIP-32 intra-batch dedup: with a poll interval shorter than `batchMs`, an unchanged
    /// reading must NOT enqueue a second sample into the open window. The value is already the
    /// *pending* half of the baseline pair, so the gate suppresses it even though nothing has been
    /// published yet — a "commit only on publish" model without the pending half would double it.
    #[test]
    fn an_unchanged_reading_inside_an_open_batch_window_enqueues_one_sample_only() {
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);
        let poll = |e: &mut Engine, at: Instant, v: f64, h: &Health| {
            process_group(
                e,
                g,
                PublishMode::OnChange,
                200,
                &[reading("LINE_SPEED", json!(v), Quality::Good)],
                at,
                TS,
                h,
            )
            .len()
        };

        // Three 50 ms polls of the SAME value inside one 200 ms window.
        assert_eq!(poll(&mut e, t0, 10.0, &h), 0, "buffered, not published yet");
        assert_eq!(poll(&mut e, t0 + Duration::from_millis(50), 10.0, &h), 0);
        assert_eq!(poll(&mut e, t0 + Duration::from_millis(100), 10.0, &h), 0);
        assert_eq!(
            h.samples_suppressed.load(Ordering::Relaxed),
            2,
            "the two unchanged repeats are suppressed against the pending value"
        );

        let flush = e.take_due(200, t0 + Duration::from_millis(200));
        assert_eq!(flush.len(), 1);
        assert_eq!(
            flush[0].samples.len(),
            1,
            "one sample rode the window, not three copies of the same value"
        );

        // A genuinely changed value inside a window still enqueues, and BOTH samples ride the flush.
        assert_eq!(poll(&mut e, t0 + Duration::from_millis(250), 11.0, &h), 0);
        assert_eq!(poll(&mut e, t0 + Duration::from_millis(300), 12.0, &h), 0);
        let flush = e.take_due(200, t0 + Duration::from_millis(450));
        assert_eq!(
            flush[0].samples.len(),
            2,
            "a newer, different value replaces the pending one — both samples stay in the batch"
        );
    }

    /// D-EIP-32 leaves the quality semantics alone: BAD/UNCERTAIN readings pass the gate exactly as
    /// before — against a committed baseline, against an in-flight pending one, and repeatedly —
    /// and they never become a baseline themselves, so the GOOD value they interrupt is unaffected.
    #[test]
    fn quality_transitions_still_bypass_the_gate_with_a_value_in_flight() {
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);
        let gate = |e: &mut Engine, at: Instant, v: Value, q: Quality| {
            process_group(
                e,
                g,
                PublishMode::OnChange,
                200,
                &[reading("LINE_SPEED", v, q)],
                at,
                TS,
                &h,
            )
            .len()
        };

        // GOOD 10 is buffered (pending). BAD and UNCERTAIN both still pass, twice over.
        assert_eq!(gate(&mut e, t0, json!(10.0), Quality::Good), 0);
        assert_eq!(gate(&mut e, t0, Value::Null, Quality::Bad), 0);
        assert_eq!(gate(&mut e, t0, Value::Null, Quality::Bad), 0);
        assert_eq!(gate(&mut e, t0, json!(10.0), Quality::Uncertain), 0);
        // The unchanged GOOD repeat is still suppressed against the pending value.
        assert_eq!(gate(&mut e, t0, json!(10.0), Quality::Good), 0);

        let flush = e.take_due(200, t0 + Duration::from_millis(200));
        assert_eq!(
            flush[0].samples.len(),
            4,
            "one GOOD + two BAD + one UNCERTAIN rode the window; only the GOOD repeat was gated"
        );
        assert_eq!(h.samples_bad.load(Ordering::Relaxed), 2);
        assert_eq!(h.samples_uncertain.load(Ordering::Relaxed), 1);
        assert_eq!(
            h.samples_suppressed.load(Ordering::Relaxed),
            1,
            "exactly the unchanged GOOD repeat — no non-GOOD sample was ever suppressed"
        );

        // The non-GOOD samples left the baseline alone: after the flush is confirmed, 10.0 is the
        // committed value and repeats of it suppress.
        e.settle("LINE_SPEED", true);
        assert_eq!(
            gate(
                &mut e,
                t0 + Duration::from_secs(1),
                json!(10.0),
                Quality::Good
            ),
            0
        );
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 2);
        assert!(
            e.take_due(200, t0 + Duration::from_secs(5)).is_empty(),
            "nothing was enqueued, so no window reopened"
        );
    }

    /// Four-slot timestamp model (edgecommons/edgecommons#79): serverTs is the CAPTURE time — the
    /// read-completion stamp the driver injected — not the publish time. Simulate batching latency
    /// by flushing the window long after the reads and prove every sample (GOOD and BAD alike)
    /// still carries the read-time stamp, which can never equal a stamp minted at flush time.
    #[test]
    fn a_delayed_batch_flush_carries_the_read_time_server_ts_not_publish_time() {
        let d = one_signal_device(json!({ "type": "none" }), "always");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);

        // Two reads buffer into a 100ms batch window, each stamped with the injected read-time TS.
        assert!(process_group(
            &mut e,
            g,
            PublishMode::Always,
            100,
            &[reading("LINE_SPEED", json!(10.0), Quality::Good)],
            t0,
            TS,
            &h
        )
        .is_empty());
        assert!(process_group(
            &mut e,
            g,
            PublishMode::Always,
            100,
            &[reading("LINE_SPEED", Value::Null, Quality::Bad)],
            t0 + Duration::from_millis(40),
            TS,
            &h
        )
        .is_empty());
        // The publish happens a long simulated batching latency later.
        let publish_time_stamp = publish::now_iso();
        let flush = e.take_due(100, t0 + Duration::from_secs(30));
        assert_eq!(flush.len(), 1);
        assert_eq!(flush[0].samples.len(), 2);
        for s in &flush[0].samples {
            assert_eq!(
                s.server_ts.as_deref(),
                Some(TS),
                "the read-time capture stamp survives the delay"
            );
            assert_ne!(
                s.server_ts.as_deref(),
                Some(publish_time_stamp.as_str()),
                "not re-stamped at publish time"
            );
        }
    }

    #[test]
    fn stale_accounting_counts_aged_and_never_read_signals() {
        let d = dev(json!({
            "id": "p", "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" },
                { "name": "b", "tagPath": "B", "type": "real" }
            ] } ]
        }));
        let g = &d.poll_groups[0];
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);
        let ids = || d.signals().map(|s| s.tag_path.as_str());

        // A read GOOD at t0; B never read.
        process_group(
            &mut e,
            g,
            PublishMode::Always,
            0,
            &[reading("A", json!(1.0), Quality::Good)],
            t0,
            TS,
            &h,
        );
        assert_eq!(
            e.count_stale(ids(), 60, t0 + Duration::from_secs(30)),
            0,
            "both within the window"
        );
        assert_eq!(
            e.count_stale(ids(), 60, t0 + Duration::from_secs(70)),
            2,
            "A aged out, B never read"
        );

        // Refresh A at t0+70: only B remains stale.
        process_group(
            &mut e,
            g,
            PublishMode::Always,
            0,
            &[reading("A", json!(2.0), Quality::Good)],
            t0 + Duration::from_secs(70),
            TS,
            &h,
        );
        assert_eq!(
            e.count_stale(ids(), 60, t0 + Duration::from_secs(80)),
            1,
            "A fresh again, B still stale"
        );
    }

    #[test]
    fn overrun_is_counted_when_a_cycle_runs_longer_than_its_interval() {
        let h = Health::default();
        record_cycle(Duration::from_millis(600), Duration::from_millis(500), &h);
        record_cycle(Duration::from_millis(100), Duration::from_millis(500), &h);
        assert_eq!(h.poll_cycles.load(Ordering::Relaxed), 2);
        assert_eq!(h.overruns.load(Ordering::Relaxed), 1);
    }
}
