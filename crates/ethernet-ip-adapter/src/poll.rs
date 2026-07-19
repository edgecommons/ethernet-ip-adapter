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
// publish select-loop (`poll_until_disconnected`) and the
// `repoll` / publish glue live in the excluded live-infra seam [`crate::poll_driver`]; the pure
// gating/counting/overrun logic below is what the unit tests drive.

/// Gate + count + batch one group's readings (§4.4, §6.2). Returns the samples to publish **now**
/// (batchMs == 0); anything buffered flushes later via [`Engine::take_due`]. Bumps the S5 counters on
/// `health`.
pub(crate) fn process_group(
    engine: &mut Engine,
    group: &PollGroup,
    mode: PublishMode,
    batch_ms: u64,
    readings: &[Reading],
    now: Instant,
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

        if !publish::should_publish(
            st.baseline.as_ref(),
            &reading.value,
            reading.quality,
            mode,
            &spec.deadband,
        ) {
            health.samples_suppressed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if good {
            if mode == PublishMode::OnChange {
                health.samples_changed.fetch_add(1, Ordering::Relaxed);
            }
            // The onChange baseline is the last *published* value.
            st.baseline = Some(reading.value.clone());
        }

        // Batched samples carry an explicit serverTs (preserve read times); the immediate/newest one
        // leaves it to the facade default (§6.2).
        let server_ts = (batch_ms > 0).then(publish::now_iso);
        let sample = publish::sample_of(
            reading.value.clone(),
            reading.quality,
            reading.quality_raw.as_deref(),
            server_ts,
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
                if quality == Quality::Good { "0x00" } else { "0x04 path segment error" }.to_string(),
            ),
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
            published += process_group(&mut engine, group, PublishMode::OnChange, 0, &r, Instant::now(), &health).len();
        }
        assert_eq!(published, 2, "fewer publishes than polls: the within-band read is suppressed");
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
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(100.0), Quality::Good)], now, &h).len(), 1);
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(100.9), Quality::Good)], now, &h).len(), 0, "0.9 < 1% suppressed");
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(101.5), Quality::Good)], now, &h).len(), 1, "1.5 ≥ 1% publishes");

        // none: any change republishes.
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let mut e = Engine::new(Instant::now());
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(1.0), Quality::Good)], now, &h).len(), 1);
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(1.0), Quality::Good)], now, &h).len(), 0, "no change");
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", json!(1.1), Quality::Good)], now, &h).len(), 1);
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
            assert_eq!(process_group(&mut e, g, PublishMode::Always, 0, &[reading("LINE_SPEED", json!(5.0), Quality::Good)], now, &h).len(), 1);
        }
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 0);

        // non-numeric (a dint used as a flag, string values here): any change.
        let d = dev(json!({
            "id": "p", "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [ { "name": "state", "tagPath": "STATE", "type": "dint" } ] } ]
        }));
        let g = &d.poll_groups[0];
        let mut e = Engine::new(Instant::now());
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("STATE", json!("RUN"), Quality::Good)], now, &h).len(), 1);
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("STATE", json!("RUN"), Quality::Good)], now, &h).len(), 0);
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("STATE", json!("STOP"), Quality::Good)], now, &h).len(), 1);
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
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("ZONE_TEMPS", json!([1.0, 2.0, 3.0]), Quality::Good)], now, &h).len(), 1);
        // No element moves ≥ 0.5 ⇒ suppressed.
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("ZONE_TEMPS", json!([1.1, 2.1, 3.1]), Quality::Good)], now, &h).len(), 0);
        // The 2nd element moves ≥ 0.5 ⇒ publishes.
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("ZONE_TEMPS", json!([1.1, 2.7, 3.1]), Quality::Good)], now, &h).len(), 1);
    }

    #[test]
    fn a_bad_read_always_passes_the_gate_and_is_not_swallowed() {
        let d = one_signal_device(json!({ "type": "none" }), "onChange");
        let g = &d.poll_groups[0];
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let now = Instant::now();
        // Two consecutive identical BAD reads: both publish (a failure is information), none suppressed.
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", Value::Null, Quality::Bad)], now, &h).len(), 1);
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0, &[reading("LINE_SPEED", Value::Null, Quality::Bad)], now, &h).len(), 1);
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
            process_group(&mut e, g, PublishMode::OnChange, 0,
                &[reading("LINE_SPEED", Value::Null, Quality::Uncertain)], now, &h).len(),
            1,
        );
        assert_eq!(process_group(&mut e, g, PublishMode::OnChange, 0,
            &[reading("LINE_SPEED", Value::Null, Quality::Uncertain)], now, &h).len(), 1);
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
        assert!(process_group(&mut e, g, PublishMode::Always, 100, &[reading("LINE_SPEED", json!(10.0), Quality::Good)], t0, &h).is_empty());
        assert!(process_group(&mut e, g, PublishMode::Always, 100, &[reading("LINE_SPEED", json!(11.0), Quality::Good)], t0 + Duration::from_millis(40), &h).is_empty());
        // Not due at t0+50.
        assert!(e.take_due(100, t0 + Duration::from_millis(50)).is_empty());
        // Due at t0+100: both samples ride one update, in read order, each with an explicit serverTs.
        let flush = e.take_due(100, t0 + Duration::from_millis(100));
        assert_eq!(flush.len(), 1);
        assert_eq!(flush[0].samples.len(), 2);
        assert_eq!(flush[0].samples[0].value, Some(json!(10.0)));
        assert!(flush[0].samples[0].server_ts.is_some(), "batched samples carry an explicit serverTs");
        assert!(flush[0].samples[0].source_ts.is_none(), "sourceTs is never emitted");
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
        process_group(&mut e, g, PublishMode::Always, 0, &[reading("A", json!(1.0), Quality::Good)], t0, &h);
        assert_eq!(e.count_stale(ids(), 60, t0 + Duration::from_secs(30)), 0, "both within the window");
        assert_eq!(e.count_stale(ids(), 60, t0 + Duration::from_secs(70)), 2, "A aged out, B never read");

        // Refresh A at t0+70: only B remains stale.
        process_group(&mut e, g, PublishMode::Always, 0, &[reading("A", json!(2.0), Quality::Good)], t0 + Duration::from_secs(70), &h);
        assert_eq!(e.count_stale(ids(), 60, t0 + Duration::from_secs(80)), 1, "A fresh again, B still stale");
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
