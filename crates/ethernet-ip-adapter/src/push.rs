//! # The push engine (§3.2, §4.6, §6) — consumed class-1 I/O → gated publishes
//!
//! One task per push-mode device drives [`consume_push`]: it consumes the [`IoUpdate`] stream a
//! [`PushSession`] produces (the device's input assembly at the negotiated RPI), applies the
//! **`sampleMs` floor** and the shared deadband / `publishMode` gate per field, batches, and publishes
//! through the mode-agnostic [`publish`] path. `IoUpdate::Up` records the negotiated APIs and clears
//! the unreachable alarm; `IoUpdate::Lost` breaks into the supervisor's backoff ladder.
//!
//! **Pause is not here** (that is slice S6): this engine always publishes what survives the gate. The
//! backend already applies the run/idle → quality mapping (Idle ⇒ UNCERTAIN, keeping the value), so an
//! Idle sample still publishes — a failure/idle is information (§5.4, §6.2). Consumption is
//! latest-wins in the backend translator; here each delivered frame is gated independently.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, EventsFacade, Sample, Severity};
use serde_json::json;

use crate::app::{Health, LinkState};
use crate::config::{DeadbandSpec, DeviceConfig, GlobalConfig, IoFieldSpec, PublishMode};
use crate::device::{IoUpdate, PushSession, Quality, Reading};
use crate::metrics::DeviceMetrics;
use crate::publish::{self, Engine, Publish};

/// Consume one push session's [`IoUpdate`] stream until the link is lost (§3.2). Gates + batches each
/// consumed frame's fields and publishes what survives; returns on `Lost` / end-of-stream so the
/// supervisor reconnects.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn consume_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    session: &mut dyn PushSession,
    data: &DataFacade,
    events: &EventsFacade,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    adapter: &str,
) {
    let Some(io) = cfg.io.as_ref() else {
        tracing::error!(instance = %cfg.id, "push device has no io block");
        return;
    };
    let assembly = io.assemblies.input;
    let sample_ms = io.input.sample_ms;
    let batch_ms = cfg.effective_batch_ms(global);
    // Push has no poll groups; publishMode resolves device ▸ global ▸ built-in (onChange).
    let mode = cfg
        .defaults
        .publish_mode
        .or(global.defaults.publish_mode)
        .unwrap_or(PublishMode::OnChange);
    // The single `publishMode` dimension value this push device emits under (§8.5).
    let mode_token = mode.as_str();
    let stale_secs = global.health_thresholds.stale_signal_secs;
    let metrics_interval = Duration::from_secs(global.metrics_interval_secs.max(1));

    // Field lookups by stable id: the address builder and the per-field deadband.
    let fields: HashMap<String, &IoFieldSpec> = io
        .input
        .signals
        .iter()
        .map(|f| (f.signal_id(assembly), f))
        .collect();
    let deadbands: HashMap<String, DeadbandSpec> = io
        .input
        .signals
        .iter()
        .map(|f| (f.signal_id(assembly), f.deadband.clone().unwrap_or_default()))
        .collect();

    let start = Instant::now();
    let mut engine = Engine::new(start);
    let mut since_health = start;

    loop {
        // Frames arrive on the channel; we also wake for the next batch close and the health tick.
        let mut wake = since_health + metrics_interval;
        if let Some(bd) = engine.next_batch_deadline(batch_ms) {
            wake = wake.min(bd);
        }
        let wait = wake.saturating_duration_since(Instant::now());

        tokio::select! {
            biased;

            update = session.updates().recv() => {
                match update {
                    Some(IoUpdate::Up { o2t_api_ms, t2o_api_ms }) => {
                        health.set_link(LinkState::Online);
                        // The class-1 connection is open (§8.8 ioConnectionState); a transition ⇒
                        // flush southbound_health + connection + io immediately (§8.7).
                        dm.on_io_up();
                        dm.emit_now().await;
                        let _ = events
                            .emit(
                                Severity::Info,
                                "device-connected",
                                Some(format!("class-1 connection up to {}", cfg.connection.endpoint)),
                                Some(json!({
                                    "instance": cfg.id, "adapter": adapter,
                                    "o2tApiMs": o2t_api_ms, "t2oApiMs": t2o_api_ms
                                })),
                            )
                            .await;
                        let _ = events
                            .clear_alarm(Severity::Critical, "device-unreachable", None)
                            .await;
                    }
                    Some(IoUpdate::Data { readings, sequence, run_mode, received_at }) => {
                        health.frames_consumed.fetch_add(1, Ordering::Relaxed);
                        // §8.8: count the frame, infer sequence gaps, record the lived inter-arrival + run/idle.
                        dm.record_frame_consumed(sequence, received_at, run_mode);
                        tracing::debug!(
                            instance = %cfg.id, sequence, run_mode, fields = readings.len(),
                            "push frame received"
                        );
                        let now = Instant::now();
                        for p in process_frame(&mut engine, &readings, &deadbands, mode, sample_ms, batch_ms, now, health) {
                            publish_field(data, cfg, adapter, &fields, assembly, &p.signal_id, p.samples, health, dm, mode_token, false).await;
                        }
                    }
                    Some(IoUpdate::Lost { error }) => {
                        tracing::warn!(instance = %cfg.id, error = %error, "class-1 connection lost; reconnecting");
                        health.read_errors.fetch_add(1, Ordering::Relaxed);
                        // The watchdog expiry / peer close (§8.8 ioTimeouts; ioConnectionState → 0).
                        dm.on_io_lost();
                        return;
                    }
                    None => {
                        tracing::warn!(instance = %cfg.id, "push session ended; reconnecting");
                        return;
                    }
                }
            }

            _ = tokio::time::sleep(wait) => {}
        }

        let now = Instant::now();
        for p in engine.take_due(batch_ms, now) {
            // A coalescing-window flush (§8.5 batchFlushes/batchSize).
            publish_field(data, cfg, adapter, &fields, assembly, &p.signal_id, p.samples, health, dm, mode_token, true).await;
        }
        if now.saturating_duration_since(since_health) >= metrics_interval {
            let stale = engine.count_stale(fields.keys().map(String::as_str), stale_secs, now);
            health.stale_signals.store(stale, Ordering::Relaxed);
            // The full §8 family set for this push device (§8.7).
            dm.emit_periodic().await;
            since_health = now;
        }
    }
}

/// Gate + count + batch one consumed frame's readings (§4.6, §6.2). The **`sampleMs` floor** throttles
/// GOOD samples to at most one per window per field; a non-GOOD sample (BAD / IDLE) bypasses both the
/// floor and the deadband — a failure/idle is information. Returns the samples to publish now
/// (batchMs == 0); buffered ones flush via [`Engine::take_due`].
#[allow(clippy::too_many_arguments)]
fn process_frame(
    engine: &mut Engine,
    readings: &[Reading],
    deadbands: &HashMap<String, DeadbandSpec>,
    mode: PublishMode,
    sample_ms: u64,
    batch_ms: u64,
    now: Instant,
    health: &Health,
) -> Vec<Publish> {
    let default_db = DeadbandSpec::default();
    let mut out = Vec::new();
    for reading in readings {
        let deadband = deadbands.get(&reading.signal_id).unwrap_or(&default_db);
        let good = reading.quality == Quality::Good;
        let st = engine.state.entry(reading.signal_id.clone()).or_default();

        match reading.quality {
            Quality::Good => {
                health.samples_good.fetch_add(1, Ordering::Relaxed);
                st.last_good = Some(now);
            }
            // A BAD frame-field is a failure; an IDLE (UNCERTAIN) field is neither GOOD nor BAD
            // (values present, process not running) — counted in neither tally.
            Quality::Bad => {
                health.samples_bad.fetch_add(1, Ordering::Relaxed);
            }
            Quality::Uncertain => {}
        }

        // The sampleMs floor: throttle GOOD samples only (a BAD/IDLE sample always publishes).
        if good && sample_ms > 0 {
            if let Some(last) = st.last_eligible {
                if now.saturating_duration_since(last) < Duration::from_millis(sample_ms) {
                    health.samples_suppressed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }

        if !publish::should_publish(st.baseline.as_ref(), &reading.value, reading.quality, mode, deadband) {
            health.samples_suppressed.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        st.last_eligible = Some(now);
        if good {
            if mode == PublishMode::OnChange {
                health.samples_changed.fetch_add(1, Ordering::Relaxed);
            }
            st.baseline = Some(reading.value.clone());
        }

        let server_ts = (batch_ms > 0).then(publish::now_iso);
        let sample = publish::sample_of(
            reading.value.clone(),
            reading.quality,
            reading.quality_raw.as_deref(),
            server_ts,
        );
        if let Some(samples) = st.batcher.add(sample, now, batch_ms) {
            out.push(Publish {
                signal_id: reading.signal_id.clone(),
                samples,
            });
        }
    }
    out
}

/// Resolve a stable id to its input field and publish its samples (§6.1) — the push analog of the
/// poll `publish_by_id`, using the field's `a<inst>/<off>/<type>` id + assembly address (§5.2).
#[allow(clippy::too_many_arguments)]
async fn publish_field(
    data: &DataFacade,
    cfg: &DeviceConfig,
    adapter: &str,
    fields: &HashMap<String, &IoFieldSpec>,
    assembly: u16,
    signal_id: &str,
    samples: Vec<Sample>,
    health: &Health,
    dm: &DeviceMetrics,
    publish_mode: &'static str,
    from_batch: bool,
) {
    let Some(field) = fields.get(signal_id) else {
        return;
    };
    let n = samples.len() as u64;
    let (res, latency) = publish::publish(
        data,
        &field.signal_id(assembly),
        &field.name,
        field.address_json(assembly, &cfg.connection),
        &publish::DeviceParts {
            adapter,
            instance: &cfg.id,
            endpoint: &cfg.connection.endpoint,
        },
        samples,
    )
    .await;
    let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    match res {
        Ok(()) => {
            health.signals_published.fetch_add(n, Ordering::Relaxed);
            health.publish_latency_ms.store(latency_ms, Ordering::Relaxed);
            dm.record_publish(publish_mode, n, from_batch, latency_ms, true);
        }
        Err(e) => {
            tracing::warn!(instance = %cfg.id, signal_id = %field.signal_id(assembly), error = %e, "publish failed");
            dm.record_publish(publish_mode, n, from_batch, latency_ms, false);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Push-engine gating — scripted [`Reading`]s + a mock [`PushSession`], no socket / no OpENer
    //! (§12.3).
    use super::*;
    use crate::config::IoConfig;
    use crate::device::{DeviceError, Result as DevResult};
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use tokio::sync::mpsc;

    fn reading(id: &str, value: Value, quality: Quality) -> Reading {
        let raw = match quality {
            Quality::Good => "0x00",
            Quality::Uncertain => "IDLE",
            Quality::Bad => "0x04 path segment error",
        };
        Reading {
            signal_id: id.to_string(),
            name: Some(id.to_string()),
            value,
            quality,
            quality_raw: Some(raw.to_string()),
        }
    }

    fn deadbands(pairs: &[(&str, DeadbandSpec)]) -> HashMap<String, DeadbandSpec> {
        pairs.iter().map(|(id, d)| ((*id).to_string(), d.clone())).collect()
    }

    fn none_db() -> DeadbandSpec {
        DeadbandSpec::default()
    }

    /// A mock [`PushSession`] that replays a preloaded [`IoUpdate`] script off an mpsc channel.
    struct ScriptedPush {
        rx: mpsc::Receiver<IoUpdate>,
    }

    impl ScriptedPush {
        fn new(script: Vec<IoUpdate>) -> Self {
            let (tx, rx) = mpsc::channel(16);
            for u in script {
                tx.try_send(u).expect("script fits the channel");
            }
            Self { rx }
        }
    }

    #[async_trait]
    impl PushSession for ScriptedPush {
        fn updates(&mut self) -> &mut mpsc::Receiver<IoUpdate> {
            &mut self.rx
        }
        async fn set_output(&mut self, _f: &IoFieldSpec, _v: &Value) -> DevResult<()> {
            Err(DeviceError::Unsupported("scripted"))
        }
        async fn close(&mut self) {}
    }

    #[test]
    fn sample_ms_floor_throttles_the_publish_rate() {
        // always mode ⇒ only the sampleMs floor gates.
        let dbs = deadbands(&[("a100/0/udint", none_db())]);
        let h = Health::default();
        let t0 = Instant::now();
        let mut e = Engine::new(t0);

        let go = |e: &mut Engine, now: Instant, v: i64, h: &Health| {
            process_frame(e, &[reading("a100/0/udint", json!(v), Quality::Good)], &dbs, PublishMode::Always, 100, 0, now, h).len()
        };
        assert_eq!(go(&mut e, t0, 1, &h), 1, "first frame publishes");
        assert_eq!(go(&mut e, t0 + Duration::from_millis(50), 2, &h), 0, "within 100ms ⇒ throttled");
        assert_eq!(go(&mut e, t0 + Duration::from_millis(120), 3, &h), 1, "past the floor ⇒ publishes");
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn deadband_gates_a_push_field_in_onchange() {
        let dbs = deadbands(&[("a100/4/real", DeadbandSpec { kind: crate::config::DeadbandKind::Absolute, value: 0.5 })]);
        let h = Health::default();
        let now = Instant::now();
        let mut e = Engine::new(now);
        let go = |e: &mut Engine, v: f64, h: &Health| {
            process_frame(e, &[reading("a100/4/real", json!(v), Quality::Good)], &dbs, PublishMode::OnChange, 0, 0, now, h).len()
        };
        assert_eq!(go(&mut e, 10.0, &h), 1, "first publishes");
        assert_eq!(go(&mut e, 10.2, &h), 0, "0.2 < 0.5 suppressed");
        assert_eq!(go(&mut e, 11.0, &h), 1, "0.8 ≥ 0.5 publishes");
    }

    #[test]
    fn a_bad_or_idle_sample_still_publishes_even_unchanged() {
        let dbs = deadbands(&[("a100/0/bool.1", none_db())]);
        let h = Health::default();
        let now = Instant::now();
        let mut e = Engine::new(now);
        // IDLE (UNCERTAIN) frame: publishes despite onChange + a sampleMs floor + no value change.
        assert_eq!(
            process_frame(&mut e, &[reading("a100/0/bool.1", json!(true), Quality::Uncertain)], &dbs, PublishMode::OnChange, 500, 0, now, &h).len(),
            1
        );
        assert_eq!(
            process_frame(&mut e, &[reading("a100/0/bool.1", json!(true), Quality::Uncertain)], &dbs, PublishMode::OnChange, 500, 0, now, &h).len(),
            1
        );
        // A BAD frame publishes too.
        assert_eq!(
            process_frame(&mut e, &[reading("a100/0/bool.1", Value::Null, Quality::Bad)], &dbs, PublishMode::OnChange, 500, 0, now, &h).len(),
            1
        );
        assert_eq!(h.samples_bad.load(Ordering::Relaxed), 1);
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn consumes_scripted_updates_from_a_mock_push_session() {
        // Feed Up → Data → Data → Lost through the mock session; assert the engine gates the frames
        // and the loop terminates on Lost.
        let dbs = deadbands(&[("a100/0/udint", none_db())]);
        let mut session = ScriptedPush::new(vec![
            IoUpdate::Up { o2t_api_ms: 100, t2o_api_ms: 100 },
            IoUpdate::Data {
                readings: vec![reading("a100/0/udint", json!(1), Quality::Good)],
                sequence: 1,
                run_mode: true,
                received_at: Instant::now(),
            },
            IoUpdate::Data {
                readings: vec![reading("a100/0/udint", json!(1), Quality::Good)], // unchanged ⇒ suppressed
                sequence: 2,
                run_mode: true,
                received_at: Instant::now(),
            },
            IoUpdate::Lost { error: DeviceError::Transient(anyhow::anyhow!("watchdog")) },
        ]);
        let h = Health::default();
        let mut e = Engine::new(Instant::now());
        let mut published = 0usize;
        let mut up_seen = false;
        loop {
            match session.updates().recv().await {
                Some(IoUpdate::Up { .. }) => up_seen = true,
                Some(IoUpdate::Data { readings, .. }) => {
                    published += process_frame(&mut e, &readings, &dbs, PublishMode::OnChange, 0, 0, Instant::now(), &h).len();
                }
                Some(IoUpdate::Lost { .. }) | None => break,
            }
        }
        assert!(up_seen, "the Up transition was delivered");
        assert_eq!(published, 1, "the first frame published; the unchanged second was suppressed");
        assert_eq!(h.samples_good.load(Ordering::Relaxed), 2);
        assert_eq!(h.samples_suppressed.load(Ordering::Relaxed), 1);
    }

    /// The §4.6 worked push config, used by the wire-shape test.
    fn push_io() -> IoConfig {
        serde_json::from_value(json!({
            "rpiMs": 100,
            "assemblies": { "config": 151, "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 32, "sampleMs": 500,
                "signals": [
                    { "name": "motor-run", "offset": 0, "type": "bool", "bit": 0 },
                    { "name": "line-counts", "offset": 4, "type": "udint", "arrayCount": 7 }
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn wire_shape_of_both_id_forms() {
        use crate::config::DeviceConfig;
        use edgecommons::prelude::Quality as FQ;

        // --- POLL id form: signal.id = tagPath, channel = name, address = {tagPath,type,arrayCount,slot} ---
        let poll = DeviceConfig::from_value(&json!({
            "id": "filler-plc",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [ { "signals": [
                { "name": "zone-temps", "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 8 }
            ] } ]
        }))
        .unwrap();
        let spec = poll.signals().next().unwrap();
        let sample = publish::sample_of(json!([1.0, 2.0]), Quality::Good, Some("0x00"), Some("2026-07-18T12:00:00Z".into()));
        let update = publish::build_update(
            &spec.tag_path,
            &spec.name,
            spec.address_json(&poll.connection),
            &publish::DeviceParts { adapter: "ethernet-ip", instance: &poll.id, endpoint: &poll.connection.endpoint },
            vec![sample],
        );
        assert_eq!(update.signal_id.as_deref(), Some("ZONE_TEMPS"), "signal.id is the verbatim tagPath");
        assert_eq!(update.signal_name.as_deref(), Some("zone-temps"));
        assert_eq!(update.effective_signal_path(), Some("zone-temps"), "channel = name, not the id");
        assert_eq!(
            update.signal_address,
            Some(json!({ "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 8, "slot": 0 }))
        );
        assert_eq!(update.device, Some(json!({ "adapter": "ethernet-ip", "instance": "filler-plc", "endpoint": "127.0.0.1:44818" })));
        let s = &update.samples[0];
        assert_eq!(s.value, Some(json!([1.0, 2.0])));
        assert_eq!(s.quality, Some(FQ::Good));
        assert_eq!(s.quality_raw.as_deref(), Some("0x00"));
        assert!(s.server_ts.is_some(), "serverTs present");
        assert!(s.source_ts.is_none(), "sourceTs never emitted (D-EIP-11)");

        // --- PUSH id form: signal.id = a<inst>/<off>/<type>[.<bit>], address = {assembly,offset,type,bit,...} ---
        let conn = poll.connection.clone();
        let io = push_io();
        let assembly = io.assemblies.input;
        let field = &io.input.signals[0]; // motor-run, bool bit 0
        let bad = publish::sample_of(Value::Null, Quality::Bad, Some("0x04 path segment error"), None);
        let update = publish::build_update(
            &field.signal_id(assembly),
            &field.name,
            field.address_json(assembly, &conn),
            &publish::DeviceParts { adapter: "ethernet-ip", instance: "palletizer-io", endpoint: "opener:44818" },
            vec![bad],
        );
        assert_eq!(update.signal_id.as_deref(), Some("a100/0/bool.0"), "push id form (D-EIP-18)");
        assert_eq!(update.signal_name.as_deref(), Some("motor-run"));
        assert_eq!(
            update.signal_address,
            Some(json!({ "assembly": 100, "offset": 0, "type": "bool", "bit": 0, "slot": 0 }))
        );
        let arr_field = &io.input.signals[1]; // line-counts, udint[7] at offset 4
        assert_eq!(arr_field.signal_id(assembly), "a100/4/udint");
        assert_eq!(
            arr_field.address_json(assembly, &conn),
            json!({ "assembly": 100, "offset": 4, "type": "udint", "arrayCount": 7, "slot": 0 })
        );
        let s = &update.samples[0];
        assert_eq!(s.quality, Some(FQ::Bad));
        assert_eq!(s.value, Some(Value::Null), "a BAD sample's value is JSON null");
        assert!(s.source_ts.is_none());
    }
}
