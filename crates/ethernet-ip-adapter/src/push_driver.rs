//! # The push loop driver (§3.2, §4.6, §6) — the class-1 consume → gate → publish composition
//!
//! [`consume_push`] consumes one push-mode device's [`crate::device::IoUpdate`] stream (the input
//! assembly at the negotiated RPI), services the `sb/*` control channel in line with it, and publishes
//! what survives the gate. It is the push mode's *composition logic*, not I/O glue: the
//! consumption-continues-while-paused rule (D-EIP-14), the resume rebase, the loss bookkeeping on both
//! the `Lost` and the stream-ended paths, the `io_stats` fold with its one-shot redirect event, and
//! every control verb's contract are decided here, over three injected seams — [`PushSession`] (the
//! class-1 stream), [`crate::publish::Publisher`] (the broker), and [`EventSink`]. The pure decision it
//! composes — the `sampleMs` floor + deadband gating + batching ([`crate::push::process_frame`]) —
//! lives in its own module.
//!
//! The loop therefore runs under unit test against scripted seams (`#[cfg(test)] mod tests` below, on
//! a paused clock); the live OpENer suite (§11) and the deployed regression validate it against a real
//! adapter, which is conformance evidence rather than coverage evidence.
//!
//! **Clock:** as in [`crate::poll_driver`], the loop schedules on [`tokio::time::Instant`] — the
//! system clock at runtime, the simulated clock under `#[tokio::test(start_paused = true)]`. Frame
//! receipt instants come off the seam as `std::time::Instant` and stay that way (they are the sample
//! capture time, §5.4).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use edgecommons::prelude::{Sample, Severity};
use serde_json::json;
use tokio::time::Instant;

use crate::app::{apply_pause, DeviceControl, EventSink, Health, LinkState};
use crate::config::{DeadbandSpec, DeviceConfig, GlobalConfig, IoFieldSpec, PublishMode};
use crate::device::{IoUpdate, PushSession};
use crate::metrics::DeviceMetrics;
use crate::publish::{self, Publisher};
use crate::push::process_frame;

/// How [`consume_push`] left the consume loop (§7.5, §10.2) — the push analog of
/// [`crate::poll_driver::PollExit`].
pub(crate) enum PushExit {
    /// The class-1 link was lost (watchdog / peer close / end of stream) — reconnect.
    LinkLost,
    /// An `sb/reconnect` asked to ForwardClose + ForwardOpen now (§7.5).
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
    /// Cancellation or control-channel close (§10.3, D-EIP-27): the caller closes the session
    /// (ForwardClose + I/O socket teardown) and leaves — no reconnect, no backoff, no
    /// `device-unreachable` alarm.
    Stopped,
}

/// What woke the consume loop — returned by the `select!` so `session` is no longer borrowed by the
/// time a control message is serviced (the update branch borrows the session's update receiver).
enum Woke {
    Control(Option<DeviceControl>),
    Update(Option<IoUpdate>),
    Tick,
    /// The instance token fired — tear this instance down (§10.3).
    Cancelled,
}

/// Consume one push session's [`IoUpdate`] stream until the link is lost (§3.2). Gates + batches each
/// consumed frame's fields and publishes what survives; returns on `Lost` / end-of-stream so the
/// supervisor reconnects.
///
/// `cancel` is this instance's child of the app root token (§10.3): when it fires the loop returns
/// [`PushExit::Stopped`] and the caller's unconditional `session.close()` performs the ForwardClose
/// and releases the I/O socket.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn consume_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    session: &mut dyn PushSession,
    sink: &dyn Publisher,
    events: &dyn EventSink,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    adapter: &str,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    cancel: &tokio_util::sync::CancellationToken,
) -> PushExit {
    let Some(io) = cfg.io.as_ref() else {
        tracing::error!(instance = %cfg.id, "push device has no io block");
        return PushExit::LinkLost;
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
        .map(|f| {
            (
                f.signal_id(assembly),
                f.deadband.clone().unwrap_or_default(),
            )
        })
        .collect();

    let start = Instant::now();
    let mut engine = crate::publish::Engine::new(start.into_std());
    let mut since_health = start;
    // A pause that arrived while the link was down carries in through the shared flag (§9.2).
    let mut paused = health.paused.load(Ordering::Relaxed);

    loop {
        // Frames arrive on the channel; we also wake for the next batch close and the health tick.
        // While paused, batches don't accrue (nothing is published) and the windows open at the
        // moment of the pause were discarded (D-EIP-32), so only the health tick matters.
        let mut wake = since_health + metrics_interval;
        if !paused {
            if let Some(bd) = engine.next_batch_deadline(batch_ms) {
                wake = wake.min(Instant::from_std(bd));
            }
        }
        let wait = wake.saturating_duration_since(Instant::now());

        // Return only a plain value from each arm so `session` is free (the update arm borrows its
        // receiver) by the time a control message is serviced below.
        let woke = tokio::select! {
            biased;
            () = cancel.cancelled() => Woke::Cancelled,
            ctrl = control.recv() => Woke::Control(ctrl),
            update = session.updates().recv() => Woke::Update(update),
            _ = tokio::time::sleep(wait) => Woke::Tick,
        };

        match woke {
            // Teardown (shutdown / instance stop, §10.3): leave without a reconnect, a backoff, or
            // an unreachable alarm; the caller's `session.close()` does the ForwardClose + socket
            // teardown on the way out.
            Woke::Cancelled => {
                tracing::info!(instance = %cfg.id, "cancelled; closing the class-1 connection and stopping");
                return PushExit::Stopped;
            }
            Woke::Control(None) => {
                // The control channel closed (component shutting down) — leave cleanly. This is a
                // teardown path, not a lost link: no alarm, no reconnect (§10.3).
                tracing::info!(instance = %cfg.id, "control channel closed; stopping");
                return PushExit::Stopped;
            }
            Woke::Control(Some(ctrl)) => {
                match ctrl {
                    // The push on-demand read: answer from the last consumed frame (§7.2) — live even
                    // while paused, since consumption never stopped.
                    DeviceControl::Snapshot { reply } => {
                        let _ = reply.send(session.last_input());
                    }
                    // A push write stages an OUTPUT-assembly field into the O→T producer buffer
                    // (applied next-frame, §7.3).
                    DeviceControl::WriteOutput {
                        field,
                        value,
                        reply,
                    } => {
                        let result = session
                            .set_output(&field, &value)
                            .await
                            .map_err(|e| e.to_string());
                        if result.is_err() {
                            health.write_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = reply.send(result);
                    }
                    DeviceControl::Pause { by, reply } => {
                        let changed =
                            apply_pause(cfg, health, dm, events, true, by.as_deref()).await;
                        // Open `batchMs` windows are DISCARDED, not held (§7.4, D-EIP-32). Holding
                        // them would land a pre-pause burst AFTER the §7.4.8 resume rebase, making
                        // a stale value the last published one while the rebased current value is
                        // suppressed — a wrong last-known value downstream.
                        let dropped = engine.discard_open_batches();
                        if dropped > 0 {
                            tracing::info!(instance = %cfg.id, dropped, "paused with open batch windows; buffered samples discarded");
                        }
                        paused = true;
                        let _ = reply.send(changed);
                    }
                    DeviceControl::Resume { reply } => {
                        let changed = apply_pause(cfg, health, dm, events, false, None).await;
                        if changed {
                            // Re-base change-detection + staleness to the current snapshot so the paused
                            // span's accumulated drift is not published as one giant burst (§7.4.8).
                            if let Some(snap) = session.last_input() {
                                let pairs: Vec<(String, serde_json::Value)> = snap
                                    .readings
                                    .iter()
                                    .map(|r| (r.signal_id.clone(), r.value.clone()))
                                    .collect();
                                engine.rebase_from(&pairs, Instant::now().into_std());
                            }
                        }
                        paused = false;
                        let _ = reply.send(changed);
                    }
                    DeviceControl::Reconnect { reply } => {
                        return PushExit::Reconnect(reply);
                    }
                    // Poll-only verbs never route to a push task; answer defensively.
                    DeviceControl::ReadNow { reply, .. } => {
                        let _ =
                            reply
                                .send(Err("push instance - reads answer from the input snapshot"
                                    .to_string()));
                    }
                    DeviceControl::Write(req) => {
                        let _ = req.ack.send(Err(
                            "push instance - writes target the output assembly".to_string(),
                        ));
                    }
                    DeviceControl::Repoll { reply } => {
                        let _ =
                            reply.send(Err("push instance - data arrives cyclically".to_string()));
                    }
                    // Push browse is answered from the configured layout by the commander — it never
                    // routes here; answer defensively.
                    DeviceControl::Browse { reply, .. } => {
                        let _ = reply.send(Err(crate::app::BrowseError::Unsupported));
                    }
                }
                continue;
            }
            Woke::Update(update) => match update {
                Some(IoUpdate::Up {
                    o2t_api_ms,
                    t2o_api_ms,
                }) => {
                    health.set_link(LinkState::Online);
                    // The class-1 connection is open (§8.8 ioConnectionState); a transition ⇒
                    // flush southbound_health + connection + io immediately (§8.7).
                    dm.on_io_up(o2t_api_ms, t2o_api_ms);
                    dm.emit_now().await;
                    events
                        .emit(
                            Severity::Info,
                            "device-connected",
                            Some(format!(
                                "class-1 connection up to {}",
                                cfg.connection.endpoint
                            )),
                            Some(json!({
                                "instance": cfg.id, "adapter": adapter,
                                "o2tApiMs": o2t_api_ms, "t2oApiMs": t2o_api_ms
                            })),
                        )
                        .await;
                    events
                        .clear_alarm(Severity::Critical, "device-unreachable", None)
                        .await;
                }
                Some(IoUpdate::Data {
                    readings,
                    sequence,
                    run_mode,
                    received_at,
                }) => {
                    health.frames_consumed.fetch_add(1, Ordering::Relaxed);
                    // §8.8: count the frame, infer sequence gaps, record the lived inter-arrival + run/idle.
                    // Consumption continues while paused (the snapshot + sequence validation stay live);
                    // only PUBLISHING is gated off (§7.4).
                    dm.record_frame_consumed(sequence, received_at, run_mode);
                    tracing::debug!(
                        instance = %cfg.id, sequence, run_mode, paused, fields = readings.len(),
                        "push frame received"
                    );
                    if !paused {
                        // Capture time (four-slot timestamp model): serverTs is the frame's
                        // receipt instant, so a batchMs flush carries the receipt-time stamp.
                        let server_ts = publish::iso_at(received_at);
                        let now = Instant::now().into_std();
                        for p in process_frame(
                            &mut engine,
                            &readings,
                            &deadbands,
                            mode,
                            sample_ms,
                            batch_ms,
                            now,
                            &server_ts,
                            health,
                        ) {
                            let published = publish_field(
                                sink,
                                cfg,
                                adapter,
                                &fields,
                                assembly,
                                &p.signal_id,
                                p.samples,
                                health,
                                dm,
                                mode_token,
                                false,
                            )
                            .await;
                            // Promote the field's pending baseline only once the publish resolved;
                            // a failure drops it so the value is retried (D-EIP-32).
                            engine.settle(&p.signal_id, published);
                        }
                    }
                }
                Some(IoUpdate::Lost { error }) => {
                    tracing::warn!(instance = %cfg.id, error = %error, "class-1 connection lost; reconnecting");
                    health.read_errors.fetch_add(1, Ordering::Relaxed);
                    // The watchdog expiry / peer close (§8.8 ioTimeouts; ioConnectionState → 0).
                    dm.on_io_lost();
                    return PushExit::LinkLost;
                }
                None => {
                    // The translator's event stream ended WITHOUT a preceding `Lost` — a real loss
                    // transition that would otherwise go unrecorded. Do the same bookkeeping the
                    // `Lost` arm does; this is the only correct home for it, because synthesizing a
                    // `Lost` in the translator would double-count when one DID precede the close.
                    tracing::warn!(instance = %cfg.id, "push session ended; reconnecting");
                    health.read_errors.fetch_add(1, Ordering::Relaxed);
                    // ioConnectionState → 0, ioTimeouts, stack-counter baseline rebase (§8.8).
                    dm.on_io_lost();
                    return PushExit::LinkLost;
                }
            },
            Woke::Tick => {}
        }

        let now = Instant::now();
        if !paused {
            for p in engine.take_due(batch_ms, now.into_std()) {
                // A coalescing-window flush (§8.5 batchFlushes/batchSize).
                let published = publish_field(
                    sink,
                    cfg,
                    adapter,
                    &fields,
                    assembly,
                    &p.signal_id,
                    p.samples,
                    health,
                    dm,
                    mode_token,
                    true,
                )
                .await;
                engine.settle(&p.signal_id, published);
            }
        }
        if now.saturating_duration_since(since_health) >= metrics_interval {
            // Staleness is suspended while paused (§9.3).
            let stale = if paused {
                0
            } else {
                engine.count_stale(
                    fields.keys().map(String::as_str),
                    stale_secs,
                    now.into_std(),
                )
            };
            health.stale_signals.store(stale, Ordering::Relaxed);
            // Fold the class-1 stack's live drop/produce counters into EtherNetIpIo before the emit,
            // so framesProduced / staleFramesDropped / sizeMismatchDropped / malformedFrames /
            // produceOverruns read REAL values (§8.8, the S5-flagged gap) rather than 0.
            if let Some(stats) = session.io_stats() {
                // A newly refused O→T redirect (D-ENIP-17), reported once per ForwardOpen by the
                // covered latch in `record_io_stats`: the device asked for its outputs at an address
                // the stack refuses, so a device that requires it is not receiving them (§6.3, §8.8).
                if dm.record_io_stats(stats) {
                    let msg = "forward-open reply pointed the O→T stream at a foreign address; address refused, sockaddr port honoured";
                    let ctx = json!({ "refusedRedirects": stats.refused_redirects });
                    events
                        .emit(
                            Severity::Warning,
                            "io-redirect-refused",
                            Some(msg.into()),
                            Some(ctx),
                        )
                        .await;
                }
            }
            // The full §8 family set for this push device (§8.7).
            dm.emit_periodic().await;
            since_health = now;
        }
    }
}

/// Resolve a stable id to its input field and publish its samples (§6.1) — the push analog of the
/// poll `publish_by_id`, using the field's `a<inst>/<off>/<type>` id + assembly address (§5.2).
///
/// Returns whether the samples reached the bus, which is what
/// [`crate::publish::Engine::settle`] needs to promote or drop the field's pending baseline
/// (D-EIP-32). A frame field with no configured layout entry publishes nothing, so it reports
/// `false`: nothing was published, so nothing may become a suppression baseline.
#[allow(clippy::too_many_arguments)]
async fn publish_field(
    sink: &dyn Publisher,
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
) -> bool {
    let Some(field) = fields.get(signal_id) else {
        return false;
    };
    let n = samples.len() as u64;
    let (res, latency) = publish::publish_via(
        sink,
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
            health
                .publish_latency_ms
                .store(latency_ms, Ordering::Relaxed);
            dm.record_publish(publish_mode, n, from_batch, latency_ms, true);
            true
        }
        Err(e) => {
            tracing::warn!(instance = %cfg.id, signal_id = %field.signal_id(assembly), error = %e, "publish failed");
            dm.record_publish(publish_mode, n, from_batch, latency_ms, false);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! The class-1 consume loop, driven against scripted seams on a **paused clock**: a
    //! [`ScriptedPush`] whose `IoUpdate` stream the test writes, a [`RecordingPublisher`], a
    //! [`RecordingEvents`], and a [`RecordingMetrics`]-backed [`DeviceMetrics`]. No OpENer, no
    //! socket, no broker.

    use super::*;
    use crate::device::{InputSnapshot, IoLinkStats, Quality};
    use crate::metrics::{HEALTH, IO, PUBLISH};
    use crate::testutil::{
        device_metrics_with, reading, RecordingEvents, RecordingMetrics, RecordingPublisher,
        ScriptedPush,
    };
    use serde_json::{json, Value};
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;

    /// The stable push `signal.id` of the single input field these tests configure (D-EIP-18).
    const FIELD_ID: &str = "a100/0/udint";

    fn push_device(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).expect("a valid push device config")
    }

    fn global(v: Value) -> GlobalConfig {
        GlobalConfig::from_value(&v).expect("a valid global config")
    }

    /// One input field (`a100/0/udint`) plus one output field, at a 100 ms RPI.
    fn io_device(extra: Value) -> DeviceConfig {
        let mut v = json!({
            "id": "io-1",
            "mode": "push",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "udint" } ] },
                "output": { "sizeBytes": 4, "signals": [
                    { "name": "setpoint", "offset": 0, "type": "udint" } ] }
            }
        });
        if let Value::Object(extra) = extra {
            for (k, val) in extra {
                v[k] = val;
            }
        }
        push_device(v)
    }

    fn frame(value: i64, sequence: u16) -> IoUpdate {
        IoUpdate::Data {
            readings: vec![reading(FIELD_ID, json!(value), Quality::Good)],
            sequence,
            run_mode: true,
            received_at: std::time::Instant::now(),
        }
    }

    struct PushRig {
        cfg: DeviceConfig,
        global: GlobalConfig,
        health: Arc<Health>,
        metrics: Arc<RecordingMetrics>,
        dm: Arc<DeviceMetrics>,
        events: Arc<RecordingEvents>,
        sink: Arc<RecordingPublisher>,
        push: ScriptedPush,
        frames: Option<mpsc::Sender<IoUpdate>>,
        tx: Option<mpsc::Sender<DeviceControl>>,
        rx: mpsc::Receiver<DeviceControl>,
        cancel: CancellationToken,
    }

    impl PushRig {
        fn new(cfg: DeviceConfig, global: GlobalConfig) -> Self {
            let health = Arc::new(Health::default());
            let (metrics, dm) = device_metrics_with(cfg.clone(), &global, Arc::clone(&health));
            let (tx, rx) = mpsc::channel(32);
            let (frames, push) = ScriptedPush::new();
            Self {
                cfg,
                global,
                health,
                metrics,
                dm,
                events: Arc::new(RecordingEvents::default()),
                sink: Arc::new(RecordingPublisher::default()),
                push,
                frames: Some(frames),
                tx: Some(tx),
                rx,
                cancel: CancellationToken::new(),
            }
        }

        fn simple() -> Self {
            Self::new(io_device(json!({})), global(json!({})))
        }

        fn control(&self) -> mpsc::Sender<DeviceControl> {
            self.tx.clone().expect("the control sender is still open")
        }

        /// Close the control channel (the component shutting down).
        fn close_control(&mut self) {
            self.tx = None;
        }

        fn producer(&self) -> mpsc::Sender<IoUpdate> {
            self.frames
                .clone()
                .expect("the class-1 producer is still open")
        }

        /// End the `IoUpdate` stream without a preceding `Lost` (the translator task dying).
        fn end_stream(&mut self) {
            self.frames = None;
        }

        fn cancel_after(&self, d: Duration) {
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                cancel.cancel();
            });
        }

        fn send_after(&self, d: Duration, msg: DeviceControl) {
            let tx = self.control();
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = tx.send(msg).await;
            });
        }

        fn frame_after(&self, d: Duration, update: IoUpdate) {
            let tx = self.producer();
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = tx.send(update).await;
            });
        }

        async fn run(&mut self) -> PushExit {
            self.cancel_after(Duration::from_secs(600));
            consume_push(
                &self.cfg,
                &self.global,
                &mut self.push,
                self.sink.as_ref(),
                self.events.as_ref(),
                &self.dm,
                &self.health,
                "ethernet-ip",
                &mut self.rx,
                &self.cancel,
            )
            .await
        }

        /// Whether an alarm of `event_type` was cleared (as opposed to merely emitted).
        fn cleared(&self, event_type: &str) -> bool {
            self.events
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|(kind, t, _)| kind == "clear" && t == event_type)
        }
    }

    /// §8.8 + §6.3: the class-1 connection coming up flips `ioConnectionState`, records the
    /// negotiated APIs, emits `device-connected`, and **clears** the unreachable alarm — the raise
    /// and the clear are a pair, or a console shows a stuck alarm on a healthy link.
    #[tokio::test(start_paused = true)]
    async fn up_event_emits_connected_and_clears_alarm() {
        let mut rig = PushRig::simple();
        rig.frame_after(
            Duration::from_millis(10),
            IoUpdate::Up {
                o2t_api_ms: 96,
                t2o_api_ms: 104,
            },
        );
        rig.cancel_after(Duration::from_millis(50));

        let exit = rig.run().await;

        assert!(matches!(exit, PushExit::Stopped));
        assert_eq!(rig.health.link(), LinkState::Online);
        let ctx = rig
            .events
            .last_ctx("device-connected")
            .expect("device-connected emitted");
        assert_eq!(ctx["o2tApiMs"], json!(96));
        assert_eq!(ctx["t2oApiMs"], json!(104));
        assert!(
            rig.cleared("device-unreachable"),
            "the Up edge clears the unreachable alarm"
        );
        let io = rig
            .metrics
            .last(IO)
            .expect("the transition flushed EtherNetIpIo immediately");
        assert_eq!(io["ioConnectionState"], 1.0);
    }

    /// D-EIP-14: pausing stops **publishing**, not consumption. The frames keep being accepted, the
    /// sequence validation and frame counters stay live, and nothing is published.
    #[tokio::test(start_paused = true)]
    async fn data_frames_gate_publish_but_consumption_continues_while_paused() {
        let mut rig = PushRig::simple();
        let (p_tx, p_rx) = oneshot::channel();
        rig.control()
            .send(DeviceControl::Pause {
                by: None,
                reply: p_tx,
            })
            .await
            .unwrap();
        rig.frame_after(Duration::from_millis(10), frame(1, 1));
        // A forward jump of 2 ⇒ one missed frame.
        rig.frame_after(Duration::from_millis(20), frame(2, 3));
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        assert!(p_rx.await.unwrap());
        assert_eq!(rig.sink.count(), 0, "a paused instance publishes nothing");
        assert_eq!(
            rig.health.frames_consumed.load(Ordering::Relaxed),
            2,
            "…but consumption never stopped"
        );
        rig.dm.emit_periodic().await;
        let io = rig.metrics.last(IO).unwrap();
        assert_eq!(io["framesConsumedTotal"], 2.0);
        assert_eq!(
            io["sequenceGapsTotal"], 1.0,
            "sequence validation stays live while paused"
        );
    }

    /// A `Lost` and a translator that simply ended must be accounted the SAME way — the second is
    /// the hole that would otherwise leave a real loss transition unrecorded.
    #[tokio::test(start_paused = true)]
    async fn lost_and_stream_end_both_return_link_lost_with_io_lost_bookkeeping() {
        // (a) an explicit Lost.
        let mut rig = PushRig::simple();
        rig.frame_after(
            Duration::from_millis(10),
            IoUpdate::Lost {
                error: crate::device::DeviceError::Transient(anyhow::anyhow!("watchdog")),
            },
        );
        let exit = rig.run().await;
        assert!(matches!(exit, PushExit::LinkLost));
        assert_eq!(rig.health.read_errors.load(Ordering::Relaxed), 1);
        rig.dm.emit_periodic().await;
        assert_eq!(rig.metrics.last(IO).unwrap()["ioTimeoutsTotal"], 1.0);
        assert_eq!(rig.metrics.last(IO).unwrap()["ioConnectionState"], 0.0);

        // (b) the stream ending with no preceding Lost — same bookkeeping, not silence.
        let mut rig = PushRig::simple();
        rig.end_stream();
        let exit = rig.run().await;
        assert!(matches!(exit, PushExit::LinkLost));
        assert_eq!(rig.health.read_errors.load(Ordering::Relaxed), 1);
        rig.dm.emit_periodic().await;
        assert_eq!(
            rig.metrics.last(IO).unwrap()["ioTimeoutsTotal"],
            1.0,
            "a translator that died without a Lost is still a loss transition"
        );
    }

    /// §7.4.8: resuming re-bases change detection from the live input snapshot, so the paused span's
    /// accumulated drift is not published as one giant "everything changed" burst.
    #[tokio::test(start_paused = true)]
    async fn resume_rebases_engine_from_last_snapshot() {
        let mut rig = PushRig::simple();
        rig.push.set_snapshot(Some(InputSnapshot {
            readings: vec![reading(FIELD_ID, json!(5), Quality::Good)],
            received_at: std::time::Instant::now(),
            run_mode: true,
        }));
        let (p_tx, _p_rx) = oneshot::channel();
        rig.control()
            .send(DeviceControl::Pause {
                by: None,
                reply: p_tx,
            })
            .await
            .unwrap();
        // Drift while paused, then resume, then the same value again, then a real change.
        rig.frame_after(Duration::from_millis(10), frame(5, 1));
        let (r_tx, r_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(20),
            DeviceControl::Resume { reply: r_tx },
        );
        rig.frame_after(Duration::from_millis(30), frame(5, 2));
        rig.frame_after(Duration::from_millis(40), frame(9, 3));
        rig.cancel_after(Duration::from_millis(60));

        rig.run().await;

        assert!(r_rx.await.unwrap());
        let published = rig.sink.updates();
        assert_eq!(
            published.len(),
            1,
            "the unchanged post-resume frame is suppressed against the re-based baseline; only \
             the real change publishes"
        );
        assert_eq!(published[0].samples[0].value, Some(json!(9)));
    }

    /// §7.4 / D-EIP-32, the sharp edge of the pause rule on push: an open `batchMs` window held
    /// across a pause would flush **after** the §7.4.8 resume rebase, making a stale pre-pause value
    /// the last published one while the rebased current value is suppressed — a wrong last-known
    /// value downstream. Pause discards the window, so the rebase cannot be masked.
    #[tokio::test(start_paused = true)]
    async fn pause_discards_the_open_window_so_no_stale_value_lands_after_the_resume_rebase() {
        let mut rig = PushRig::new(
            io_device(json!({ "defaults": { "batchMs": 200 } })),
            global(json!({})),
        );
        // The device sits at 9 by the time the operator resumes; 7 is what was buffered when the
        // pause arrived.
        rig.push.set_snapshot(Some(InputSnapshot {
            readings: vec![reading(FIELD_ID, json!(9), Quality::Good)],
            received_at: std::time::Instant::now(),
            run_mode: true,
        }));
        rig.frame_after(Duration::from_millis(10), frame(7, 1));
        let (p_tx, p_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(20),
            DeviceControl::Pause {
                by: None,
                reply: p_tx,
            },
        );
        let (r_tx, r_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(30),
            DeviceControl::Resume { reply: r_tx },
        );
        // The current value right after the resume, then a real change.
        rig.frame_after(Duration::from_millis(40), frame(9, 2));
        rig.frame_after(Duration::from_millis(250), frame(11, 3));
        // Past both the discarded window's old deadline (210) and the new one's (450).
        rig.cancel_after(Duration::from_millis(500));

        rig.run().await;

        assert!(p_rx.await.unwrap() && r_rx.await.unwrap());
        let updates = rig.sink.updates();
        assert!(
            updates
                .iter()
                .all(|u| u.samples.iter().all(|s| s.value != Some(json!(7)))),
            "the pre-pause value never escapes — it would otherwise land after the rebase and \
             become the last published value while the device reads 9"
        );
        assert_eq!(
            updates.len(),
            1,
            "the post-resume frame equal to the rebased baseline is suppressed; only the real \
             change publishes"
        );
        assert_eq!(updates[0].samples[0].value, Some(json!(11)));
    }

    /// D-EIP-32 on the push path: a failed publish leaves the onChange baseline where it was, so
    /// the identical next frame is republished instead of being suppressed for the rest of the
    /// session. On Greengrass the awaited IPC error is the ordinary failure mode, which is what
    /// makes this the P1 half of the defect.
    #[tokio::test(start_paused = true)]
    async fn a_failed_publish_is_retried_on_the_next_identical_frame() {
        let mut rig = PushRig::simple();
        rig.sink.push_result(true);
        rig.sink.push_result(false);
        rig.sink.push_result(true);
        rig.frame_after(Duration::from_millis(10), frame(1, 1));
        rig.frame_after(Duration::from_millis(20), frame(2, 2));
        rig.frame_after(Duration::from_millis(30), frame(2, 3));
        rig.frame_after(Duration::from_millis(40), frame(2, 4));
        rig.cancel_after(Duration::from_millis(100));

        rig.run().await;

        let values: Vec<_> = rig
            .sink
            .updates()
            .iter()
            .map(|u| u.samples[0].value.clone())
            .collect();
        assert_eq!(
            values,
            vec![Some(json!(1)), Some(json!(2)), Some(json!(2))],
            "the frame whose publish failed is republished on its next occurrence; the fourth \
             frame, unchanged against a value that DID reach the bus, is suppressed"
        );
        assert_eq!(rig.health.signals_published.load(Ordering::Relaxed), 2);
    }

    /// D-ENIP-17: a refused O→T redirect warns **once per ForwardOpen** (the latch), not on every
    /// metrics interval — and not never.
    #[tokio::test(start_paused = true)]
    async fn io_stats_fold_fires_redirect_event_once_per_forward_open() {
        let mut rig = PushRig::new(
            io_device(json!({})),
            global(json!({ "metricsIntervalSecs": 1 })),
        );
        rig.push.set_stats(Some(IoLinkStats {
            frames_produced: 10,
            refused_redirects: 1,
            ..IoLinkStats::default()
        }));
        rig.cancel_after(Duration::from_millis(2_500));

        rig.run().await;

        assert_eq!(
            rig.events.count("io-redirect-refused"),
            1,
            "two metrics intervals folded the same cumulative counter — one warning, not two"
        );
        assert_eq!(
            rig.events.last_ctx("io-redirect-refused").unwrap()["refusedRedirects"],
            json!(1)
        );
        let io = rig.metrics.last(IO).unwrap();
        assert_eq!(
            io["framesProducedTotal"], 10.0,
            "the real stack counters are folded in"
        );
    }

    /// §7.3: a push write stages an output-assembly field into the O→T producer buffer, and a
    /// rejected staging counts against `southbound_health.writeErrors`.
    #[tokio::test(start_paused = true)]
    async fn write_output_stages_field_and_failure_counts() {
        let mut rig = PushRig::simple();
        let field = rig
            .cfg
            .io
            .as_ref()
            .unwrap()
            .output
            .as_ref()
            .unwrap()
            .signals[0]
            .clone();
        // The first staging is accepted; the device refuses everything after it.
        rig.push.fail_outputs_after(1, "output assembly is full");
        let tx = rig.control();
        let (ok_tx, ok_rx) = oneshot::channel();
        tx.send(DeviceControl::WriteOutput {
            field: field.clone(),
            value: json!(11),
            reply: ok_tx,
        })
        .await
        .unwrap();
        let (bad_tx, bad_rx) = oneshot::channel();
        tx.send(DeviceControl::WriteOutput {
            field,
            value: json!(12),
            reply: bad_tx,
        })
        .await
        .unwrap();
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        assert!(ok_rx.await.unwrap().is_ok(), "the first field was staged");
        assert!(bad_rx
            .await
            .unwrap()
            .unwrap_err()
            .contains("output assembly is full"));
        assert_eq!(
            rig.push.outputs(),
            vec![
                ("setpoint".to_string(), json!(11)),
                ("setpoint".to_string(), json!(12)),
            ],
            "both stagings reached the seam, in order"
        );
        assert_eq!(rig.health.write_errors.load(Ordering::Relaxed), 1);
    }

    /// §7.2: a push `sb/read` answers from the last consumed frame — including while paused, since
    /// consumption never stopped. There is no per-field round-trip in implicit I/O.
    #[tokio::test(start_paused = true)]
    async fn snapshot_verb_answers_last_input_even_paused() {
        let mut rig = PushRig::simple();
        rig.push.set_snapshot(Some(InputSnapshot {
            readings: vec![reading(FIELD_ID, json!(7), Quality::Good)],
            received_at: std::time::Instant::now(),
            run_mode: true,
        }));
        let (p_tx, _p_rx) = oneshot::channel();
        rig.control()
            .send(DeviceControl::Pause {
                by: None,
                reply: p_tx,
            })
            .await
            .unwrap();
        let (s_tx, s_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(10),
            DeviceControl::Snapshot { reply: s_tx },
        );
        rig.cancel_after(Duration::from_millis(30));

        rig.run().await;

        let snap = s_rx
            .await
            .unwrap()
            .expect("the snapshot answers while paused");
        assert_eq!(snap.readings[0].value, json!(7));
    }

    /// §6.2 / §8.5 / §8.7: consumed frames coalesce into one `batchMs` window and flush together,
    /// and the family set keeps emitting on `metricsIntervalSecs`.
    #[tokio::test(start_paused = true)]
    async fn batch_flush_and_metrics_cadence() {
        let mut rig = PushRig::new(
            io_device(json!({ "defaults": { "batchMs": 200, "publishMode": "always" } })),
            global(json!({ "metricsIntervalSecs": 1 })),
        );
        rig.frame_after(Duration::from_millis(50), frame(1, 1));
        rig.frame_after(Duration::from_millis(100), frame(2, 2));
        rig.cancel_after(Duration::from_millis(2_500));

        rig.run().await;

        let updates = rig.sink.updates();
        assert_eq!(updates.len(), 1, "one window closed ⇒ one publish");
        assert_eq!(
            updates[0].samples.len(),
            2,
            "both frames' samples ride the one flush"
        );
        assert_eq!(updates[0].signal_id.as_deref(), Some(FIELD_ID));

        assert!(
            rig.metrics.emits(HEALTH) >= 2,
            "southbound_health emits once per second"
        );
        assert!(rig.metrics.emits(IO) >= 2, "so does EtherNetIpIo");
        // The publish family rides the same cadence; its running totals are read off the last emit.
        let row = rig
            .metrics
            .last(PUBLISH)
            .expect("EtherNetIpPublish emitted on the cadence");
        assert_eq!(row["batchFlushesTotal"], 1.0);
        assert_eq!(row["dataMessagesPublishedTotal"], 1.0);
        assert_eq!(row["batchSize"], 2.0);
    }

    /// Poll-only verbs never route to a push task; if one arrives it is answered, not dropped — a
    /// dropped reply hangs the `sb/*` caller until its command timeout. (The poll mirror of this is
    /// `poll_driver::tests::push_verbs_answered_defensively`.)
    #[tokio::test(start_paused = true)]
    async fn poll_verbs_answered_defensively() {
        let mut rig = PushRig::simple();
        let signal = crate::config::SignalSpec {
            name: "line-speed".into(),
            tag_path: "LINE_SPEED".into(),
            eip_type: crate::config::EipType::Real,
            array_count: None,
            scale: None,
            offset: None,
            deadband: DeadbandSpec::default(),
        };
        let tx = rig.control();
        let (r_tx, r_rx) = oneshot::channel();
        tx.send(DeviceControl::ReadNow {
            specs: vec![signal.clone()],
            reply: r_tx,
        })
        .await
        .unwrap();
        let (w_tx, w_rx) = oneshot::channel();
        tx.send(DeviceControl::Write(crate::app::WriteRequest {
            signal,
            value: json!(42.0),
            ack: w_tx,
        }))
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
        drop(tx);
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PushExit::Stopped));
        assert!(
            r_rx.await.unwrap().unwrap_err().contains("input snapshot"),
            "a push instance has no per-tag read, and says where reads come from instead"
        );
        assert!(
            w_rx.await.unwrap().unwrap_err().contains("output assembly"),
            "a push write targets the output assembly, not a tag path"
        );
        assert!(
            rp_rx.await.unwrap().unwrap_err().contains("cyclically"),
            "there is nothing to re-poll on a cyclic connection"
        );
        assert!(
            matches!(
                b_rx.await.unwrap(),
                Err(crate::app::BrowseError::Unsupported)
            ),
            "push browse is answered from the configured layout by the commander, never here"
        );
    }

    /// A closed control channel is the component going down, not a lost class-1 link: `Stopped`, no
    /// alarm, and none of the loss bookkeeping — otherwise a shutdown reads as an outage and the
    /// ladder reconnects into a runtime that is being torn down.
    #[tokio::test(start_paused = true)]
    async fn control_channel_close_is_stopped_not_link_lost() {
        let mut rig = PushRig::simple();
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PushExit::Stopped));
        assert!(!rig.events.has("device-unreachable"));
        assert_eq!(
            rig.health.read_errors.load(Ordering::Relaxed),
            0,
            "a shutdown is not a read error"
        );
        rig.dm.emit_periodic().await;
        assert_eq!(
            rig.metrics.last(IO).unwrap()["ioTimeoutsTotal"],
            0.0,
            "…and not a watchdog expiry either"
        );
        assert_eq!(
            rig.push.closed(),
            0,
            "the ForwardClose stays with the caller, which runs it on every exit path"
        );
    }

    /// §10.3: a cancelled push instance leaves as `Stopped` with no alarm and no reconnect. The
    /// ForwardClose is deliberately NOT done here — the caller's unconditional `session.close()`
    /// owns it, so it also covers the LinkLost and Reconnect exits.
    #[tokio::test(start_paused = true)]
    async fn cancelled_returns_stopped_without_alarm() {
        let mut rig = PushRig::simple();
        rig.frame_after(Duration::from_millis(10), frame(1, 1));
        rig.cancel_after(Duration::from_millis(50));

        let exit = rig.run().await;

        assert!(matches!(exit, PushExit::Stopped));
        assert!(
            !rig.events.has("device-unreachable"),
            "a stop raises no alarm"
        );
        assert_eq!(
            rig.push.closed(),
            0,
            "the driver leaves the ForwardClose to its caller, which runs it on EVERY exit path"
        );
    }
}
