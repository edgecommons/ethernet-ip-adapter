//! # The push loop driver (§3.2, §4.6, §6) — the live-infra seam (excluded from coverage, §12.2)
//!
//! A **thin driver seam**: [`consume_push`] consumes one push-mode device's [`crate::device::IoUpdate`]
//! stream (the input assembly at the negotiated RPI), servicing the `sb/*` control channel in line with
//! it, and publishes what survives the gate. Every branch here is driven by a `.await` on the
//! [`PushSession`] update channel (a live class-1 socket against OpENer / a real adapter) or the `data()`
//! publish facade (a live broker); the **pure decision** it composes — the `sampleMs` floor + deadband
//! gating + batching ([`crate::push::process_frame`]) — is unit-tested in its home module. The loop is
//! validated by the live OpENer suite (§11) and the S9 deployed regression, exactly as `file-replicator`
//! validates its `dest/*/client.rs` seams.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, Sample, Severity};
use serde_json::json;

use crate::app::{apply_pause, DeviceControl, EventSink, Health, LinkState};
use crate::config::{DeadbandSpec, DeviceConfig, GlobalConfig, IoFieldSpec, PublishMode};
use crate::device::{IoUpdate, PushSession};
use crate::metrics::DeviceMetrics;
use crate::publish::{self};
use crate::push::process_frame;

/// How [`consume_push`] left the consume loop (§7.5, §10.2) — the push analog of
/// [`crate::poll_driver::PollExit`].
pub(crate) enum PushExit {
    /// The class-1 link was lost (watchdog / peer close / end of stream) — reconnect.
    LinkLost,
    /// An `sb/reconnect` asked to ForwardClose + ForwardOpen now (§7.5).
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
}

/// What woke the consume loop — returned by the `select!` so `session` is no longer borrowed by the
/// time a control message is serviced (the update branch borrows the session's update receiver).
enum Woke {
    Control(Option<DeviceControl>),
    Update(Option<IoUpdate>),
    Tick,
}

/// Consume one push session's [`IoUpdate`] stream until the link is lost (§3.2). Gates + batches each
/// consumed frame's fields and publishes what survives; returns on `Lost` / end-of-stream so the
/// supervisor reconnects.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn consume_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    session: &mut dyn PushSession,
    data: &DataFacade,
    events: &dyn EventSink,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    adapter: &str,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
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
        .map(|f| (f.signal_id(assembly), f.deadband.clone().unwrap_or_default()))
        .collect();

    let start = Instant::now();
    let mut engine = crate::publish::Engine::new(start);
    let mut since_health = start;
    // A pause that arrived while the link was down carries in through the shared flag (§9.2).
    let mut paused = health.paused.load(Ordering::Relaxed);

    loop {
        // Frames arrive on the channel; we also wake for the next batch close and the health tick.
        // While paused, batches don't accrue (nothing is published), so only the health tick matters.
        let mut wake = since_health + metrics_interval;
        if !paused {
            if let Some(bd) = engine.next_batch_deadline(batch_ms) {
                wake = wake.min(bd);
            }
        }
        let wait = wake.saturating_duration_since(Instant::now());

        // Return only a plain value from each arm so `session` is free (the update arm borrows its
        // receiver) by the time a control message is serviced below.
        let woke = tokio::select! {
            biased;
            ctrl = control.recv() => Woke::Control(ctrl),
            update = session.updates().recv() => Woke::Update(update),
            _ = tokio::time::sleep(wait) => Woke::Tick,
        };

        match woke {
            Woke::Control(None) => {
                // The control channel closed (component shutting down) — leave cleanly.
                return PushExit::LinkLost;
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
                    DeviceControl::WriteOutput { field, value, reply } => {
                        let result = session.set_output(&field, &value).await.map_err(|e| e.to_string());
                        if result.is_err() {
                            health.write_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = reply.send(result);
                    }
                    DeviceControl::Pause { by, reply } => {
                        let changed = apply_pause(cfg, health, dm, events, true, by.as_deref()).await;
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
                                engine.rebase_from(&pairs, Instant::now());
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
                        let _ = reply.send(Err("push instance - reads answer from the input snapshot".to_string()));
                    }
                    DeviceControl::Write(req) => {
                        let _ = req.ack.send(Err("push instance - writes target the output assembly".to_string()));
                    }
                    DeviceControl::Repoll { reply } => {
                        let _ = reply.send(Err("push instance - data arrives cyclically".to_string()));
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
                Some(IoUpdate::Up { o2t_api_ms, t2o_api_ms }) => {
                    health.set_link(LinkState::Online);
                    // The class-1 connection is open (§8.8 ioConnectionState); a transition ⇒
                    // flush southbound_health + connection + io immediately (§8.7).
                    dm.on_io_up(o2t_api_ms, t2o_api_ms);
                    dm.emit_now().await;
                    events
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
                    events
                        .clear_alarm(Severity::Critical, "device-unreachable", None)
                        .await;
                }
                Some(IoUpdate::Data { readings, sequence, run_mode, received_at }) => {
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
                        let now = Instant::now();
                        for p in process_frame(&mut engine, &readings, &deadbands, mode, sample_ms, batch_ms, now, health) {
                            publish_field(data, cfg, adapter, &fields, assembly, &p.signal_id, p.samples, health, dm, mode_token, false).await;
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
                    tracing::warn!(instance = %cfg.id, "push session ended; reconnecting");
                    return PushExit::LinkLost;
                }
            },
            Woke::Tick => {}
        }

        let now = Instant::now();
        if !paused {
            for p in engine.take_due(batch_ms, now) {
                // A coalescing-window flush (§8.5 batchFlushes/batchSize).
                publish_field(data, cfg, adapter, &fields, assembly, &p.signal_id, p.samples, health, dm, mode_token, true).await;
            }
        }
        if now.saturating_duration_since(since_health) >= metrics_interval {
            // Staleness is suspended while paused (§9.3).
            let stale = if paused {
                0
            } else {
                engine.count_stale(fields.keys().map(String::as_str), stale_secs, now)
            };
            health.stale_signals.store(stale, Ordering::Relaxed);
            // Fold the class-1 stack's live drop/produce counters into EtherNetIpIo before the emit,
            // so framesProduced / staleFramesDropped / sizeMismatchDropped / malformedFrames /
            // produceOverruns read REAL values (§8.8, the S5-flagged gap) rather than 0.
            if let Some(stats) = session.io_stats() {
                dm.record_io_stats(stats);
            }
            // The full §8 family set for this push device (§8.7).
            dm.emit_periodic().await;
            since_health = now;
        }
    }
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
    let (res, latency) = crate::publish_sink::publish(
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
