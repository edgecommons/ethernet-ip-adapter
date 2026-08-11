//! # The poll loop driver (§3.2, §6) — the scheduled read → gate → batch → publish composition
//!
//! [`poll_until_disconnected`] owns one poll-mode device's session and runs the scheduled read → gate
//! → batch → publish select-loop, servicing the `sb/*` control channel in line with it. It is the
//! poll mode's *composition logic*, not I/O glue: the wake computation, the group re-arm, the
//! batch-flush ordering, the paused keepalive, the metric attribution, and every control verb's
//! contract are decided here, over three injected seams — [`DeviceSession`] (the wire),
//! [`crate::publish::Publisher`] (the broker), and [`EventSink`] (the `evt` surface). The pure
//! decisions it composes — the deadband/change/batch/stale gating
//! ([`crate::poll::process_group`]), the overrun accounting ([`crate::poll::record_cycle`]), the
//! [`crate::publish`] gate primitives — live in their own modules.
//!
//! The loop therefore runs under unit test against scripted seams (`#[cfg(test)] mod tests` below,
//! on a paused clock); the live cpppo suite (§11) and the deployed regression validate it against a
//! real device, which is conformance evidence rather than coverage evidence.
//!
//! **Clock:** the loop schedules on [`tokio::time::Instant`] — the same wall clock as
//! `std::time::Instant` at runtime (tokio reads the system clock unless the runtime is paused), and
//! the *simulated* clock under `#[tokio::test(start_paused = true)]`, which is what makes the
//! cadence/flush/keepalive/metric-interval behaviour deterministically testable. The pure engine
//! primitives keep taking `std::time::Instant`; the conversion happens at the call boundary.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use edgecommons::prelude::Sample;
use tokio::time::Instant;

use crate::app::{apply_pause, DeviceControl, EventSink, Health, LinkState};
use crate::config::{DeviceConfig, GlobalConfig, PollGroup, PublishMode, SignalSpec};
use crate::device::DeviceSession;
use crate::metrics::{DeviceMetrics, RESULT_ERROR, RESULT_SUCCESS};
use crate::poll::{process_group, record_cycle};
use crate::publish::{self, Engine, Publisher};

/// How [`poll_until_disconnected`] left the poll loop (§7.5, §10.2, §10.3). The supervisor
/// ([`crate::supervisor`]) reconnects on `LinkLost` and `Reconnect` — but an explicit `reconnect`
/// skips the backoff + the unreachable alarm and carries its reply to fulfill after the next connect
/// resolves. `Stopped` is the teardown exit: no reconnect, no backoff, no alarm.
pub(crate) enum PollExit {
    /// The link broke (a connection-level read/probe failure) — back off and reconnect.
    LinkLost,
    /// An `sb/reconnect` asked to drop + re-establish now (§7.5).
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
    /// Cancellation or control-channel close (§10.3, D-EIP-27): the session has been closed
    /// (UnRegisterSession on the wire); the supervisor must NOT reconnect, back off, or raise a
    /// `device-unreachable` alarm.
    Stopped,
}

/// The per-cycle deltas of the shared [`Health`] sample counters — attributes one poll cycle's samples
/// to its `(pollGroup, result)` metric combo (§8.4) without threading the emitter into the gating hot
/// path. Pure atomic-counter plumbing; the gating logic it wraps is tested in [`crate::poll`].
#[derive(Clone, Copy, Default)]
struct SampleSnapshot {
    good: u64,
    bad: u64,
    uncertain: u64,
    changed: u64,
    suppressed: u64,
}

impl SampleSnapshot {
    fn take(health: &Health) -> Self {
        Self {
            good: health.samples_good.load(Ordering::Relaxed),
            bad: health.samples_bad.load(Ordering::Relaxed),
            uncertain: health.samples_uncertain.load(Ordering::Relaxed),
            changed: health.samples_changed.load(Ordering::Relaxed),
            suppressed: health.samples_suppressed.load(Ordering::Relaxed),
        }
    }

    /// The counts accrued between `self` (before the cycle) and `now` (after it).
    fn delta_since(self, before: Self) -> Self {
        Self {
            good: self.good - before.good,
            bad: self.bad - before.bad,
            uncertain: self.uncertain - before.uncertain,
            changed: self.changed - before.changed,
            suppressed: self.suppressed - before.suppressed,
        }
    }
}

/// Poll each group on its own cadence, gate + batch + publish, until the link breaks (§3.2).
///
/// A single task owns the session (it is not `Sync`), so all groups, the batch flushes, and the write
/// channel serialize here. The loop sleeps until the earliest of {the next group deadline, the next
/// batch-window close, the next health emit}, then services whichever are due. A read that returns
/// `Err` is a connection-level failure: the loop closes the session and returns so the connect loop
/// backs off.
///
/// `cancel` is this instance's child of the app root token (§10.3): when it fires the loop closes the
/// session — sending UnRegisterSession on the wire — and returns [`PollExit::Stopped`]. An in-flight
/// CIP call is not interrupted (it must resolve for the session to stay coherent for `close()`), so
/// the cancel is observed at the next loop head; that bound is the `in_flight` term of the shutdown
/// budget.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll_until_disconnected(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    mut session: Box<dyn DeviceSession>,
    sink: &dyn Publisher,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    adapter: &str,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    events: &dyn EventSink,
    keepalive_ms: u64,
    cancel: &tokio_util::sync::CancellationToken,
) -> PollExit {
    // Resolve each group's cadence + publish mode once; batchMs + staleness are device/global-wide.
    let intervals: Vec<Duration> = cfg
        .poll_groups
        .iter()
        .map(|g| Duration::from_millis(cfg.effective_poll_ms(g, global).max(1)))
        .collect();
    let modes: Vec<PublishMode> = cfg
        .poll_groups
        .iter()
        .map(|g| cfg.effective_publish_mode(g, global))
        .collect();
    // signal.id → its group's publishMode token, so a batched flush (which has lost the group
    // context) still attributes to the right `EtherNetIpPublish.publishMode` combo (§8.5).
    let mode_of: HashMap<String, &'static str> = cfg
        .poll_groups
        .iter()
        .flat_map(|g| {
            let mode = cfg.effective_publish_mode(g, global).as_str();
            g.signals.iter().map(move |s| (s.tag_path.clone(), mode))
        })
        .collect();
    let batch_ms = cfg.effective_batch_ms(global);
    let stale_secs = global.health_thresholds.stale_signal_secs;
    let metrics_interval = Duration::from_secs(global.metrics_interval_secs.max(1));
    let keepalive = Duration::from_millis(keepalive_ms.max(1));

    let start = Instant::now();
    let mut engine = Engine::new(start.into_std());
    let mut deadlines: Vec<Instant> = intervals.iter().map(|d| start + *d).collect();
    let mut since_health = start;
    let mut since_keepalive = start;
    // A pause that arrived while the link was down carries in through the shared flag (§9.2).
    let mut paused = health.paused.load(Ordering::Relaxed);

    loop {
        // Earliest wake: while running, the nearest group deadline / batch close / health emit; while
        // paused, only the health emit and the keepalive probe (no ticks flow, D-EIP-14/§7.4). A
        // paused instance has no open batch window to wake for — pause discarded them (D-EIP-32).
        let mut wake = since_health + metrics_interval;
        if paused {
            wake = wake.min(since_keepalive + keepalive);
        } else {
            wake = wake.min(*deadlines.iter().min().expect("at least one poll group"));
            if let Some(bd) = engine.next_batch_deadline(batch_ms) {
                wake = wake.min(Instant::from_std(bd));
            }
        }
        let wait = wake.saturating_duration_since(Instant::now());

        tokio::select! {
            biased;

            // Teardown (shutdown / instance stop, §10.3): close this task's own session — the
            // session is `!Sync` and owned here, which is why close lives in the task — then leave
            // without a reconnect, a backoff, or an unreachable alarm.
            () = cancel.cancelled() => {
                tracing::info!(instance = %cfg.id, "cancelled; closing the session and stopping");
                session.close().await;
                return PollExit::Stopped;
            }

            // Every session-touching verb shares this one task, so it can never race a read on the
            // same connection (§7).
            ctrl = control.recv() => {
                let Some(ctrl) = ctrl else {
                    // The control channel closed (component shutting down) — leave cleanly. This is
                    // a teardown path, not a lost link: no alarm, no reconnect (§10.3).
                    tracing::info!(instance = %cfg.id, "control channel closed; stopping");
                    session.close().await;
                    return PollExit::Stopped;
                };
                match ctrl {
                    DeviceControl::Write(req) => {
                        let result = session
                            .write_signal(&req.signal, &req.value)
                            .await
                            .map_err(|e| e.to_string());
                        if let Err(e) = &result {
                            tracing::warn!(instance = %cfg.id, tag_path = %req.signal.tag_path, error = %e, "write failed");
                            // A failed confirmed write (§8.1 southbound_health.writeErrors).
                            health.write_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = req.ack.send(result);
                    }
                    DeviceControl::ReadNow { specs, reply } => {
                        // An on-demand read serializes with the loop and works while paused (§7.2).
                        match session.read_signals(&specs).await {
                            Ok(readings) => {
                                health.record_observed(&readings);
                                let _ = reply.send(Ok(readings));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e.to_string()));
                                health.read_errors.fetch_add(1, Ordering::Relaxed);
                                session.close().await;
                                return PollExit::LinkLost;
                            }
                        }
                    }
                    DeviceControl::Pause { by, reply } => {
                        let changed = apply_pause(cfg, health, dm, events, true, by.as_deref()).await;
                        // Open `batchMs` windows are DISCARDED, not held (§7.4, D-EIP-32): flushing
                        // now would publish through an instance that must go quiet, and holding
                        // them releases a stale burst the moment it resumes. A pause forfeits at
                        // most one batch window of buffered telemetry.
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
                            // Re-base staleness so the paused span doesn't count (§7.4.5/§9.3).
                            engine.rebase_stale(Instant::now().into_std());
                            // Re-arm group deadlines from now so a paused span isn't a catch-up storm.
                            let base = Instant::now();
                            for (i, d) in deadlines.iter_mut().enumerate() {
                                *d = base + intervals[i];
                            }
                        }
                        paused = false;
                        let _ = reply.send(changed);
                    }
                    DeviceControl::Reconnect { reply } => {
                        session.close().await;
                        return PollExit::Reconnect(reply);
                    }
                    DeviceControl::Repoll { reply } => {
                        if paused {
                            let _ = reply.send(Err("instance is paused - resume first".to_string()));
                        } else {
                            match repoll_all_groups(
                                &cfg.poll_groups, &modes, &mode_of, batch_ms, &mut engine, &mut session,
                                sink, cfg, dm, health, adapter,
                            ).await {
                                Ok(count) => {
                                    let _ = reply.send(Ok(count));
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                    session.close().await;
                                    return PollExit::LinkLost;
                                }
                            }
                        }
                    }
                    DeviceControl::Browse { cursor, max, reply } => {
                        // Paged CIP tag discovery over the session (§7.5). A browse failure does not
                        // break the link (the next poll detects a truly-dead link).
                        match session.browse(cursor, max).await {
                            Ok(page) => {
                                let _ = reply.send(Ok(page));
                            }
                            Err(crate::device::DeviceError::Unsupported(_)) => {
                                let _ = reply.send(Err(crate::app::BrowseError::Unsupported));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(crate::app::BrowseError::Failed(e.to_string())));
                            }
                        }
                    }
                    // Push-only verbs never route to a poll task; answer defensively.
                    DeviceControl::Snapshot { reply } => {
                        let _ = reply.send(None);
                    }
                    DeviceControl::WriteOutput { reply, .. } => {
                        let _ = reply.send(Err("not a push instance".to_string()));
                    }
                }
                continue;
            }

            _ = tokio::time::sleep(wait) => {}
        }

        let now = Instant::now();

        if paused {
            // 1p. Keepalive probe: no polls flow, so a cheap round-trip keeps `connected` truthful
            // (§7.4.3). A probe failure drives the normal reconnect path (still paused after).
            if now.saturating_duration_since(since_keepalive) >= keepalive {
                since_keepalive = now;
                if let Err(e) = session.probe().await {
                    tracing::warn!(instance = %cfg.id, error = %e, "paused keepalive probe failed; reconnecting");
                    health.read_errors.fetch_add(1, Ordering::Relaxed);
                    session.close().await;
                    return PollExit::LinkLost;
                }
                health.set_link(LinkState::Online);
            }
        } else {
            // 1. Flush any batch windows that closed (a coalescing-window flush → EtherNetIpPublish, §8.5).
            for p in engine.take_due(batch_ms, now.into_std()) {
                let mode = mode_of
                    .get(&p.signal_id)
                    .copied()
                    .unwrap_or_else(|| PublishMode::OnChange.as_str());
                let published = publish_by_id(
                    sink,
                    cfg,
                    adapter,
                    &p.signal_id,
                    p.samples,
                    health,
                    dm,
                    mode,
                    true,
                )
                .await;
                // The flushed window's value becomes the onChange baseline only now that the
                // publish resolved — a failure leaves the old baseline so the value is retried
                // rather than silently suppressed for the rest of the session (D-EIP-32).
                engine.settle(&p.signal_id, published);
            }

            // 2. Poll the earliest due group (there may be none — we woke for a flush/health tick).
            if let Some(idx) = (0..deadlines.len())
                .filter(|&i| deadlines[i] <= now)
                .min_by_key(|&i| deadlines[i])
            {
                // Re-arm this group (guard against catch-up storms if a cycle overran).
                deadlines[idx] = (deadlines[idx] + intervals[idx]).max(now);

                let group = &cfg.poll_groups[idx];
                let group_id = group.id.as_deref().unwrap_or("group").to_string();
                let tag_reads = group.signals.len() as u64;
                let before = SampleSnapshot::take(health);
                let started = Instant::now();
                let readings = match session.read_signals(&group.signals).await {
                    Ok(r) => r,
                    Err(e) => {
                        // A connection-level failure (link down / misconfigured). Leave the poll loop so
                        // the connect loop can back off; the per-signal failures came back as BAD readings.
                        tracing::warn!(instance = %cfg.id, error = %e, transient = e.is_transient(), "read failed; reconnecting");
                        health.read_errors.fetch_add(1, Ordering::Relaxed);
                        // An error poll cycle (§8.4 result=error).
                        dm.record_poll_cycle(
                            &group_id,
                            RESULT_ERROR,
                            0,
                            tag_reads,
                            false,
                            0,
                            0,
                            0,
                            0,
                            0,
                        );
                        session.close().await;
                        return PollExit::LinkLost;
                    }
                };
                // What the device declared for each of these tags (D-EIP-35) — the `observedType`
                // `sb/signals` reports, recorded on every cycle so a re-programmed controller
                // corrects the surface on its next reply.
                health.record_observed(&readings);
                // Capture time (four-slot timestamp model): serverTs is stamped the moment the
                // group's read completed, so a batchMs flush carries the read-time stamp.
                let server_ts = publish::now_iso();
                let elapsed = started.elapsed();
                let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
                health.poll_latency_ms.store(elapsed_ms, Ordering::Relaxed);
                record_cycle(elapsed, intervals[idx], health);

                let now2 = Instant::now().into_std();
                for p in process_group(
                    &mut engine,
                    group,
                    modes[idx],
                    batch_ms,
                    &readings,
                    now2,
                    &server_ts,
                    health,
                ) {
                    let mode = mode_of
                        .get(&p.signal_id)
                        .copied()
                        .unwrap_or_else(|| modes[idx].as_str());
                    let published = publish_by_id(
                        sink,
                        cfg,
                        adapter,
                        &p.signal_id,
                        p.samples,
                        health,
                        dm,
                        mode,
                        false,
                    )
                    .await;
                    engine.settle(&p.signal_id, published);
                }

                // Attribute this cycle's samples to its (pollGroup, success) combo (§8.4).
                let d = SampleSnapshot::take(health).delta_since(before);
                dm.record_poll_cycle(
                    &group_id,
                    RESULT_SUCCESS,
                    elapsed_ms,
                    tag_reads,
                    publish::cycle_overran(elapsed, intervals[idx]),
                    d.good,
                    d.bad,
                    d.uncertain,
                    d.changed,
                    d.suppressed,
                );
            }
        }

        // 3. Metrics emit cadence: the full §8 family set for this poll device (§8.7). Staleness is
        // suspended while paused — a paused signal is paused, not stale (§9.3).
        if now.saturating_duration_since(since_health) >= metrics_interval {
            let stale = if paused {
                0
            } else {
                engine.count_stale(
                    cfg.signals().map(|s| s.tag_path.as_str()),
                    stale_secs,
                    now.into_std(),
                )
            };
            health.stale_signals.store(stale, Ordering::Relaxed);
            dm.emit_periodic().await;
            since_health = now;
        }
    }
}

/// Force an immediate poll of ALL groups now (`repoll`, §7.5): read each group, gate + publish, and
/// return the total signals read. A connection-level read error returns `Err` (the caller reconnects).
#[allow(clippy::too_many_arguments)]
async fn repoll_all_groups(
    groups: &[PollGroup],
    modes: &[PublishMode],
    mode_of: &HashMap<String, &'static str>,
    batch_ms: u64,
    engine: &mut Engine,
    session: &mut Box<dyn DeviceSession>,
    sink: &dyn Publisher,
    cfg: &DeviceConfig,
    dm: &DeviceMetrics,
    health: &Health,
    adapter: &str,
) -> std::result::Result<u64, String> {
    let mut polled = 0u64;
    for (idx, group) in groups.iter().enumerate() {
        let readings = session
            .read_signals(&group.signals)
            .await
            .map_err(|e| e.to_string())?;
        health.record_observed(&readings);
        // Capture time (four-slot timestamp model): stamped at read completion, as on the timer.
        let server_ts = publish::now_iso();
        polled += group.signals.len() as u64;
        let now = Instant::now().into_std();
        for p in process_group(
            engine, group, modes[idx], batch_ms, &readings, now, &server_ts, health,
        ) {
            let mode = mode_of
                .get(&p.signal_id)
                .copied()
                .unwrap_or_else(|| modes[idx].as_str());
            let published = publish_by_id(
                sink,
                cfg,
                adapter,
                &p.signal_id,
                p.samples,
                health,
                dm,
                mode,
                false,
            )
            .await;
            engine.settle(&p.signal_id, published);
        }
    }
    Ok(polled)
}

/// Resolve a stable id to its configured signal and publish its samples (§6.1). Records the publish
/// latency + published-sample count on `health` and the per-`publishMode` [`crate::metrics::PUBLISH`]
/// counters on `dm` (§8.5). `from_batch` marks a coalescing-window flush.
///
/// Returns whether the samples reached the bus — the caller feeds that to
/// [`Engine::settle`], which promotes the signal's pending baseline on success and drops it on
/// failure (D-EIP-32). An id with no configured signal publishes nothing, so it reports `false`
/// too: nothing was published, so nothing may become a suppression baseline.
#[allow(clippy::too_many_arguments)]
async fn publish_by_id(
    sink: &dyn Publisher,
    cfg: &DeviceConfig,
    adapter: &str,
    signal_id: &str,
    samples: Vec<Sample>,
    health: &Health,
    dm: &DeviceMetrics,
    publish_mode: &'static str,
    from_batch: bool,
) -> bool {
    let Some(spec) = cfg.find_signal(signal_id) else {
        return false;
    };
    publish_samples(
        sink,
        cfg,
        adapter,
        spec,
        samples,
        health,
        dm,
        publish_mode,
        from_batch,
    )
    .await
}

/// Publish one signal's samples through the mode-agnostic [`crate::publish::publish_via`] path.
/// Returns whether the facade confirmed the publish.
#[allow(clippy::too_many_arguments)]
async fn publish_samples(
    sink: &dyn Publisher,
    cfg: &DeviceConfig,
    adapter: &str,
    spec: &SignalSpec,
    samples: Vec<Sample>,
    health: &Health,
    dm: &DeviceMetrics,
    publish_mode: &'static str,
    from_batch: bool,
) -> bool {
    let n = samples.len() as u64;
    let (res, latency) = publish::publish_via(
        sink,
        &spec.tag_path,
        &spec.name,
        spec.address_json(&cfg.connection),
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
            tracing::warn!(instance = %cfg.id, tag_path = %spec.tag_path, error = %e, "publish failed");
            dm.record_publish(publish_mode, n, from_batch, latency_ms, false);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! The poll loop, driven against scripted seams on a **paused clock**: a
    //! [`ScriptedSession`] for the wire, a [`RecordingPublisher`] for the broker, a
    //! [`RecordingEvents`] for the `evt` surface, and a [`RecordingMetrics`]-backed
    //! [`DeviceMetrics`]. No socket, no broker, no PLC — every branch below is the loop's own
    //! composition logic (§3.2, §7, §8).
    //!
    //! Time is simulated: each test spawns its stimuli on timers, so the runtime advances its clock
    //! to whichever deadline comes next (the driver's or the test's) and the interleaving is
    //! deterministic.

    use super::*;
    use crate::app::{BrowseError, WriteRequest};
    use crate::device::{BrowsePage, BrowsedTag, DeviceError, Quality, Reading};
    use crate::metrics::{HEALTH, POLL, PUBLISH};
    use crate::testutil::{
        device_metrics_with, reading, RecordingEvents, RecordingMetrics, RecordingPublisher,
        ScriptedSession,
    };
    use serde_json::{json, Value};
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;

    fn poll_device(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).expect("a valid device config")
    }

    fn global(v: Value) -> GlobalConfig {
        GlobalConfig::from_value(&v).expect("a valid global config")
    }

    /// One group, one `real` signal, at `poll_ms` in `mode`.
    fn one_group(poll_ms: u64, mode: &str) -> Value {
        json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [ {
                "id": "fast", "pollIntervalMs": poll_ms, "publishMode": mode,
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ]
            } ]
        })
    }

    /// Everything one driver run needs. The session/publisher/events/metrics handles stay with the
    /// test while the driver owns its `Box<dyn DeviceSession>` and its `&dyn` seams.
    struct Rig {
        cfg: DeviceConfig,
        global: GlobalConfig,
        health: Arc<Health>,
        metrics: Arc<RecordingMetrics>,
        dm: Arc<DeviceMetrics>,
        events: Arc<RecordingEvents>,
        sink: Arc<RecordingPublisher>,
        session: Arc<ScriptedSession>,
        tx: Option<mpsc::Sender<DeviceControl>>,
        rx: mpsc::Receiver<DeviceControl>,
        cancel: CancellationToken,
    }

    impl Rig {
        fn new(cfg: DeviceConfig, global: GlobalConfig, repeat: Vec<Reading>) -> Self {
            let health = Arc::new(Health::default());
            let (metrics, dm) = device_metrics_with(cfg.clone(), &global, Arc::clone(&health));
            let (tx, rx) = mpsc::channel(32);
            Self {
                cfg,
                global,
                health,
                metrics,
                dm,
                events: Arc::new(RecordingEvents::default()),
                sink: Arc::new(RecordingPublisher::default()),
                session: ScriptedSession::new(repeat),
                tx: Some(tx),
                rx,
                cancel: CancellationToken::new(),
            }
        }

        /// The default rig: one group at `poll_ms` in `mode`, one GOOD reading per poll.
        fn simple(poll_ms: u64, mode: &str, value: Value) -> Self {
            Self::new(
                poll_device(one_group(poll_ms, mode)),
                global(json!({})),
                vec![reading("LINE_SPEED", value, Quality::Good)],
            )
        }

        fn control(&self) -> mpsc::Sender<DeviceControl> {
            self.tx.clone().expect("the control sender is still open")
        }

        /// Close the control channel (the component shutting down).
        fn close_control(&mut self) {
            self.tx = None;
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

        async fn run(&mut self) -> PollExit {
            // A far-future backstop, so a loop that wedges fails loudly instead of hanging the suite.
            self.cancel_after(Duration::from_secs(600));
            poll_until_disconnected(
                &self.cfg,
                &self.global,
                Box::new(Arc::clone(&self.session)),
                self.sink.as_ref(),
                &self.dm,
                &self.health,
                "ethernet-ip",
                &mut self.rx,
                self.events.as_ref(),
                self.global.health_thresholds.keepalive_probe_interval_ms,
                &self.cancel,
            )
            .await
        }

        /// How many times a given `signal.id` was published.
        fn published(&self, signal_id: &str) -> usize {
            self.sink.ids().iter().filter(|id| *id == signal_id).count()
        }
    }

    // ---- teardown ----

    /// §10.3 / D-EIP-27: a cancelled instance closes its own session (UnRegisterSession reaches the
    /// wire) and leaves as `Stopped` — no alarm, and the supervisor must not reconnect.
    #[tokio::test(start_paused = true)]
    async fn cancel_closes_the_session_and_returns_stopped() {
        let mut rig = Rig::simple(100, "always", json!(1.0));
        rig.cancel_after(Duration::from_millis(250));

        let exit = rig.run().await;

        assert!(
            matches!(exit, PollExit::Stopped),
            "a cancel is a stop, not a lost link"
        );
        assert_eq!(
            rig.session.closed(),
            1,
            "the cancel path closes the session on the wire"
        );
        assert_eq!(
            rig.session.reads_done(),
            2,
            "it polled until the cancel, then stopped"
        );
        assert!(
            !rig.events.has("device-unreachable"),
            "a stop raises no alarm"
        );
    }

    /// D-EIP-35: the wire representation each reply declared reaches the shared per-instance state
    /// the command surface reads, so `sb/signals` can report `observedType` without a device
    /// round-trip. The loop is the only place that sees every reading, which is why the recording
    /// lives here rather than in the session.
    #[tokio::test(start_paused = true)]
    async fn the_poll_loop_records_the_observed_representation_of_every_reading() {
        let mut rig = Rig::new(
            poll_device(one_group(100, "always")),
            global(json!({})),
            vec![Reading {
                observed_type: Some("DWORD".to_string()),
                ..reading("LINE_SPEED", json!(1.0), Quality::Good)
            }],
        );
        assert_eq!(
            rig.health.observed_type("LINE_SPEED"),
            None,
            "nothing is claimed before the first reply"
        );
        rig.cancel_after(Duration::from_millis(250));

        rig.run().await;

        assert_eq!(
            rig.health.observed_type("LINE_SPEED").as_deref(),
            Some("DWORD"),
            "what the device declared reaches the surface sb/signals reads"
        );
    }

    /// A closed control channel is the component going down, not a link failure: `Stopped`, session
    /// closed, no alarm — otherwise shutdown looks like an outage and the supervisor reconnects.
    #[tokio::test(start_paused = true)]
    async fn control_channel_close_is_stopped_not_link_lost() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::Stopped));
        assert_eq!(rig.session.closed(), 1, "the session still closes cleanly");
        assert!(!rig.events.has("device-unreachable"));
    }

    // ---- the read path ----

    /// A connection-level read failure must not be swallowed: the session closes, the loop reports
    /// `LinkLost` so the ladder backs off, `readErrors` counts, and the cycle is attributed as an
    /// **error** poll cycle (§8.4 result=error) rather than vanishing.
    #[tokio::test(start_paused = true)]
    async fn read_error_closes_session_and_returns_link_lost_with_error_cycle_recorded() {
        let mut rig = Rig::simple(50, "always", json!(1.0));
        rig.session
            .push_read_err(DeviceError::Transient(anyhow::anyhow!("connection reset")));

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::LinkLost));
        assert_eq!(
            rig.session.closed(),
            1,
            "the broken session is closed before backing off"
        );
        assert_eq!(rig.health.read_errors.load(Ordering::Relaxed), 1);
        assert_eq!(rig.sink.count(), 0, "a failed read publishes nothing");

        rig.dm.emit_periodic().await;
        assert_eq!(
            rig.metrics.sum(POLL, "pollCyclesTotal"),
            1.0,
            "the failed cycle is still counted (result=error), not dropped"
        );
        assert_eq!(
            rig.metrics.sum(POLL, "tagReadsTotal"),
            1.0,
            "the attempted tag reads are attributed to the error cycle"
        );
    }

    /// Each group keeps its own cadence, and a cycle that overran its interval re-arms to `now`
    /// (`(deadline+interval).max(now)`) instead of replaying every missed tick as a burst.
    #[tokio::test(start_paused = true)]
    async fn groups_poll_on_their_own_cadence_and_rearm_without_catchup_storm() {
        let cfg = poll_device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [
                { "id": "fast", "pollIntervalMs": 100, "publishMode": "always",
                  "signals": [ { "name": "fast-sig", "tagPath": "FAST", "type": "real" } ] },
                { "id": "slow", "pollIntervalMs": 500, "publishMode": "always",
                  "signals": [ { "name": "slow-sig", "tagPath": "SLOW", "type": "real" } ] }
            ]
        }));
        let mut rig = Rig::new(
            cfg,
            global(json!({})),
            vec![
                reading("FAST", json!(1.0), Quality::Good),
                reading("SLOW", json!(2.0), Quality::Good),
            ],
        );
        // The first cycle takes 450 ms — 4.5 fast intervals' worth of missed ticks.
        rig.session.push_read_delay(Duration::from_millis(450));
        rig.cancel_after(Duration::from_millis(1_100));

        rig.run().await;

        assert_eq!(
            rig.published("SLOW"),
            2,
            "the slow group keeps its own 500 ms cadence, unaffected by the fast group"
        );
        let fast = rig.published("FAST");
        assert!(
            (5..=8).contains(&fast),
            "the 450 ms stall costs at most ONE catch-up poll, not a replay of every missed \
             100 ms tick (got {fast} fast polls in 1.1 s)"
        );

        rig.dm.emit_periodic().await;
        assert_eq!(
            rig.metrics.sum(POLL, "pollOverrunsTotal"),
            1.0,
            "exactly the stalled cycle is flagged as an overrun"
        );
    }

    /// The loop flushes closed batch windows **before** polling, so a flush that coincides with a
    /// poll carries the samples of the window that just closed — not the sample the imminent poll is
    /// about to produce — and every such publish is attributed `from_batch` (§8.5).
    #[tokio::test(start_paused = true)]
    async fn batch_windows_flush_before_the_next_poll_and_attribute_from_batch() {
        let cfg = poll_device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "defaults": { "batchMs": 200 },
            "pollGroups": [ {
                "id": "fast", "pollIntervalMs": 100, "publishMode": "always",
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ]
            } ]
        }));
        let mut rig = Rig::new(
            cfg,
            global(json!({})),
            vec![reading("LINE_SPEED", json!(1.0), Quality::Good)],
        );
        rig.cancel_after(Duration::from_millis(650));

        rig.run().await;

        let updates = rig.sink.updates();
        assert_eq!(updates.len(), 2, "two 200 ms windows closed in the run");
        assert_eq!(
            rig.sink.samples(),
            4,
            "no sample was lost or duplicated across the windows"
        );
        for u in &updates {
            assert_eq!(
                u.samples.len(),
                2,
                "the window that closed at a poll deadline carries its OWN two samples — the \
                 coincident poll's sample belongs to the next window"
            );
        }

        rig.dm.emit_periodic().await;
        assert_eq!(rig.metrics.sum(PUBLISH, "dataMessagesPublishedTotal"), 2.0);
        assert_eq!(
            rig.metrics.sum(PUBLISH, "batchFlushesTotal"),
            2.0,
            "every publish here is a coalescing-window flush"
        );
        assert_eq!(rig.metrics.all(PUBLISH)[0]["batchSize"], 2.0);
    }

    // ---- pause / resume ----

    /// §7.4.3: while paused no polls flow, so a cheap keepalive probe keeps `connected` truthful —
    /// and a probe failure drives the normal reconnect path instead of leaving a stale `connected`.
    #[tokio::test(start_paused = true)]
    async fn paused_loop_probes_keepalive_and_probe_failure_reconnects() {
        let mut rig = Rig::new(
            poll_device(one_group(100, "always")),
            global(json!({ "healthThresholds": { "keepaliveProbeIntervalMs": 200 } })),
            vec![reading("LINE_SPEED", json!(1.0), Quality::Good)],
        );
        // The first probe answers; the second fails.
        rig.session.push_probe(Ok(()));
        rig.session
            .push_probe(Err(DeviceError::Transient(anyhow::anyhow!(
                "no route to host"
            ))));
        let (reply, paused) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(10),
            DeviceControl::Pause {
                by: Some("site/op".into()),
                reply,
            },
        );

        let exit = rig.run().await;

        assert!(paused.await.expect("the pause was acknowledged"));
        assert!(
            matches!(exit, PollExit::LinkLost),
            "a dead keepalive is a lost link"
        );
        assert_eq!(rig.session.closed(), 1);
        assert_eq!(rig.health.read_errors.load(Ordering::Relaxed), 1);
        assert_eq!(
            rig.session.reads_done(),
            0,
            "no polls flow while paused (D-EIP-14)"
        );
        assert!(rig.events.has("adapter-paused"));
    }

    /// §7.4.5 / §9.3: resuming re-arms every group deadline from *now* (no catch-up storm for the
    /// paused span) and re-bases the staleness clock (a paused signal is paused, not stale).
    #[tokio::test(start_paused = true)]
    async fn pause_resume_rebase_deadlines_and_staleness() {
        let mut rig = Rig::new(
            poll_device(one_group(100, "always")),
            global(json!({
                "metricsIntervalSecs": 1,
                "healthThresholds": { "staleSignalSecs": 1, "keepaliveProbeIntervalMs": 60000 }
            })),
            vec![reading("LINE_SPEED", json!(1.0), Quality::Good)],
        );
        let (p_tx, p_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(250),
            DeviceControl::Pause {
                by: None,
                reply: p_tx,
            },
        );
        let (r_tx, r_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(3_000),
            DeviceControl::Resume { reply: r_tx },
        );
        rig.cancel_after(Duration::from_millis(3_250));

        rig.run().await;

        assert!(
            p_rx.await.unwrap() && r_rx.await.unwrap(),
            "both transitions changed state"
        );
        assert_eq!(
            rig.session.reads_done(),
            4,
            "2 polls before the pause + 2 after the resume — the 2.75 s paused span is NOT \
             replayed as ~27 catch-up polls"
        );
        let rows = rig.metrics.all(HEALTH);
        assert!(
            rows.len() >= 3,
            "the health cadence kept emitting while paused"
        );
        assert!(
            rows.iter().all(|v| v["staleSignals"] == 0.0),
            "staleness is suspended while paused and re-based on resume, so the 2.75 s quiet \
             span never counts against a 1 s threshold"
        );
        assert!(rig.events.has("adapter-paused") && rig.events.has("adapter-resumed"));
    }

    // ---- the control verbs (§7) ----

    /// `sb/write` is confirmed: the value reaches the session, the ack carries the outcome, and a
    /// rejected write counts against `southbound_health.writeErrors` (§8.1).
    #[tokio::test(start_paused = true)]
    async fn write_verb_journals_and_failure_counts_write_errors() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        let spec = rig.cfg.signals().next().unwrap().clone();
        let (ok_tx, ok_rx) = oneshot::channel();
        let (bad_tx, bad_rx) = oneshot::channel();
        let tx = rig.control();
        tx.send(DeviceControl::Write(WriteRequest {
            signal: spec.clone(),
            value: json!(42.0),
            ack: ok_tx,
        }))
        .await
        .unwrap();
        // The device starts rejecting writes, then a second one arrives.
        let session = Arc::clone(&rig.session);
        let later = rig.control();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            session.fail_writes("CIP 0x0C: object state conflict");
            later
                .send(DeviceControl::Write(WriteRequest {
                    signal: spec,
                    value: json!(7.0),
                    ack: bad_tx,
                }))
                .await
                .unwrap();
        });
        drop(tx);
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::Stopped));
        assert!(ok_rx.await.unwrap().is_ok(), "the confirmed write is acked");
        let err = bad_rx
            .await
            .unwrap()
            .expect_err("the rejected write is acked as a failure");
        assert!(
            err.contains("object state conflict"),
            "the device's reason reaches the caller"
        );
        assert_eq!(
            rig.session.writes(),
            vec![
                ("LINE_SPEED".to_string(), json!(42.0)),
                ("LINE_SPEED".to_string(), json!(7.0)),
            ],
            "both writes reached the wire, in order"
        );
        assert_eq!(rig.health.write_errors.load(Ordering::Relaxed), 1);
    }

    /// §7.2: an on-demand read serializes with the loop — and a connection-level failure on it is a
    /// lost link (the caller gets the reason; the ladder backs off).
    #[tokio::test(start_paused = true)]
    async fn read_now_error_is_link_lost() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        let specs: Vec<_> = rig.cfg.signals().cloned().collect();
        rig.session
            .push_read_err(DeviceError::Transient(anyhow::anyhow!("session timed out")));
        let (tx, rx) = oneshot::channel();
        rig.control()
            .send(DeviceControl::ReadNow { specs, reply: tx })
            .await
            .unwrap();

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::LinkLost));
        assert!(rx.await.unwrap().unwrap_err().contains("session timed out"));
        assert_eq!(rig.session.closed(), 1);
        assert_eq!(rig.health.read_errors.load(Ordering::Relaxed), 1);
    }

    /// §7.5: browse answers a page, maps an `Unsupported` backend to `BROWSE_UNSUPPORTED`, and maps
    /// any other failure to `BROWSE_FAILED` — **without** breaking the link.
    #[tokio::test(start_paused = true)]
    async fn browse_unsupported_maps_to_browse_error() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        rig.session.push_browse(Ok(BrowsePage {
            tags: vec![BrowsedTag {
                name: "LINE_SPEED".into(),
                type_name: "REAL".into(),
                array_dim: None,
                instance_id: 1,
            }],
            next_cursor: None,
        }));
        rig.session
            .push_browse(Err(DeviceError::Unsupported("no tag-list service")));
        rig.session
            .push_browse(Err(DeviceError::Transient(anyhow::anyhow!(
                "browse timed out"
            ))));

        let tx = rig.control();
        let (a_tx, a_rx) = oneshot::channel();
        let (b_tx, b_rx) = oneshot::channel();
        let (c_tx, c_rx) = oneshot::channel();
        for reply in [a_tx, b_tx, c_tx] {
            tx.send(DeviceControl::Browse {
                cursor: None,
                max: 50,
                reply,
            })
            .await
            .unwrap();
        }
        drop(tx);
        rig.close_control();

        let exit = rig.run().await;

        assert!(
            matches!(exit, PollExit::Stopped),
            "a browse failure never breaks the link"
        );
        assert_eq!(a_rx.await.unwrap().ok().map(|p| p.tags.len()), Some(1));
        assert!(matches!(b_rx.await.unwrap(), Err(BrowseError::Unsupported)));
        assert!(
            matches!(c_rx.await.unwrap(), Err(BrowseError::Failed(m)) if m.contains("browse timed out"))
        );
    }

    /// §7.5: `repoll` is refused while paused (it would publish through a deliberately quiet
    /// instance) and polls every group once when running.
    #[tokio::test(start_paused = true)]
    async fn repoll_while_paused_refused() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        let tx = rig.control();
        let (p_tx, _p_rx) = oneshot::channel();
        tx.send(DeviceControl::Pause {
            by: None,
            reply: p_tx,
        })
        .await
        .unwrap();
        let (r1_tx, r1_rx) = oneshot::channel();
        tx.send(DeviceControl::Repoll { reply: r1_tx })
            .await
            .unwrap();
        let (res_tx, _res_rx) = oneshot::channel();
        tx.send(DeviceControl::Resume { reply: res_tx })
            .await
            .unwrap();
        let (r2_tx, r2_rx) = oneshot::channel();
        tx.send(DeviceControl::Repoll { reply: r2_tx })
            .await
            .unwrap();
        drop(tx);
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::Stopped));
        assert!(
            r1_rx.await.unwrap().unwrap_err().contains("paused"),
            "a paused instance refuses repoll and says why"
        );
        assert_eq!(
            r2_rx.await.unwrap().unwrap(),
            1,
            "the resumed repoll read the group's signal"
        );
        assert_eq!(rig.published("LINE_SPEED"), 1, "and published it");
    }

    /// Push-only verbs never route to a poll task; if one arrives it is answered, not dropped — a
    /// dropped reply hangs the caller until its command timeout.
    #[tokio::test(start_paused = true)]
    async fn push_verbs_answered_defensively() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        let field = crate::config::IoFieldSpec {
            name: "motor-run".into(),
            offset: 0,
            eip_type: crate::config::EipType::Udint,
            bit: None,
            array_count: None,
            scale: None,
            value_offset: None,
            deadband: None,
        };
        let tx = rig.control();
        let (s_tx, s_rx) = oneshot::channel();
        tx.send(DeviceControl::Snapshot { reply: s_tx })
            .await
            .unwrap();
        let (w_tx, w_rx) = oneshot::channel();
        tx.send(DeviceControl::WriteOutput {
            field,
            value: json!(1),
            reply: w_tx,
        })
        .await
        .unwrap();
        drop(tx);
        rig.close_control();

        let exit = rig.run().await;

        assert!(matches!(exit, PollExit::Stopped));
        assert!(
            s_rx.await.unwrap().is_none(),
            "a poll instance has no input snapshot"
        );
        assert!(w_rx
            .await
            .unwrap()
            .unwrap_err()
            .contains("not a push instance"));
    }

    /// §7.5: an explicit `reconnect` closes the session and **carries its reply out** of the loop,
    /// so the connect ladder can fulfil it after the next attempt resolves. A dropped reply leaves
    /// the `sb/reconnect` caller hanging.
    #[tokio::test(start_paused = true)]
    async fn reconnect_verb_closes_session_and_carries_reply() {
        let mut rig = Rig::simple(60_000, "always", json!(1.0));
        let (tx, rx) = oneshot::channel();
        rig.control()
            .send(DeviceControl::Reconnect { reply: tx })
            .await
            .unwrap();

        let exit = rig.run().await;

        let PollExit::Reconnect(reply) = exit else {
            panic!("an explicit reconnect must exit as Reconnect, carrying its reply");
        };
        assert_eq!(
            rig.session.closed(),
            1,
            "the session is dropped before re-establishing"
        );
        // The ladder fulfils it after the next connect resolves — the channel is still live.
        reply
            .send(Ok(()))
            .expect("the reply sender survived the exit");
        assert!(rx.await.unwrap().is_ok());
    }

    // ---- publish accounting (§8.5) ----

    /// A publish failure is accounted as a failure (and does NOT count as published signals); a
    /// success records the sample count and the measured publish latency — **and** the failure does
    /// not advance the onChange baseline, so the identical next reading is republished rather than
    /// suppressed for the rest of the session (D-EIP-32).
    ///
    /// The onChange baseline is the last *published* value: a value whose publish failed never
    /// reached the bus, so it may not suppress anything. Scripted per-publish outcomes (not a timer)
    /// decide which attempt fails, so the sequence is a property of the run, not of a race.
    #[tokio::test(start_paused = true)]
    async fn publish_failure_is_accounted_and_the_identical_value_is_republished() {
        let mut rig = Rig::simple(100, "onChange", json!(2.0));
        // Reads: 1.0 → 2.0 → 2.0, then 2.0 forever. Publishes: ok, FAIL, ok.
        rig.session
            .push_read(vec![reading("LINE_SPEED", json!(1.0), Quality::Good)]);
        rig.session
            .push_read(vec![reading("LINE_SPEED", json!(2.0), Quality::Good)]);
        rig.sink.push_result(true);
        rig.sink.push_result(false);
        rig.sink.push_result(true);
        rig.cancel_after(Duration::from_millis(450));

        rig.run().await;

        let values: Vec<_> = rig
            .sink
            .updates()
            .iter()
            .map(|u| u.samples[0].value.clone())
            .collect();
        assert_eq!(
            values,
            vec![Some(json!(1.0)), Some(json!(2.0)), Some(json!(2.0))],
            "the reading whose publish failed is republished on its next occurrence; once THAT \
             publish is confirmed, the fourth poll's unchanged 2.0 is suppressed again"
        );
        assert_eq!(
            rig.health.signals_published.load(Ordering::Relaxed),
            2,
            "only the successful publishes count as published"
        );

        rig.dm.emit_periodic().await;
        let row = rig.metrics.all(PUBLISH).remove(0);
        assert_eq!(row["dataMessagesPublishedTotal"], 3.0);
        assert_eq!(
            row["samplesPublishedTotal"], 2.0,
            "a failed publish contributes no samples"
        );
        assert_eq!(row["publishFailuresTotal"], 1.0);
        assert!(
            row.contains_key("publishLatencyMs"),
            "the success recorded a latency"
        );
    }

    /// The other half of D-EIP-32's retry rule: a failed publish must not over-suppress *later,
    /// different* values either. The deadband is measured from the last **published** value, so a
    /// reading that moved past the band relative to it publishes — even though it sits inside the
    /// band around the value whose publish failed.
    #[tokio::test(start_paused = true)]
    async fn a_failed_publish_does_not_shrink_the_deadband_window_for_later_values() {
        let cfg = poll_device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [ {
                "id": "fast", "pollIntervalMs": 100, "publishMode": "onChange",
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real",
                               "deadband": { "type": "absolute", "value": 1.0 } } ]
            } ]
        }));
        let mut rig = Rig::new(
            cfg,
            global(json!({})),
            vec![reading("LINE_SPEED", json!(11.5), Quality::Good)],
        );
        // Reads: 10.0 (ok) → 11.0 (FAILS) → 11.5. 11.5 is only 0.5 from the failed 11.0 but 1.5
        // from the last published 10.0, so it must publish.
        rig.session
            .push_read(vec![reading("LINE_SPEED", json!(10.0), Quality::Good)]);
        rig.session
            .push_read(vec![reading("LINE_SPEED", json!(11.0), Quality::Good)]);
        rig.sink.push_result(true);
        rig.sink.push_result(false);
        rig.cancel_after(Duration::from_millis(350));

        rig.run().await;

        let values: Vec<_> = rig
            .sink
            .updates()
            .iter()
            .map(|u| u.samples[0].value.clone())
            .collect();
        assert_eq!(
            values,
            vec![Some(json!(10.0)), Some(json!(11.0)), Some(json!(11.5))],
            "the deadband is measured from 10.0 — the last value that actually reached the bus — \
             not from the 11.0 whose publish failed"
        );
    }

    /// §7.4 / D-EIP-32: pausing DISCARDS the open `batchMs` windows. Nothing is published at pause
    /// time (the instance must go quiet) and nothing pre-pause escapes on resume, so an operator
    /// never sees a burst of stale telemetry the moment they resume.
    #[tokio::test(start_paused = true)]
    async fn pause_discards_open_batch_windows_so_nothing_stale_flushes_on_resume() {
        let cfg = poll_device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "defaults": { "batchMs": 200 },
            "pollGroups": [ {
                "id": "fast", "pollIntervalMs": 100, "publishMode": "always",
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ]
            } ]
        }));
        let mut rig = Rig::new(
            cfg,
            global(json!({ "healthThresholds": { "keepaliveProbeIntervalMs": 60000 } })),
            vec![reading("LINE_SPEED", json!(1.0), Quality::Good)],
        );
        // The one pre-pause poll reads a distinctive value, so a stale flush is unmistakable.
        rig.session
            .push_read(vec![reading("LINE_SPEED", json!(42.0), Quality::Good)]);
        let (p_tx, p_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(150),
            DeviceControl::Pause {
                by: None,
                reply: p_tx,
            },
        );
        let (r_tx, r_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(1_000),
            DeviceControl::Resume { reply: r_tx },
        );
        // Long enough for the post-resume polls (1_100, 1_200) to fill and flush a fresh window.
        rig.cancel_after(Duration::from_millis(1_400));

        rig.run().await;

        assert!(p_rx.await.unwrap() && r_rx.await.unwrap());
        let updates = rig.sink.updates();
        assert!(
            updates
                .iter()
                .all(|u| u.samples.iter().all(|s| s.value != Some(json!(42.0)))),
            "the sample buffered when the pause arrived was discarded, not released on resume"
        );
        assert_eq!(
            updates.len(),
            1,
            "exactly the one window that opened AFTER the resume flushed"
        );
        assert_eq!(
            updates[0].samples.len(),
            2,
            "…carrying only its own post-resume samples"
        );
    }

    /// §8.4: each cycle attributes the *delta* of the shared sample counters, so a second cycle adds
    /// its own counts rather than re-reporting the running totals.
    #[tokio::test(start_paused = true)]
    async fn sample_snapshot_delta_attributes_cycle_counts() {
        let cfg = poll_device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [ {
                "id": "mixed", "pollIntervalMs": 100, "publishMode": "always",
                "signals": [
                    { "name": "good-sig", "tagPath": "GOOD", "type": "real" },
                    { "name": "bad-sig", "tagPath": "BAD", "type": "real" }
                ]
            } ]
        }));
        let mut rig = Rig::new(
            cfg,
            global(json!({})),
            // Cycle 2 onwards: one signal goes BAD.
            vec![
                reading("GOOD", json!(1.0), Quality::Good),
                reading("BAD", Value::Null, Quality::Bad),
            ],
        );
        // Cycle 1: both signals read GOOD — so the two cycles have DIFFERENT counts, and a snapshot
        // that reported running totals instead of deltas would show it.
        rig.session.push_read(vec![
            reading("GOOD", json!(1.0), Quality::Good),
            reading("BAD", json!(2.0), Quality::Good),
        ]);
        rig.cancel_after(Duration::from_millis(250));

        rig.run().await;
        rig.dm.emit_periodic().await;

        assert_eq!(rig.metrics.sum(POLL, "pollCyclesTotal"), 2.0);
        assert_eq!(
            rig.metrics.sum(POLL, "samplesGoodTotal"),
            3.0,
            "2 GOOD in the first cycle + 1 in the second — each cycle contributes its own delta"
        );
        assert_eq!(rig.metrics.sum(POLL, "samplesBadTotal"), 1.0);
        assert_eq!(
            rig.metrics.sum(POLL, "tagReadErrorsTotal"),
            1.0,
            "a BAD read is also a failed CIP read"
        );
        assert_eq!(
            rig.metrics.sum(POLL, "tagReadsTotal"),
            4.0,
            "2 signals × 2 cycles"
        );
    }

    /// §8.7 cadence + §9.3: the family set emits on `metricsIntervalSecs`, and the stale count is
    /// suspended while paused (it reports 0, not "everything is stale").
    #[tokio::test(start_paused = true)]
    async fn metrics_emit_on_interval_and_stale_count_suspended_while_paused() {
        // A 60 s poll interval: nothing is ever read, so the single signal goes stale after 1 s.
        let mut rig = Rig::new(
            poll_device(one_group(60_000, "always")),
            global(json!({
                "metricsIntervalSecs": 1,
                "healthThresholds": { "staleSignalSecs": 1, "keepaliveProbeIntervalMs": 60000 }
            })),
            vec![reading("LINE_SPEED", json!(1.0), Quality::Good)],
        );
        let (p_tx, _p_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(1_500),
            DeviceControl::Pause {
                by: None,
                reply: p_tx,
            },
        );
        rig.cancel_after(Duration::from_millis(2_500));

        rig.run().await;

        let rows = rig.metrics.all(HEALTH);
        assert!(
            rows.len() >= 3,
            "one emit per second, plus the pause-transition flush"
        );
        assert_eq!(
            rows[0]["staleSignals"], 1.0,
            "a signal with no GOOD read for staleSignalSecs is stale while running"
        );
        assert_eq!(
            rows[rows.len() - 1]["staleSignals"],
            0.0,
            "…and the count is suspended once paused — a paused signal is paused, not stale"
        );
        assert!(
            rig.metrics.emits(POLL) >= 1,
            "the poll family emits on the same cadence"
        );
    }
}
