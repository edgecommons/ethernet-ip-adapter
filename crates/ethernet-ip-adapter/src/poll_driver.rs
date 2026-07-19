//! # The poll loop driver (§3.2, §6) — the live-infra seam (excluded from coverage, §12.2)
//!
//! A **thin driver seam**: [`poll_until_disconnected`] owns one poll-mode device's session and runs
//! the scheduled read → gate → batch → publish select-loop, servicing the `sb/*` control channel in
//! line with it. Every branch here is driven by a `.await` on the [`DeviceSession`] seam (a live socket
//! against cpppo / ControlLogix) or the `data()` publish facade (a live broker); the **pure decisions**
//! it composes — the deadband/change/batch/stale gating ([`crate::poll::process_group`]), the overrun
//! accounting ([`crate::poll::record_cycle`]), the [`crate::publish`] gate primitives — are unit-tested
//! in their home modules. The loop itself is validated by the live cpppo suite (§11) and the S9 deployed
//! regression, exactly as `file-replicator` validates its `dest/*/client.rs` seams.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, Sample};

use crate::app::{apply_pause, DeviceControl, EventSink, Health, LinkState};
use crate::config::{DeviceConfig, GlobalConfig, PollGroup, PublishMode, SignalSpec};
use crate::device::DeviceSession;
use crate::metrics::{DeviceMetrics, RESULT_ERROR, RESULT_SUCCESS};
use crate::poll::{process_group, record_cycle};
use crate::publish::{self, Engine};

/// How [`poll_until_disconnected`] left the poll loop (§7.5, §10.2). The supervisor
/// ([`crate::supervisor`]) reconnects on either — but an explicit `reconnect` skips the backoff + the
/// unreachable alarm and carries its reply to fulfill after the next connect resolves.
pub(crate) enum PollExit {
    /// The link broke (a connection-level read/probe failure) — back off and reconnect.
    LinkLost,
    /// An `sb/reconnect` asked to drop + re-establish now (§7.5).
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll_until_disconnected(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    mut session: Box<dyn DeviceSession>,
    data: &DataFacade,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    adapter: &str,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    events: &dyn EventSink,
    keepalive_ms: u64,
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
    let mut engine = Engine::new(start);
    let mut deadlines: Vec<Instant> = intervals.iter().map(|d| start + *d).collect();
    let mut since_health = start;
    let mut since_keepalive = start;
    // A pause that arrived while the link was down carries in through the shared flag (§9.2).
    let mut paused = health.paused.load(Ordering::Relaxed);

    loop {
        // Earliest wake: while running, the nearest group deadline / batch close / health emit; while
        // paused, only the health emit and the keepalive probe (no ticks flow, D-EIP-14/§7.4).
        let mut wake = since_health + metrics_interval;
        if paused {
            wake = wake.min(since_keepalive + keepalive);
        } else {
            wake = wake.min(*deadlines.iter().min().expect("at least one poll group"));
            if let Some(bd) = engine.next_batch_deadline(batch_ms) {
                wake = wake.min(bd);
            }
        }
        let wait = wake.saturating_duration_since(Instant::now());

        tokio::select! {
            biased;

            // Every session-touching verb shares this one task, so it can never race a read on the
            // same connection (§7).
            ctrl = control.recv() => {
                let Some(ctrl) = ctrl else {
                    // The control channel closed (component shutting down) — leave cleanly.
                    session.close().await;
                    return PollExit::LinkLost;
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
                        paused = true;
                        let _ = reply.send(changed);
                    }
                    DeviceControl::Resume { reply } => {
                        let changed = apply_pause(cfg, health, dm, events, false, None).await;
                        if changed {
                            // Re-base staleness so the paused span doesn't count (§7.4.5/§9.3).
                            engine.rebase_stale(Instant::now());
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
                                data, cfg, dm, health, adapter,
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
            for p in engine.take_due(batch_ms, now) {
                let mode = mode_of.get(&p.signal_id).copied().unwrap_or_else(|| PublishMode::OnChange.as_str());
                publish_by_id(data, cfg, adapter, &p.signal_id, p.samples, health, dm, mode, true).await;
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
                        dm.record_poll_cycle(&group_id, RESULT_ERROR, 0, tag_reads, false, 0, 0, 0, 0, 0);
                        session.close().await;
                        return PollExit::LinkLost;
                    }
                };
                let elapsed = started.elapsed();
                let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
                health.poll_latency_ms.store(elapsed_ms, Ordering::Relaxed);
                record_cycle(elapsed, intervals[idx], health);

                let now2 = Instant::now();
                for p in process_group(&mut engine, group, modes[idx], batch_ms, &readings, now2, health) {
                    let mode = mode_of.get(&p.signal_id).copied().unwrap_or_else(|| modes[idx].as_str());
                    publish_by_id(data, cfg, adapter, &p.signal_id, p.samples, health, dm, mode, false).await;
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
                engine.count_stale(cfg.signals().map(|s| s.tag_path.as_str()), stale_secs, now)
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
    data: &DataFacade,
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
        polled += group.signals.len() as u64;
        let now = Instant::now();
        for p in process_group(engine, group, modes[idx], batch_ms, &readings, now, health) {
            let mode = mode_of.get(&p.signal_id).copied().unwrap_or_else(|| modes[idx].as_str());
            publish_by_id(data, cfg, adapter, &p.signal_id, p.samples, health, dm, mode, false).await;
        }
    }
    Ok(polled)
}

/// Resolve a stable id to its configured signal and publish its samples (§6.1). Records the publish
/// latency + published-sample count on `health` and the per-`publishMode` [`crate::metrics::PUBLISH`]
/// counters on `dm` (§8.5). `from_batch` marks a coalescing-window flush.
#[allow(clippy::too_many_arguments)]
async fn publish_by_id(
    data: &DataFacade,
    cfg: &DeviceConfig,
    adapter: &str,
    signal_id: &str,
    samples: Vec<Sample>,
    health: &Health,
    dm: &DeviceMetrics,
    publish_mode: &'static str,
    from_batch: bool,
) {
    let Some(spec) = cfg.find_signal(signal_id) else {
        return;
    };
    publish_samples(data, cfg, adapter, spec, samples, health, dm, publish_mode, from_batch).await;
}

/// Publish one signal's samples through the mode-agnostic [`crate::publish_sink`] path.
#[allow(clippy::too_many_arguments)]
async fn publish_samples(
    data: &DataFacade,
    cfg: &DeviceConfig,
    adapter: &str,
    spec: &SignalSpec,
    samples: Vec<Sample>,
    health: &Health,
    dm: &DeviceMetrics,
    publish_mode: &'static str,
    from_batch: bool,
) {
    let n = samples.len() as u64;
    let (res, latency) = crate::publish_sink::publish(
        data,
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
            health.publish_latency_ms.store(latency_ms, Ordering::Relaxed);
            dm.record_publish(publish_mode, n, from_batch, latency_ms, true);
        }
        Err(e) => {
            tracing::warn!(instance = %cfg.id, tag_path = %spec.tag_path, error = %e, "publish failed");
            dm.record_publish(publish_mode, n, from_batch, latency_ms, false);
        }
    }
}
