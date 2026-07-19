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

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, Sample};

use crate::app::{apply_pause, DeviceControl, EventSink, Health, LinkState};
use crate::config::{DeviceConfig, GlobalConfig, PollGroup, PublishMode, SignalSpec};
use crate::device::{DeviceSession, Quality, Reading};
use crate::metrics::{DeviceMetrics, RESULT_ERROR, RESULT_SUCCESS};
use crate::publish::{self, Engine, Publish};

/// How [`poll_until_disconnected`] left the poll loop (§7.5, §10.2). The supervisor
/// ([`crate::app`]) reconnects on either — but an explicit `reconnect` skips the backoff + the
/// unreachable alarm and carries its reply to fulfill after the next connect resolves.
pub(crate) enum PollExit {
    /// The link broke (a connection-level read/probe failure) — back off and reconnect.
    LinkLost,
    /// An `sb/reconnect` asked to drop + re-establish now (§7.5).
    Reconnect(tokio::sync::oneshot::Sender<std::result::Result<(), String>>),
}

/// The per-cycle deltas of the shared [`Health`] sample counters — used to attribute one poll
/// cycle's samples to its `(pollGroup, result)` metric combo (§8.4) without threading the emitter
/// into the gating hot path.
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

/// Gate + count + batch one group's readings (§4.4, §6.2). Returns the samples to publish **now**
/// (batchMs == 0); anything buffered flushes later via [`Engine::take_due`]. Bumps the S5 counters on
/// `health`.
fn process_group(
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
fn record_cycle(elapsed: Duration, interval: Duration, health: &Health) {
    health.poll_cycles.fetch_add(1, Ordering::Relaxed);
    if publish::cycle_overran(elapsed, interval) {
        health.overruns.fetch_add(1, Ordering::Relaxed);
    }
}

/// Resolve a stable id to its configured signal and publish its samples (§6.1). Records the publish
/// latency + published-sample count on `health` and the per-`publishMode` [`EtherNetIpPublish`]
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

/// Publish one signal's samples through the mode-agnostic [`publish`] path.
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
    let (res, latency) = publish::publish(
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

#[cfg(test)]
mod tests {
    //! Poll-engine gating/batching/stale/overrun — driven with canned [`Reading`]s and a scripted
    //! mock [`DeviceSession`], no socket / no enip (§12.3).
    use super::*;
    use crate::device::{BrowsePage, DeviceError, Result as DevResult};
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
