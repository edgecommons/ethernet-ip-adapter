//! # Transactional configuration reload (§10.4, D-EIP-28)
//!
//! The adapter applies a configuration change as **one transaction over the live instance set**: a
//! pure diff ([`plan`]) decides which instances keep running, which stop, and which start, and a
//! [`ReloadTransaction`] performs that swap under the same deadline-bounded stop engine shutdown
//! uses ([`crate::lifecycle`]).
//!
//! ## The core contract this implements (verified against `edgecommons` 0.5.0)
//!
//! Exactly **one** [`ConfigurationApplyListener`] may be registered per runtime, and core drives it
//! in a fixed order:
//!
//! 1. `prepare_configuration_apply(candidate)` runs under
//!    `tokio::time::timeout(validation_timeout, …)` (default 5 s) and **must not change the live
//!    runtime**. Ours is allocation-only: parse, diff, stage — no sockets, no broker, no spawns.
//! 2. `commit()` is awaited with **no external timeout** ("deliberately not externally cancelled"),
//!    while the *old* snapshot is still `gg.config()`. It must therefore bound its own stages — ours
//!    does, through [`crate::lifecycle::stop_budget`]. Core stores the candidate and bumps the
//!    generation only **after** commit returns `Ok`.
//! 3. On a commit `Err`, core awaits `rollback()` fully, then rejects the candidate and keeps the
//!    prior snapshot. A prepare `Err`/timeout rejects the candidate with nothing else called.
//!
//! Because the whole sequence is serialized by core's apply lock, this one coordinator serves every
//! reload source — the `-c FILE` watcher, a Kubernetes ConfigMap update, `GG_CONFIG`, and the
//! built-in `reload-config` verb.
//!
//! ## Granularity: instance-diff restart (D-EIP-28)
//!
//! Only added, removed, and changed instances restart. **Any change outside `component.instances`**
//! — `component.global`, but also `topic`, `hierarchy`/`identity`, `tags`, `credentials`,
//! `metricEmission`, … — restarts **every** instance, because facades, UNS identity, and
//! [`crate::metrics::DeviceMetrics`] bind those at spawn from the configuration snapshot; keeping an
//! instance running across such a change would publish on stale topics or with a stale identity.
//!
//! Consequence, stated plainly rather than hidden: an untouched instance keeps its session, its
//! `Arc<GlobalConfig>`, and its in-memory pause state; an instance that restarts **loses its pause
//! state** (pause is in-memory — D-EIP-14) and reconnects with a fresh session.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use edgecommons::prelude::{
    Config, ConfigurationApplicationError, ConfigurationApplicationResult,
    ConfigurationApplyListener, PreparedConfigurationApply, Severity,
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::app::EventSink;
use crate::config::{DeviceConfig, GlobalConfig};
use crate::lifecycle::{DeviceRegistry, DeviceRuntime};

/// A reload arrived before the startup launch loop finished: rejected, because applying a diff
/// against a half-populated registry would double-start instances.
const CODE_STARTING: &str = "STARTING";
/// A reload arrived after the shutdown root was cancelled: rejected, because commit would open
/// device sessions the teardown has already stopped waiting for.
const CODE_SHUTTING_DOWN: &str = "SHUTTING_DOWN";
/// The candidate's `component.global` does not parse (unknown key, wrong type).
const CODE_INVALID_GLOBAL: &str = "INVALID_GLOBAL";
/// The candidate declares no instance this adapter can run — the reload-time analog of startup's
/// refuse-to-start. The running generation keeps operating.
const CODE_NO_VALID_INSTANCES: &str = "NO_VALID_INSTANCES";
/// Every launch failed and nothing was kept, so the commit would leave the adapter with no device.
const CODE_NO_RUNNING_INSTANCES: &str = "NO_RUNNING_INSTANCES";
/// A rollback could not relaunch one of the instances it stopped. Core wraps this in its own
/// `CONFIG_APPLICATION_ROLLBACK_FAILED` validation error.
const CODE_ROLLBACK_RELAUNCH_FAILED: &str = "ROLLBACK_RELAUNCH_FAILED";

/// How long a commit waits for one operator notification (an alarm clear, the `config-applied`
/// event) before giving up on it and moving on.
///
/// A plain publish awaits a funnel send and a submission ack with no timeout of its own, so a wedged
/// broker or a saturated publish funnel would otherwise stall a commit — which core never cancels —
/// while it holds the apply lock, queueing every later reload behind it. Generous enough that a
/// healthy broker always makes it, short enough that an unhealthy one costs a reload seconds, not
/// forever. A notification that misses it is logged; a reload is never failed over one.
const NOTIFY_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Await one best-effort operator notification under [`NOTIFY_BUDGET`], logging (never failing) when
/// it does not make it out in time.
async fn notify(publish: impl std::future::Future<Output = ()>, instance: Option<&str>, what: &str) {
    if tokio::time::timeout(NOTIFY_BUDGET, publish).await.is_err() {
        tracing::warn!(
            instance = instance.unwrap_or("-"),
            budget_ms = NOTIFY_BUDGET.as_millis() as u64,
            "{what} did not complete within the notification budget; continuing the reload"
        );
    }
}

// =====================================================================================
// The pure diff (§10.4) — every decision here is unit-tested inside the coverage gate
// =====================================================================================

/// The raw document with `component.instances` removed: the "everything else" view whose change
/// restarts every instance (D-EIP-28). Pure.
pub(crate) fn non_instance_view(raw: &Value) -> Value {
    let mut view = raw.clone();
    if let Some(component) = view.get_mut("component").and_then(Value::as_object_mut) {
        component.remove("instances");
    }
    view
}

/// The candidate's `(id, raw subtree)` list in declaration order: entries without an `id` are
/// skipped and a duplicate id resolves to the **first** subtree — exactly what `Config::instance`
/// and `Config::instance_ids` do, so the plan can never disagree with the snapshot it was built
/// from. Pure.
pub(crate) fn candidate_instances(candidate_raw: &Value) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    let Some(entries) = candidate_raw
        .get("component")
        .and_then(|c| c.get("instances"))
        .and_then(Value::as_array)
    else {
        return out;
    };
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if out.iter().any(|(seen, _)| seen == id) {
            tracing::warn!(
                instance = %id,
                "duplicate id in component.instances[]; keeping the first declaration"
            );
            continue;
        }
        out.push((id.to_string(), entry.clone()));
    }
    out
}

/// One instance as both startup and the reload plan see it: its parsed configuration plus the raw
/// `component.instances[]` subtree the diff compares and a rollback relaunches from.
pub(crate) type ParsedInstance = (DeviceConfig, Value);

/// `(instance id, why it was skipped)` — the skip-bad report, warned and surfaced, never fatal.
pub(crate) type SkippedInstance = (String, String);

/// Every instance in `raw` this adapter can run, in declaration order, paired with its raw subtree —
/// plus the `(id, parse error)` of the ones it cannot.
///
/// **Startup and reload share this function**, which is what makes the two paths agree on the same
/// instance set: duplicate ids resolve first-wins (so a document declaring `plc-1` twice launches it
/// **once**, against the subtree `Config::instance` also returns), entries without an `id` are
/// invisible, and a malformed entry is skipped rather than fatal (§4.4). A startup that deduped
/// differently from the plan would strand the extra runtime forever — the reload would stop the id
/// once and the surplus one would keep polling the device on the retired configuration.
pub(crate) fn parse_instances(raw: &Value) -> (Vec<ParsedInstance>, Vec<SkippedInstance>) {
    let mut valid = Vec::new();
    let mut skipped = Vec::new();
    for (id, subtree) in candidate_instances(raw) {
        match DeviceConfig::from_value(&subtree) {
            Ok(cfg) => valid.push((cfg, subtree)),
            Err(e) => skipped.push((id, e)),
        }
    }
    (valid, skipped)
}

/// Why a candidate cannot be planned at all — the candidate is rejected and the running generation
/// keeps operating untouched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReloadPlanError {
    /// `component.global` failed to parse.
    InvalidGlobal(String),
    /// Zero valid instances after skip-bad. (Contrast startup, where zero-valid refuses to start:
    /// at reload time the running generation is still there, so the *candidate* is refused.)
    NoValidInstances,
}

impl std::fmt::Display for ReloadPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGlobal(e) => write!(f, "{e}"),
            Self::NoValidInstances => write!(
                f,
                "no valid instance in component.instances[]; keeping the running configuration"
            ),
        }
    }
}

/// What the transaction will do to the live instance set.
#[derive(Debug)]
pub(crate) struct ReloadPlan {
    /// `true` ⇒ every running instance restarts (something outside `component.instances` changed).
    pub restart_all: bool,
    /// The candidate's parsed `component.global`.
    pub global: Arc<GlobalConfig>,
    /// Untouched instances — session, facades, `Arc<GlobalConfig>`, and pause state all survive.
    pub keep: Vec<String>,
    /// Instances to stop: removed + changed + (when `restart_all`) every running one.
    pub stop: Vec<String>,
    /// Instances to launch: added + changed + (when `restart_all`) every surviving one.
    pub start: Vec<(DeviceConfig, Value)>,
    /// The subset of `stop` with no successor in the candidate — these get their `device-unreachable`
    /// alarm cleared, because nothing will ever clear it for them again.
    pub removed: Vec<String>,
    /// `(id, parse error)` for malformed instances: warned, never fatal (startup parity).
    pub skipped: Vec<(String, String)>,
}

/// THE reload decision. Pure — no clock, no I/O, no registry mutation.
///
/// `running` is the registry's `(id, raw)` snapshot, **not** the previous `Config`: an instance that
/// was skipped at startup (malformed then, valid now, raw unchanged) is absent from `running` and so
/// correctly plans as a Start. Raw comparison is `serde_json`'s structural equality —
/// object-key-order-insensitive, array-order-sensitive — so a re-serialized ConfigMap with reordered
/// keys does not churn every device.
///
/// # Errors
/// [`ReloadPlanError::InvalidGlobal`] when `component.global` does not parse, and
/// [`ReloadPlanError::NoValidInstances`] when the candidate contains no instance this adapter can
/// run. Both reject the candidate.
pub(crate) fn plan(
    running: &[(String, Value)],
    running_non_instance: &Value,
    candidate_raw: &Value,
) -> std::result::Result<ReloadPlan, ReloadPlanError> {
    let global_raw = candidate_raw
        .get("component")
        .and_then(|c| c.get("global"))
        .cloned()
        .unwrap_or(Value::Null);
    let global = GlobalConfig::from_value(&global_raw).map_err(ReloadPlanError::InvalidGlobal)?;

    // Anything outside `component.instances` binds at spawn (facades, identity, topics, metric
    // dimensions), so a change there is a fleet-wide restart.
    let restart_all = non_instance_view(candidate_raw) != *running_non_instance;

    let mut keep = Vec::new();
    let mut stop = Vec::new();
    let mut start = Vec::new();
    // Skip-bad-instance and duplicate-id first-wins come from the SAME helper startup uses, so the
    // instance set a reload plans over is exactly the set startup would have launched.
    let (candidate, skipped) = parse_instances(candidate_raw);
    // Every candidate instance this adapter can run — the successor set the removal pass reads.
    let mut valid: Vec<String> = Vec::new();

    for (cfg, raw) in candidate {
        let id = cfg.id.clone();
        valid.push(id.clone());
        match running.iter().find(|(running_id, _)| *running_id == id) {
            Some((_, running_raw)) if !restart_all && *running_raw == raw => keep.push(id),
            Some(_) => {
                stop.push(id);
                start.push((cfg, raw));
            }
            None => start.push((cfg, raw)),
        }
    }

    if keep.is_empty() && start.is_empty() {
        return Err(ReloadPlanError::NoValidInstances);
    }

    // Running instances the candidate no longer declares (or declares malformed): stop them, and
    // record that nothing succeeds them so the transaction can clear their latched alarm.
    let mut removed = Vec::new();
    for (id, _) in running {
        if !valid.iter().any(|valid_id| valid_id == id) {
            stop.push(id.clone());
            removed.push(id.clone());
        }
    }

    Ok(ReloadPlan {
        restart_all,
        global: Arc::new(global),
        keep,
        stop,
        start,
        removed,
        skipped,
    })
}

// =====================================================================================
// The launcher seam
// =====================================================================================

/// Builds and **starts** one instance's runtime, bound to a specific configuration snapshot.
///
/// Production ([`crate::supervisor`]) mints the instance facades from that snapshot via
/// `EdgeCommons::instance_from_config_snapshot`, builds the `Health`/`DeviceMetrics` (with the same
/// snapshot, so metric identity follows the candidate), spawns the device task (plus the
/// cert-lifecycle task on a TLS poll instance) under a child of the app root token, and defines the
/// metric families. Startup and reload go through the SAME implementation, which is what keeps
/// skip-bad, facade binding, and metric definition provably identical in both paths.
///
/// The trait exists so the transaction below is hermetically testable: the test double records the
/// calls and spawns stub tasks that end on their token.
pub(crate) trait DeviceLauncher: Send + Sync {
    /// Launch `cfg` (raw subtree `raw`) against `global` and configuration `snapshot`.
    ///
    /// # Errors
    /// Whatever construction failed — a UNS-token violation in the instance id, or the runtime
    /// already shutting down. A failure is skipped-with-a-warning by the caller, never fatal.
    fn launch(
        &self,
        cfg: &DeviceConfig,
        raw: &Value,
        global: &Arc<GlobalConfig>,
        snapshot: &Arc<Config>,
    ) -> anyhow::Result<DeviceRuntime>;

    /// The component-scope event sink — where the `config-applied` operator event goes.
    fn component_events(&self) -> Arc<dyn EventSink>;

    /// Recompute the `repoll` verb's advertised availability for the new generation (D-EIP-25).
    fn set_repoll_availability(&self, all_push: bool);
}

// =====================================================================================
// The coordinator + the transaction
// =====================================================================================

/// The generation a reload is measured against, and the one a rollback restores.
#[derive(Clone)]
pub(crate) struct PriorGeneration {
    /// The configuration snapshot the running instances' facades are bound to.
    pub snapshot: Arc<Config>,
    /// [`non_instance_view`] of that snapshot — the restart-all comparison key.
    pub non_instance: Value,
    /// That snapshot's parsed `component.global`.
    pub global: Arc<GlobalConfig>,
}

impl PriorGeneration {
    /// The prior generation for a freshly-parsed snapshot (startup, and after every commit).
    pub fn of(snapshot: &Arc<Config>, global: &Arc<GlobalConfig>) -> Self {
        Self {
            snapshot: Arc::clone(snapshot),
            non_instance: non_instance_view(&snapshot.raw),
            global: Arc::clone(global),
        }
    }
}

/// The single [`ConfigurationApplyListener`] for this component: it owns the live instance set for
/// the duration of an apply, so a rejected candidate leaves the running generation exactly as it was.
pub(crate) struct ReloadCoordinator {
    launcher: Arc<dyn DeviceLauncher>,
    registry: Arc<DeviceRegistry>,
    /// The app root token — the shutdown gate for both prepare and commit.
    root: CancellationToken,
    /// Set once the startup launch loop has finished. A reload arriving before it is rejected, which
    /// closes the register-early window without ever double-starting an instance.
    started: Arc<AtomicBool>,
    /// The generation currently running. Replaced at the end of every successful commit. Never
    /// locked across an `.await`.
    prior: Arc<Mutex<PriorGeneration>>,
}

impl ReloadCoordinator {
    /// Build the coordinator over the live registry, seeded with the startup generation.
    pub fn new(
        launcher: Arc<dyn DeviceLauncher>,
        registry: Arc<DeviceRegistry>,
        root: CancellationToken,
        started: Arc<AtomicBool>,
        prior: PriorGeneration,
    ) -> Self {
        Self {
            launcher,
            registry,
            root,
            started,
            prior: Arc::new(Mutex::new(prior)),
        }
    }
}

#[async_trait::async_trait]
impl ConfigurationApplyListener for ReloadCoordinator {
    /// Stage the transaction. **I/O-free and allocation-only** — it parses the candidate, diffs it
    /// against the running set, and returns; it starts, stops, and publishes nothing. That is what
    /// keeps it far inside core's 5 s prepare timeout and satisfies "prepare must not change the
    /// live runtime".
    async fn prepare_configuration_apply(
        &self,
        config: Arc<Config>,
    ) -> ConfigurationApplicationResult<Box<dyn PreparedConfigurationApply>> {
        if !self.started.load(Ordering::Acquire) {
            return Err(ConfigurationApplicationError::new(
                CODE_STARTING,
                "component is still starting; re-send the change or use reload-config",
            ));
        }
        if self.root.is_cancelled() {
            return Err(ConfigurationApplicationError::new(
                CODE_SHUTTING_DOWN,
                "component is shutting down; candidate not applied",
            ));
        }

        let prior = self.prior.lock().unwrap().clone();
        let running = self.registry.snapshot_running();
        let plan = plan(&running, &prior.non_instance, &config.raw).map_err(|e| match &e {
            ReloadPlanError::InvalidGlobal(_) => {
                ConfigurationApplicationError::new(CODE_INVALID_GLOBAL, e.to_string())
            }
            ReloadPlanError::NoValidInstances => {
                ConfigurationApplicationError::new(CODE_NO_VALID_INSTANCES, e.to_string())
            }
        })?;

        for (id, reason) in &plan.skipped {
            tracing::warn!(instance = %id, error = %reason, "skipping malformed device in the reloaded configuration");
        }
        tracing::info!(
            restart_all = plan.restart_all,
            keep = plan.keep.len(),
            stop = plan.stop.len(),
            start = plan.start.len(),
            skipped = plan.skipped.len(),
            "prepared a configuration change"
        );

        Ok(Box::new(ReloadTransaction {
            undo: UndoState {
                stopped: Vec::new(),
                launched: Vec::new(),
                prior,
            },
            plan,
            snapshot: config,
            launcher: Arc::clone(&self.launcher),
            registry: Arc::clone(&self.registry),
            root: self.root.clone(),
            prior_slot: Arc::clone(&self.prior),
        }))
    }
}

/// What a rollback needs to put the prior generation back.
pub(crate) struct UndoState {
    /// The instances this commit stopped, with the configuration they were running.
    pub stopped: Vec<(DeviceConfig, Value)>,
    /// The instances this commit launched (ids), to be stopped again on rollback.
    pub launched: Vec<String>,
    /// The generation to restore.
    pub prior: PriorGeneration,
}

/// The staged transaction: it holds the plan and the undo record, and performs the swap in
/// [`PreparedConfigurationApply::commit`].
pub(crate) struct ReloadTransaction {
    plan: ReloadPlan,
    /// The candidate snapshot — every instance this transaction launches is bound to it.
    snapshot: Arc<Config>,
    launcher: Arc<dyn DeviceLauncher>,
    registry: Arc<DeviceRegistry>,
    root: CancellationToken,
    /// The coordinator's prior-generation slot, updated on a successful commit.
    prior_slot: Arc<Mutex<PriorGeneration>>,
    undo: UndoState,
}

#[async_trait::async_trait]
impl PreparedConfigurationApply for ReloadTransaction {
    /// Swap the live instance set to the candidate: **stop → swap the global → launch → publish**.
    ///
    /// Core deliberately does not cancel this future, so every stage bounds itself. There are two
    /// kinds of wait, and each has its own bound: the stop stage runs under
    /// [`crate::lifecycle::stop_budget`] and aborts stragglers, and the two operator notifications
    /// (the removed instances' alarm clear, and `config-applied`) are **best-effort under
    /// [`NOTIFY_BUDGET`]** — they reach the broker through a publish that has no timeout of its own,
    /// so a wedged broker or a full publish funnel would otherwise stall the commit while it holds
    /// core's apply lock, queueing every later reload behind it. A notification that does not make it
    /// out in time is logged and the reload proceeds: a failed notification must never fail a reload.
    ///
    /// Removal happens *before* the stop so command routing answers `NO_SUCH_INSTANCE` /
    /// `DEVICE_UNAVAILABLE` during the swap instead of dispatching into dying channels.
    async fn commit(&mut self) -> ConfigurationApplicationResult<()> {
        // Nothing has been done yet, so core's follow-up rollback is a no-op.
        if self.root.is_cancelled() {
            return Err(ConfigurationApplicationError::new(
                CODE_SHUTTING_DOWN,
                "component is shutting down; candidate not applied",
            ));
        }
        // The budget of the generation being torn down (its `requestTimeoutMs` is what bounds the
        // in-flight CIP call a cancel has to wait out).
        let budget = crate::lifecycle::stop_budget(&self.registry.global().timeouts);

        // 1. Detach: out of the registry first, so nothing routes to a dying instance.
        let mut stopping: Vec<DeviceRuntime> = Vec::new();
        for id in &self.plan.stop {
            if let Some(rt) = self.registry.remove(id) {
                // The configuration it is *running* — already parsed and validated by definition,
                // so the undo record needs no re-parse.
                self.undo
                    .stopped
                    .push((rt.handle.cfg.clone(), rt.raw.clone()));
                stopping.push(rt);
            }
        }

        // 2. The event sinks of the instances that are going away for good — captured now, because
        //    the stop consumes the runtimes, and *used* only after it (stage 4).
        let clearing: Vec<(String, Arc<dyn EventSink>)> = self
            .plan
            .removed
            .iter()
            .filter_map(|id| {
                stopping
                    .iter()
                    .find(|rt| rt.handle.cfg.id == *id)
                    .map(|rt| (id.clone(), Arc::clone(&rt.handle.events)))
            })
            .collect();

        // 3. Bounded stop — the same cancel → close → join → abort engine shutdown uses, so a
        //    replaced instance's session is UnRegisterSession'd / ForwardClose'd before its
        //    successor connects. An overrun aborts stragglers; it is not a commit failure (the
        //    device side watchdogs the connection out).
        let report = crate::lifecycle::stop_runtimes(stopping, budget).await;
        tracing::info!(
            joined = report.joined,
            aborted = report.aborted,
            budget_ms = budget.as_millis() as u64,
            "stopped the instances the candidate replaces"
        );

        // 4. Alarm hygiene, AFTER the stop: an instance that is going away for good must not leave a
        //    latched `device-unreachable` on the bus — nothing will ever clear it. Clearing it while
        //    the instance was still live would race its own alarm: a link drop in that window (which
        //    spans a broker round-trip per earlier removal) re-raises the alarm, the cancel then ends
        //    the task, and the alarm latches forever — precisely what this stage exists to prevent.
        //    (A *restarted* instance clears its own on the next connect.)
        for (id, events) in clearing {
            notify(
                events.clear_alarm(Severity::Critical, "device-unreachable", None),
                Some(&id),
                "clearing the device-unreachable alarm",
            )
            .await;
        }

        // 5. Publish the candidate's global. Kept instances deliberately retain the `Arc` they were
        //    spawned with — they are kept precisely because nothing they bound has changed.
        self.registry.set_global(Arc::clone(&self.plan.global));

        // 6. Launch, bound to the candidate snapshot. A launch failure is skipped with a warning
        //    (launch-time skip-bad parity), not a transaction failure — and it joins the plan's
        //    parse-time skips, so no instance id can silently vanish from the `config-applied` event.
        let mut skipped = self.plan.skipped.clone();
        for (cfg, raw) in &self.plan.start {
            match self
                .launcher
                .launch(cfg, raw, &self.plan.global, &self.snapshot)
            {
                Ok(rt) => {
                    self.undo.launched.push(cfg.id.clone());
                    self.registry.insert(rt);
                }
                Err(e) => {
                    tracing::warn!(
                        instance = %cfg.id, error = %e,
                        "skipping device that could not be launched from the reloaded configuration"
                    );
                    skipped.push((cfg.id.clone(), e.to_string()));
                }
            }
        }
        if self.registry.is_empty() {
            return Err(ConfigurationApplicationError::new(
                CODE_NO_RUNNING_INSTANCES,
                "no instance is running after applying the candidate",
            ));
        }

        // 7. The surfaces that describe the new generation.
        tracing::info!(
            instances = ?self.registry.ids(),
            restart_all = self.plan.restart_all,
            "configuration applied"
        );
        self.launcher
            .set_repoll_availability(self.registry.all_push());
        let context = json!({
            "started": self.undo.launched,
            "stopped": self.plan.stop,
            "kept": self.plan.keep,
            "skipped": skipped
                .iter()
                .map(|(id, reason)| json!([id, reason]))
                .collect::<Vec<Value>>(),
            "restartAll": self.plan.restart_all,
        });
        let component_events = self.launcher.component_events();
        notify(
            component_events.emit(
                Severity::Info,
                "config-applied",
                Some("configuration applied".to_string()),
                Some(context),
            ),
            None,
            "emitting the config-applied event",
        )
        .await;

        // 8. This generation is now the one a later reload diffs against. Core stores the snapshot
        //    and bumps its generation as soon as we return `Ok`.
        {
            let mut slot = self.prior_slot.lock().unwrap();
            *slot = PriorGeneration::of(&self.snapshot, &self.plan.global);
        }
        Ok(())
    }

    /// Restore the generation that was running before [`Self::commit`] was attempted: stop whatever
    /// this commit launched, put the prior global back, and relaunch the instances it stopped —
    /// bound to the **prior** snapshot, which core is keeping.
    ///
    /// **Fidelity, stated honestly:** this restores the prior *set and configuration*, not its live
    /// state. Restored instances reconnect with fresh sessions, in-memory pause on a restarted or
    /// stopped instance is gone (the accepted D-EIP-14 consequence), and interval counters restart.
    /// What can never be lost is the prior configuration itself: core keeps the snapshot and this
    /// transaction retained every stopped instance's `cfg` + raw subtree.
    async fn rollback(&mut self) -> ConfigurationApplicationResult<()> {
        let budget = crate::lifecycle::stop_budget(&self.undo.prior.global.timeouts);

        let mut stopping: Vec<DeviceRuntime> = Vec::new();
        for id in std::mem::take(&mut self.undo.launched) {
            if let Some(rt) = self.registry.remove(&id) {
                stopping.push(rt);
            }
        }
        let report = crate::lifecycle::stop_runtimes(stopping, budget).await;
        tracing::info!(
            joined = report.joined,
            aborted = report.aborted,
            "stopped the instances the failed candidate launched"
        );

        self.registry
            .set_global(Arc::clone(&self.undo.prior.global));

        // One bad relaunch must not strand the rest, so the loop continues and reports at the end.
        let mut failed: Vec<String> = Vec::new();
        for (cfg, raw) in std::mem::take(&mut self.undo.stopped) {
            match self.launcher.launch(
                &cfg,
                &raw,
                &self.undo.prior.global,
                &self.undo.prior.snapshot,
            ) {
                Ok(rt) => self.registry.insert(rt),
                Err(e) => {
                    tracing::error!(instance = %cfg.id, error = %e, "could not restore instance during rollback");
                    failed.push(cfg.id.clone());
                }
            }
        }

        if failed.is_empty() {
            tracing::info!("restored the previous configuration generation");
            Ok(())
        } else {
            Err(ConfigurationApplicationError::new(
                CODE_ROLLBACK_RELAUNCH_FAILED,
                format!(
                    "the previous configuration was restored except for: {}",
                    failed.join(", ")
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{DeviceControl, Health};
    use crate::commands::DeviceHandle;
    use crate::lifecycle::DeviceRegistry;
    use crate::testutil::RecordingEvents;
    use std::time::Duration;

    // ---------------------------------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------------------------------

    /// A minimal but REAL adapter document: the shape core hands us (`component.global` +
    /// `component.instances[]` beside the library sections).
    fn document(global: Value, instances: Vec<Value>) -> Value {
        json!({
            "topic": { "includeRoot": false },
            "component": { "global": global, "instances": instances },
        })
    }

    fn poll_instance(id: &str, interval_ms: u64) -> Value {
        json!({
            "id": id,
            "adapter": "sim",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [ {
                "pollIntervalMs": interval_ms,
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ]
            } ]
        })
    }

    fn push_instance(id: &str) -> Value {
        json!({
            "id": id,
            "adapter": "sim",
            "mode": "push",
            "connection": { "endpoint": "opener:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "udint" } ] }
            }
        })
    }

    fn snapshot(raw: &Value) -> Arc<Config> {
        Arc::new(
            Config::from_value(
                "com.mbreissi.edgecommons.EthernetIpAdapter",
                "thing-1",
                raw.clone(),
            )
            .expect("the test document is a valid configuration"),
        )
    }

    fn running_of(doc: &Value) -> Vec<(String, Value)> {
        candidate_instances(doc)
    }

    /// The refusal of a prepare, without requiring `Debug` on the staged transaction.
    fn refusal(
        outcome: ConfigurationApplicationResult<Box<dyn PreparedConfigurationApply>>,
        why: &str,
    ) -> ConfigurationApplicationError {
        match outcome {
            Ok(_) => panic!("{why}"),
            Err(e) => e,
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The launcher double
    // ---------------------------------------------------------------------------------------------

    /// What a launch was asked to do — enough to prove which snapshot/global an instance was bound
    /// to, which is the whole point of the rollback-fidelity assertion.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LaunchRecord {
        id: String,
        /// The `Arc<Config>` identity, as a pointer — `prior` vs `candidate` is the assertion.
        snapshot: usize,
        global: usize,
    }

    /// Everything the transaction did, in order.
    #[derive(Default)]
    struct Journal {
        launches: Vec<LaunchRecord>,
        /// `("stop", id)` when an instance's task observed its cancellation, `("launch", id)` when
        /// one was started, `("clear", id)` when a removed instance's alarm was cleared — so an
        /// ordering inversion (launching before stopping, clearing before stopping) is visible, not
        /// merely absent from the final state.
        order: Vec<(&'static str, String)>,
        availability: Vec<bool>,
    }

    /// A per-instance event sink that records into the instance's own [`RecordingEvents`] **and**
    /// into the shared journal, so alarm hygiene can be ordered against the stop stage.
    struct InstanceEvents {
        id: String,
        inner: Arc<RecordingEvents>,
        journal: Arc<Mutex<Journal>>,
    }

    #[async_trait::async_trait]
    impl EventSink for InstanceEvents {
        async fn emit(&self, s: Severity, t: &str, m: Option<String>, c: Option<Value>) {
            self.inner.emit(s, t, m, c).await;
        }
        async fn raise_alarm(&self, s: Severity, t: &str, m: Option<String>, c: Option<Value>) {
            self.inner.raise_alarm(s, t, m, c).await;
        }
        async fn clear_alarm(&self, s: Severity, t: &str, c: Option<Value>) {
            self.journal
                .lock()
                .unwrap()
                .order
                .push(("clear", self.id.clone()));
            self.inner.clear_alarm(s, t, c).await;
        }
    }

    /// An event sink whose publishes never complete — a wedged broker or a full publish funnel.
    struct WedgedEvents;

    #[async_trait::async_trait]
    impl EventSink for WedgedEvents {
        async fn emit(&self, _: Severity, _: &str, _: Option<String>, _: Option<Value>) {
            std::future::pending::<()>().await;
        }
        async fn raise_alarm(&self, _: Severity, _: &str, _: Option<String>, _: Option<Value>) {
            std::future::pending::<()>().await;
        }
        async fn clear_alarm(&self, _: Severity, _: &str, _: Option<Value>) {
            std::future::pending::<()>().await;
        }
    }

    struct FakeLauncher {
        journal: Arc<Mutex<Journal>>,
        events: Arc<RecordingEvents>,
        /// Instance ids whose launch must fail (launch-time skip-bad / rollback-failure paths).
        fail: Mutex<Vec<String>>,
        /// Stub tasks that ignore their cancellation token — the wedged-task case.
        wedge: Mutex<Vec<String>>,
        /// Every event sink this launcher hands out never completes a publish — the wedged-broker
        /// case, which the commit's notification budget has to survive.
        stalled: AtomicBool,
        /// Per-instance recording event sinks, so a test can inspect what an instance emitted.
        sinks: Mutex<std::collections::HashMap<String, Arc<RecordingEvents>>>,
        /// Keeps every stub instance's control receiver alive for the test's lifetime.
        channels: Mutex<Vec<tokio::sync::mpsc::Receiver<DeviceControl>>>,
    }

    impl FakeLauncher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                journal: Arc::new(Mutex::new(Journal::default())),
                events: Arc::new(RecordingEvents::default()),
                fail: Mutex::new(Vec::new()),
                wedge: Mutex::new(Vec::new()),
                stalled: AtomicBool::new(false),
                sinks: Mutex::new(std::collections::HashMap::new()),
                channels: Mutex::new(Vec::new()),
            })
        }

        fn fail_all(&self) {
            *self.fail.lock().unwrap() = vec!["*".to_string()];
        }

        fn fail_none(&self) {
            self.fail.lock().unwrap().clear();
        }

        fn fail_instance(&self, id: &str) {
            self.fail.lock().unwrap().push(id.to_string());
        }

        fn wedge_instance(&self, id: &str) {
            self.wedge.lock().unwrap().push(id.to_string());
        }

        fn stall_events(&self) {
            self.stalled.store(true, Ordering::Relaxed);
        }

        fn sink(&self, id: &str) -> Arc<RecordingEvents> {
            let mut sinks = self.sinks.lock().unwrap();
            Arc::clone(
                sinks
                    .entry(id.to_string())
                    .or_insert_with(|| Arc::new(RecordingEvents::default())),
            )
        }

        /// The ordered journal of stops, launches, and alarm clears.
        fn order(&self) -> Vec<(&'static str, String)> {
            self.journal.lock().unwrap().order.clone()
        }

        /// Build a runtime exactly as the production launcher does — handle, child token, spawned
        /// task — but with a stub task instead of a device loop. The stub records its own
        /// cancellation, which is what makes the stop-before-launch ordering assertable.
        fn runtime(&self, cfg: &DeviceConfig, raw: &Value, cancel: CancellationToken) -> DeviceRuntime {
            let health = Arc::new(Health::default());
            let (control, rx) = tokio::sync::mpsc::channel::<DeviceControl>(4);
            self.channels.lock().unwrap().push(rx);
            let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::clone(&health));
            let events: Arc<dyn EventSink> = if self.stalled.load(Ordering::Relaxed) {
                Arc::new(WedgedEvents)
            } else {
                Arc::new(InstanceEvents {
                    id: cfg.id.clone(),
                    inner: self.sink(&cfg.id),
                    journal: Arc::clone(&self.journal),
                })
            };
            let wedged = self.wedge.lock().unwrap().contains(&cfg.id);
            let token = cancel.clone();
            let journal = Arc::clone(&self.journal);
            let id = cfg.id.clone();
            let task = tokio::spawn(async move {
                if wedged {
                    std::future::pending::<()>().await;
                } else {
                    token.cancelled().await;
                    journal.lock().unwrap().order.push(("stop", id));
                }
            });
            DeviceRuntime {
                handle: DeviceHandle {
                    cfg: cfg.clone(),
                    control,
                    health,
                    dm,
                    events,
                },
                raw: raw.clone(),
                cancel,
                tasks: vec![task],
            }
        }
    }

    impl DeviceLauncher for FakeLauncher {
        fn launch(
            &self,
            cfg: &DeviceConfig,
            raw: &Value,
            global: &Arc<GlobalConfig>,
            snapshot: &Arc<Config>,
        ) -> anyhow::Result<DeviceRuntime> {
            let fail = self.fail.lock().unwrap();
            if fail.iter().any(|f| f == "*" || *f == cfg.id) {
                anyhow::bail!("launch refused for `{}`", cfg.id);
            }
            drop(fail);
            {
                let mut journal = self.journal.lock().unwrap();
                journal.launches.push(LaunchRecord {
                    id: cfg.id.clone(),
                    snapshot: Arc::as_ptr(snapshot) as usize,
                    global: Arc::as_ptr(global) as usize,
                });
                journal.order.push(("launch", cfg.id.clone()));
            }
            Ok(self.runtime(cfg, raw, CancellationToken::new()))
        }

        fn component_events(&self) -> Arc<dyn EventSink> {
            if self.stalled.load(Ordering::Relaxed) {
                return Arc::new(WedgedEvents);
            }
            Arc::clone(&self.events) as Arc<dyn EventSink>
        }

        fn set_repoll_availability(&self, all_push: bool) {
            self.journal.lock().unwrap().availability.push(all_push);
        }
    }

    /// A registry populated from `doc` through the fake launcher — the "already running" generation.
    fn running_registry(
        launcher: &Arc<FakeLauncher>,
        doc: &Value,
        root: &CancellationToken,
    ) -> (Arc<DeviceRegistry>, Arc<Config>, Arc<GlobalConfig>) {
        let snap = snapshot(doc);
        let global = Arc::new(
            GlobalConfig::from_value(snap.global()).expect("the fixture global parses"),
        );
        let registry = Arc::new(DeviceRegistry::default());
        registry.set_global(Arc::clone(&global));
        for (id, raw) in candidate_instances(doc) {
            let cfg = DeviceConfig::from_value(&raw).expect("the fixture instance parses");
            assert_eq!(cfg.id, id);
            registry.insert(launcher.runtime(&cfg, &raw, root.child_token()));
        }
        // The startup population is not a "launch" — clear what `runtime` did not record anyway.
        launcher.journal.lock().unwrap().order.clear();
        (registry, snap, global)
    }

    fn coordinator(
        launcher: &Arc<FakeLauncher>,
        registry: &Arc<DeviceRegistry>,
        root: &CancellationToken,
        snapshot: &Arc<Config>,
        global: &Arc<GlobalConfig>,
        started: bool,
    ) -> ReloadCoordinator {
        ReloadCoordinator::new(
            Arc::clone(launcher) as Arc<dyn DeviceLauncher>,
            Arc::clone(registry),
            root.clone(),
            Arc::new(AtomicBool::new(started)),
            PriorGeneration::of(snapshot, global),
        )
    }

    // =============================================================================================
    // The pure plan
    // =============================================================================================

    /// The core diff, all five dispositions in one candidate: unchanged instances are kept (so their
    /// sessions and pause state survive), an added one starts, a removed one stops and is marked for
    /// alarm clearing, and a changed one stops AND starts.
    #[test]
    fn plan_keeps_unchanged_starts_added_stops_removed_restarts_changed() {
        let before = document(
            json!({}),
            vec![
                poll_instance("keep-me", 500),
                poll_instance("change-me", 500),
                poll_instance("remove-me", 500),
            ],
        );
        let after = document(
            json!({}),
            vec![
                poll_instance("keep-me", 500),
                poll_instance("change-me", 250),
                poll_instance("add-me", 500),
            ],
        );

        let p = plan(&running_of(&before), &non_instance_view(&before), &after).unwrap();

        assert!(!p.restart_all, "only instances changed");
        assert_eq!(p.keep, vec!["keep-me"]);
        assert_eq!(p.stop, vec!["change-me", "remove-me"]);
        assert_eq!(
            p.start.iter().map(|(c, _)| c.id.clone()).collect::<Vec<_>>(),
            vec!["change-me", "add-me"]
        );
        assert_eq!(
            p.removed,
            vec!["remove-me"],
            "only the instance with no successor gets its alarm cleared"
        );
        assert!(p.skipped.is_empty());
    }

    /// A `component.global` change restarts every instance — the accepted granularity rule.
    #[test]
    fn plan_restarts_all_on_a_global_change() {
        let before = document(
            json!({}),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );
        let after = document(
            json!({ "timeouts": { "requestTimeoutMs": 3000 } }),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );

        let p = plan(&running_of(&before), &non_instance_view(&before), &after).unwrap();

        assert!(p.restart_all);
        assert!(p.keep.is_empty(), "nothing survives a global change");
        assert_eq!(p.stop, vec!["plc-1", "plc-2"]);
        assert_eq!(
            p.start.iter().map(|(c, _)| c.id.clone()).collect::<Vec<_>>(),
            vec!["plc-1", "plc-2"]
        );
        assert!(p.removed.is_empty(), "a restart is not a removal");
        assert_eq!(p.global.timeouts.request_timeout_ms, 3000);
    }

    /// The trigger is ANY change outside `component.instances`, not just `component.global`: the
    /// facades, UNS identity, and metric identity an instance binds at spawn all come from there.
    #[test]
    fn plan_restarts_all_on_a_non_instance_change() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let mut after = before.clone();
        after["topic"]["includeRoot"] = json!(true);

        let p = plan(&running_of(&before), &non_instance_view(&before), &after).unwrap();

        assert!(p.restart_all, "a topic change restarts every instance");
        assert_eq!(p.stop, vec!["plc-1"]);
        assert_eq!(p.start.len(), 1);
    }

    /// Comparison is structural, not textual: a re-serialized document with reordered object keys is
    /// the SAME configuration. A fingerprint/string compare here would restart the whole fleet on
    /// every ConfigMap rewrite.
    #[test]
    fn plan_object_key_order_does_not_restart() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let reordered = json!({
            "component": {
                "instances": [ {
                    "pollGroups": [ {
                        "signals": [ { "type": "real", "tagPath": "LINE_SPEED", "name": "line-speed" } ],
                        "pollIntervalMs": 500
                    } ],
                    "connection": { "slot": 0, "endpoint": "127.0.0.1:44818" },
                    "adapter": "sim",
                    "id": "plc-1"
                } ],
                "global": {}
            },
            "topic": { "includeRoot": false },
        });

        let p = plan(
            &running_of(&before),
            &non_instance_view(&before),
            &reordered,
        )
        .unwrap();

        assert!(!p.restart_all, "key order is not a configuration change");
        assert_eq!(p.keep, vec!["plc-1"]);
        assert!(p.stop.is_empty());
        assert!(p.start.is_empty());
    }

    /// Skip-bad-instance parity: a malformed entry is reported, the rest of the candidate applies.
    #[test]
    fn plan_skips_malformed_and_reports_them() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let after = document(
            json!({}),
            vec![
                poll_instance("plc-1", 500),
                json!({ "id": "broken", "adapter": "sim", "connection": { "endpoint": "x:1" },
                        "pollGroups": [], "nonsense": true }),
            ],
        );

        let p = plan(&running_of(&before), &non_instance_view(&before), &after).unwrap();

        assert_eq!(p.keep, vec!["plc-1"]);
        assert!(p.start.is_empty(), "the malformed instance never starts");
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].0, "broken");
        assert!(
            p.skipped[0].1.contains("nonsense"),
            "the parse error names the offending key: {}",
            p.skipped[0].1
        );
    }

    /// Fail-only-if-zero-valid, mapped for reload: the CANDIDATE is rejected (the running generation
    /// keeps operating) rather than the component stopping.
    #[test]
    fn plan_rejects_zero_valid_instances() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let all_bad = document(
            json!({}),
            vec![json!({ "id": "broken", "adapter": "sim", "connection": { "endpoint": "x:1" },
                         "pollGroups": [], "nonsense": true })],
        );
        assert_eq!(
            plan(&running_of(&before), &non_instance_view(&before), &all_bad).unwrap_err(),
            ReloadPlanError::NoValidInstances
        );

        let none = document(json!({}), vec![]);
        assert_eq!(
            plan(&running_of(&before), &non_instance_view(&before), &none).unwrap_err(),
            ReloadPlanError::NoValidInstances
        );
    }

    /// A malformed `component.global` rejects the candidate outright — it is not skippable, every
    /// instance would bind it.
    #[test]
    fn plan_rejects_invalid_global() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let after = document(
            json!({ "timeouts": { "requestTimeoutMs": "soon" } }),
            vec![poll_instance("plc-1", 500)],
        );

        match plan(&running_of(&before), &non_instance_view(&before), &after).unwrap_err() {
            ReloadPlanError::InvalidGlobal(e) => assert!(
                e.contains("component.global"),
                "the error names the section: {e}"
            ),
            other => panic!("expected InvalidGlobal, got {other:?}"),
        }
    }

    /// Duplicate ids resolve first-wins — the same rule `Config::instance` applies, so the plan and
    /// the snapshot can never disagree about which subtree an id means.
    #[test]
    fn plan_dedupes_duplicate_ids_first_wins() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let after = document(
            json!({}),
            vec![poll_instance("plc-1", 500), poll_instance("plc-1", 250)],
        );

        let p = plan(&running_of(&before), &non_instance_view(&before), &after).unwrap();

        assert_eq!(p.keep, vec!["plc-1"], "the FIRST declaration wins");
        assert!(p.stop.is_empty(), "the duplicate does not restart anything");
        assert!(p.start.is_empty());
    }

    /// An entry with no `id` is invisible to `Config::instance_ids`, so it must be invisible here
    /// too — otherwise the plan would try to run an instance the snapshot cannot address. A document
    /// with no `component.instances` at all is simply an empty candidate.
    #[test]
    fn candidate_instances_skips_id_less_entries_and_a_missing_list() {
        let doc = document(
            json!({}),
            vec![
                json!({ "adapter": "sim", "connection": { "endpoint": "x:1" } }),
                poll_instance("plc-1", 500),
            ],
        );
        assert_eq!(
            candidate_instances(&doc)
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>(),
            vec!["plc-1"]
        );

        assert!(candidate_instances(&json!({ "topic": {} })).is_empty());
        assert!(candidate_instances(&json!({ "component": {} })).is_empty());
    }

    /// Startup and reload derive their instance set from the SAME function, so a document declaring
    /// an id twice launches it **once**, against the subtree `Config::instance` also resolves to.
    ///
    /// This is what keeps the two paths from disagreeing: a startup that launched both declarations
    /// would run two runtimes under one id, and a later reload — which stops an id once — would stop
    /// only the first, leaving the surplus one polling the device on the retired configuration until
    /// the process exits.
    #[test]
    fn startup_and_reload_share_one_deduped_instance_set() {
        let doc = document(
            json!({}),
            vec![
                poll_instance("plc-1", 500),
                json!({ "adapter": "sim", "connection": { "endpoint": "x:1" } }), // no id
                poll_instance("plc-1", 250),                                      // duplicate id
                json!({ "id": "broken", "adapter": "sim", "connection": { "endpoint": "x:1" },
                        "pollGroups": [], "nonsense": true }),
                poll_instance("plc-2", 500),
            ],
        );

        let (startup, skipped) = parse_instances(&doc);
        assert_eq!(
            startup.iter().map(|(c, _)| c.id.clone()).collect::<Vec<_>>(),
            vec!["plc-1", "plc-2"],
            "the duplicate id is launched once, and the id-less entry not at all"
        );
        assert_eq!(
            startup[0].0.poll_groups[0].poll_interval_ms,
            Some(500),
            "first declaration wins, exactly as `Config::instance` resolves it"
        );
        assert_eq!(skipped.len(), 1, "the malformed entry is skipped, not fatal");
        assert_eq!(skipped[0].0, "broken");

        // …and the plan agrees with that startup set: re-applying the same document moves nothing.
        // If startup had launched the duplicate twice, the plan would keep one and never stop the
        // other — the stranded-runtime defect.
        let running: Vec<(String, Value)> = startup
            .iter()
            .map(|(cfg, raw)| (cfg.id.clone(), raw.clone()))
            .collect();
        let p = plan(&running, &non_instance_view(&doc), &doc).unwrap();
        assert_eq!(p.keep, vec!["plc-1", "plc-2"]);
        assert!(p.stop.is_empty() && p.start.is_empty());
    }

    /// The plan diffs the RUNNING set, not the previous `Config`: an instance that was skipped at
    /// startup is not running, so it starts now even though its raw subtree never changed.
    #[test]
    fn plan_starts_a_previously_skipped_instance_whose_raw_is_unchanged() {
        let doc = document(
            json!({}),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );
        // `plc-2` failed to launch at startup, so only `plc-1` is running.
        let running = vec![("plc-1".to_string(), poll_instance("plc-1", 500))];

        let p = plan(&running, &non_instance_view(&doc), &doc).unwrap();

        assert!(!p.restart_all);
        assert_eq!(p.keep, vec!["plc-1"]);
        assert_eq!(
            p.start.iter().map(|(c, _)| c.id.clone()).collect::<Vec<_>>(),
            vec!["plc-2"],
            "the instance that is not running starts, unchanged raw or not"
        );
        assert!(p.stop.is_empty());
    }

    // =============================================================================================
    // The transaction
    // =============================================================================================

    /// The swap order is stop → swap the global → launch, proven by the *interleaving*: every
    /// replaced instance's task records its own cancellation, and no launch may appear before the
    /// last of those. Launching first would open a second session to a device that still has one
    /// open — the defect this ordering exists to prevent, which a final-state-only assertion would
    /// not see. The launches are also pinned to the CANDIDATE snapshot and global, since that is what
    /// binds a new instance's facades, topics, identity, and metric dimensions.
    #[tokio::test(start_paused = true)]
    async fn commit_stops_then_swaps_global_then_launches_in_order() {
        let before = document(
            json!({}),
            vec![poll_instance("keep-me", 500), poll_instance("change-me", 500)],
        );
        let after = document(
            json!({ "timeouts": { "requestTimeoutMs": 1500 } }),
            vec![poll_instance("keep-me", 500), poll_instance("change-me", 250)],
        );

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let candidate = snapshot(&after);
        let candidate_ptr = Arc::as_ptr(&candidate) as usize;
        let mut tx = coord
            .prepare_configuration_apply(Arc::clone(&candidate))
            .await
            .expect("the candidate prepares");
        tx.commit().await.expect("the commit succeeds");

        // A global change restarts everything, so both instances stop and both come back.
        assert_eq!(
            registry.ids(),
            vec!["keep-me", "change-me"],
            "the registry holds exactly the candidate's instance set"
        );
        assert_eq!(
            registry.global().timeouts.request_timeout_ms,
            1500,
            "the candidate's global is published"
        );

        let order = launcher.order();
        let stopped: std::collections::BTreeSet<String> = order
            .iter()
            .filter(|(kind, _)| *kind == "stop")
            .map(|(_, id)| id.clone())
            .collect();
        assert_eq!(
            stopped,
            ["change-me".to_string(), "keep-me".to_string()]
                .into_iter()
                .collect(),
            "both replaced instances observed their cancellation: {order:?}"
        );
        let launched: Vec<String> = order
            .iter()
            .filter(|(kind, _)| *kind == "launch")
            .map(|(_, id)| id.clone())
            .collect();
        assert_eq!(launched, vec!["keep-me", "change-me"], "launches in plan order");
        let last_stop = order.iter().rposition(|(kind, _)| *kind == "stop").unwrap();
        let first_launch = order.iter().position(|(kind, _)| *kind == "launch").unwrap();
        assert!(
            last_stop < first_launch,
            "every replaced instance stopped BEFORE any successor launched: {order:?}"
        );

        // Commit-path launches bind the candidate, not the snapshot core is still publishing.
        let launches = launcher.journal.lock().unwrap().launches.clone();
        let published_global = Arc::as_ptr(&registry.global()) as usize;
        assert_eq!(
            launches
                .iter()
                .map(|l| (l.snapshot == candidate_ptr, l.global == published_global))
                .collect::<Vec<_>>(),
            vec![(true, true), (true, true)],
            "each launch was bound to the candidate snapshot and the candidate's global"
        );
    }

    /// The pause-survival contract: an untouched instance is not merely re-created with the same
    /// configuration — it is the SAME runtime, so its `Health` (and the pause flag living in it)
    /// survives the reload.
    #[tokio::test(start_paused = true)]
    async fn commit_keeps_untouched_runtimes_by_identity() {
        let before = document(
            json!({}),
            vec![poll_instance("paused-one", 500), poll_instance("other", 500)],
        );
        let after = document(
            json!({}),
            vec![poll_instance("paused-one", 500), poll_instance("other", 250)],
        );

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);

        let health_before = Arc::clone(
            &registry
                .handles()
                .into_iter()
                .find(|h| h.cfg.id == "paused-one")
                .unwrap()
                .health,
        );
        health_before.paused.store(true, Ordering::Relaxed);

        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);
        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let health_after = Arc::clone(
            &registry
                .handles()
                .into_iter()
                .find(|h| h.cfg.id == "paused-one")
                .unwrap()
                .health,
        );
        assert!(
            Arc::ptr_eq(&health_before, &health_after),
            "the untouched instance keeps its live runtime"
        );
        assert!(
            health_after.paused.load(Ordering::Relaxed),
            "pause survives on an instance the reload did not touch"
        );
        assert_eq!(
            launcher.journal.lock().unwrap().launches.len(),
            1,
            "only the changed instance was relaunched"
        );
    }

    /// A reload racing shutdown must lose: once the root is cancelled, commit refuses rather than
    /// opening device sessions the teardown is no longer waiting for.
    #[tokio::test(start_paused = true)]
    async fn commit_refuses_when_shutting_down() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let after = document(json!({}), vec![poll_instance("plc-1", 250)]);

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .expect("prepare happens before the shutdown signal");

        // …and the shutdown signal lands between prepare and commit.
        root.cancel();

        let err = tx.commit().await.expect_err("the commit is refused");
        assert_eq!(err.code, CODE_SHUTTING_DOWN);
        assert_eq!(registry.ids(), vec!["plc-1"], "the registry is untouched");
        assert!(
            launcher.journal.lock().unwrap().launches.is_empty(),
            "nothing was launched"
        );
        // Nothing was done, so core's follow-up rollback is a clean no-op.
        tx.rollback().await.expect("rollback after a no-op commit");
    }

    /// Core deliberately does not cancel `commit`, so `commit` bounds itself: a stopping instance
    /// that ignores its token is aborted at the stop budget instead of wedging the reload forever.
    #[tokio::test(start_paused = true)]
    async fn commit_is_bounded_when_a_stopping_task_wedges() {
        let before = document(json!({}), vec![poll_instance("wedged", 500)]);
        let after = document(json!({}), vec![poll_instance("wedged", 250)]);

        let launcher = FakeLauncher::new();
        launcher.wedge_instance("wedged");
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        // The successor must not wedge too, or the test could not observe the registry afterwards.
        launcher.wedge.lock().unwrap().clear();
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();

        let budget = crate::lifecycle::stop_budget(&global.timeouts);
        let started = tokio::time::Instant::now();
        tx.commit().await.expect("a wedged stop is not a commit failure");
        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);

        assert!(
            elapsed <= budget,
            "commit stayed inside its own budget: {elapsed:?} > {budget:?}"
        );
        assert!(
            elapsed >= budget,
            "the wedge is real: the stop ran out the whole budget before aborting ({elapsed:?})"
        );
        assert_eq!(registry.ids(), vec!["wedged"], "the successor is running");
    }

    /// An instance the candidate drops must not leave a latched `device-unreachable` behind — no
    /// task will ever clear it again — and the clear must happen **after** the instance is stopped.
    /// Clearing it while the task is still live races the task's own alarm: a link drop in that
    /// window re-raises it, the cancel then ends the task, and the alarm latches forever.
    #[tokio::test(start_paused = true)]
    async fn commit_clears_the_unreachable_alarm_for_removed_instances() {
        let before = document(
            json!({}),
            vec![poll_instance("stays", 500), poll_instance("goes", 500)],
        );
        let after = document(json!({}), vec![poll_instance("stays", 500)]);

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let removed = launcher.sink("goes");
        let cleared = removed
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|(kind, event, _)| kind == "clear" && event == "device-unreachable");
        assert!(cleared, "the removed instance's alarm was cleared");
        assert!(
            !launcher
                .sink("stays")
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|(kind, _, _)| kind == "clear"),
            "a kept instance's alarms are not touched"
        );
        assert_eq!(registry.ids(), vec!["stays"]);

        // The ordering that makes the clear stick: the instance's task had already observed its
        // cancellation, so nothing can re-raise the alarm behind the clear.
        let order = launcher.order();
        let stopped = order
            .iter()
            .position(|(kind, id)| *kind == "stop" && id == "goes")
            .expect("the removed instance recorded its cancellation");
        let cleared_at = order
            .iter()
            .position(|(kind, id)| *kind == "clear" && id == "goes")
            .expect("the removed instance recorded its alarm clear");
        assert!(
            stopped < cleared_at,
            "the alarm is cleared only after the instance is stopped: {order:?}"
        );
    }

    /// The failure path end to end: every launch fails and nothing was kept, so the commit reports
    /// `NO_RUNNING_INSTANCES` and the rollback puts the prior set back — bound to the PRIOR snapshot
    /// and global, which is what core keeps active.
    #[tokio::test(start_paused = true)]
    async fn commit_fails_and_rollback_restores_the_prior_set_when_nothing_runs() {
        let before = document(
            json!({}),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );
        // A global change ⇒ restart-all ⇒ nothing is kept, so a total launch failure empties the
        // registry — the only way a commit can fail after it has already stopped instances.
        let after = document(
            json!({ "timeouts": { "requestTimeoutMs": 1500 } }),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let prior_snapshot = Arc::as_ptr(&snap) as usize;
        let prior_global = Arc::as_ptr(&global) as usize;
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        launcher.fail_all();
        let err = tx.commit().await.expect_err("nothing runs after the commit");
        assert_eq!(err.code, CODE_NO_RUNNING_INSTANCES);
        assert!(registry.is_empty(), "the failed commit left nothing running");

        launcher.fail_none();
        tx.rollback().await.expect("the prior generation is restored");

        assert_eq!(
            registry.ids(),
            vec!["plc-1", "plc-2"],
            "the prior instance set is back"
        );
        assert_eq!(
            registry.global().timeouts.request_timeout_ms,
            global.timeouts.request_timeout_ms,
            "the prior global is back"
        );
        let launches = launcher.journal.lock().unwrap().launches.clone();
        assert_eq!(
            launches
                .iter()
                .map(|l| (l.id.clone(), l.snapshot == prior_snapshot, l.global == prior_global))
                .collect::<Vec<_>>(),
            vec![
                ("plc-1".to_string(), true, true),
                ("plc-2".to_string(), true, true)
            ],
            "the restored instances are bound to the PRIOR snapshot and global"
        );
    }

    /// The operator surfaces of a successful reload: the `config-applied` event describing what
    /// happened, and the recomputed `repoll` availability for the new instance set. Every id in the
    /// candidate is accounted for — including one that parsed cleanly but failed to launch, which
    /// would otherwise appear in no list at all and simply vanish from the event.
    #[tokio::test(start_paused = true)]
    async fn commit_emits_config_applied_and_recomputes_repoll_availability() {
        let before = document(
            json!({}),
            vec![poll_instance("stays", 500), poll_instance("goes", 500)],
        );
        let after = document(
            json!({}),
            vec![
                poll_instance("stays", 500),
                push_instance("io-1"),
                poll_instance("wont-start", 500),
                json!({ "id": "broken", "adapter": "sim", "connection": { "endpoint": "x:1" },
                        "pollGroups": [], "nonsense": true }),
            ],
        );

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        // A valid instance whose launch fails — the production analog is a UNS-token violation in
        // the id, which only the facade mint can detect.
        launcher.fail_instance("wont-start");
        tx.commit().await.unwrap();

        let ctx = launcher
            .events
            .last_ctx("config-applied")
            .expect("the component event was emitted");
        assert_eq!(ctx["started"], json!(["io-1"]));
        assert_eq!(ctx["stopped"], json!(["goes"]));
        assert_eq!(ctx["kept"], json!(["stays"]));
        assert_eq!(ctx["restartAll"], json!(false));
        assert_eq!(ctx["skipped"][0][0], json!("broken"), "the parse-time skip");
        assert_eq!(
            ctx["skipped"][1][0],
            json!("wont-start"),
            "the launch failure is reported as a skip, with its reason: {}",
            ctx["skipped"]
        );
        assert!(
            ctx["skipped"][1][1]
                .as_str()
                .is_some_and(|reason| reason.contains("wont-start")),
            "the skip carries the launch error: {}",
            ctx["skipped"]
        );
        assert_eq!(
            registry.ids(),
            vec!["stays", "io-1"],
            "the instance that could not launch is not in the running set"
        );

        assert_eq!(
            launcher.journal.lock().unwrap().availability,
            vec![false],
            "a poll instance still runs, so repoll stays available"
        );
    }

    /// Two reloads in a row: the second one diffs against the generation the FIRST one applied, not
    /// against the startup document. A commit that never advances its prior slot would see the
    /// (unchanged) candidate as another non-instance change and restart the whole fleet again — a
    /// spurious device outage on every subsequent apply.
    #[tokio::test(start_paused = true)]
    async fn a_second_reload_diffs_against_the_generation_the_first_one_applied() {
        let before = document(
            json!({}),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );
        // A non-instance change, so the first reload restarts everything.
        let after = document(
            json!({ "timeouts": { "requestTimeoutMs": 1500 } }),
            vec![poll_instance("plc-1", 500), poll_instance("plc-2", 500)],
        );

        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut first = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        first.commit().await.expect("the first reload applies");
        assert_eq!(launcher.journal.lock().unwrap().launches.len(), 2);

        // Re-apply the SAME document — core re-delivers a candidate on every source update, not only
        // on a change. Nothing may move.
        launcher.journal.lock().unwrap().launches.clear();
        let mut second = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();
        second.commit().await.expect("the second reload applies");

        let ctx = launcher
            .events
            .last_ctx("config-applied")
            .expect("the second apply emitted its event");
        assert_eq!(
            ctx["restartAll"],
            json!(false),
            "the candidate matches the generation the first reload installed"
        );
        assert_eq!(ctx["kept"], json!(["plc-1", "plc-2"]));
        assert_eq!(ctx["started"], json!([]));
        assert_eq!(ctx["stopped"], json!([]));
        assert!(
            launcher.journal.lock().unwrap().launches.is_empty(),
            "an unchanged candidate restarts nothing"
        );
        assert_eq!(registry.ids(), vec!["plc-1", "plc-2"]);
    }

    /// A commit is not allowed to hang on a broker. The alarm clear and the `config-applied` event
    /// both go out through a publish with no timeout of its own, and core deliberately never cancels
    /// a commit — so a wedged broker would otherwise stall the reload while it holds core's apply
    /// lock. Each notification is bounded and best-effort: the reload completes regardless.
    #[tokio::test(start_paused = true)]
    async fn commit_is_not_stalled_by_a_wedged_notification() {
        let before = document(
            json!({}),
            vec![poll_instance("stays", 500), poll_instance("goes", 500)],
        );
        let after = document(json!({}), vec![poll_instance("stays", 500)]);

        let launcher = FakeLauncher::new();
        // Every publish this launcher hands out never completes.
        launcher.stall_events();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let mut tx = coord
            .prepare_configuration_apply(snapshot(&after))
            .await
            .unwrap();

        let started = tokio::time::Instant::now();
        tx.commit()
            .await
            .expect("a wedged broker is not a commit failure");
        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);

        // One removed instance ⇒ one alarm clear, plus the config-applied event: two budgets, and
        // nothing else in this commit waits (the stopping task cancels immediately).
        assert!(
            elapsed >= NOTIFY_BUDGET,
            "the wedge is real: the commit waited out a notification budget ({elapsed:?})"
        );
        assert!(
            elapsed <= 2 * NOTIFY_BUDGET + Duration::from_secs(1),
            "the commit is bounded by its notification budgets, not by the broker: {elapsed:?}"
        );
        assert_eq!(
            registry.ids(),
            vec!["stays"],
            "the swap itself completed regardless of the notifications"
        );
    }

    /// An unusable candidate is refused **at prepare**, with the typed code core surfaces in
    /// `lastErrors` — and the running generation keeps operating, untouched. This is the reload-time
    /// mapping of "fail only if zero valid instances".
    #[tokio::test(start_paused = true)]
    async fn prepare_rejects_an_invalid_candidate_and_keeps_the_running_generation() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);

        let no_instances = document(
            json!({}),
            vec![json!({ "id": "broken", "adapter": "sim", "connection": { "endpoint": "x:1" },
                         "pollGroups": [], "nonsense": true })],
        );
        let err = refusal(
            coord
                .prepare_configuration_apply(snapshot(&no_instances))
                .await,
            "a candidate with no valid instance must be refused",
        );
        assert_eq!(err.code, CODE_NO_VALID_INSTANCES);
        assert!(err.message.contains("keeping the running configuration"));

        let bad_global = document(
            json!({ "timeouts": { "requestTimeoutMs": "soon" } }),
            vec![poll_instance("plc-1", 500)],
        );
        let err = refusal(
            coord.prepare_configuration_apply(snapshot(&bad_global)).await,
            "a candidate with a malformed global must be refused",
        );
        assert_eq!(err.code, CODE_INVALID_GLOBAL);
        assert!(err.message.contains("component.global"));

        assert_eq!(
            registry.ids(),
            vec!["plc-1"],
            "a refused candidate leaves the running generation exactly as it was"
        );
        assert!(launcher.journal.lock().unwrap().launches.is_empty());
    }

    /// The early window and the prepare contract: a reload arriving before startup finished is
    /// rejected, and prepare stays far inside core's 5 s timeout even on a large candidate because
    /// it performs no I/O at all.
    #[tokio::test]
    async fn prepare_rejects_before_started_and_is_io_free() {
        let before = document(json!({}), vec![poll_instance("plc-1", 500)]);
        let launcher = FakeLauncher::new();
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);

        let starting = coordinator(&launcher, &registry, &root, &snap, &global, false);
        let err = refusal(
            starting.prepare_configuration_apply(snapshot(&before)).await,
            "a reload before startup finished must be refused",
        );
        assert_eq!(err.code, CODE_STARTING);

        // Shutdown is refused at prepare too, not only at commit.
        let shutting_down = coordinator(&launcher, &registry, &root, &snap, &global, true);
        root.cancel();
        let err = refusal(
            shutting_down
                .prepare_configuration_apply(snapshot(&before))
                .await,
            "a reload during shutdown must be refused",
        );
        assert_eq!(err.code, CODE_SHUTTING_DOWN);

        // …and the timing smoke test, on a candidate far larger than any real deployment.
        let root = CancellationToken::new();
        let (registry, snap, global) = running_registry(&launcher, &before, &root);
        let coord = coordinator(&launcher, &registry, &root, &snap, &global, true);
        let big = document(
            json!({}),
            (0..100)
                .map(|i| poll_instance(&format!("plc-{i}"), 500))
                .collect(),
        );
        let candidate = snapshot(&big);
        let started = std::time::Instant::now();
        let tx = coord.prepare_configuration_apply(candidate).await;
        let elapsed = started.elapsed();
        assert!(tx.is_ok());
        assert!(
            elapsed < Duration::from_secs(1),
            "prepare is allocation-only: {elapsed:?} for 100 instances"
        );
        // Preparing changed nothing: the live set is still the one that was running.
        assert_eq!(registry.ids(), vec!["plc-1"]);
    }
}
