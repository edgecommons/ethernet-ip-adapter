//! # Device-task lifecycle (§10.3, D-EIP-27)
//!
//! The runtime registry, the cancellation tree, and the deadline-bounded stop engine. Pure and
//! hermetic — no sockets, no broker, no facades; [`crate::supervisor`] composes these onto the live
//! tasks, which is why every decision here is unit-tested inside the coverage gate (§12.2).
//!
//! ## Teardown order: cancel → close → join → flush
//!
//! 1. **Cancel first**, from the root token down, so every instance tears down *concurrently* rather
//!    than one budget after another.
//! 2. **Each task closes its own session on the way out** — the session is `!Sync` and owned by the
//!    device task (the same reason [`crate::app::DeviceControl`] exists), so the close cannot be
//!    performed from here. Poll sends UnRegisterSession (`EipClient::close`); push sends ForwardClose
//!    and releases the class-1 sockets.
//! 3. **Join under one absolute budget** ([`stop_budget`]) so those frames actually reach the wire
//!    before the process exits — and **abort** whatever is still running when the budget expires, so
//!    a wedged peer can never hang shutdown. Phase 1 made every close individually bounded; this
//!    composes those bounds into one whole-teardown bound.
//! 4. **`flush_metrics` last**, in the supervisor, so the final counters ride out while messaging is
//!    still up; the library's RAII unsubscribes and the `STOPPED` state follow when `gg` drops.
//!
//! Everything here is idempotent: [`CancellationToken::cancel`] is idempotent, `close()` is
//! idempotent per the [`crate::device`] seam contract, and [`DeviceRegistry::take_all`] consumes —
//! so a second [`shutdown_all`] pass over an empty registry is a no-op.
//!
//! ## The same engine stops one instance
//!
//! A configuration change (§10.4, [`crate::reload`]) stops the instances its candidate replaces
//! through exactly the same path — [`stop_runtimes`], with the same [`stop_budget`] — so a replaced
//! device's session is UnRegisterSession'd / ForwardClose'd before its successor connects, and a
//! wedged instance can no more hang a reload than it can hang shutdown.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::commands::DeviceHandle;
use crate::config::{GlobalConfig, Timeouts};

/// The 5 s cap on the push session's close handoff — the single home for the number the class-1
/// teardown and the shutdown budget must agree on (`eip/live.rs` reads it from here).
pub(crate) const PUSH_CLOSE_HANDOFF_CAP: Duration = Duration::from_secs(5);

/// Documented mirror of `enip`'s (crate-private) `CLOSE_HANDOFF_DEADLINE` (2 s): the bound on the
/// poll session's UnRegisterSession handoff inside `EipClient::close()`. Kept as a mirror because
/// the budget only needs an upper bound; drift is absorbed by [`STOP_GRACE`] and the clamp.
pub(crate) const ENIP_SESSION_CLOSE_BOUND: Duration = Duration::from_secs(2);

/// Slack over the composed protocol bounds — scheduling, the final metric flush of a task, and any
/// drift between [`ENIP_SESSION_CLOSE_BOUND`] and the crate's own constant.
pub(crate) const STOP_GRACE: Duration = Duration::from_millis(500);

/// The teardown budget never shrinks below this, however small the configured timeouts are.
pub(crate) const STOP_BUDGET_FLOOR: Duration = Duration::from_secs(1);

/// The teardown budget never grows beyond this, however large `requestTimeoutMs` is — shutdown must
/// stay well inside a supervisor's grace period (Kubernetes default 30 s, Greengrass default 15 s).
pub(crate) const STOP_BUDGET_CEILING: Duration = Duration::from_secs(10);

/// The whole-teardown budget (D-EIP-27): one in-flight request bound (a cancel arriving during a CIP
/// read/write is observed only after that call resolves) + the worst per-session close bound (poll:
/// ForwardClose ≤ `requestTimeoutMs`, then the 2 s `enip` handoff; push: the
/// [`PUSH_CLOSE_HANDOFF_CAP`], which itself contains ForwardClose + `IoManager` shutdown + client
/// close) + [`STOP_GRACE`]; clamped to [[`STOP_BUDGET_FLOOR`], [`STOP_BUDGET_CEILING`]].
///
/// At the shipped defaults (`requestTimeoutMs: 2000`) that is 2 s + max(5 s, 4 s) + 0.5 s = **7.5 s**.
pub(crate) fn stop_budget(timeouts: &Timeouts) -> Duration {
    let in_flight = Duration::from_millis(timeouts.request_timeout_ms.max(1));
    let close_worst = PUSH_CLOSE_HANDOFF_CAP.max(in_flight + ENIP_SESSION_CLOSE_BOUND);
    (in_flight + close_worst + STOP_GRACE).clamp(STOP_BUDGET_FLOOR, STOP_BUDGET_CEILING)
}

/// One instance's live runtime: the routing view + the supervision view.
pub(crate) struct DeviceRuntime {
    /// The routing view shared with the command surface (cfg, control, health, dm, events).
    pub handle: DeviceHandle,
    /// This instance's raw `component.instances[]` subtree — the configuration-diff key
    /// ([`crate::reload::plan`]) and the undo record a rollback relaunches from.
    pub raw: serde_json::Value,
    /// Child of the app root token; cancelling it stops this instance's tasks.
    pub cancel: CancellationToken,
    /// The device task, plus the cert-lifecycle task when the instance is TLS poll.
    pub tasks: Vec<JoinHandle<()>>,
}

/// The live per-instance registry — the ONE source of truth for the connectivity provider, the
/// command surface, and shutdown. Insertion order is configuration order at startup, and
/// kept-instances-then-newly-launched after a configuration change; it is the order the connectivity
/// list and the routing snapshot report. The single-instance command default depends on the live
/// *count*, not on that order (§10.4).
///
/// Lock discipline: a `std::sync::RwLock`, **never** held across an `.await` — every method takes
/// it, copies or moves what it needs, and drops it before returning.
#[derive(Default)]
pub(crate) struct DeviceRegistry {
    inner: RwLock<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    devices: Vec<DeviceRuntime>,
    global: Option<Arc<GlobalConfig>>,
}

impl DeviceRegistry {
    /// Append a launched runtime. The caller guarantees id-uniqueness: startup and every reload
    /// derive their instance set from [`crate::reload::parse_instances`], which resolves a duplicate
    /// id first-wins exactly as `Config::instance` does — so an id is launched once, and stopping it
    /// stops all of it.
    pub fn insert(&self, rt: DeviceRuntime) {
        self.inner.write().unwrap().devices.push(rt);
    }

    /// Remove one instance's runtime by id, if present — the reload transaction's detach step
    /// (shutdown drains with [`Self::take_all`] instead).
    pub fn remove(&self, id: &str) -> Option<DeviceRuntime> {
        let mut state = self.inner.write().unwrap();
        let idx = state.devices.iter().position(|rt| rt.handle.cfg.id == id)?;
        Some(state.devices.remove(idx))
    }

    /// Drain every runtime out of the registry (the shutdown pass).
    pub fn take_all(&self) -> Vec<DeviceRuntime> {
        std::mem::take(&mut self.inner.write().unwrap().devices)
    }

    /// An order-preserving snapshot of **every** routing view — the whole ordered set.
    ///
    /// Per-request routing does not use this: [`Self::handle`] and [`Self::sole_handle`] clone at
    /// most one [`DeviceHandle`] (each of which carries a full `DeviceConfig`), where this clones
    /// them all. Reach for it only where the ordered set itself is the answer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn handles(&self) -> Vec<DeviceHandle> {
        self.inner
            .read()
            .unwrap()
            .devices
            .iter()
            .map(|rt| rt.handle.clone())
            .collect()
    }

    /// The routing view of ONE instance — a single-handle clone, so per-request routing does not
    /// deep-clone the whole snapshot ([`crate::commands::Commander::resolve`]'s hot path).
    ///
    /// Takes the read lock once, scans in insertion order (single-digit instance counts), and clones
    /// at most one handle; the lock is dropped before returning, so no verb holds it across an
    /// `.await`.
    pub fn handle(&self, id: &str) -> Option<DeviceHandle> {
        self.inner
            .read()
            .unwrap()
            .devices
            .iter()
            .find(|rt| rt.handle.cfg.id == id)
            .map(|rt| rt.handle.clone())
    }

    /// The unaddressed-request routing outcome (D-EIP-13): the sole running instance, or why there
    /// is not one — so the caller can answer `DEVICE_UNAVAILABLE` (nothing running) and `BAD_ARGS`
    /// (several running) from the same single-lock scan, cloning at most one handle.
    pub fn sole_handle(&self) -> SoleHandle {
        let state = self.inner.read().unwrap();
        let mut devices = state.devices.iter();
        match (devices.next(), devices.next()) {
            (Some(rt), None) => SoleHandle::One(rt.handle.clone()),
            (Some(_), Some(_)) => SoleHandle::Many,
            (None, _) => SoleHandle::None,
        }
    }

    /// The live instance ids, in configuration order.
    pub fn ids(&self) -> Vec<String> {
        self.inner
            .read()
            .unwrap()
            .devices
            .iter()
            .map(|rt| rt.handle.cfg.id.clone())
            .collect()
    }

    /// The connectivity sample for every live instance — the one provider behind both the `state`
    /// keepalive's `instances[]` and the built-in `status` verb (§9.1).
    pub fn connectivity(&self) -> Vec<edgecommons::prelude::InstanceConnectivity> {
        self.inner
            .read()
            .unwrap()
            .devices
            .iter()
            .map(|rt| crate::app::connectivity_of(&rt.handle.cfg, &rt.handle.health))
            .collect()
    }

    /// Publish the generation's parsed `component.global`.
    pub fn set_global(&self, g: Arc<GlobalConfig>) {
        self.inner.write().unwrap().global = Some(g);
    }

    /// The generation's parsed `component.global`.
    ///
    /// Read by the command surface (so `sb/signals` reflects the post-swap generation) and by the
    /// reload transaction (whose stop stage is budgeted from the generation being torn down).
    ///
    /// # Panics
    /// Panics when no global has been published yet; `App::new` sets it before anything can read it.
    pub fn global(&self) -> Arc<GlobalConfig> {
        self.inner
            .read()
            .unwrap()
            .global
            .clone()
            .expect("the registry global is set before the registry is readable")
    }

    /// The `(id, raw subtree)` view of what is actually running — the reload plan's input (the
    /// running set, deliberately not the previous `Config`).
    pub fn snapshot_running(&self) -> Vec<(String, serde_json::Value)> {
        self.inner
            .read()
            .unwrap()
            .devices
            .iter()
            .map(|rt| (rt.handle.cfg.id.clone(), rt.raw.clone()))
            .collect()
    }

    /// Whether every live instance runs push mode — the `repoll` availability rule (D-EIP-25),
    /// recomputed after every generation swap.
    pub fn all_push(&self) -> bool {
        let state = self.inner.read().unwrap();
        !state.devices.is_empty()
            && state
                .devices
                .iter()
                .all(|rt| matches!(rt.handle.cfg.mode, crate::config::DeviceMode::Push))
    }

    /// Whether no instance is live.
    // The shutdown drain reads the emptiness of what it just took, under the same lock acquisition;
    // this is the standalone probe the reload transaction uses to refuse an empty generation.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().devices.is_empty()
    }
}

/// What [`DeviceRegistry::sole_handle`] found: the one running instance, none, or several.
///
/// The three outcomes are exactly the three answers the command surface owes an unaddressed request
/// (D-EIP-13), which is why the distinction is made under the registry lock rather than by counting
/// a cloned snapshot afterwards.
// The `One` variant is a whole `DeviceHandle` (a `DeviceConfig` among other things), so the enum is
// as large as one. Boxing it — clippy's suggestion — would put a heap allocation on the very path
// this accessor exists to make cheaper, to save moving a few hundred bytes of an already-owned
// handle exactly once per request. The value is constructed, matched, and unwrapped immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SoleHandle {
    /// Exactly one instance is running — it answers the request.
    One(DeviceHandle),
    /// No instance is running (the stop stage of a configuration change that restarts everything).
    None,
    /// Several instances are running, so the request has to name one.
    Many,
}

/// The stop report — pure accounting, asserted by the tests and logged by the supervisor.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct StopReport {
    /// Tasks that ended on their own (cooperatively, or by panicking) within the budget.
    pub joined: usize,
    /// Tasks still running when the budget expired, and therefore aborted.
    pub aborted: usize,
}

/// Join every handle under ONE absolute deadline (`now + budget`); a handle that does not finish in
/// the remaining window is `abort()`ed and counted.
///
/// Sequential awaits are fine: the tasks run concurrently regardless of await order, and the
/// deadline is absolute — so the whole set costs at most `budget`, not `budget` per task.
pub(crate) async fn stop_tasks(
    tasks: Vec<(String, Vec<JoinHandle<()>>)>,
    budget: Duration,
) -> StopReport {
    let deadline = tokio::time::Instant::now() + budget;
    let mut report = StopReport::default();
    for (id, handles) in tasks {
        for mut handle in handles {
            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => report.joined += 1,
                // The task ended, just not cleanly (a panic, or an earlier abort). It is reaped
                // either way — the point of the join is that it is no longer running.
                Ok(Err(e)) => {
                    tracing::warn!(instance = %id, error = %e, "device task ended abnormally");
                    report.joined += 1;
                }
                Err(_) => {
                    handle.abort();
                    report.aborted += 1;
                    tracing::warn!(
                        instance = %id,
                        "device task did not stop within the teardown budget; aborted"
                    );
                }
            }
        }
    }
    report
}

/// Stop a set of runtimes under one absolute budget: cancel each token, then join-or-abort every
/// task it owns.
///
/// The cancel is the stop signal; consuming the [`DeviceRuntime`]s is the second half of it.
/// Dropping each one drops its [`DeviceHandle`], releasing the registry's `DeviceControl` sender, so
/// once the instance's own tasks let go of their clones the device task sees a closed control
/// channel too — the same `Stopped` exit, reached from either side.
///
/// Shared by shutdown ([`shutdown_all`]) and by the configuration transaction
/// ([`crate::reload`]), which stops one generation's replaced instances the same way.
pub(crate) async fn stop_runtimes(runtimes: Vec<DeviceRuntime>, budget: Duration) -> StopReport {
    let tasks: Vec<(String, Vec<JoinHandle<()>>)> = runtimes
        .into_iter()
        .map(|rt| {
            // Redundant when the token is a child of an already-cancelled root — and exactly right
            // for a per-instance stop, where nothing else has cancelled it.
            rt.cancel.cancel();
            (rt.handle.cfg.id.clone(), rt.tasks)
        })
        .collect();
    stop_tasks(tasks, budget).await
}

/// Cancel the root, then drain-and-stop until the registry is empty.
///
/// The drain is a **loop**, not a single pass: a reload transaction committing concurrently can
/// insert freshly-launched runtimes after the drain started. Their tokens are children of the
/// already-cancelled root, so they are born cancelled, exit immediately, and are reaped by the next
/// pass. The budget is absolute across all passes.
///
/// **Boundary of that guarantee:** the loop reaps an insert that lands before the registry drains
/// empty. An insert landing *after* the final empty [`DeviceRegistry::take_all`] is not joined — it
/// exits on its own, because its token is still a child of the cancelled root, but nobody waits for
/// it. That is harmless as designed (born cancelled, the task returns before it opens a session, so
/// there is no ForwardClose/UnRegisterSession to wait for) and it is why the configuration-commit
/// gate must decide against the root token rather than rely on this drain: anything that can open a
/// session has to be refused once the root is cancelled, not merely reaped afterwards.
pub(crate) async fn shutdown_all(
    registry: &DeviceRegistry,
    root: &CancellationToken,
    budget: Duration,
) -> StopReport {
    let deadline = tokio::time::Instant::now() + budget;
    root.cancel();

    let mut report = StopReport::default();
    loop {
        let runtimes = registry.take_all();
        if runtimes.is_empty() {
            return report;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let pass = stop_runtimes(runtimes, remaining).await;
        report.joined += pass.joined;
        report.aborted += pass.aborted;
    }
}

/// Gate a fallible startup step on the teardown path: `Ok` passes straight through, and an `Err`
/// stops whatever already started — the same cancel → close → join → abort sequence
/// [`shutdown_all`] runs — before the error escapes.
///
/// Startup launches instances one at a time and is fallible *after* the first of them is already
/// polling its device (minting a facade, registering the command surface). Returning that error
/// directly would leave those tasks running and publishing with the process on its way out, their
/// poll sessions never unregistered and their class-1 connections never ForwardClosed — the F4
/// defect on the residual path. Every early return from [`crate::supervisor::App::run`]'s setup
/// therefore comes through here, so a failed start tears down exactly like a signalled shutdown.
pub(crate) async fn stop_on_startup_error<T, E: std::fmt::Display>(
    outcome: std::result::Result<T, E>,
    registry: &DeviceRegistry,
    root: &CancellationToken,
    budget: Duration,
) -> std::result::Result<T, E> {
    match outcome {
        Ok(value) => Ok(value),
        Err(e) => {
            tracing::error!(error = %e, "startup failed; stopping the instances already running");
            let report = shutdown_all(registry, root, budget).await;
            tracing::info!(
                joined = report.joined,
                aborted = report.aborted,
                budget_ms = budget.as_millis() as u64,
                "startup teardown complete"
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{EventSink, Health, LinkState};
    use crate::config::DeviceConfig;
    use serde_json::json;

    fn poll_device(id: &str) -> DeviceConfig {
        DeviceConfig::from_value(&json!({
            "id": id,
            "adapter": "ethernet-ip",
            "connection": { "endpoint": "127.0.0.1:44818", "slot": 0 },
            "pollGroups": [ { "signals": [
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" }
            ] } ]
        }))
        .unwrap()
    }

    fn push_device(id: &str) -> DeviceConfig {
        DeviceConfig::from_value(&json!({
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
        }))
        .unwrap()
    }

    /// A [`DeviceHandle`] over the existing test doubles, plus the receiver end so the control
    /// channel stays open for the lifetime of the test.
    fn handle(
        cfg: DeviceConfig,
        health: Arc<Health>,
    ) -> (
        DeviceHandle,
        tokio::sync::mpsc::Receiver<crate::app::DeviceControl>,
    ) {
        let (control, rx) = tokio::sync::mpsc::channel(4);
        let (_svc, dm) = crate::testutil::device_metrics(cfg.clone(), Arc::clone(&health));
        let events: Arc<dyn EventSink> = Arc::new(crate::testutil::RecordingEvents::default());
        (
            DeviceHandle {
                cfg,
                control,
                health,
                dm,
                events,
            },
            rx,
        )
    }

    /// A runtime whose single task ends when its token is cancelled — the cooperative shape every
    /// real device task has.
    fn cooperative_runtime(cfg: DeviceConfig, cancel: CancellationToken) -> DeviceRuntime {
        let raw = json!({ "id": cfg.id });
        let (h, rx) = handle(cfg, Arc::new(Health::default()));
        let token = cancel.clone();
        let task = tokio::spawn(async move {
            let _keep_channel_open = rx;
            token.cancelled().await;
        });
        DeviceRuntime {
            handle: h,
            raw,
            cancel,
            tasks: vec![task],
        }
    }

    /// A registry-only runtime (no tasks) — for the routing/ordering assertions. The returned
    /// receiver keeps the control channel open for the lifetime of the test.
    fn inert_runtime(
        cfg: DeviceConfig,
        raw: serde_json::Value,
    ) -> (
        DeviceRuntime,
        tokio::sync::mpsc::Receiver<crate::app::DeviceControl>,
    ) {
        let (h, rx) = handle(cfg, Arc::new(Health::default()));
        (
            DeviceRuntime {
                handle: h,
                raw,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
            },
            rx,
        )
    }

    /// The budget composes the Phase-1 per-session bounds, and the push close cap dominates at the
    /// shipped defaults. A silent change to either term shows up here.
    #[test]
    fn stop_budget_composes_the_phase1_bounds() {
        // Defaults: requestTimeoutMs 2000 ⇒ 2 s + max(5 s, 2 s + 2 s) + 0.5 s = 7.5 s.
        assert_eq!(
            stop_budget(&Timeouts::default()),
            Duration::from_millis(7_500)
        );

        // requestTimeoutMs 4000 ⇒ 4 s + max(5 s, 6 s) + 0.5 s = 10.5 s, clamped to the 10 s ceiling.
        let t = Timeouts {
            request_timeout_ms: 4_000,
            ..Timeouts::default()
        };
        assert_eq!(stop_budget(&t), STOP_BUDGET_CEILING);
    }

    /// A pathological `requestTimeoutMs` can neither collapse the budget to nothing nor make
    /// shutdown outlive the supervisor's grace period.
    #[test]
    fn stop_budget_clamps_floor_and_ceiling() {
        let zero = Timeouts {
            request_timeout_ms: 0,
            ..Timeouts::default()
        };
        assert!(
            stop_budget(&zero) >= STOP_BUDGET_FLOOR,
            "the floor holds for a zero request timeout"
        );

        let huge = Timeouts {
            request_timeout_ms: 60_000,
            ..Timeouts::default()
        };
        assert_eq!(stop_budget(&huge), STOP_BUDGET_CEILING);
    }

    /// Cooperative tasks are joined, not aborted, and the report counts them — including a task
    /// that ended by panicking, which is reaped like any other finished task (it is no longer
    /// running, which is the whole point of the join).
    #[tokio::test(start_paused = true)]
    async fn stop_tasks_joins_cooperative_tasks_and_reports() {
        let mut tasks = Vec::new();
        let tokens: Vec<CancellationToken> = (0..3).map(|_| CancellationToken::new()).collect();
        for (i, token) in tokens.iter().enumerate() {
            let t = token.clone();
            tasks.push((
                format!("plc-{i}"),
                vec![tokio::spawn(async move { t.cancelled().await })],
            ));
        }
        for token in &tokens {
            token.cancel();
        }
        tasks.push((
            "plc-panicked".to_string(),
            vec![tokio::spawn(async { panic!("device task blew up") })],
        ));

        let report = stop_tasks(tasks, Duration::from_secs(5)).await;
        assert_eq!(
            report,
            StopReport {
                joined: 4,
                aborted: 0
            }
        );
    }

    /// The F4 class itself: a task that ignores its cancel must not be waited on unboundedly. The
    /// deadline is absolute, so the whole set still costs at most one budget.
    #[tokio::test(start_paused = true)]
    async fn stop_tasks_aborts_stragglers_at_the_absolute_deadline() {
        let cooperative = CancellationToken::new();
        cooperative.cancel();
        let c = cooperative.clone();

        let tasks = vec![
            (
                "plc-ok".to_string(),
                vec![tokio::spawn(async move { c.cancelled().await })],
            ),
            (
                "plc-wedged".to_string(),
                vec![tokio::spawn(async { std::future::pending::<()>().await })],
            ),
        ];

        let budget = Duration::from_secs(4);
        let started = tokio::time::Instant::now();
        let report = stop_tasks(tasks, budget).await;
        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);

        assert_eq!(
            report,
            StopReport {
                joined: 1,
                aborted: 1
            }
        );
        assert!(
            elapsed <= budget,
            "the deadline is absolute: {elapsed:?} > {budget:?}"
        );
    }

    /// A runtime inserted after the root was cancelled — what a configuration commit racing shutdown
    /// does — is born cancelled and reaped by the next drain pass, not left running.
    #[tokio::test(start_paused = true)]
    async fn shutdown_all_reaps_a_runtime_inserted_after_cancel() {
        let registry = Arc::new(DeviceRegistry::default());
        registry.set_global(Arc::new(GlobalConfig::default()));

        let root = CancellationToken::new();

        // The instance that is already running when the shutdown starts. On cancel it does what a
        // concurrent commit would: it inserts a freshly-launched runtime into the registry.
        let first = root.child_token();
        let (h, rx) = handle(poll_device("plc-1"), Arc::new(Health::default()));
        let reg = Arc::clone(&registry);
        let root_for_task = root.clone();
        let token = first.clone();
        let task = tokio::spawn(async move {
            let _keep_channel_open = rx;
            token.cancelled().await;
            let late = root_for_task.child_token();
            assert!(
                late.is_cancelled(),
                "a child minted from an already-cancelled root is born cancelled"
            );
            reg.insert(cooperative_runtime(poll_device("plc-late"), late));
        });
        registry.insert(DeviceRuntime {
            handle: h,
            raw: json!({ "id": "plc-1" }),
            cancel: first,
            tasks: vec![task],
        });

        let report = shutdown_all(&registry, &root, Duration::from_secs(5)).await;

        assert_eq!(
            report,
            StopReport {
                joined: 2,
                aborted: 0
            },
            "the drain loop reaped the late insert as well as the original"
        );
        assert!(registry.is_empty(), "the registry drains empty");
    }

    /// A startup that fails **after** instances are already running must not leak them: the error
    /// path runs the same bounded teardown as shutdown, so the earlier instances are cancelled,
    /// drained, and joined (closing their sessions) instead of polling on into process exit.
    #[tokio::test(start_paused = true)]
    async fn stop_on_startup_error_tears_down_what_already_started() {
        let registry = DeviceRegistry::default();
        let root = CancellationToken::new();

        // Two instances launched before the third one's setup failed.
        let tokens: Vec<CancellationToken> = ["plc-1", "plc-2"]
            .iter()
            .map(|id| {
                let cancel = root.child_token();
                registry.insert(cooperative_runtime(poll_device(id), cancel.clone()));
                cancel
            })
            .collect();

        let failed: anyhow::Result<()> = Err(anyhow::anyhow!("no facade for `plc-3`"));
        let out = stop_on_startup_error(failed, &registry, &root, Duration::from_secs(5)).await;

        let err = out.expect_err("the startup error still propagates");
        assert!(
            err.to_string().contains("plc-3"),
            "the original error is unchanged: {err}"
        );
        assert!(root.is_cancelled(), "the root token was cancelled");
        for token in &tokens {
            assert!(
                token.is_cancelled(),
                "every launched instance was cancelled"
            );
        }
        assert!(
            registry.is_empty(),
            "the registry drained — no task left running"
        );
    }

    /// The success path is inert: it neither cancels the root nor disturbs the registry, so wrapping
    /// startup in it cannot cost a running adapter its instances.
    #[tokio::test(start_paused = true)]
    async fn stop_on_startup_error_passes_success_through_untouched() {
        let registry = DeviceRegistry::default();
        let root = CancellationToken::new();
        let (rt, _rx) = inert_runtime(poll_device("plc-1"), json!({ "id": "plc-1" }));
        registry.insert(rt);

        let out: anyhow::Result<u8> =
            stop_on_startup_error(Ok(7), &registry, &root, Duration::from_secs(5)).await;

        assert_eq!(out.unwrap(), 7);
        assert!(!root.is_cancelled(), "a successful startup cancels nothing");
        assert_eq!(registry.ids(), vec!["plc-1"], "the registry is untouched");
    }

    /// Routing order is configuration order (the single-instance command default depends on it),
    /// removal is by id, and the shutdown drain empties the registry.
    #[test]
    fn registry_preserves_insertion_order_and_removes_by_id() {
        let registry = DeviceRegistry::default();
        assert!(registry.is_empty());

        let mut _rxs = Vec::new();
        for id in ["plc-a", "plc-b", "plc-c"] {
            let (rt, rx) = inert_runtime(poll_device(id), json!({ "id": id }));
            registry.insert(rt);
            _rxs.push(rx);
        }
        assert_eq!(registry.ids(), vec!["plc-a", "plc-b", "plc-c"]);
        assert_eq!(
            registry
                .handles()
                .iter()
                .map(|h| h.cfg.id.clone())
                .collect::<Vec<_>>(),
            vec!["plc-a", "plc-b", "plc-c"],
            "handles() preserves the same order"
        );

        let removed = registry.remove("plc-b").expect("plc-b is live");
        assert_eq!(removed.handle.cfg.id, "plc-b");
        assert!(registry.remove("plc-b").is_none(), "removal is idempotent");
        assert_eq!(registry.ids(), vec!["plc-a", "plc-c"], "order survives");

        let drained = registry.take_all();
        assert_eq!(drained.len(), 2);
        assert!(registry.is_empty());
        assert!(registry.take_all().is_empty(), "a second drain is a no-op");
    }

    /// The targeted routing accessors the command surface resolves through: `handle` clones exactly
    /// the addressed instance (`None` for an id the registry does not run), and `sole_handle`
    /// distinguishes the three unaddressed outcomes (D-EIP-13) — none running, exactly one, several
    /// — from a single scan. Against `handles()` the same answers cost a clone of every running
    /// instance's `DeviceConfig`.
    #[test]
    fn handle_and_sole_handle_return_single_clones() {
        let registry = DeviceRegistry::default();

        // Nothing running: no id resolves, and the unaddressed outcome is `None`.
        assert!(registry.handle("plc-a").is_none());
        assert!(matches!(registry.sole_handle(), SoleHandle::None));

        let (rt, _rx_a) = inert_runtime(poll_device("plc-a"), json!({ "id": "plc-a" }));
        let health_a = Arc::clone(&rt.handle.health);
        registry.insert(rt);

        // One running: the addressed lookup and the sole-instance default find the same instance,
        // and the clone shares the live `Health` the device task writes (it is a handle clone, not a
        // detached copy).
        let addressed = registry.handle("plc-a").expect("plc-a is live");
        assert_eq!(addressed.cfg.id, "plc-a");
        assert!(Arc::ptr_eq(&addressed.health, &health_a));
        match registry.sole_handle() {
            SoleHandle::One(h) => {
                assert_eq!(h.cfg.id, "plc-a");
                assert!(Arc::ptr_eq(&h.health, &health_a));
            }
            _ => panic!("exactly one instance is running"),
        }
        // An id the registry does not run never falls back to "the only device".
        assert!(registry.handle("ghost").is_none());

        // Several running: the addressed lookup still resolves each one; the unaddressed outcome is
        // `Many`, and insertion order does not make the first one a default.
        let (rt, _rx_b) = inert_runtime(poll_device("plc-b"), json!({ "id": "plc-b" }));
        registry.insert(rt);
        assert_eq!(
            registry
                .handle("plc-a")
                .map(|h| h.cfg.id.clone())
                .as_deref(),
            Some("plc-a")
        );
        assert_eq!(
            registry
                .handle("plc-b")
                .map(|h| h.cfg.id.clone())
                .as_deref(),
            Some("plc-b")
        );
        assert!(matches!(registry.sole_handle(), SoleHandle::Many));

        // Back to one: the survivor answers unaddressed requests again.
        registry.remove("plc-a").expect("plc-a is live");
        match registry.sole_handle() {
            SoleHandle::One(h) => assert_eq!(h.cfg.id, "plc-b"),
            _ => panic!("the survivor is the sole instance"),
        }
        assert!(
            registry.handle("plc-a").is_none(),
            "a stopped instance stops routing"
        );

        // Drained: `None` again.
        registry.take_all();
        assert!(matches!(registry.sole_handle(), SoleHandle::None));
    }

    /// The connectivity provider reads the SAME `Health` the device task writes, so flipping the
    /// link/paused state moves the reported element with no re-registration.
    #[test]
    fn registry_connectivity_derives_from_the_shared_health() {
        let registry = DeviceRegistry::default();
        let (rt, _rx) = inert_runtime(poll_device("plc-1"), json!({ "id": "plc-1" }));
        let health = Arc::clone(&rt.handle.health);
        registry.insert(rt);

        let before = registry.connectivity();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].instance, "plc-1");
        assert!(!before[0].connected);
        assert_eq!(before[0].state.as_deref(), Some("CONNECTING"));

        health.set_link(LinkState::Online);
        health
            .paused
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let after = registry.connectivity();
        assert!(after[0].connected, "connected stays truthful while paused");
        assert_eq!(after[0].state.as_deref(), Some("PAUSED"));
        assert_eq!(after[0].attributes["paused"], json!(true));
    }

    /// The generation views the configuration transaction reads: the parsed global, the running
    /// `(id, raw)` set, and the all-push `repoll` availability rule.
    #[test]
    fn registry_exposes_the_generation_views() {
        let registry = DeviceRegistry::default();
        registry.set_global(Arc::new(GlobalConfig::default()));
        assert_eq!(
            registry.global().timeouts.request_timeout_ms,
            Timeouts::default().request_timeout_ms
        );
        assert!(!registry.all_push(), "an empty registry is not all-push");

        let (rt, _rx1) =
            inert_runtime(push_device("io-1"), json!({ "id": "io-1", "mode": "push" }));
        registry.insert(rt);
        assert!(registry.all_push());
        assert_eq!(
            registry.snapshot_running(),
            vec![("io-1".to_string(), json!({ "id": "io-1", "mode": "push" }))]
        );

        let (rt, _rx2) = inert_runtime(poll_device("plc-1"), json!({ "id": "plc-1" }));
        registry.insert(rt);
        assert!(!registry.all_push(), "one poll instance can service repoll");
        assert_eq!(registry.snapshot_running().len(), 2);
    }
}
