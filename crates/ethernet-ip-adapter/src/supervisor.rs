//! # Runtime construction (§3.2, §10.3) — the EdgeCommons wiring an instance is built from
//!
//! This module is the component's **construction glue**: [`App`] parses the component configuration,
//! builds the live [`crate::lifecycle::DeviceRegistry`] and the cancellation root, installs the single
//! configuration-application coordinator, and publishes the connectivity + `sb/*` surfaces;
//! [`RuntimeLauncher`] is the production body of [`crate::reload::DeviceLauncher`] — the one place an
//! instance's facades, metric identity, control channel, and tasks are constructed — and
//! [`FacadeEventSink`] / [`DroppedEvents`] are the `evt`-surface bindings. It makes **no runtime
//! decision of its own**: what to launch, stop, or keep is decided in [`crate::reload`], how a
//! teardown is bounded in [`crate::lifecycle`], and what a running instance does in
//! [`crate::reconnect`] / [`crate::security_lifecycle`] / the poll+push drivers — every one of them
//! inside the coverage gate and unit-tested against injected seams.
//!
//! This file is inside the gate too, and reads **uncovered**: every path here needs an
//! `Arc<EdgeCommons>`, and the core library's offline test constructor is `pub(crate)`, so a
//! dependent crate cannot build a runtime in a unit test. It is exercised by the HOST / full-system
//! E2E and the deployed regression instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use edgecommons::prelude::*;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::app::{DeviceControl, EventSink, Health};
use crate::config::{DeviceConfig, DeviceMode, GlobalConfig};
use crate::lifecycle::{DeviceRegistry, DeviceRuntime};
use crate::metrics::DeviceMetrics;
use crate::publish::Publisher;
use crate::reload::{DeviceLauncher, PriorGeneration, ReloadCoordinator};

pub struct App {
    /// The startup configuration snapshot — the generation the first instances bind to. A reload
    /// replaces it (in the coordinator's prior slot); this field stays the startup document, which
    /// is all `start_instances` needs.
    config: Arc<Config>,
    metrics: Arc<dyn MetricService>,
    global: Arc<GlobalConfig>,
    /// The startup instance set as `(parsed config, raw subtree)`, deduped first-wins by
    /// [`crate::reload::parse_instances`] — the same list a reload plans against.
    devices: Vec<(DeviceConfig, Value)>,
    /// The live per-instance registry (§10.3): the ONE source of truth for the connectivity
    /// provider, the command surface, the configuration transaction, and the shutdown drain.
    registry: Arc<DeviceRegistry>,
    /// The app-wide cancellation root. Every instance runs under a child of it, so one `cancel()`
    /// reaches every device task, and each instance can still be stopped on its own — which is what
    /// a configuration change does to the instances it replaces (§10.4).
    root: CancellationToken,
    /// Flipped once the startup launch loop has published every surface. A reload arriving before
    /// then is rejected with `STARTING` rather than diffing against a half-populated registry.
    started: Arc<AtomicBool>,
    /// The ONE construction path for an instance runtime — startup and every reload go through it,
    /// which is what makes skip-bad, facade binding, and metric definition provably identical.
    launcher: Arc<RuntimeLauncher>,
}

impl App {
    /// Parse the component configuration, build the live registry, and install the single
    /// configuration-application coordinator (§10.4, D-EIP-28).
    ///
    /// # Errors
    /// A malformed `component.global`, zero valid instances, or a coordinator that is somehow
    /// already installed (a programming error — core allows exactly one).
    pub fn new(gg: &Arc<EdgeCommons>) -> anyhow::Result<Self> {
        let config = gg.config();
        let metrics = gg.metrics();

        let global = Arc::new(
            GlobalConfig::from_value(config.global())
                .map_err(|e| anyhow::anyhow!("invalid component.global: {e}"))?,
        );

        // The SAME instance-set rule a configuration change applies (`reload::parse_instances`):
        // declaration order, duplicate ids first-wins, id-less entries invisible, malformed entries
        // skipped with a warning. Startup deduping differently from the plan would leave a surplus
        // runtime the reload could never stop (§10.4).
        let (devices, skipped) = crate::reload::parse_instances(&config.raw);
        for (id, e) in &skipped {
            tracing::warn!("skipping malformed device `{id}`: {e}");
        }
        anyhow::ensure!(
            !devices.is_empty(),
            "no valid devices in component.instances[]"
        );

        let registry = Arc::new(DeviceRegistry::default());
        registry.set_global(Arc::clone(&global));
        let root = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let launcher = Arc::new(RuntimeLauncher {
            gg: Arc::downgrade(gg),
            creds: gg.credentials(),
            root: root.clone(),
        });

        // Configuration changes apply as ONE transaction over the live instance set: core prepares
        // and commits this coordinator BEFORE it publishes a candidate snapshot, so a rejected
        // candidate leaves the running generation untouched. Core allows exactly one coordinator —
        // a second registration is a programming error, so it fails startup loudly rather than
        // leaving the component running with a silently inert reload path.
        let coordinator = Arc::new(ReloadCoordinator::new(
            Arc::clone(&launcher) as Arc<dyn DeviceLauncher>,
            Arc::clone(&registry),
            root.clone(),
            Arc::clone(&started),
            PriorGeneration::of(&config, &global),
        ));
        gg.add_config_apply_listener(coordinator)
            .map_err(|e| anyhow::anyhow!("config apply listener: {e}"))?;

        Ok(Self {
            config,
            metrics,
            global,
            devices,
            registry,
            root,
            started,
            launcher,
        })
    }

    pub async fn run(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        let budget = crate::lifecycle::stop_budget(&self.global.timeouts);

        // Startup is fallible while instances are ALREADY running (facade minting, command
        // registration), so its error takes the same bounded teardown as a signalled shutdown before
        // it propagates: a failed start must not leave device tasks polling and publishing with
        // their sessions unclosed (§10.3, D-EIP-27).
        crate::lifecycle::stop_on_startup_error(
            self.start_instances(gg),
            &self.registry,
            &self.root,
            budget,
        )
        .await?;

        gg.shutdown_signal().await;
        tracing::info!("shutdown signal received; stopping device tasks");
        let report = crate::lifecycle::shutdown_all(&self.registry, &self.root, budget).await;
        tracing::info!(
            joined = report.joined,
            aborted = report.aborted,
            budget_ms = budget.as_millis() as u64,
            "device teardown complete"
        );
        self.metrics.flush_metrics().await.ok();
        Ok(())
    }

    /// Launch every launchable instance into the registry, then publish the two surfaces that read
    /// it (the connectivity provider and the `sb/*` command surface) and open the reload gate. The
    /// launch pass and its skip-bad rule are [`crate::reload::launch_startup_set`]; this is its
    /// wiring.
    ///
    /// Fallible, and deliberately *only* fallible: whatever it has already launched is live by the
    /// time it can fail, so its `Err` is routed through
    /// [`crate::lifecycle::stop_on_startup_error`] rather than returned to the caller directly.
    fn start_instances(&self, gg: &EdgeCommons) -> anyhow::Result<()> {
        // The same launcher a configuration change calls — one construction path, one behavior —
        // under the launch-time skip-bad rule (§10.4): a bad adapter token costs that instance, not
        // the healthy ones beside it, and startup fails only when nothing at all is launchable.
        let outcome = crate::reload::launch_startup_set(
            self.launcher.as_ref(),
            &self.devices,
            &self.global,
            &self.config,
        );
        // Register FIRST, including on the fatal path: whatever started is live, and only the
        // registry gets it into the bounded teardown (D-EIP-27).
        let launched = outcome.launched.len();
        for runtime in outcome.launched {
            self.registry.insert(runtime);
        }
        if let Some(e) = outcome.fatal {
            return Err(e);
        }
        if !outcome.skipped.is_empty() {
            // The component is running a SUBSET of what was configured — one summary line beside the
            // per-instance warnings, so an operator scanning the startup log sees it at a glance.
            tracing::warn!(
                launched,
                skipped = outcome.skipped.len(),
                instances = %outcome.skipped.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(", "),
                "started without every configured instance"
            );
        }

        // ONE provider, TWO surfaces: the library pushes this sample into the `state` keepalive's
        // `instances[]` every tick, and returns the same sample from the built-in `status` verb. It
        // reads the registry, so it reports what is actually running — across every generation, with
        // no re-registration.
        let reg = Arc::clone(&self.registry);
        let provider: Arc<InstanceConnectivityProvider> = Arc::new(move || reg.connectivity());
        gg.set_instance_connectivity_provider(Some(provider));

        // The full southbound command surface (§7): all nine `sb/*` verbs + the three edge-console
        // panels, mode-aware, with instance routing and the §7.1 error codes. Registered ONCE, over
        // the registry, so routing follows the live instance set instead of a startup snapshot.
        if let Some(commands) = gg.commands() {
            crate::commands::register_all(&commands, Arc::clone(&self.registry))?;
        }

        // Every surface now reads the live registry: a configuration change may be applied against
        // it. Before this point a reload is refused with `STARTING` (§10.4).
        self.started.store(true, Ordering::Release);
        Ok(())
    }
}

/// The production [`DeviceLauncher`]: the one place an instance runtime is built and started.
///
/// Startup calls it per configured device; a configuration commit calls it for every added or
/// changed instance, and a rollback calls it to restore the prior set — always against an explicit
/// configuration snapshot, so the facades, the UNS identity, and the metric identity of an instance
/// are exactly the ones its generation declared.
struct RuntimeLauncher {
    /// **Weak** on purpose: core holds the coordinator, the coordinator holds this launcher. A
    /// strong reference here would be an `Arc` cycle through the runtime and would suppress the RAII
    /// teardown (unsubscribes, `STOPPED` state) that dropping `gg` in `main` performs. A failed
    /// upgrade means the runtime is going away — the launch is refused.
    gg: Weak<EdgeCommons>,
    /// The credentials vault, when the component declares a `credentials` section — the source of TLS
    /// cert/key/CA material for `mode: tls` connections (CIP Security Phase 1). `None` otherwise.
    creds: Option<Arc<dyn edgecommons::credentials::CredentialService>>,
    /// The app root: every instance's token is a child of it, so shutdown reaches every generation.
    root: CancellationToken,
}

impl DeviceLauncher for RuntimeLauncher {
    fn launch(
        &self,
        cfg: &DeviceConfig,
        raw: &Value,
        global: &Arc<GlobalConfig>,
        snapshot: &Arc<Config>,
    ) -> anyhow::Result<DeviceRuntime> {
        let gg = self
            .gg
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("the runtime is shutting down"))?;

        // Resolve the backend BEFORE anything is built or spawned: an adapter token nothing
        // implements is a bad instance, and refusing the launch here is what turns it into a
        // *skipped* instance on both paths (§10.4) instead of one that never connects and never says
        // why. The refusal is typed, so the caller can tell it apart from a real construction
        // failure; the warning belongs to the caller, which knows whether it skipped or gave up.
        let Some(backend) = crate::reconnect::backend_for(&cfg.adapter, global, self.creds.clone())
        else {
            return Err(anyhow::Error::new(crate::reconnect::UnknownAdapter {
                instance: cfg.id.clone(),
                adapter: cfg.adapter.clone(),
            }));
        };

        // Facades bound to THIS snapshot, not to whatever core's current snapshot happens to be:
        // during a commit the candidate has not been published yet, and the instance must already
        // mint its topics and stamp its identity from the configuration it is being started for.
        let instance = gg.instance_from_config_snapshot(&cfg.id, Arc::clone(snapshot))?;

        // Allow-list entries matching no configured tag are warned, not rejected (§4.4) — on every
        // launch, so a reload reports them exactly as startup does.
        for ghost in cfg.unmatched_allow_entries() {
            tracing::warn!(
                instance = %cfg.id, tag_path = %ghost,
                "writes.allow entry matches no configured tagPath (kept for sb/write-by-ref)"
            );
        }

        let cancel = self.root.child_token();

        // One control channel per device. The command inbox cannot touch the session directly —
        // the session lives in the device's own task and is not `Sync` — so every session-touching
        // verb is *sent* to that task as a [`DeviceControl`], which serializes it against the
        // poll/push loop.
        let (control_tx, control_rx) = tokio::sync::mpsc::channel::<DeviceControl>(16);

        let health = Arc::new(Health::default());

        // The full §8 metric set for this device, dimensioned BY INSTANCE (a fleet view can show one
        // device down without averaging it away): the mandatory `southbound_health` plus the six
        // `EtherNetIp*` families, defined up front and emitted on the `metricsIntervalSecs` cadence +
        // connect/disconnect/pause/resume/push-up/lost transitions. `define_metric` replaces by name,
        // so defining them again for a relaunched instance is idempotent.
        let dm = Arc::new(DeviceMetrics::new(
            gg.metrics(),
            Arc::clone(snapshot),
            cfg.clone(),
            global,
            Arc::clone(&health),
        ));
        dm.define_all();

        let events: Arc<dyn EventSink> = Arc::new(FacadeEventSink(instance.events()));

        // The routing view the command surface reads (routing, allow-list, status snapshot) and the
        // connectivity provider samples.
        let handle = crate::commands::DeviceHandle {
            cfg: cfg.clone(),
            control: control_tx.clone(),
            health: Arc::clone(&health),
            dm: Arc::clone(&dm),
            events: Arc::clone(&events),
        };

        // The supervision view: every spawned task's join handle, so shutdown (and a reload that
        // replaces this instance) can actually wait for the session close instead of discarding it.
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // CIP Security Phase 2b: a per-instance cert-lifecycle task for a TLS poll device watches
        // the vault for a rotated client cert / trust store and cert-expiry threshold crossings,
        // reconnecting so the fresh material takes effect without a restart (§4.2).
        let tls_poll = !matches!(cfg.mode, DeviceMode::Push)
            && crate::eip::tls::SecurityConfig::from_connection(&cfg.connection)
                .ok()
                .flatten()
                .is_some_and(|s| s.is_tls());
        if tls_poll {
            tasks.push(tokio::spawn(crate::security_lifecycle::run_security_lifecycle(
                cfg.clone(),
                self.creds.clone(),
                control_tx,
                Arc::clone(&events),
                Arc::clone(&dm),
                Some(Arc::clone(&health)),
                cancel.clone(),
            )));
        }

        tasks.push(tokio::spawn(crate::reconnect::run_device(
            cfg.clone(),
            Arc::clone(global),
            backend,
            Arc::new(crate::publish_sink::FacadePublisher(instance.data())) as Arc<dyn Publisher>,
            events,
            dm,
            health,
            control_rx,
            cancel.clone(),
        )));

        Ok(DeviceRuntime {
            handle,
            raw: raw.clone(),
            cancel,
            tasks,
        })
    }

    fn component_events(&self) -> Arc<dyn EventSink> {
        match self.gg.upgrade() {
            Some(gg) => Arc::new(FacadeEventSink(gg.events())),
            // Shutting down: swallow the event rather than fail a commit over it.
            None => Arc::new(DroppedEvents),
        }
    }

    fn set_repoll_availability(&self, all_push: bool) {
        let Some(gg) = self.gg.upgrade() else {
            return;
        };
        let Some(commands) = gg.commands() else {
            return;
        };
        let (state, reason) = crate::commands::repoll_availability(all_push);
        if let Err(e) = commands.set_command_availability("repoll", state, reason) {
            tracing::warn!(error = %e, "could not update the repoll verb's availability");
        }
    }
}

/// The event sink of a runtime that is already gone — every emit is a no-op. Only reachable when the
/// `EdgeCommons` runtime dropped between a commit's launch stage and its event, i.e. at process exit.
struct DroppedEvents;

#[async_trait::async_trait]
impl EventSink for DroppedEvents {
    async fn emit(&self, _: Severity, _: &str, _: Option<String>, _: Option<serde_json::Value>) {}
    async fn raise_alarm(&self, _: Severity, _: &str, _: Option<String>, _: Option<serde_json::Value>) {}
    async fn clear_alarm(&self, _: Severity, _: &str, _: Option<serde_json::Value>) {}
}

/// Production [`EventSink`] over the `events()` facade. Errors are best-effort (a failed publish must
/// not stall the loop) — matching the template's `let _ = events…` behavior.
pub struct FacadeEventSink(pub EventsFacade);

#[async_trait::async_trait]
impl EventSink for FacadeEventSink {
    async fn emit(&self, severity: Severity, event_type: &str, message: Option<String>, context: Option<serde_json::Value>) {
        let _ = self.0.emit(severity, event_type.to_string(), message, context).await;
    }
    async fn raise_alarm(&self, severity: Severity, event_type: &str, message: Option<String>, context: Option<serde_json::Value>) {
        let _ = self.0.raise_alarm(severity, event_type.to_string(), message, context).await;
    }
    async fn clear_alarm(&self, severity: Severity, event_type: &str, context: Option<serde_json::Value>) {
        let _ = self.0.clear_alarm(severity, event_type.to_string(), context).await;
    }
}
