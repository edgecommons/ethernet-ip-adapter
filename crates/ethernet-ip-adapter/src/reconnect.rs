//! # The reconnect ladders (§3.2, §10.2) — connect → drive → back off → reconnect
//!
//! One device task's whole lifecycle lives here: [`run_device`] connects within the configured
//! deadline, hands the session to the mode's engine loop ([`crate::poll_driver`] /
//! [`crate::push_driver`]), and decides what happens when that loop returns — alarm or silence,
//! backoff or straight back to connect, a reply to fulfil or a task to end.
//!
//! It is **composition logic, not I/O glue**: the alarm/clear pairing on the connect edge, the
//! `attempt` ladder and its reset, the permanent-vs-transient wait, the TLS handshake-failure edge
//! latch, the §7.5 `sb/reconnect` reply carried across the connect boundary, the ForwardClose that
//! must run on every push exit path, and the D-ENIP-17 "a requested reconnect is not a watchdog
//! timeout" distinction are all decided in this file. Every one of them is decided over injected
//! seams — [`DeviceBackend`] (the wire), [`crate::publish::Publisher`] (the broker), [`EventSink`]
//! (the `evt` surface), [`DeviceMetrics`] — so the ladders run as ordinary unit tests on a paused
//! clock (`#[cfg(test)] mod tests` below). The live cpppo/OpENer suites (§11) and the deployed
//! regression validate them against real devices, which is conformance evidence rather than
//! coverage evidence.
//!
//! Backend construction is the one thing that is *not* decided here: [`backend_for`] maps the
//! configured adapter token to its [`DeviceBackend`], and [`crate::supervisor::RuntimeLauncher`]
//! calls it at launch time so an unknown token fails the launch (reported as a skip on the reload
//! path, §10.4) instead of idling a task forever.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::credentials::CredentialService;
use edgecommons::prelude::Severity;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::app::{
    connect_reason, rand01, serve_control_disconnected, Backoff, DeviceControl, DisconnectedWait,
    EventSink, Health, LinkState,
};
use crate::config::{DeviceConfig, DeviceMode, GlobalConfig};
use crate::device::DeviceBackend;
use crate::metrics::DeviceMetrics;
use crate::publish::Publisher;
use crate::sim::SimBackend;

/// A configured `adapter` token no backend implements (§3.4).
///
/// It is a **bad instance**, not a broken runtime — the same class of configuration defect as an
/// instance whose subtree does not parse — so both paths skip it and keep the healthy instances
/// beside it running (§10.4 skip-bad; startup still refuses to run when *nothing* is launchable).
/// It is carried as a typed cause precisely so the startup path can tell it apart from a genuine
/// construction failure (a UNS-token violation in the instance id, a runtime already shutting down),
/// which stays fatal.
#[derive(Debug, thiserror::Error)]
#[error("device `{instance}`: unknown adapter `{adapter}` (expected `ethernet-ip` or `sim`)")]
pub(crate) struct UnknownAdapter {
    pub instance: String,
    pub adapter: String,
}

impl UnknownAdapter {
    /// Whether `e` is (or was caused by) an unresolvable adapter token.
    pub(crate) fn is_cause(e: &anyhow::Error) -> bool {
        e.downcast_ref::<Self>().is_some()
    }
}

/// Select the backend for a configured adapter token (§3.4). `None` for an unknown token — the
/// caller (the launcher) turns that into an [`UnknownAdapter`] launch refusal, so a typo'd `adapter`
/// surfaces as a skipped instance with a warning instead of one that silently never connects.
pub(crate) fn backend_for(
    adapter: &str,
    global: &GlobalConfig,
    creds: Option<Arc<dyn CredentialService>>,
) -> Option<Box<dyn DeviceBackend>> {
    match adapter {
        // The in-process simulator — `cargo run` works with no PLC / no OpENer (the runnable configs
        // select this; it stands in for both poll reads and class-1 push frames).
        "sim" => Some(Box::new(SimBackend)),
        // The real EtherNet/IP backend over the owned `enip` stack (poll + push). Selected against a
        // live cpppo / ControlLogix / OpENer target. The credentials vault (when present) sources TLS
        // material for `mode: tls` connections.
        "ethernet-ip" => Some(Box::new(
            crate::eip::EipBackend::new(global.timeouts.clone()).credentials(creds),
        )),
        _ => None,
    }
}

/// The connect log line (D-EIP-34): `connected to <endpoint>`, and when the device named itself,
/// `connected to <endpoint> (<product name> rev <major.minor>)`.
///
/// A device that refused the identity read yields the bare form rather than `(unknown)` — the
/// absence of a nameplate is not worth a word in the line an operator reads on every reconnect.
fn connect_line(endpoint: &str, identity: Option<&crate::device::DeviceIdentity>) -> String {
    match identity {
        Some(id) => format!("connected to {endpoint} ({})", id.summary()),
        None => format!("connected to {endpoint}"),
    }
}

/// One line, at connect, when this instance carries **experimental** signals (D-EIP-16 / D-EIP-34):
/// name them, and name the device they are about to be read from.
///
/// The value of saying it here rather than only at config-parse time is the device: an operator
/// reading a support ticket needs to know which controller the experimental readings came off, and
/// the product name only exists once a session is up.
///
/// It states a **status**, not a prediction. BOOL arrays are an experimental capability whose
/// behaviour is not established across controller families; whether a given device answers them
/// well is what the reading itself will show, and this line stays true either way — including after
/// packed-BOOL decoding lands, when the capability is still labelled experimental until validated.
fn warn_experimental_signals(cfg: &DeviceConfig, identity: Option<&crate::device::DeviceIdentity>) {
    let experimental = cfg.experimental_signal_warnings();
    if experimental.is_empty() {
        return;
    }
    let names: Vec<&str> = experimental.iter().map(|(name, _)| name.as_str()).collect();
    let product = identity.map_or_else(
        || "a device that did not identify itself".to_string(),
        |id| id.summary(),
    );
    tracing::warn!(
        instance = %cfg.id,
        signals = %names.join(", "),
        product = %product,
        endpoint = %cfg.connection.endpoint,
        "this instance polls signals that use an EXPERIMENTAL capability (BOOL arrays, D-EIP-16); \
         how they behave on this device is not established, so treat their readings as unvalidated \
         and report what you observe"
    );
}

/// One device's lifecycle: connect, poll, publish, reconnect — also servicing the device's
/// [`DeviceControl`] channel so every `sb/*` verb serializes with the engine loop (§7).
///
/// The connect loop and the poll loop are nested on purpose. A read failure that breaks the link
/// drops out of the poll loop and back into connect — which is the only place that knows how to
/// back off. An explicit `reconnect` short-circuits the backoff; `pause`/`resume` are serviced in
/// both the loop and the backoff wait, so they take effect whether the device is up or reconnecting.
///
/// `cancel` is this instance's child of the app root token (§10.3): every wait selects on it, and
/// the driver closes the session before returning, so a teardown reaches the wire (UnRegisterSession
/// / ForwardClose) instead of dropping the socket. A cancelled exit raises no alarm, emits no event,
/// and never backs off — the link did not fail, the instance was stopped.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_device(
    cfg: DeviceConfig,
    global: Arc<GlobalConfig>,
    backend: Box<dyn DeviceBackend>,
    sink: Arc<dyn Publisher>,
    events: Arc<dyn EventSink>,
    dm: Arc<DeviceMetrics>,
    health: Arc<Health>,
    mut control: tokio::sync::mpsc::Receiver<DeviceControl>,
    cancel: CancellationToken,
) {
    let backoff = Backoff::from_timeouts(&global.timeouts);
    let connect_timeout = Duration::from_millis(global.timeouts.connect_ms.max(1));
    let keepalive_ms = global.health_thresholds.keepalive_probe_interval_ms;
    // Whether this instance runs over TLS (CIP Security Phase 1) — drives the handshake-failure
    // metric/event on the connect path.
    let tls_instance = crate::eip::tls::SecurityConfig::from_connection(&cfg.connection)
        .ok()
        .flatten()
        .is_some_and(|s| s.is_tls());

    // Push (class-1 implicit I/O) has its own connect → consume → reconnect loop over the
    // `PushSession` seam; it never enters the poll loop (a push device has no poll groups).
    if matches!(cfg.mode, DeviceMode::Push) {
        run_push(
            &cfg,
            &global,
            backend.as_ref(),
            sink.as_ref(),
            events.as_ref(),
            &dm,
            &health,
            backoff,
            connect_timeout,
            &mut control,
            &cancel,
        )
        .await;
        return;
    }

    let mut attempt: u32 = 0;
    // A pending explicit-`reconnect` reply: fulfilled after the *next* connect attempt resolves.
    let mut pending_reconnect: Option<
        tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    > = None;

    loop {
        // Connect within the configured deadline (§4.1 connectMs).
        dm.on_connect_attempt();
        let started = Instant::now();
        // No session is open yet, so a cancel here has nothing to close: drop the connect future and
        // leave (the enip connect is itself deadline-bounded; the half-open socket dies with RAII).
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            o = tokio::time::timeout(connect_timeout, backend.connect(&cfg.connection)) => o,
        };

        match outcome {
            Ok(Ok(session)) => {
                attempt = 0;
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                dm.on_connected(latency_ms, Instant::now());
                // Capture the negotiated security posture for the sb/status/state surface (§3.4), and
                // clear any prior handshake-failing state.
                let security = session.security();
                health.set_security(security.clone());
                // D-EIP-34: and what the device says it is. One source for the status object, the
                // event context, and the log line below — so no two surfaces can name a different
                // device. `None` (refused / not read) is ordinary and never blocks anything.
                let identity = session.identity();
                health.set_identity(identity.clone());
                // Phase 2b: surface the connected cert's days-to-expiry as a gauge immediately, even
                // before the lifecycle task's first re-read (§4.2).
                if let Some(days) = security.as_ref().and_then(|s| s.client_cert_expiry_days) {
                    dm.set_cert_expiry_days(days);
                }
                health.tls_handshake_failing.store(false, Ordering::Relaxed);
                health.set_link(LinkState::Online);
                // A transition: flush southbound_health + connection immediately (§8.7).
                dm.emit_now().await;
                tracing::info!(
                    instance = %cfg.id,
                    "{}",
                    connect_line(&cfg.connection.endpoint, identity.as_ref())
                );
                warn_experimental_signals(&cfg, identity.as_ref());
                let mut connected_ctx = json!({ "instance": cfg.id, "adapter": backend.kind() });
                if let Some(id) = &identity {
                    connected_ctx["identity"] = crate::metrics::identity_json(id);
                }
                if let Some(sec) = &security {
                    connected_ctx["security"] = json!(if sec.tls { "tls" } else { "plaintext" });
                    if !sec.peer_verified && sec.tls {
                        // A no-verify TLS session is a loud, commissioning/debug posture (§3.3).
                        events
                            .emit(
                                Severity::Warning,
                                "tls-peer-unverified",
                                Some(format!(
                                    "connected to {} over TLS WITHOUT peer verification (verifyPeer:false)",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                    }
                }
                events
                    .emit(
                        Severity::Info,
                        "device-connected",
                        Some(format!("connected to {}", cfg.connection.endpoint)),
                        Some(connected_ctx),
                    )
                    .await;
                // A raised alarm is cleared by the SAME wire type, so the pair rides one channel.
                events
                    .clear_alarm(Severity::Critical, "device-unreachable", None)
                    .await;
                // An explicit reconnect that asked for this connect: it succeeded.
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Ok(()));
                }

                let exit = crate::poll_driver::poll_until_disconnected(
                    &cfg,
                    &global,
                    session,
                    sink.as_ref(),
                    &dm,
                    &health,
                    backend.kind(),
                    &mut control,
                    events.as_ref(),
                    keepalive_ms,
                    &cancel,
                )
                .await;

                dm.on_connection_dropped(Instant::now());
                health.set_security(None);
                // The identity belonged to the session that just ended. A device can be swapped at
                // the same address between one connect and the next, so a stale nameplate on a
                // disconnected instance would be worse than none: `sb/status` reports `null` until
                // the next session reads it again. (The dialect memory is deliberately NOT cleared —
                // that is a fact about the device, learned, not a property of the session.)
                health.set_identity(None);
                match exit {
                    // The driver already closed the session on its way out — nothing to reconnect.
                    crate::poll_driver::PollExit::Stopped => return,
                    crate::poll_driver::PollExit::LinkLost => {
                        health.set_link(LinkState::Backoff);
                        health.reconnects.fetch_add(1, Ordering::Relaxed);
                        dm.emit_now().await;
                        events
                            .raise_alarm(
                                Severity::Critical,
                                "device-unreachable",
                                Some(format!("lost the link to {}", cfg.connection.endpoint)),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                        let wait = backoff.delay(attempt, rand01());
                        match serve_control_disconnected(
                            &mut control,
                            &cfg,
                            &health,
                            &dm,
                            events.as_ref(),
                            wait,
                            &cancel,
                        )
                        .await
                        {
                            DisconnectedWait::Stopped => return,
                            DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                            DisconnectedWait::Elapsed => {}
                        }
                        attempt = attempt.saturating_add(1);
                    }
                    // An explicit reconnect: no alarm, no backoff — straight back to connect, carrying
                    // the reply to fulfill after the next connect resolves (§7.5).
                    crate::poll_driver::PollExit::Reconnect(reply) => {
                        health.set_link(LinkState::Connecting);
                        pending_reconnect = Some(reply);
                    }
                }
            }

            // Connect failed (Err) or timed out (Elapsed). A permanent failure will fail identically
            // forever, so back off to the ceiling immediately.
            other => {
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let reason = connect_reason(&other, connect_timeout);
                // An explicit reconnect that asked for this connect: it failed → RECONNECT_FAILED.
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Err(reason.clone()));
                }
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                // A permanent connect failure on a TLS instance is a cert/suite/protocol handshake
                // failure (a transient TCP hiccup or pre-handshake IO is not) — count it and fire the
                // `tls-handshake-failed` event on the transition into failing (§3.4).
                if tls_instance && permanent {
                    dm.on_tls_handshake_failure();
                    dm.emit_now().await;
                    if !health.tls_handshake_failing.swap(true, Ordering::Relaxed) {
                        events
                            .emit(
                                Severity::Warning,
                                "tls-handshake-failed",
                                Some(format!(
                                    "TLS handshake to {} failed: {reason}",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id, "security": "tls" })),
                            )
                            .await;
                    }
                }
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "connect failed"
                );
                attempt = attempt.saturating_add(1);
                match serve_control_disconnected(
                    &mut control,
                    &cfg,
                    &health,
                    &dm,
                    events.as_ref(),
                    wait,
                    &cancel,
                )
                .await
                {
                    DisconnectedWait::Stopped => return,
                    DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                    DisconnectedWait::Elapsed => {}
                }
            }
        }
    }
}

/// One push device's lifecycle: open the class-1 connection, consume the [`crate::device::IoUpdate`]
/// stream through the push engine ([`crate::push_driver::consume_push`]) — servicing the control
/// channel — and reconnect on loss with the same backoff ladder as poll (§10.2).
#[allow(clippy::too_many_arguments)]
async fn run_push(
    cfg: &DeviceConfig,
    global: &GlobalConfig,
    backend: &dyn DeviceBackend,
    sink: &dyn Publisher,
    events: &dyn EventSink,
    dm: &Arc<DeviceMetrics>,
    health: &Arc<Health>,
    backoff: Backoff,
    connect_timeout: Duration,
    control: &mut tokio::sync::mpsc::Receiver<DeviceControl>,
    cancel: &CancellationToken,
) {
    let Some(io) = cfg.io.clone() else {
        tracing::error!(instance = %cfg.id, "push device has no io block");
        return;
    };
    let mut attempt: u32 = 0;
    let mut pending_reconnect: Option<
        tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    > = None;

    loop {
        health.set_link(LinkState::Connecting);
        dm.on_connect_attempt();
        let started = Instant::now();
        // No class-1 connection is open yet, so a cancel here has nothing to ForwardClose.
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            o = tokio::time::timeout(connect_timeout, backend.open_push(&cfg.connection, &io)) => o,
        };
        match outcome {
            Ok(Ok(mut session)) => {
                attempt = 0;
                // The class-1 ForwardOpen succeeded (§8.8 forwardOpens; §8.2 sessionConnected).
                dm.on_forward_open(true);
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                dm.on_connected(latency_ms, Instant::now());
                // D-EIP-34: the identity the backend read over the explicit session that carried the
                // ForwardOpen. Stored here, before the engine loop, so the `device-connected` event
                // the push driver emits on the first frame can name the device.
                let identity = session.identity();
                health.set_identity(identity.clone());
                tracing::info!(
                    instance = %cfg.id,
                    "{}",
                    connect_line(&cfg.connection.endpoint, identity.as_ref())
                );
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Ok(()));
                }

                let exit = crate::push_driver::consume_push(
                    cfg,
                    global,
                    session.as_mut(),
                    sink,
                    events,
                    dm,
                    health,
                    backend.kind(),
                    control,
                    cancel,
                )
                .await;
                // Unconditional, and therefore also the teardown path: ForwardClose + the class-1
                // socket release happen before this task returns.
                session.close().await;

                dm.on_connection_dropped(Instant::now());
                // The nameplate belonged to the connection that just ended (see the poll ladder).
                health.set_identity(None);
                match exit {
                    crate::push_driver::PushExit::Stopped => return,
                    crate::push_driver::PushExit::LinkLost => {
                        health.set_link(LinkState::Backoff);
                        health.reconnects.fetch_add(1, Ordering::Relaxed);
                        dm.emit_now().await;
                        events
                            .raise_alarm(
                                Severity::Critical,
                                "device-unreachable",
                                Some(format!(
                                    "lost the class-1 link to {}",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id })),
                            )
                            .await;
                        let wait = backoff.delay(attempt, rand01());
                        match serve_control_disconnected(
                            control, cfg, health, dm, events, wait, cancel,
                        )
                        .await
                        {
                            DisconnectedWait::Stopped => return,
                            DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                            DisconnectedWait::Elapsed => {}
                        }
                        attempt = attempt.saturating_add(1);
                    }
                    crate::push_driver::PushExit::Reconnect(reply) => {
                        health.set_link(LinkState::Connecting);
                        // The class-1 connection just closed and a fresh ForwardOpen follows, so the
                        // §8.8 stack-counter baselines belong to a connection that no longer exists:
                        // rebase them, and with them the per-connection latches, so a redirect that is
                        // refused again on the new connection re-reports (D-ENIP-17). Deliberately NOT
                        // `on_io_lost` — a requested reconnect is not a watchdog timeout.
                        dm.on_io_link_replaced();
                        pending_reconnect = Some(reply);
                    }
                }
            }
            other => {
                // The ForwardOpen was refused / timed out (§8.8 forwardOpenFailures; §8.2 connectFailures).
                dm.on_forward_open(false);
                dm.on_connect_failure();
                health.set_link(LinkState::Backoff);
                let reason = connect_reason(&other, connect_timeout);
                if let Some(reply) = pending_reconnect.take() {
                    let _ = reply.send(Err(reason.clone()));
                }
                let permanent = matches!(&other, Ok(Err(e)) if !e.is_transient());
                let wait = if permanent {
                    Duration::from_millis(backoff.max_ms)
                } else {
                    backoff.delay(attempt, rand01())
                };
                tracing::warn!(
                    instance = %cfg.id, error = %reason, permanent,
                    wait_ms = wait.as_millis() as u64, "push open failed"
                );
                attempt = attempt.saturating_add(1);
                match serve_control_disconnected(control, cfg, health, dm, events, wait, cancel)
                    .await
                {
                    DisconnectedWait::Stopped => return,
                    DisconnectedWait::Reconnect(reply) => pending_reconnect = Some(reply),
                    DisconnectedWait::Elapsed => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The connect → drive → reconnect ladders, driven against scripted seams on a **paused clock**:
    //! a [`ScriptedBackend`] handing out [`ScriptedSession`]s / [`ScriptedPush`]es, a
    //! [`RecordingPublisher`], a [`RecordingEvents`], and a [`RecordingMetrics`]-backed
    //! [`DeviceMetrics`]. No socket, no broker, no PLC.
    //!
    //! **On backoff assertions.** The wait is jittered: `Backoff::delay(attempt, rand01())` picks a
    //! point *inside* `[0, cap(attempt)]`. A bare `wait ≤ cap(attempt)` assertion is therefore
    //! one-sided — it holds for every fraction, so it pins the ceiling but says nothing about which
    //! rung was used, and a ladder that stopped resetting `attempt` would still satisfy it most of
    //! the time. Where the rung itself is the claim — the exponential climb and the reset on a
    //! successful connect — the test **pins the fraction** at `1.0` with a
    //! [`crate::testutil::JitterGuard`], so every wait is exactly its rung's cap and the claim is an
    //! equality. A permanent failure's wait is unjittered `max_ms` by construction and is asserted
    //! exactly with no guard.

    use super::*;
    use crate::config::GlobalConfig;
    use crate::device::{DeviceError, IoLinkStats, IoUpdate, Quality, SecurityStatus};
    use crate::metrics::{CONNECTION, HEALTH, IO};
    use crate::testutil::{
        device_metrics_with, reading, scripted_identity, RecordingEvents, RecordingMetrics,
        RecordingPublisher, ScriptedBackend, ScriptedPush, ScriptedSession, SecureSession,
        SharedPush, WarnLog,
    };
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::Instant as TokioInstant;

    fn device(v: Value) -> DeviceConfig {
        DeviceConfig::from_value(&v).expect("a valid device config")
    }

    fn global(v: Value) -> GlobalConfig {
        GlobalConfig::from_value(&v).expect("a valid global config")
    }

    /// A poll device with one group at `poll_ms`, optionally carrying a `connection.security` block.
    fn poll_device(poll_ms: u64, security: Option<Value>) -> DeviceConfig {
        let mut connection = json!({ "endpoint": "127.0.0.1:44818" });
        if let Some(sec) = security {
            connection["security"] = sec;
        }
        device(json!({
            "id": "plc-1",
            "connection": connection,
            "pollGroups": [ {
                "id": "fast", "pollIntervalMs": poll_ms,
                "signals": [ { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ]
            } ]
        }))
    }

    /// A push device: one input field (`a100/0/udint`) at a 100 ms RPI.
    fn push_device() -> DeviceConfig {
        device(json!({
            "id": "io-1",
            "mode": "push",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "io": {
                "rpiMs": 100,
                "assemblies": { "output": 150, "input": 100 },
                "input": { "sizeBytes": 8, "signals": [
                    { "name": "motor-run", "offset": 0, "type": "udint" } ] }
            }
        }))
    }

    /// A tight reconnect window so a paused-clock test walks several rungs quickly.
    fn fast_backoff() -> Value {
        json!({ "timeouts": { "connectMs": 500, "reconnectBackoffMinMs": 100, "reconnectBackoffMaxMs": 800 } })
    }

    /// Everything one ladder run needs; the seam handles stay with the test while `run_device` owns
    /// its boxed backend and `Arc<dyn …>` seams.
    struct Rig {
        cfg: DeviceConfig,
        global: Arc<GlobalConfig>,
        health: Arc<Health>,
        metrics: Arc<RecordingMetrics>,
        dm: Arc<DeviceMetrics>,
        events: Arc<RecordingEvents>,
        sink: Arc<RecordingPublisher>,
        backend: Arc<ScriptedBackend>,
        tx: Option<mpsc::Sender<DeviceControl>>,
        rx: Option<mpsc::Receiver<DeviceControl>>,
        cancel: CancellationToken,
    }

    impl Rig {
        fn new(cfg: DeviceConfig, global: GlobalConfig) -> Self {
            let health = Arc::new(Health::default());
            let (metrics, dm) = device_metrics_with(cfg.clone(), &global, Arc::clone(&health));
            let (tx, rx) = mpsc::channel(32);
            Self {
                cfg,
                global: Arc::new(global),
                health,
                metrics,
                dm,
                events: Arc::new(RecordingEvents::default()),
                sink: Arc::new(RecordingPublisher::default()),
                backend: Arc::new(ScriptedBackend::new("ethernet-ip")),
                tx: Some(tx),
                rx: Some(rx),
                cancel: CancellationToken::new(),
            }
        }

        fn control(&self) -> mpsc::Sender<DeviceControl> {
            self.tx.clone().expect("the control sender is still open")
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

        /// Run the ladder to completion (every test arranges a cancel, so it always terminates).
        async fn run(&mut self) {
            // A far-future backstop, so a wedged ladder fails loudly instead of hanging the suite.
            self.cancel_after(Duration::from_secs(600));
            run_device(
                self.cfg.clone(),
                Arc::clone(&self.global),
                Box::new(Arc::clone(&self.backend)),
                Arc::clone(&self.sink) as Arc<dyn Publisher>,
                Arc::clone(&self.events) as Arc<dyn EventSink>,
                Arc::clone(&self.dm),
                Arc::clone(&self.health),
                self.rx.take().expect("the ladder runs once per rig"),
                self.cancel.clone(),
            )
            .await;
        }

        /// The gap between successive connect attempts — the backoff the ladder actually waited.
        fn waits(&self) -> Vec<Duration> {
            let at = self.backend.attempt_times();
            at.windows(2).map(|w| w[1] - w[0]).collect()
        }

        /// One `<measure>Total` from the last row of a metric family (§8's Total/Interval pair
        /// convention — the Total is monotonic, so the last row carries the run's whole count).
        fn total(&self, family: &str, measure: &str) -> f64 {
            self.metrics
                .last(family)
                .unwrap_or_else(|| panic!("{family} was never emitted"))
                .get(&format!("{measure}Total"))
                .copied()
                .unwrap_or_else(|| panic!("{family} carries no {measure}Total"))
        }
    }

    /// A session that always answers one GOOD reading.
    fn good_session() -> Arc<ScriptedSession> {
        ScriptedSession::new(vec![reading("LINE_SPEED", json!(1.0), Quality::Good)])
    }

    // ---- backend selection ----

    /// A typo'd adapter token must not produce an instance that silently idles forever: the mapping
    /// is total, and `None` is what makes the launcher refuse the launch (§10.4 skip-bad).
    #[test]
    fn backend_for_maps_sim_ethernet_ip_and_unknown() {
        let g = global(json!({}));
        assert_eq!(
            backend_for("sim", &g, None).expect("sim backend").kind(),
            "sim"
        );
        assert_eq!(
            backend_for("ethernet-ip", &g, None)
                .expect("eip backend")
                .kind(),
            "ethernet-ip"
        );
        assert!(
            backend_for("etherne-tip", &g, None).is_none(),
            "an unknown adapter token yields no backend, so the launch is refused"
        );
    }

    /// The refusal must stay **recognizable** as a bad-instance defect all the way to the startup
    /// path: that is what keeps one typo'd token from taking the healthy instances down with it,
    /// while a genuine construction failure still fails startup (§10.4).
    #[test]
    fn an_unknown_adapter_refusal_is_distinguishable_from_a_construction_failure() {
        let refusal = anyhow::Error::new(UnknownAdapter {
            instance: "plc-1".to_string(),
            adapter: "etherne-tip".to_string(),
        });
        assert!(UnknownAdapter::is_cause(&refusal));
        assert!(
            refusal.to_string().contains("etherne-tip") && refusal.to_string().contains("plc-1"),
            "the message names the instance and the token an operator has to fix: {refusal}"
        );
        assert!(
            !UnknownAdapter::is_cause(&anyhow::anyhow!("the runtime is shutting down")),
            "an ordinary construction failure is NOT a bad instance"
        );
    }

    // ---- the connect edge ----

    /// §6.3: a successful connect announces itself AND clears the unreachable alarm on the same wire
    /// type — otherwise a device that came back stays red on every console watching the alarm.
    #[tokio::test(start_paused = true)]
    async fn connect_success_publishes_connected_event_and_clears_alarm() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        rig.backend.push_session(Box::new(good_session()));
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        assert!(rig.events.has("device-connected"));
        assert_eq!(
            rig.events.last_ctx("device-connected").unwrap()["adapter"],
            json!("ethernet-ip"),
            "the event names the backend that connected"
        );
        assert_eq!(
            rig.events.count("device-unreachable"),
            1,
            "the clear rides the same type"
        );
        assert_eq!(rig.backend.connects(), 1);
        assert!(rig.total(CONNECTION, "connectAttempts") >= 1.0);
        assert_eq!(
            rig.metrics
                .last(CONNECTION)
                .unwrap()
                .get("sessionConnected")
                .copied(),
            Some(1.0),
            "the connection gauge flushed at the transition (§8.7)"
        );
    }

    // ---- identity at connect (D-EIP-34) ----

    /// **The identity the session read reaches every surface the connect owns**, from one source:
    /// the `Health` object `sb/status` answers from, and the `device-connected` event's context. It
    /// is the same rendered shape in both places, so a fleet consumer parses one thing.
    #[tokio::test(start_paused = true)]
    async fn a_connect_publishes_the_identity_on_the_event_and_stores_it_for_status() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        rig.backend.push_session(Box::new(
            good_session().with_identity(scripted_identity("1756-L71/B")),
        ));
        // Read the stored identity while the session is still up — the ladder clears it on the way
        // out, so a post-run read would prove the wrong thing.
        let health = Arc::clone(&rig.health);
        let seen: Arc<Mutex<Option<crate::device::DeviceIdentity>>> = Arc::new(Mutex::new(None));
        let seen_task = Arc::clone(&seen);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            *seen_task.lock().unwrap() = health.identity();
        });
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        let ctx = rig.events.last_ctx("device-connected").expect("the event");
        assert_eq!(ctx["identity"]["productName"], json!("1756-L71/B"));
        assert_eq!(ctx["identity"]["revision"], json!("7.3"));
        assert_eq!(ctx["identity"]["vendorId"], json!(0x1337));
        assert_eq!(
            ctx["identity"]["serialNumber"],
            json!("0x00C0FFEE"),
            "the serial is the hex label an operator reads off a nameplate, not a number"
        );

        let stored = seen.lock().unwrap().clone().expect("stored on Health");
        assert_eq!(stored.product_name, "1756-L71/B");
        assert_eq!(
            crate::metrics::identity_json(&stored),
            ctx["identity"],
            "one renderer: the status object and the event context cannot disagree"
        );
    }

    /// A device that refused the read simply has none: the connect announces itself exactly as it
    /// always did, with no `identity` key and nothing invented.
    #[tokio::test(start_paused = true)]
    async fn a_connect_without_an_identity_announces_itself_unchanged() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        rig.backend.push_session(Box::new(good_session()));
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        let ctx = rig.events.last_ctx("device-connected").expect("the event");
        assert_eq!(ctx["adapter"], json!("ethernet-ip"));
        assert!(
            ctx.get("identity").is_none(),
            "no identity key rather than a null or a placeholder: {ctx}"
        );
    }

    /// **A nameplate belongs to a session, not to an address.** When the link drops, the stored
    /// identity goes with it — a device can be swapped at the same endpoint between one connect and
    /// the next, and a stale product name on a disconnected instance is worse than none.
    #[tokio::test(start_paused = true)]
    async fn a_lost_link_clears_the_stored_identity() {
        let mut rig = Rig::new(poll_device(20, None), global(fast_backoff()));
        let first = good_session().with_identity(scripted_identity("1756-L71/B"));
        first.push_read_err(DeviceError::Transient(anyhow::anyhow!("connection reset")));
        rig.backend.push_session(Box::new(first));
        // The ladder reconnects into a session that never resolves, so the run ends while the
        // instance is between sessions — exactly the window the claim is about.
        rig.backend.hang_connects();
        rig.cancel_after(Duration::from_secs(2));

        rig.run().await;

        assert!(
            rig.health.identity().is_none(),
            "the identity of a session that ended must not outlive it"
        );
    }

    /// **Push instances carry an identity too.** The class-1 ladder stores what the backend read over
    /// the explicit session, and the push driver's `device-connected` (emitted on the first frame,
    /// not at open) names it.
    #[tokio::test(start_paused = true)]
    async fn a_push_connect_publishes_the_identity_on_the_event() {
        let mut rig = Rig::new(push_device(), global(json!({})));
        let (tx, push) = ScriptedPush::new();
        push.set_identity(Some(scripted_identity("1734-AENTR")));
        rig.backend.push_io(Box::new(push));
        tokio::spawn(async move {
            let _ = tx
                .send(IoUpdate::Up {
                    o2t_api_ms: 100,
                    t2o_api_ms: 100,
                })
                .await;
            // Held open so the driver keeps consuming until the cancel.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(tx);
        });
        rig.cancel_after(Duration::from_millis(100));

        rig.run().await;

        let ctx = rig.events.last_ctx("device-connected").expect("the event");
        assert_eq!(ctx["identity"]["productName"], json!("1734-AENTR"));
        assert_eq!(
            ctx["o2tApiMs"],
            json!(100),
            "the class-1 facts are still there — identity is added beside them, not instead"
        );
    }

    /// **The connect line names the product**, and stays readable when the device did not name
    /// itself: `connected to <endpoint> (<product> rev <maj.min>)`, else the bare form. No
    /// `(unknown)` filler on a line an operator reads at every reconnect.
    #[test]
    fn the_connect_line_names_the_product_when_there_is_one() {
        assert_eq!(
            connect_line("10.0.0.5:44818", Some(&scripted_identity("1756-L71/B"))),
            "connected to 10.0.0.5:44818 (1756-L71/B rev 7.3)"
        );
        assert_eq!(
            connect_line("10.0.0.5:44818", None),
            "connected to 10.0.0.5:44818"
        );
    }

    /// **The experimental-signal note fires at connect, names the signals AND the device** (D-EIP-16
    /// / D-EIP-34), and states a status rather than a prediction — so it stays true whatever the
    /// device does with the reading, and after packed-BOOL decoding lands.
    #[tokio::test(start_paused = true)]
    async fn an_instance_with_experimental_signals_is_warned_about_naming_the_device() {
        let cfg = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "10.0.0.5:44818" },
            "pollGroups": [ { "id": "fast", "pollIntervalMs": 60000, "signals": [
                { "name": "alarms", "tagPath": "ALARM_BITS", "type": "bool", "arrayCount": 8 },
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" }
            ] } ]
        }));
        let warns = WarnLog::default();
        {
            let _guard = tracing::subscriber::set_default(warns.clone());
            warn_experimental_signals(&cfg, Some(&scripted_identity("1756-L71/B")));
        }
        let messages = warns.messages();
        assert_eq!(
            messages.len(),
            1,
            "one line, not one per signal: {messages:?}"
        );
        let line = &messages[0];
        assert!(line.contains("EXPERIMENTAL"), "{line}");
        for forbidden in ["will fail", "expected BAD", "BAD on", "will read"] {
            assert!(
                !line.contains(forbidden),
                "the note states the experimental STATUS; it must not predict an outcome the \
                 reading itself will report — and must stay true if packed-BOOL decoding lands: \
                 {line}"
            );
        }

        // A configuration with no experimental signal says nothing at all.
        let quiet = WarnLog::default();
        {
            let _guard = tracing::subscriber::set_default(quiet.clone());
            warn_experimental_signals(&poll_device(60_000, None), None);
        }
        assert!(quiet.is_empty(), "{:?}", quiet.messages());
    }

    /// The note travels with the connect, so the structured fields carry the signal names and the
    /// product — which is what makes a support ticket answerable.
    #[tokio::test(start_paused = true)]
    async fn the_experimental_note_is_emitted_on_the_connect_edge() {
        let cfg = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "10.0.0.5:44818" },
            "pollGroups": [ { "id": "fast", "pollIntervalMs": 60000, "signals": [
                { "name": "alarms", "tagPath": "ALARM_BITS", "type": "bool", "arrayCount": 8 }
            ] } ]
        }));
        let mut rig = Rig::new(cfg, global(json!({})));
        rig.backend.push_session(Box::new(
            good_session().with_identity(scripted_identity("1756-L71/B")),
        ));
        rig.cancel_after(Duration::from_millis(50));

        let warns = WarnLog::default();
        {
            let _guard = tracing::subscriber::set_default(warns.clone());
            rig.run().await;
        }
        assert!(
            warns.contains("EXPERIMENTAL"),
            "the connect edge says it: {:?}",
            warns.messages()
        );
    }

    /// The reconnect ladder end to end: a lost link raises the alarm, counts a reconnect, waits
    /// inside the backoff window, and comes back — a second connect against the same backend.
    #[tokio::test(start_paused = true)]
    async fn link_lost_raises_alarm_backs_off_and_reconnects() {
        let mut rig = Rig::new(poll_device(20, None), global(fast_backoff()));
        let first = good_session();
        first.push_read_err(DeviceError::Transient(anyhow::anyhow!("connection reset")));
        rig.backend.push_session(Box::new(first));
        rig.backend.push_session(Box::new(good_session()));
        rig.cancel_after(Duration::from_secs(3));

        rig.run().await;

        assert!(
            rig.events.has("device-unreachable"),
            "a lost link raises the alarm"
        );
        assert!(
            rig.metrics.sum(HEALTH, "reconnects") >= 1.0,
            "the lost link is counted as a reconnect"
        );
        assert_eq!(
            rig.backend.connects(),
            2,
            "it reconnected after the backoff"
        );
        // The gap between the two connects is the poll loop's own span (it polls once, at its 20 ms
        // cadence, and that read is what breaks the link) plus the backoff — so the ladder's first
        // rung is bounded by 20 ms + base_ms.
        let waits = rig.waits();
        assert!(
            waits[0] <= Duration::from_millis(20 + 100),
            "the first rung waits inside base_ms: {:?}",
            waits[0]
        );
        assert_eq!(
            rig.events.count("device-connected"),
            2,
            "the re-established link announces itself again"
        );
    }

    /// A permanent connect failure (a misconfigured endpoint) will fail identically forever, so the
    /// ladder goes straight to the ceiling instead of hammering the device (D-EIP §10.2).
    #[tokio::test(start_paused = true)]
    async fn permanent_connect_failure_backs_off_at_the_ceiling() {
        let mut rig = Rig::new(poll_device(60_000, None), global(fast_backoff()));
        for _ in 0..3 {
            rig.backend
                .push_connect_err(DeviceError::Permanent(anyhow::anyhow!("no such device")));
        }
        rig.cancel_after(Duration::from_secs(3));

        rig.run().await;

        let waits = rig.waits();
        assert!(
            waits.len() >= 3,
            "the three scripted permanent failures ran: {waits:?}"
        );
        for w in waits.iter().take(3) {
            assert_eq!(
                *w,
                Duration::from_millis(800),
                "a permanent failure waits the unjittered ceiling from the first attempt: {waits:?}"
            );
        }
        assert!(!rig.events.has("device-connected"));
    }

    /// The transient ladder: each wait is its rung's cap (the climb doubles from `base_ms` to
    /// `max_ms`), and a successful connect **resets** `attempt` — so the next failure waits a rung-0
    /// window again rather than the ceiling the previous outage climbed to.
    ///
    /// The jitter fraction is pinned at `1.0` for the whole test, which is what makes both halves
    /// exact: unpinned, each wait is a uniform sample inside its rung and the post-success
    /// assertion would hold ~1 run in 7 even with the reset deleted.
    #[tokio::test(start_paused = true)]
    async fn transient_failures_backoff_exponentially_and_reset_on_success() {
        let _jitter = crate::testutil::JitterGuard::pin(1.0);
        let mut rig = Rig::new(poll_device(20, None), global(fast_backoff()));
        // Three transient failures (rungs 0..2), then a session whose first read breaks the link,
        // then one more transient failure — which must start from rung 0 again.
        for _ in 0..3 {
            rig.backend
                .push_connect_err(DeviceError::Transient(anyhow::anyhow!("refused")));
        }
        let s = good_session();
        s.push_read_err(DeviceError::Transient(anyhow::anyhow!("reset")));
        rig.backend.push_session(Box::new(s));
        rig.backend
            .push_connect_err(DeviceError::Transient(anyhow::anyhow!("refused again")));
        rig.cancel_after(Duration::from_secs(5));

        rig.run().await;

        let waits = rig.waits();
        assert!(
            waits.len() >= 4,
            "at least five connect attempts ran: {waits:?}"
        );
        // Rungs 0,1,2 are gaps between failed connects — pure backoff, no session in between — so
        // with the fraction pinned each wait IS its rung's cap: the window doubles from base_ms and
        // holds at max_ms.
        assert_eq!(
            waits[..3],
            [
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
            ],
            "the transient ladder climbs exactly one rung per failure: {waits:?}"
        );
        // After the successful connect the ladder starts over: this gap is the poll loop's own span
        // (one 20 ms cadence tick, whose read breaks the link) plus a **rung-0** wait of exactly
        // 100 ms. Drop the reset and the pinned fraction makes it 20 + 800 ms instead — a difference
        // the assertion catches every run rather than one in seven.
        assert_eq!(
            waits[3],
            Duration::from_millis(20 + 100),
            "a successful connect resets the attempt ladder: {waits:?}"
        );
    }

    /// §3.4: on a TLS instance a permanent connect failure is a handshake failure — counted every
    /// time, but the event fires **once per failing episode** (the edge latch), or a device with a
    /// bad cert would fill the `evt` surface for as long as it stays broken.
    #[tokio::test(start_paused = true)]
    async fn tls_instance_permanent_failure_fires_handshake_event_on_the_transition_only() {
        let cfg = poll_device(
            60_000,
            Some(json!({ "mode": "tls", "verifyPeer": false,
                         "client": { "certFile": "client.pem", "keyFile": "client.key" } })),
        );
        let mut rig = Rig::new(cfg, global(fast_backoff()));
        for _ in 0..3 {
            rig.backend
                .push_connect_err(DeviceError::Permanent(anyhow::anyhow!("bad certificate")));
        }
        rig.cancel_after(Duration::from_secs(3));

        rig.run().await;

        assert!(rig.backend.connects() >= 3, "it kept retrying");
        assert_eq!(
            rig.events.count("tls-handshake-failed"),
            1,
            "one event per failing episode, not one per retry"
        );
        assert!(
            rig.total(CONNECTION, "tlsHandshakeFailures") >= 3.0,
            "every failed handshake is still counted"
        );
    }

    /// §7.5: an `sb/reconnect` reply is fulfilled by the connect that follows it — `Ok` when that
    /// connect succeeds, `Err` (RECONNECT_FAILED) when it does not. A dropped reply leaves the
    /// caller waiting forever.
    #[tokio::test(start_paused = true)]
    async fn explicit_reconnect_reply_fulfilled_after_next_connect_success_and_failure() {
        let mut rig = Rig::new(poll_device(60_000, None), global(fast_backoff()));
        rig.backend.push_session(Box::new(good_session()));
        rig.backend.push_session(Box::new(good_session()));
        rig.backend
            .push_connect_err(DeviceError::Permanent(anyhow::anyhow!("gone")));

        let (ok_tx, ok_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(50),
            DeviceControl::Reconnect { reply: ok_tx },
        );
        let (fail_tx, fail_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(150),
            DeviceControl::Reconnect { reply: fail_tx },
        );
        rig.cancel_after(Duration::from_secs(2));

        rig.run().await;

        assert!(
            ok_rx.await.unwrap().is_ok(),
            "the first reconnect reconnected"
        );
        assert!(
            fail_rx.await.unwrap().is_err(),
            "the second one's connect failed — RECONNECT_FAILED, not silence"
        );
    }

    /// §10.3: a teardown that lands while the connect is still in flight must return immediately —
    /// no alarm, no reconnect — or shutdown wedges behind a connect deadline.
    #[tokio::test(start_paused = true)]
    async fn cancel_during_connect_returns_without_alarm_or_reconnect() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        rig.backend.hang_connects();
        rig.cancel_after(Duration::from_millis(100));

        let started = TokioInstant::now();
        rig.run().await;

        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the cancel is observed, not the connect deadline"
        );
        assert_eq!(rig.backend.connects(), 1, "no reconnect after a stop");
        assert!(
            !rig.events.has("device-unreachable"),
            "a stop raises no alarm"
        );
        assert!(!rig.events.has("device-connected"));
    }

    /// §3.4 + Phase 2b: the negotiated posture reaches the shared [`Health`] (which `sb/status` and
    /// the keepalive read) and the connected cert's days-to-expiry lands on the gauge immediately —
    /// before the lifecycle task's first re-read.
    #[tokio::test(start_paused = true)]
    async fn security_status_lands_in_health_and_cert_gauge_on_connect() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        let posture = SecurityStatus {
            tls: true,
            tls_version: Some("1.3".to_string()),
            peer_verified: true,
            client_cert_expiry_days: Some(12),
            ..SecurityStatus::default()
        };
        rig.backend
            .push_session(Box::new(SecureSession::new(good_session(), Some(posture))));

        // Sample Health while the session is UP (the ladder clears the posture on its way out).
        let observed: Arc<Mutex<Option<SecurityStatus>>> = Arc::new(Mutex::new(None));
        let probe = Arc::clone(&observed);
        let health = Arc::clone(&rig.health);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            *probe.lock().unwrap() = health.security();
        });
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        let seen = observed
            .lock()
            .unwrap()
            .clone()
            .expect("a posture while connected");
        assert!(seen.tls && seen.tls_version.as_deref() == Some("1.3"));
        assert_eq!(
            rig.events.last_ctx("device-connected").unwrap()["security"],
            json!("tls")
        );
        let conn = rig
            .metrics
            .last(CONNECTION)
            .expect("connection emitted on connect");
        assert_eq!(conn.get("certExpiryDays").copied(), Some(12.0));
    }

    /// §3.3: `verifyPeer:false` is a commissioning shortcut, not a configuration to forget about —
    /// every session it produces says so out loud on the `evt` surface.
    #[tokio::test(start_paused = true)]
    async fn tls_peer_unverified_session_emits_the_warning() {
        let mut rig = Rig::new(poll_device(60_000, None), global(json!({})));
        let posture = SecurityStatus {
            tls: true,
            peer_verified: false,
            ..SecurityStatus::default()
        };
        rig.backend
            .push_session(Box::new(SecureSession::new(good_session(), Some(posture))));
        rig.cancel_after(Duration::from_millis(50));

        rig.run().await;

        assert!(
            rig.events.has("tls-peer-unverified"),
            "an unverified TLS peer is announced"
        );
        assert_eq!(
            rig.events.last_ctx("tls-peer-unverified").unwrap()["instance"],
            json!("plc-1")
        );
    }

    /// The backoff window is not a dead zone (§7.5, §10.3): an `sb/reconnect` arriving inside it cuts
    /// the wait short and is answered by the connect that follows, and a cancel inside it returns at
    /// once. With a minute-long ceiling, getting either wrong wedges the instance for that minute.
    #[tokio::test(start_paused = true)]
    async fn stop_or_reconnect_during_the_poll_backoff_is_honoured_immediately() {
        // The backoff is FULL jitter — `delay = rand01 * cap` — so `reconnectBackoffMinMs: 30_000`
        // buys a wait sampled from [0, 30 s), NOT a 30 s wait. Unpinned, this test is a lottery:
        // whenever the sample lands under the 200 ms below, the ladder finishes the backoff first,
        // reconnects on its own, burns the second session on its read error, and the reconnect that
        // arrives later gets a connect with an empty session pool — answered `Err`, so `answered`
        // reads `Some(false)`. That is a test defect, not a ladder defect, and it is what made this
        // test flaky in CI. Pinning the fraction at 1.0 makes the first wait exactly 30 s, so
        // "the request arrived mid-backoff" is true by construction rather than by luck.
        let _jitter = crate::testutil::JitterGuard::pin(1.0);
        let slow = json!({ "timeouts": {
            "connectMs": 500, "reconnectBackoffMinMs": 30_000, "reconnectBackoffMaxMs": 60_000 } });
        let mut rig = Rig::new(poll_device(20, None), global(slow));
        // Two sessions, each of which loses its link on the first read.
        for _ in 0..2 {
            let s = good_session();
            s.push_read_err(DeviceError::Transient(anyhow::anyhow!("reset")));
            rig.backend.push_session(Box::new(s));
        }

        // Inside the first (exactly 30 s, jitter pinned) backoff, ask for a reconnect …
        let (reply, reply_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(200),
            DeviceControl::Reconnect { reply },
        );

        // … and stop the instance once that reconnect has been ANSWERED, which puts the cancel
        // inside the second backoff without racing for it. A second independent timer would be
        // flaky here: under a paused clock an idle ladder auto-advances, so the reconnect's timer
        // and a cancel timer can land in the same advance step, and a cancel that wins tears the
        // ladder down before the reply is sent — the oneshot then resolves Err. Sequencing the
        // cancel behind the reply makes the ordering causal instead of chronological.
        let answered: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&answered);
        let cancel = rig.cancel.clone();
        tokio::spawn(async move {
            let outcome = reply_rx.await;
            *seen.lock().expect("answer slot") = Some(matches!(outcome, Ok(Ok(()))));
            cancel.cancel();
        });

        let started = TokioInstant::now();
        rig.run().await;

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "neither the reconnect nor the cancel waited out the 30 s backoff"
        );
        assert_eq!(
            *answered.lock().expect("answer slot"),
            Some(true),
            "the reconnect requested mid-backoff reconnected and was answered"
        );
        assert_eq!(
            rig.backend.connects(),
            2,
            "exactly the requested reconnect, then the stop"
        );
    }

    // ---- the push ladder ----

    /// §8.8/§8.2: a refused ForwardOpen counts on **both** families (the class-1 open and the
    /// connection attempt) and then backs off — a push device that cannot open must not spin.
    #[tokio::test(start_paused = true)]
    async fn push_open_failure_counts_forward_open_and_backs_off() {
        let mut g = fast_backoff();
        g["metricsIntervalSecs"] = json!(1);
        let mut rig = Rig::new(push_device(), global(g));
        rig.backend
            .push_open_err(DeviceError::Transient(anyhow::anyhow!(
                "forward open refused"
            )));
        // Held for the whole run: an open producer keeps the second session consuming (and emitting)
        // rather than ending its stream.
        let (_frames, push) = ScriptedPush::new();
        rig.backend.push_io(Box::new(push));
        rig.cancel_after(Duration::from_secs(3));

        rig.run().await;

        assert_eq!(
            rig.backend.opens(),
            2,
            "it retried the ForwardOpen after backing off"
        );
        assert_eq!(rig.total(IO, "forwardOpenFailures"), 1.0);
        assert_eq!(rig.total(IO, "forwardOpens"), 1.0);
        assert!(rig.total(CONNECTION, "connectFailures") >= 1.0);
        let waits = rig.waits();
        assert!(
            waits[0] <= Duration::from_millis(100),
            "the first rung waits inside base_ms: {:?}",
            waits[0]
        );
    }

    /// The push mirror of the poll ladder's permanent/backoff contract: a ForwardOpen that is
    /// refused permanently waits the unjittered ceiling, a reconnect asked for inside that wait is
    /// served (and answered `Err` when its open fails too — RECONNECT_FAILED, not silence), and a
    /// cancel inside it returns at once.
    #[tokio::test(start_paused = true)]
    async fn push_permanent_open_failure_holds_the_ceiling_and_serves_control() {
        let slow = json!({ "timeouts": {
            "connectMs": 500, "reconnectBackoffMinMs": 30_000, "reconnectBackoffMaxMs": 60_000 } });
        let mut rig = Rig::new(push_device(), global(slow));
        for _ in 0..2 {
            rig.backend
                .push_open_err(DeviceError::Permanent(anyhow::anyhow!(
                    "connection size mismatch"
                )));
        }

        let (reply, reply_rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(200),
            DeviceControl::Reconnect { reply },
        );
        rig.cancel_after(Duration::from_millis(600));

        let started = TokioInstant::now();
        rig.run().await;

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the 60 s ceiling was not slept out"
        );
        assert!(
            reply_rx.await.unwrap().is_err(),
            "the reconnect's ForwardOpen failed — the caller is told, not left waiting"
        );
        assert_eq!(rig.backend.opens(), 2);
        // No session ever came up, so nothing flushed the IO family — read it as the next cadence
        // would (§8.7), and both refusals must be there.
        rig.dm.emit_now().await;
        assert_eq!(rig.total(IO, "forwardOpenFailures"), 2.0);
    }

    /// The ForwardClose must run on **every** exit path — lost link, requested reconnect, and
    /// teardown alike. A leaked class-1 connection keeps the device producing into a socket nobody
    /// reads until its watchdog expires.
    #[tokio::test(start_paused = true)]
    async fn push_session_close_runs_on_every_exit_path() {
        let mut rig = Rig::new(push_device(), global(fast_backoff()));
        let closes = Arc::new(AtomicUsize::new(0));

        // 1. a session whose stream ends immediately ⇒ LinkLost.
        let (frames1, p1) = ScriptedPush::new();
        drop(frames1);
        rig.backend
            .push_io(Box::new(SharedPush::new(p1, Arc::clone(&closes))));
        // 2. a session that stays open until an sb/reconnect arrives ⇒ Reconnect.
        // 3. a session that stays open until the cancel ⇒ Stopped.
        // Both producers are held for the whole run (an ended stream would be a LinkLost instead).
        let (_frames2, p2) = ScriptedPush::new();
        rig.backend
            .push_io(Box::new(SharedPush::new(p2, Arc::clone(&closes))));
        let (_frames3, p3) = ScriptedPush::new();
        rig.backend
            .push_io(Box::new(SharedPush::new(p3, Arc::clone(&closes))));

        let (reply, _rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(500),
            DeviceControl::Reconnect { reply },
        );
        rig.cancel_after(Duration::from_secs(2));

        rig.run().await;

        assert_eq!(rig.backend.opens(), 3, "three class-1 sessions were opened");
        assert_eq!(
            closes.load(Ordering::Relaxed),
            3,
            "LinkLost, Reconnect and Stopped each ForwardClose their session"
        );
    }

    /// D-ENIP-17: an operator-requested reconnect rebases the class-1 stack baselines **without**
    /// counting a watchdog timeout. Both halves matter: `ioTimeouts` must stay clean so it still
    /// finds devices that genuinely drop, and the baselines must reset so a redirect refused again
    /// on the new connection re-reports instead of reading as a zero delta.
    #[tokio::test(start_paused = true)]
    async fn push_reconnect_rebases_stack_counters_not_io_lost() {
        let mut g = fast_backoff();
        g["metricsIntervalSecs"] = json!(1);
        let mut rig = Rig::new(push_device(), global(g));
        let stats = IoLinkStats {
            frames_produced: 10,
            refused_redirects: 1,
            ..IoLinkStats::default()
        };

        let (frames1, p1) = ScriptedPush::new();
        p1.set_stats(Some(stats));
        rig.backend.push_io(Box::new(p1));
        let (frames2, p2) = ScriptedPush::new();
        p2.set_stats(Some(stats));
        rig.backend.push_io(Box::new(p2));

        // Bring each connection up so the consume loop runs its metrics cadence.
        let up = frames1.clone();
        tokio::spawn(async move {
            let _ = up
                .send(IoUpdate::Up {
                    o2t_api_ms: 100,
                    t2o_api_ms: 100,
                })
                .await;
        });
        let up2 = frames2.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2_100)).await;
            let _ = up2
                .send(IoUpdate::Up {
                    o2t_api_ms: 100,
                    t2o_api_ms: 100,
                })
                .await;
        });
        let (reply, _rx) = oneshot::channel();
        rig.send_after(
            Duration::from_millis(2_000),
            DeviceControl::Reconnect { reply },
        );
        rig.cancel_after(Duration::from_secs(4));

        rig.run().await;
        drop((frames1, frames2));

        assert_eq!(rig.backend.opens(), 2);
        assert_eq!(
            rig.total(IO, "ioTimeouts"),
            0.0,
            "a requested reconnect is not a watchdog expiry"
        );
        assert!(
            rig.total(IO, "refusedRedirects") >= 2.0,
            "both connections' refusals are counted, not folded into a stale baseline"
        );
        assert_eq!(
            rig.events.count("io-redirect-refused"),
            2,
            "the rebased baselines let the second connection's refusal re-report (D-ENIP-17)"
        );
    }
}
