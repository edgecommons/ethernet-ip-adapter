//! # Test doubles (`#[cfg(test)]` only) — excluded from the coverage denominator (§12.2)
//!
//! The sanctioned home for the adapter's recording/scripted doubles: a [`MetricService`], an
//! [`EventSink`], a [`Publisher`], a [`DeviceSession`], a [`PushSession`], and a [`DeviceBackend`],
//! plus the throwaway PKI + in-process EST responder in [`pki`] and the [`JitterGuard`] that pins the
//! reconnect backoff's jitter fraction. They are what let the poll/push loop
//! drivers, the reconnect ladders, the certificate-lifecycle driver, and the command/pause surfaces
//! run as ordinary unit tests — no broker, no socket, no PLC. Only this file (test-only doubles,
//! compiled out of the binary) is excluded from the coverage denominator; the product code it drives
//! is inside it.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edgecommons::prelude::{Config, Metric, MetricService, Severity, SignalUpdate};
use serde_json::{json, Value};

use crate::app::EventSink;
use crate::config::{DeviceConfig, GlobalConfig, IoConfig, IoFieldSpec, SignalSpec};
use crate::device::{
    BrowsePage, ConnectionConfig, DeviceBackend, DeviceError, DeviceSession, InputSnapshot,
    IoLinkStats, IoUpdate, PushSession, Quality, Reading, Result as DevResult, SecurityStatus,
};
use crate::metrics::DeviceMetrics;
use crate::publish::Publisher;

thread_local! {
    /// The backoff jitter fraction pinned for this thread, if a [`JitterGuard`] is alive.
    static PINNED_JITTER: std::cell::Cell<Option<f64>> = const { std::cell::Cell::new(None) };
}

/// The fraction [`crate::app::rand01`] returns while a [`JitterGuard`] is alive on this thread.
pub fn pinned_jitter() -> Option<f64> {
    PINNED_JITTER.with(std::cell::Cell::get)
}

/// Pin the reconnect backoff's full-jitter fraction for the current thread, restoring the previous
/// value on drop.
///
/// The ladder's wait is `fraction × cap(attempt)`; pinning the fraction turns a wait into an exact
/// value, so "rung *n* was used" is an **equality** rather than the one-sided `wait ≤ cap` bound a
/// jittered ladder otherwise forces. That distinction is the whole point: uniform jitter over
/// `[0, max_ms]` lands under a rung-0 ceiling often enough that an unpinned bound would pass a
/// ladder that stopped resetting `attempt` on a large share of runs.
///
/// A `#[tokio::test]` runs its whole future on one thread, so the guard covers everything the test
/// drives — including the tasks it spawns on that runtime.
pub struct JitterGuard(Option<f64>);

impl JitterGuard {
    /// Pin the fraction (`1.0` = every rung waits its full ceiling).
    pub fn pin(fraction: f64) -> Self {
        Self(PINNED_JITTER.with(|c| c.replace(Some(fraction))))
    }
}

impl Drop for JitterGuard {
    fn drop(&mut self) {
        PINNED_JITTER.with(|c| c.set(self.0));
    }
}

/// A [`MetricService`] that records every emit, so a test can read the last `southbound_health`
/// (e.g. the `signalsSubscribed` gauge).
#[derive(Default)]
pub struct RecordingMetrics {
    pub emitted: Mutex<Vec<(String, HashMap<String, f64>)>>,
}

impl RecordingMetrics {
    /// The most recent emit of `name`, or `None`.
    pub fn last(&self, name: &str) -> Option<HashMap<String, f64>> {
        self.emitted
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    /// Every emit of `name`, in order. A family with dimensions (`EtherNetIpPoll` per
    /// `(pollGroup, result)`, `EtherNetIpPublish` per `publishMode`) emits one row per combo, so a
    /// test that cares about the whole family sums across the rows.
    pub fn all(&self, name: &str) -> Vec<HashMap<String, f64>> {
        self.emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// How many times `name` was emitted.
    pub fn emits(&self, name: &str) -> usize {
        self.emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .count()
    }

    /// The sum of one measure across every emitted row of `name` (the family total when the family
    /// carries dimensions).
    pub fn sum(&self, name: &str, measure: &str) -> f64 {
        self.all(name)
            .iter()
            .filter_map(|v| v.get(measure).copied())
            .sum()
    }
}

#[async_trait]
impl MetricService for RecordingMetrics {
    fn define_metric(&self, _metric: Metric) {}
    fn is_metric_defined(&self, _name: &str) -> bool {
        true
    }
    async fn emit_metric(
        &self,
        name: &str,
        values: HashMap<String, f64>,
    ) -> edgecommons::Result<()> {
        self.emitted
            .lock()
            .unwrap()
            .push((name.to_string(), values));
        Ok(())
    }
    async fn emit_metric_now(
        &self,
        name: &str,
        values: HashMap<String, f64>,
    ) -> edgecommons::Result<()> {
        self.emitted
            .lock()
            .unwrap()
            .push((name.to_string(), values));
        Ok(())
    }
    async fn flush_metrics(&self) -> edgecommons::Result<()> {
        Ok(())
    }
    async fn shutdown(&self) {}
}

/// An [`EventSink`] that records every emitted event / alarm as `(kind, type, context)`.
#[derive(Default)]
pub struct RecordingEvents {
    pub events: Mutex<Vec<(String, String, Value)>>,
}

impl RecordingEvents {
    /// Whether an event of `event_type` was emitted.
    pub fn has(&self, event_type: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|(_, t, _)| t == event_type)
    }
    /// The context of the last event of `event_type`.
    pub fn last_ctx(&self, event_type: &str) -> Option<Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, t, _)| t == event_type)
            .map(|(_, _, c)| c.clone())
    }
    /// How many events of `event_type` were emitted.
    pub fn count(&self, event_type: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t, _)| t == event_type)
            .count()
    }
}

#[async_trait]
impl EventSink for RecordingEvents {
    async fn emit(
        &self,
        _severity: Severity,
        event_type: &str,
        _message: Option<String>,
        context: Option<Value>,
    ) {
        self.events.lock().unwrap().push((
            "emit".into(),
            event_type.to_string(),
            context.unwrap_or(Value::Null),
        ));
    }
    async fn raise_alarm(
        &self,
        _severity: Severity,
        event_type: &str,
        _message: Option<String>,
        context: Option<Value>,
    ) {
        self.events.lock().unwrap().push((
            "raise".into(),
            event_type.to_string(),
            context.unwrap_or(Value::Null),
        ));
    }
    async fn clear_alarm(&self, _severity: Severity, event_type: &str, context: Option<Value>) {
        self.events.lock().unwrap().push((
            "clear".into(),
            event_type.to_string(),
            context.unwrap_or(Value::Null),
        ));
    }
}

/// A minimal [`Config`] for building a [`DeviceMetrics`] in tests.
pub fn config() -> Arc<Config> {
    Arc::new(
        Config::from_value(
            "com.example.EthernetIpAdapter",
            "thing-1",
            json!({ "metricEmission": { "target": "log", "namespace": "test" } }),
        )
        .unwrap(),
    )
}

/// Build a [`DeviceMetrics`] over a fresh [`RecordingMetrics`] for `device`, returning both.
pub fn device_metrics(
    device: DeviceConfig,
    health: Arc<crate::app::Health>,
) -> (Arc<RecordingMetrics>, Arc<DeviceMetrics>) {
    let svc = Arc::new(RecordingMetrics::default());
    let global = GlobalConfig::default();
    let dm = Arc::new(DeviceMetrics::new(
        svc.clone(),
        config(),
        device,
        &global,
        health,
    ));
    (svc, dm)
}

/// Build a [`DeviceMetrics`] over a fresh [`RecordingMetrics`] for `device`, honouring `global`
/// (the cadence/threshold knobs the loop drivers resolve their metric emits against).
pub fn device_metrics_with(
    device: DeviceConfig,
    global: &GlobalConfig,
    health: Arc<crate::app::Health>,
) -> (Arc<RecordingMetrics>, Arc<DeviceMetrics>) {
    let svc = Arc::new(RecordingMetrics::default());
    let dm = Arc::new(DeviceMetrics::new(
        svc.clone(),
        config(),
        device,
        global,
        health,
    ));
    (svc, dm)
}

/// One canned seam [`Reading`], with the native status code a real backend would carry.
pub fn reading(signal_id: &str, value: Value, quality: Quality) -> Reading {
    let raw = match quality {
        Quality::Good => "0x00",
        Quality::Uncertain => "IDLE",
        Quality::Bad => "0x04 path segment error",
    };
    Reading {
        signal_id: signal_id.to_string(),
        name: Some(signal_id.to_string()),
        value,
        quality,
        quality_raw: Some(raw.to_string()),
    }
}

// =====================================================================================
// The publish seam double.
// =====================================================================================

/// A [`Publisher`] that records every update and can be told to fail.
///
/// A scripted failure still records the update, so a test can assert *what* was attempted as well as
/// how the failure was accounted (`EtherNetIpPublish.publishFailures`, no `signalsPublished` bump).
#[derive(Default)]
pub struct RecordingPublisher {
    pub published: Mutex<Vec<SignalUpdate>>,
    pub fail: AtomicBool,
    delay: Mutex<Option<std::time::Duration>>,
}

impl RecordingPublisher {
    /// Make every subsequent publish fail (or succeed again).
    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::Relaxed);
    }

    /// Make every publish take `d` — so a test can assert the measured publish latency is the wall
    /// time of the `.await`, not a constant.
    pub fn set_delay(&self, d: std::time::Duration) {
        *self.delay.lock().unwrap() = Some(d);
    }

    /// How many updates were published.
    pub fn count(&self) -> usize {
        self.published.lock().unwrap().len()
    }

    /// The `signal.id` of every published update, in order.
    pub fn ids(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap()
            .iter()
            .filter_map(|u| u.signal_id.clone())
            .collect()
    }

    /// Every published update, in order (cloned).
    pub fn updates(&self) -> Vec<SignalUpdate> {
        self.published.lock().unwrap().clone()
    }

    /// The total number of samples across every published update — a batched flush carries several.
    pub fn samples(&self) -> usize {
        self.published
            .lock()
            .unwrap()
            .iter()
            .map(|u| u.samples.len())
            .sum()
    }
}

#[async_trait]
impl Publisher for RecordingPublisher {
    async fn publish_update(&self, update: SignalUpdate) -> std::result::Result<(), String> {
        let delay = *self.delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        self.published.lock().unwrap().push(update);
        if self.fail.load(Ordering::Relaxed) {
            Err("recording publisher: scripted failure".to_string())
        } else {
            Ok(())
        }
    }
}

// =====================================================================================
// The poll seam double.
// =====================================================================================

/// A scriptable [`DeviceSession`]: a queue of read outcomes (falling back to a repeating default once
/// drained), a write journal, scripted probe/browse outcomes, and a close counter — the last of which
/// is what makes the "close twice is safe / every exit path closes the session" assertions possible.
///
/// [`DeviceSession`] is implemented for `Arc<ScriptedSession>` so a test keeps its handle while the
/// driver owns its `Box<dyn DeviceSession>`.
#[derive(Default)]
pub struct ScriptedSession {
    reads: Mutex<VecDeque<DevResult<Vec<Reading>>>>,
    delays: Mutex<VecDeque<std::time::Duration>>,
    repeat: Mutex<Vec<Reading>>,
    writes: Mutex<Vec<(String, Value)>>,
    write_err: Mutex<Option<String>>,
    probes: Mutex<VecDeque<DevResult<()>>>,
    browses: Mutex<VecDeque<DevResult<BrowsePage>>>,
    reads_done: AtomicUsize,
    closed: AtomicUsize,
}

impl ScriptedSession {
    /// A fresh session whose reads all answer `repeat` until something is queued in front of them.
    pub fn new(repeat: Vec<Reading>) -> Arc<Self> {
        let s = Self::default();
        *s.repeat.lock().unwrap() = repeat;
        Arc::new(s)
    }

    /// Queue one successful read outcome (consumed before the repeating default).
    pub fn push_read(&self, readings: Vec<Reading>) {
        self.reads.lock().unwrap().push_back(Ok(readings));
    }

    /// Queue one connection-level read failure.
    pub fn push_read_err(&self, e: DeviceError) {
        self.reads.lock().unwrap().push_back(Err(e));
    }

    /// Make the next read take `d` (on the caller's clock — simulated under a paused runtime). Models
    /// a device/cycle that overran its own poll interval.
    pub fn push_read_delay(&self, d: std::time::Duration) {
        self.delays.lock().unwrap().push_back(d);
    }

    /// Make every write fail with `msg` (a rejected CIP write).
    pub fn fail_writes(&self, msg: &str) {
        *self.write_err.lock().unwrap() = Some(msg.to_string());
    }

    /// Queue one probe outcome (the paused keepalive round-trip); the default is `Ok(())`.
    pub fn push_probe(&self, outcome: DevResult<()>) {
        self.probes.lock().unwrap().push_back(outcome);
    }

    /// Queue one browse outcome; the default is `Unsupported`.
    pub fn push_browse(&self, outcome: DevResult<BrowsePage>) {
        self.browses.lock().unwrap().push_back(outcome);
    }

    /// The `(tagPath, value)` of every attempted write, in order.
    pub fn writes(&self) -> Vec<(String, Value)> {
        self.writes.lock().unwrap().clone()
    }

    /// How many `read_signals` calls the driver made.
    pub fn reads_done(&self) -> usize {
        self.reads_done.load(Ordering::Relaxed)
    }

    /// How many times `close()` was called (0 ⇒ the session was never closed on the wire).
    pub fn closed(&self) -> usize {
        self.closed.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl DeviceSession for Arc<ScriptedSession> {
    async fn read_signals(&mut self, _signals: &[SignalSpec]) -> DevResult<Vec<Reading>> {
        self.reads_done.fetch_add(1, Ordering::Relaxed);
        let delay = self.delays.lock().unwrap().pop_front();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        match self.reads.lock().unwrap().pop_front() {
            Some(outcome) => outcome,
            None => Ok(self.repeat.lock().unwrap().clone()),
        }
    }

    async fn write_signal(&mut self, signal: &SignalSpec, value: &Value) -> DevResult<()> {
        self.writes
            .lock()
            .unwrap()
            .push((signal.tag_path.clone(), value.clone()));
        match self.write_err.lock().unwrap().clone() {
            Some(msg) => Err(DeviceError::Permanent(anyhow::anyhow!(msg))),
            None => Ok(()),
        }
    }

    async fn browse(&mut self, _cursor: Option<String>, _max: usize) -> DevResult<BrowsePage> {
        match self.browses.lock().unwrap().pop_front() {
            Some(outcome) => outcome,
            None => Err(DeviceError::Unsupported(
                "scripted session: no tag discovery",
            )),
        }
    }

    async fn probe(&mut self) -> DevResult<()> {
        match self.probes.lock().unwrap().pop_front() {
            Some(outcome) => outcome,
            None => Ok(()),
        }
    }

    async fn close(&mut self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
}

// =====================================================================================
// The push seam double.
// =====================================================================================

/// A scriptable [`PushSession`]: the test holds the `mpsc::Sender<IoUpdate>` (so it can inject `Up` /
/// `Data` / `Lost`, or drop the sender to end the stream), plus a staged-output journal, a settable
/// [`InputSnapshot`], settable [`IoLinkStats`], and a close counter.
pub struct ScriptedPush {
    rx: tokio::sync::mpsc::Receiver<IoUpdate>,
    snapshot: Mutex<Option<InputSnapshot>>,
    stats: Mutex<Option<IoLinkStats>>,
    outputs: Mutex<Vec<(String, Value)>>,
    output_err: Mutex<Option<(usize, String)>>,
    closed: AtomicUsize,
}

impl ScriptedPush {
    /// A session plus the sender the test drives its `IoUpdate` stream with.
    pub fn new() -> (tokio::sync::mpsc::Sender<IoUpdate>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (
            tx,
            Self {
                rx,
                snapshot: Mutex::new(None),
                stats: Mutex::new(None),
                outputs: Mutex::new(Vec::new()),
                output_err: Mutex::new(None),
                closed: AtomicUsize::new(0),
            },
        )
    }

    /// Set what a push `sb/read` (and the resume rebase) answers from.
    pub fn set_snapshot(&self, snapshot: Option<InputSnapshot>) {
        *self.snapshot.lock().unwrap() = snapshot;
    }

    /// Set the class-1 stack counters the metrics fold reads each interval.
    pub fn set_stats(&self, stats: Option<IoLinkStats>) {
        *self.stats.lock().unwrap() = stats;
    }

    /// Let the next `ok_count` stagings succeed, then fail every one after that with `msg`
    /// (`ok_count: 0` fails them all). Count-based rather than time-based because the session is
    /// borrowed by the running driver.
    pub fn fail_outputs_after(&self, ok_count: usize, msg: &str) {
        *self.output_err.lock().unwrap() = Some((ok_count, msg.to_string()));
    }

    /// The `(fieldName, value)` of every staged output, in order.
    pub fn outputs(&self) -> Vec<(String, Value)> {
        self.outputs.lock().unwrap().clone()
    }

    /// How many times `close()` was called (ForwardClose + socket teardown).
    pub fn closed(&self) -> usize {
        self.closed.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl PushSession for ScriptedPush {
    fn updates(&mut self) -> &mut tokio::sync::mpsc::Receiver<IoUpdate> {
        &mut self.rx
    }

    fn last_input(&self) -> Option<InputSnapshot> {
        self.snapshot.lock().unwrap().clone()
    }

    async fn set_output(&mut self, field: &IoFieldSpec, value: &Value) -> DevResult<()> {
        self.outputs
            .lock()
            .unwrap()
            .push((field.name.clone(), value.clone()));
        let mut scripted = self.output_err.lock().unwrap();
        match scripted.as_mut() {
            Some((remaining, _)) if *remaining > 0 => {
                *remaining -= 1;
                Ok(())
            }
            Some((_, msg)) => Err(DeviceError::Permanent(anyhow::anyhow!(msg.clone()))),
            None => Ok(()),
        }
    }

    fn io_stats(&self) -> Option<IoLinkStats> {
        *self.stats.lock().unwrap()
    }

    async fn close(&mut self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
}

// =====================================================================================
// The backend seam double + session wrappers — what the reconnect ladders run against.
// =====================================================================================

/// A scriptable [`DeviceBackend`]: queues of poll-connect and push-open outcomes (each consumed in
/// order, then a repeating transient failure), plus the **timestamp of every attempt**, which is
/// what lets a ladder test measure the backoff the driver actually waited.
///
/// [`DeviceBackend`] is implemented for `Arc<ScriptedBackend>` so a test keeps its handle while the
/// ladder owns its `Box<dyn DeviceBackend>`.
pub struct ScriptedBackend {
    kind: &'static str,
    sessions: Mutex<VecDeque<DevResult<Box<dyn DeviceSession>>>>,
    pushes: Mutex<VecDeque<DevResult<Box<dyn PushSession>>>>,
    /// When each connect / open_push was attempted, on the (possibly simulated) tokio clock.
    attempts: Mutex<Vec<tokio::time::Instant>>,
    connects: AtomicUsize,
    opens: AtomicUsize,
    /// `true` ⇒ every connect never resolves (models a device that accepts the TCP connection and
    /// then says nothing, so the deadline / the cancel decides).
    hang: AtomicBool,
}

impl ScriptedBackend {
    /// A backend reporting `kind` as its adapter name, with nothing queued.
    #[must_use]
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            sessions: Mutex::new(VecDeque::new()),
            pushes: Mutex::new(VecDeque::new()),
            attempts: Mutex::new(Vec::new()),
            connects: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            hang: AtomicBool::new(false),
        }
    }

    /// Queue one successful poll connect.
    pub fn push_session(&self, session: Box<dyn DeviceSession>) {
        self.sessions.lock().unwrap().push_back(Ok(session));
    }

    /// Queue one failed poll connect.
    pub fn push_connect_err(&self, e: DeviceError) {
        self.sessions.lock().unwrap().push_back(Err(e));
    }

    /// Queue one successful class-1 open (ForwardOpen).
    pub fn push_io(&self, session: Box<dyn PushSession>) {
        self.pushes.lock().unwrap().push_back(Ok(session));
    }

    /// Queue one refused class-1 open.
    pub fn push_open_err(&self, e: DeviceError) {
        self.pushes.lock().unwrap().push_back(Err(e));
    }

    /// Make every connect hang forever (never resolve).
    pub fn hang_connects(&self) {
        self.hang.store(true, Ordering::Relaxed);
    }

    /// How many poll connects were attempted.
    pub fn connects(&self) -> usize {
        self.connects.load(Ordering::Relaxed)
    }

    /// How many class-1 opens were attempted.
    pub fn opens(&self) -> usize {
        self.opens.load(Ordering::Relaxed)
    }

    /// The instant of every connect/open attempt, in order — successive gaps are the waits the
    /// reconnect ladder actually took.
    pub fn attempt_times(&self) -> Vec<tokio::time::Instant> {
        self.attempts.lock().unwrap().clone()
    }

    fn record_attempt(&self) {
        self.attempts
            .lock()
            .unwrap()
            .push(tokio::time::Instant::now());
    }
}

#[async_trait]
impl DeviceBackend for Arc<ScriptedBackend> {
    fn kind(&self) -> &'static str {
        self.kind
    }

    async fn connect(&self, _cfg: &ConnectionConfig) -> DevResult<Box<dyn DeviceSession>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        self.record_attempt();
        if self.hang.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        let queued = self.sessions.lock().unwrap().pop_front();
        queued.unwrap_or_else(|| {
            Err(DeviceError::Transient(anyhow::anyhow!(
                "scripted backend: no connect outcome queued"
            )))
        })
    }

    async fn open_push(
        &self,
        _conn: &ConnectionConfig,
        _io: &IoConfig,
    ) -> DevResult<Box<dyn PushSession>> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        self.record_attempt();
        if self.hang.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        let queued = self.pushes.lock().unwrap().pop_front();
        queued.unwrap_or_else(|| {
            Err(DeviceError::Transient(anyhow::anyhow!(
                "scripted backend: no open_push outcome queued"
            )))
        })
    }
}

/// A [`DeviceSession`] that reports a scripted [`SecurityStatus`] and delegates everything else to a
/// [`ScriptedSession`] — the TLS posture the connect edge reads (§3.4) without a socket.
pub struct SecureSession {
    inner: Arc<ScriptedSession>,
    security: Option<SecurityStatus>,
}

impl SecureSession {
    #[must_use]
    pub fn new(inner: Arc<ScriptedSession>, security: Option<SecurityStatus>) -> Self {
        Self { inner, security }
    }
}

#[async_trait]
impl DeviceSession for SecureSession {
    async fn read_signals(&mut self, signals: &[SignalSpec]) -> DevResult<Vec<Reading>> {
        self.inner.read_signals(signals).await
    }
    async fn write_signal(&mut self, signal: &SignalSpec, value: &Value) -> DevResult<()> {
        self.inner.write_signal(signal, value).await
    }
    async fn browse(&mut self, cursor: Option<String>, max: usize) -> DevResult<BrowsePage> {
        self.inner.browse(cursor, max).await
    }
    async fn probe(&mut self) -> DevResult<()> {
        self.inner.probe().await
    }
    fn security(&self) -> Option<SecurityStatus> {
        self.security.clone()
    }
    async fn close(&mut self) {
        self.inner.close().await;
    }
}

/// A [`PushSession`] that delegates to a [`ScriptedPush`] while publishing its close count through a
/// shared handle — so a ladder test can still assert the ForwardClose after the session has been
/// boxed into a backend and consumed by the driver.
pub struct SharedPush {
    inner: ScriptedPush,
    closed: Arc<AtomicUsize>,
}

impl SharedPush {
    #[must_use]
    pub fn new(inner: ScriptedPush, closed: Arc<AtomicUsize>) -> Self {
        Self { inner, closed }
    }
}

#[async_trait]
impl PushSession for SharedPush {
    fn updates(&mut self) -> &mut tokio::sync::mpsc::Receiver<IoUpdate> {
        self.inner.updates()
    }
    fn last_input(&self) -> Option<InputSnapshot> {
        self.inner.last_input()
    }
    async fn set_output(&mut self, field: &IoFieldSpec, value: &Value) -> DevResult<()> {
        self.inner.set_output(field, value).await
    }
    fn io_stats(&self) -> Option<IoLinkStats> {
        self.inner.io_stats()
    }
    async fn close(&mut self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
        self.inner.close().await;
    }
}

// =====================================================================================
// The throwaway PKI + in-process EST responder (relocated from `eip/est/tests.rs`).
// =====================================================================================

/// Throwaway test PKI + an in-process rustls EST responder.
///
/// Lives here, beside the other doubles, because two suites need it: the EST client's own tests
/// (`eip/est/tests.rs`) and the cert-lifecycle driver's ([`crate::security_lifecycle`]), which
/// enrolls against the same responder to prove the Phase-2c ⇒ Phase-2b handoff end to end.
pub mod pki {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// A minted CA, a server leaf (IP-SAN `127.0.0.1`), and a client (bootstrap) identity.
    pub struct Certs {
        pub ca_pem: String,
        pub ca_der: CertificateDer<'static>,
        pub server_chain: Vec<CertificateDer<'static>>,
        pub server_key: PrivateKeyDer<'static>,
        pub client_cert_pem: String,
        pub client_key_pem: String,
    }

    /// Mint a CA, a server leaf with an IP SAN for 127.0.0.1, and a client (bootstrap) identity.
    #[must_use]
    pub fn mint_certs() -> Certs {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType};
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut sp = CertificateParams::new(vec![]).unwrap();
        sp.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = sp.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        let cp = CertificateParams::new(vec!["eip-bootstrap".to_string()]).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        Certs {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            server_chain: vec![server_cert.der().clone()],
            server_key: PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// A GOLDEN certs-only PKCS#7 (DER, base64), produced with OpenSSL:
    ///   `openssl crl2pkcs7 -nocrl -certfile <CN=eip-originator, serial 540D9C…> -outform DER`
    /// This is the exact `application/pkcs7-mime` shape an EST `/simpleenroll` returns.
    pub const GOLDEN_PKCS7_B64: &str = "MIIBpwYJKoZIhvcNAQcCoIIBmDCCAZQCAQExADALBgkqhkiG9w0BBwGgggF8MIIBeDCCAR6gAwIBAgIUVA2cqvkfkRI6mkS7lfUe/n7qwnUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQRVNUIFRlc3QgUm9vdCBDQTAeFw0yNjA3MTkxNzA1MTBaFw0yODEwMjExNzA1MTBaMBkxFzAVBgNVBAMMDmVpcC1vcmlnaW5hdG9yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZIXphvHufMQQMj/LVXTIEOgjhpGP9iVOqqpgVpiivTB74trvg7nwmWnH5ETuvBg91Fy7wnQg+X5tQxDkXBEGe6NCMEAwHQYDVR0OBBYEFJz8r/HNFFu8ncEoCEI2Fj/Bvgp4MB8GA1UdIwQYMBaAFMbbMncP1I7iT1e0SvnldGXjuYofMAoGCCqGSM49BAMCA0gAMEUCIQDI6CbYr5yNThMcllSXBotG12/m/I4Ki1OQ7jvHfm4BqwIgCzwdSZZr2Z2rWxH41m9ddKPsZ+CaxxEt+J1CBA43sk4xAA==";
    /// The leaf certificate's serial (uppercase hex) inside the golden vector.
    pub const GOLDEN_SERIAL: &str = "540D9CAAF91F91123A9A44BB95F51EFE7EEAC275";

    /// An EST `200 OK` response carrying `body_b64` as `application/pkcs7-mime`.
    #[must_use]
    pub fn est_http_200(body_b64: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: base64\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_b64.len(),
            body_b64
        )
        .into_bytes()
    }

    /// Spawn a one-shot TLS EST responder on 127.0.0.1 that returns `response_bytes` for any
    /// request. Returns the bound port.
    pub async fn spawn_est_server(certs: &Certs, response_bytes: Vec<u8>) -> u16 {
        spawn_est_server_seq(certs, vec![response_bytes]).await
    }

    /// Spawn a TLS EST responder on 127.0.0.1 that answers successive connections with successive
    /// `responses` (the last one repeats). Returns the bound port.
    ///
    /// The sequenced form is what lets a lifecycle test drive a *failed* enrollment followed by a
    /// successful one against one configured server URL.
    pub async fn spawn_est_server_seq(certs: &Certs, responses: Vec<Vec<u8>>) -> u16 {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs.ca_der.clone()).unwrap();
        let server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.server_chain.clone(), certs.server_key.clone_key())
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let mut i = 0usize;
            while let Ok((tcp, _)) = listener.accept().await {
                // The last scripted response repeats for any further connection.
                let Some(body) = responses.get(i).or_else(|| responses.last()).cloned() else {
                    return;
                };
                i += 1;
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    // Read the request headers (until the terminator) so the client's write completes.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    for _ in 0..64 {
                        match tls.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = tls.write_all(&body).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
                }
            }
        });
        port
    }
}
