//! # The EtherNet/IP live-socket drivers (§3.4, §4.6)
//!
//! A **thin driver seam** analogous to `file-replicator`'s `dest/*/client.rs`: it opens live sockets to
//! a device over the owned `enip` stack and drives them. It holds no branching that is not driven by a
//! socket `.await`:
//!
//! * [`impl DeviceBackend for EipBackend`](EipBackend) — TCP-connect a poll session (`connect`) and
//!   ForwardOpen a class-1 push session (`open_push`).
//! * [`EipPushSession`] + [`run_translator`] — the class-1 (implicit I/O) session: bind the UDP socket,
//!   ForwardOpen, and translate the `enip` [`enip::IoEvent`] stream into seam [`IoUpdate`]s.
//!
//! The pure pieces it composes — the JSON⇄CIP codec ([`super::types`]), the field-extraction
//! ([`super::push::assembly_to_readings`]), the error classification ([`super::map_enip_error`]), the
//! loss mapping ([`super::push::map_lost_reason`]) — are unit-tested in their home modules.
//!
//! **How the driver itself is tested (§12.2).** The `tests` module below drives every path here over
//! **local sockets**: a scripted EtherNet/IP peer on a loopback `TcpListener` speaking encapsulation
//! (plaintext and TLS) plus a test-owned UDP socket standing in for the class-1 target. Connect, the
//! Phase-2a posture read, the TLS arm, ForwardOpen, the translator, `set_output`, `io_stats`, the
//! inactivity watchdog, and `close` all execute under an ordinary `cargo test` — no container, no
//! device, no fixed port, Windows and Linux alike. The live OpENer/cpppo/EthernetIPSharp suites (§11)
//! remain the *conformance* evidence against independent implementations, and the deployed regression
//! (§12.4) the on-device evidence.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{IoConfig, IoFieldSpec, Timeouts};
use crate::device::{
    ConnectionConfig, DeviceBackend, DeviceError, DeviceSession, InputSnapshot, IoLinkStats,
    IoUpdate, PushSession, Result,
};

use super::push::{assembly_to_readings, lost_reason_detail, map_lost_reason};
use super::{client_options, map_enip_error, EipBackend, VENDOR_ID};

#[async_trait]
impl DeviceBackend for EipBackend {
    fn kind(&self) -> &'static str {
        "ethernet-ip"
    }

    async fn connect(&self, conn: &ConnectionConfig) -> Result<Box<dyn DeviceSession>> {
        let sec = super::tls::SecurityConfig::from_connection(conn)
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
        // A `mode: tls` connection wraps the explicit session in TLS (CIP Security Phase 1): build the
        // rustls ClientConfig from the security block + vault material, then dial port 2221 over TLS.
        if let Some(sec) = sec.as_ref().filter(|s| s.is_tls()) {
            let mut opts = client_options(conn, self.timeouts());
            opts.port = enip::DEFAULT_TLS_PORT;
            let request_timeout = opts.request_timeout;
            let (tls_opts, meta) = super::tls::build_client_config(sec, conn, self.creds())
                .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
            let client = enip::EipClient::connect_tls(&conn.endpoint, opts, tls_opts)
                .await
                .map_err(map_enip_error)?;
            let mut status = super::tls::security_status(client.tls_session_info(), &meta, conn);
            // Phase 2a: read the target's CIP Security posture over the established (TLS) session.
            status.target = read_target_posture(&client).await;
            return Ok(Box::new(super::session::EipSession::new_secure(
                client,
                request_timeout,
                status,
            )));
        }
        let opts = client_options(conn, self.timeouts());
        let request_timeout = opts.request_timeout;
        let client = enip::EipClient::connect(&conn.endpoint, opts)
            .await
            .map_err(map_enip_error)?;
        // Phase 2a: a plaintext session still reads the target's posture (best-effort). A generic CIP
        // device reports none (targetSupportsCipSecurity: false); a CIP Security device polled
        // plaintext surfaces its objects. When no posture is read, the session stays a bare plaintext
        // session (`security()` = None ⇒ `{"mode":"plaintext"}`).
        match read_target_posture(&client).await {
            Some(target) => Ok(Box::new(super::session::EipSession::new_secure(
                client,
                request_timeout,
                super::tls::plaintext_status(Some(target)),
            ))),
            None => Ok(Box::new(super::session::EipSession::new(
                client,
                request_timeout,
            ))),
        }
    }

    async fn open_push(
        &self,
        conn: &ConnectionConfig,
        io: &IoConfig,
    ) -> Result<Box<dyn PushSession>> {
        let session = EipPushSession::open(conn, io, self.timeouts(), VENDOR_ID).await?;
        Ok(Box::new(session))
    }
}

/// Read the target's CIP Security posture over an established session (Phase 2a, §4.1), mapped to the
/// protocol-agnostic seam type. Best-effort: a device that does not implement the objects yields
/// `None`, and a connection-level read failure is swallowed (logged) so it never fails the connect —
/// the posture is a diagnostic surface, not a liveness gate. A device found in the `Factory Default`
/// state while being polled gets a WARN (an unprovisioned device on a secured poll path, §4.1).
async fn read_target_posture(
    client: &enip::EipClient,
) -> Option<crate::device::TargetSecurityPosture> {
    match client.read_security_posture().await {
        Ok(posture) => {
            if let Some(cip) = &posture.cip_security {
                if cip.state == enip::CipSecurityState::FactoryDefault {
                    tracing::warn!(
                        "target reports CIP Security state `Factory Default` — the device is \
                         unprovisioned; provision operational credentials before relying on TLS"
                    );
                }
            }
            super::tls::map_target_posture(&posture)
        }
        Err(e) => {
            tracing::debug!(error = %e, "reading target CIP Security posture failed (ignored)");
            None
        }
    }
}

/// The class-1 connection's live counters, shared between the translator task (which refreshes it
/// from the `enip` connection handle on every event) and [`PushSession::io_stats`] (which reads it
/// for the periodic `EtherNetIpIo` metric emit). Reset to zero on a lost link (the handle's counters
/// belong to one ForwardOpen).
type SharedStats = Arc<Mutex<IoLinkStats>>;

/// Map the protocol stack's per-connection counters into the protocol-agnostic seam struct.
fn map_io_stats(s: enip::IoStats) -> IoLinkStats {
    IoLinkStats {
        frames_produced: s.frames_produced,
        stale_frames: s.stale_frames,
        size_mismatch: s.size_mismatch,
        sequence_gaps: s.sequence_gaps,
        malformed_frames: s.malformed_frames,
        produce_overruns: s.produce_overruns,
        send_errors: s.send_errors,
        recv_errors: s.recv_errors,
        refused_redirects: s.refused_redirects,
    }
}

/// The most-recent decoded input frame, shared between the translator task (which writes it on every
/// accepted frame) and the session handle's [`PushSession::last_input`] (which reads it for push
/// `sb/read`). Kept live independently of the engine's consumption so an on-demand read works while
/// paused (§7.2).
type SharedSnapshot = Arc<Mutex<Option<InputSnapshot>>>;

/// Duration → whole milliseconds (saturating), for the seam's `*_api_ms` fields.
fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// The grace the aborted translator gets to actually stop (D-EIP-31). After a clean ack the task has
/// already returned and the join resolves immediately; after an `abort()` the `JoinHandle` resolves at
/// the translator's next await point, and it is always parked on one. This exists for scheduler slack
/// only — the join is a **causal** wait on a task ending, not a race between two timers.
const ABORT_JOIN_GRACE: Duration = Duration::from_millis(250);

/// A control message from the session handle to its translator task.
enum PushControl {
    /// Stage a fully-encoded output-assembly buffer; the sender receives the **staging verdict** once
    /// the I/O manager has accepted (or refused) it (D-EIP-31). `Ok(())` means the buffer is held for
    /// a live class-1 connection and rides the next O→T frame; an `Err` means it never will.
    SetOutput(Vec<u8>, oneshot::Sender<Result<()>>),
    /// ForwardClose + teardown, then acknowledge.
    Close(oneshot::Sender<()>),
}

/// A live push (class-1 I/O) session over the owned `enip` I/O manager. The [`enip::IoConnectionHandle`],
/// [`enip::EipClient`], and [`enip::IoManager`] live in the translator task; this handle keeps only
/// the seam update receiver, the control channel, and the output codec state.
pub struct EipPushSession {
    updates: mpsc::Receiver<IoUpdate>,
    control: mpsc::Sender<PushControl>,
    task: Option<JoinHandle<()>>,
    /// The validated output (O→T) layout, or `None` for a heartbeat connection (no output data).
    out_layout: Option<enip::AssemblyLayout>,
    out_fields: Vec<IoFieldSpec>,
    out_buf: Vec<u8>,
    /// The most-recent decoded input frame (§7.2), written by the translator task; the source push
    /// `sb/read` answers from.
    snapshot: SharedSnapshot,
    /// The class-1 connection's live drop/produce counters (§8.8), refreshed by the translator task;
    /// read by [`PushSession::io_stats`] for the periodic `EtherNetIpIo` emit.
    stats: SharedStats,
    /// The bound on a write's staging confirmation (D-EIP-31) — the operator's own
    /// `timeouts.requestTimeoutMs`, the same per-request bound the CIP calls run under. A translator
    /// that cannot confirm within it (wedged on a full update channel) makes `sb/write` say so
    /// instead of hanging or reporting a success that never reached the producer buffer.
    ack_cap: Duration,
}

impl EipPushSession {
    /// ForwardOpen the class-1 connection from the `io` block and start consuming it (§3.4, §4.6).
    ///
    /// # Errors
    ///
    /// A mapped [`DeviceError`] if the TCP session, the UDP bind, or the ForwardOpen fails, or if the
    /// (already-validated) layout cannot be built.
    pub async fn open(
        conn: &ConnectionConfig,
        io: &IoConfig,
        timeouts: &Timeouts,
        vendor_id: u16,
    ) -> Result<Self> {
        // Layouts (already proven at config-parse time; rebuilt here for the runtime path).
        let in_layout = io
            .input_layout()
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
        let out_layout = io
            .output_layout()
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
        let in_fields = io.input.signals.clone();
        let in_inst = io.assemblies.input;
        let out_fields = io
            .output
            .as_ref()
            .map(|o| o.signals.clone())
            .unwrap_or_default();
        let out_size = io.output.as_ref().map_or(0, |o| o.size_bytes);

        let spec = io_spec(conn, io, vendor_id)?;

        // Connect the TCP session (for CM/UCMM), bind the I/O socket, and ForwardOpen.
        let opts = client_options(conn, timeouts);
        // The staging confirmation rides the same per-request bound the operator configured for CIP
        // calls (D-EIP-31) rather than a knob of its own.
        let ack_cap = opts.request_timeout;
        let client = enip::EipClient::connect(&conn.endpoint, opts)
            .await
            .map_err(map_enip_error)?;
        let io_manager = enip::IoManager::bind("0.0.0.0:0")
            .await
            .map_err(map_enip_error)?;
        let handle = io_manager
            .forward_open(&client, spec)
            .await
            .map_err(map_enip_error)?;

        let (updates_tx, updates_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(8);
        let snapshot: SharedSnapshot = Arc::new(Mutex::new(None));
        let stats: SharedStats = Arc::new(Mutex::new(IoLinkStats::default()));
        let task = tokio::spawn(run_translator(
            handle,
            client,
            io_manager,
            in_layout,
            in_fields,
            in_inst,
            updates_tx,
            control_rx,
            Arc::clone(&snapshot),
            Arc::clone(&stats),
        ));

        Ok(Self {
            updates: updates_rx,
            control: control_tx,
            task: Some(task),
            out_layout,
            out_fields,
            out_buf: vec![0u8; out_size],
            snapshot,
            stats,
            ack_cap,
        })
    }

    /// The whole close — control handoff, ack, and join — under ONE absolute deadline derived from
    /// `cap`, plus the fixed [`ABORT_JOIN_GRACE`] (D-EIP-31). [`PushSession::close`] delegates here
    /// with the production cap; the tests inject a short one so the wedged-translator path is proven
    /// without a five-second suite.
    ///
    /// **On return the translator has ended** — cleanly (it acked, so the ForwardClose,
    /// `IoManager::shutdown` and `EipClient::close` all reached the wire) or by `abort()`. An aborted
    /// translator skips those courtesy frames; teardown still completes through the Drop chains
    /// (dropping the `IoManager`/`IoConnectionHandle` closes the manager's command channel, so its
    /// task exits and drops the UDP socket; dropping the `EipClient` closes the actor channel, so the
    /// actor exits and drops the TCP stream) and the target times the class-1 connection out on its
    /// own watchdog. That is the same trade `stop_runtimes`' abort already makes — the defect this
    /// replaces was reporting the close complete **without** making it, leaving a detached task
    /// holding both transports.
    async fn close_with_cap(&mut self, cap: Duration) {
        let Some(task) = self.task.take() else {
            return;
        };
        let deadline = tokio::time::Instant::now() + cap;
        let (ack_tx, ack_rx) = oneshot::channel();
        let clean =
            match tokio::time::timeout_at(deadline, self.control.send(PushControl::Close(ack_tx)))
                .await
            {
                // The handoff landed; the remaining budget bounds the teardown itself.
                Ok(Ok(())) => tokio::time::timeout_at(deadline, ack_rx).await.is_ok(),
                // The control channel is closed (the translator already ended), or the send itself
                // outlived the budget (a translator that never services its control channel).
                _ => false,
            };
        if !clean {
            task.abort();
        }
        // Join in EVERY path: that is what makes "close returned" mean "the translator has ended".
        if tokio::time::timeout(ABORT_JOIN_GRACE, task).await.is_err() {
            tracing::error!(
                "push translator did not terminate after abort; its transports will be released \
                 when the process exits"
            );
        }
    }
}

/// Belt and braces for a session dropped **without** `close` — an outer device task aborted at the
/// stop budget, or a panic unwinding past it (D-EIP-31). Nothing else owns the translator's
/// `JoinHandle`, so without this it would outlive the handle that spawned it.
impl Drop for EipPushSession {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Build the class-1 ForwardOpen spec from the `io` block, through the config's typed `to_enip`
/// helpers (§4.6). O→T is always point-to-point; a device with no output assembly opens a heartbeat.
///
/// # Errors
///
/// [`DeviceError::Permanent`] if the (already config-validated) timeout multiplier cannot be coded.
fn io_spec(
    conn: &ConnectionConfig,
    io: &IoConfig,
    vendor_id: u16,
) -> Result<enip::IoConnectionSpec> {
    let route = conn
        .slot
        .map(|s| vec![enip::PortSegment::backplane_slot(s)])
        .unwrap_or_default();
    let assembly = enip::AssemblyPath {
        config: io.assemblies.config,
        output: io.assemblies.output,
        input: io.assemblies.input,
        route,
    };
    let t2o = enip::DirectionSpec {
        rpi: Duration::from_millis(io.rpi_ms.max(1)),
        data_size: io.input.size_bytes,
        format: io.input.real_time_format.to_enip(),
        conn_type: io.connection_type.to_enip(),
        priority: io.priority.to_enip(),
        variable: enip::VariableLength::Fixed,
    };
    let (o2t_size, o2t_format) = match &io.output {
        Some(out) => (out.size_bytes, out.real_time_format.to_enip()),
        None => (0, enip::RealTimeFormat::Heartbeat),
    };
    let o2t = enip::DirectionSpec {
        rpi: Duration::from_millis(io.effective_o2t_rpi_ms().max(1)),
        data_size: o2t_size,
        format: o2t_format,
        conn_type: enip::ConnType::P2P,
        priority: io.priority.to_enip(),
        variable: enip::VariableLength::Fixed,
    };
    Ok(enip::IoConnectionSpec {
        assembly,
        t2o,
        o2t,
        timeout_multiplier: io
            .timeout_multiplier_enip()
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?,
        trigger: enip::ProductionTrigger::Cyclic,
        vendor_id,
    })
}

/// The seam verdict for a staging request the I/O manager refused with [`enip::EnipError::Closed`]
/// (D-EIP-31).
///
/// `Closed` is the manager's ONE word for three different situations — its task is gone, the
/// connection was removed because it was **lost**, or the connection was removed because it was
/// **closed** — and its `Display` is the bare string `"closed"`. An operator reading a refused
/// `sb/write` cannot tell a device fault from an orderly stop from that, which is why this names the
/// disposition instead. `enip` also classifies `Closed` as non-transient, so [`super::map_enip_error`]
/// would make it a [`DeviceError::Permanent`]: both dispositions are recovered by the reconnect
/// ladder — a lost class-1 connection is the textbook transient — so both are `Transient` here.
fn closed_verdict(lost: Option<enip::LostReason>) -> DeviceError {
    match lost {
        Some(reason) => DeviceError::Transient(anyhow::anyhow!(
            "class-1 connection lost ({}); output not staged",
            lost_reason_detail(reason)
        )),
        None => DeviceError::Transient(anyhow::anyhow!(
            "the class-1 connection was closed; output not staged"
        )),
    }
}

/// What one staging attempt produced (D-EIP-31).
struct Staged {
    /// The verdict the session handle answers `sb/write` with.
    verdict: Result<()>,
    /// The terminal loss the disposition consult read off the stream, if any. The translator still
    /// owes the seam this `Lost` and must end after reporting it.
    lost: Option<enip::LostReason>,
    /// Whatever the consult took off the stream **ahead** of that loss — still owed to the seam, so
    /// naming a disposition never costs a sample.
    drained: Vec<enip::IoEvent>,
}

/// Stage one encoded output-assembly buffer and turn the I/O manager's answer into a seam verdict
/// (D-EIP-31).
///
/// Everything except [`enip::EnipError::Closed`] goes through [`super::map_enip_error`] unchanged.
/// `Closed` is resolved to a disposition first, and the translator can do that because the manager
/// **delivers the loss before it can refuse the staging**: a watchdog expiry (or a dead transmit
/// path, or a dead socket) emits `IoEvent::Lost` on this connection's own stream and removes the
/// connection in the same manager-loop iteration, and the staging command is only read on a later
/// one. `Lost` is a control event the queue never evicts and a dropped sender never discards, so
/// draining the — by then terminal — stream is a **causal** read of why the connection is gone, not
/// a guess. Finding no loss there means the connection was removed deliberately (`close`/`shutdown`).
async fn stage_and_interpret(handle: &mut enip::IoConnectionHandle, bytes: Vec<u8>) -> Staged {
    let mut lost = None;
    let mut drained = Vec::new();
    let verdict = match handle.stage_output(bytes).await {
        Ok(()) => Ok(()),
        Err(enip::EnipError::Closed) => {
            while let Ok(ev) = handle.events().try_recv() {
                // Nothing is queued behind the terminal event, so this is the end of the drain.
                if let enip::IoEvent::Lost { reason } = ev {
                    lost = Some(reason);
                    break;
                }
                drained.push(ev);
            }
            Err(closed_verdict(lost))
        }
        Err(other) => Err(super::map_enip_error(other)),
    };
    Staged {
        verdict,
        lost,
        drained,
    }
}

/// Decode one accepted T→O frame into seam readings (§5), refresh the shared snapshot push `sb/read`
/// answers from (§7.2), and offer the `Data` update.
async fn emit_data(
    in_layout: &enip::AssemblyLayout,
    in_fields: &[IoFieldSpec],
    in_inst: u16,
    snapshot: &SharedSnapshot,
    updates_tx: &mpsc::Sender<IoUpdate>,
    latest: enip::IoUpdate,
) {
    let readings =
        assembly_to_readings(in_layout, in_fields, in_inst, &latest.data, latest.run_mode);
    let received_at = latest.received_at.into_std();
    // Keep the latest snapshot live for push `sb/read` (answered even while paused).
    *snapshot.lock().unwrap() = Some(InputSnapshot {
        readings: readings.clone(),
        received_at,
        run_mode: latest.run_mode,
    });
    let _ = updates_tx
        .send(IoUpdate::Data {
            readings,
            sequence: latest.sequence,
            run_mode: latest.run_mode,
            received_at,
        })
        .await;
}

/// Hand the seam whatever a disposition consult took off the event stream (D-EIP-31), so naming why
/// a staging request was refused never costs the consumer an update: latest-wins over the samples the
/// consult drained — at most one `Up` and the freshest `Data`, exactly as the translator's own event
/// arm collapses a burst — and then the loss itself, which no event arm will ever see now.
///
/// Returns `true` when that loss was terminal and the translator must end.
#[allow(clippy::too_many_arguments)]
async fn deliver_consulted_tail(
    in_layout: &enip::AssemblyLayout,
    in_fields: &[IoFieldSpec],
    in_inst: u16,
    snapshot: &SharedSnapshot,
    updates_tx: &mpsc::Sender<IoUpdate>,
    lost: Option<enip::LostReason>,
    drained: Vec<enip::IoEvent>,
) -> bool {
    let mut carried_up = None;
    let mut carried_data = None;
    for ev in drained {
        match ev {
            enip::IoEvent::Up { o2t_api, t2o_api } => carried_up = Some((o2t_api, t2o_api)),
            enip::IoEvent::Data(update) => carried_data = Some(update),
            enip::IoEvent::Lost { .. } => {}
        }
    }
    if let Some((o2t_api, t2o_api)) = carried_up {
        let _ = updates_tx
            .send(IoUpdate::Up {
                o2t_api_ms: ms(o2t_api),
                t2o_api_ms: ms(t2o_api),
            })
            .await;
    }
    if let Some(update) = carried_data {
        emit_data(in_layout, in_fields, in_inst, snapshot, updates_tx, update).await;
    }
    let Some(reason) = lost else {
        return false;
    };
    let _ = updates_tx
        .send(IoUpdate::Lost {
            error: map_lost_reason(reason),
        })
        .await;
    true
}

/// The translator task: drain `enip` I/O events (latest-wins) into seam [`IoUpdate`]s and service
/// control messages, owning the connection handle / client / manager for the connection's lifetime.
#[allow(clippy::too_many_arguments)]
async fn run_translator(
    mut handle: enip::IoConnectionHandle,
    client: enip::EipClient,
    io_manager: enip::IoManager,
    in_layout: enip::AssemblyLayout,
    in_fields: Vec<IoFieldSpec>,
    in_inst: u16,
    updates_tx: mpsc::Sender<IoUpdate>,
    mut control_rx: mpsc::Receiver<PushControl>,
    snapshot: SharedSnapshot,
    stats: SharedStats,
) {
    'task: loop {
        // Refresh the shared counters from the live connection handle (§8.8). The handle's counters
        // are updated by the I/O manager task; reading them here on every wakeup keeps the metric
        // emit's `EtherNetIpIo` drop/produce measures fresh (frames arrive at the RPI cadence).
        *stats.lock().unwrap() = map_io_stats(handle.stats());

        let mut do_output: Option<(Vec<u8>, oneshot::Sender<Result<()>>)> = None;
        let mut do_close: Option<oneshot::Sender<()>> = None;

        tokio::select! {
            ev = handle.events().recv() => {
                match ev {
                    Some(enip::IoEvent::Up { o2t_api, t2o_api }) => {
                        let _ = updates_tx
                            .send(IoUpdate::Up { o2t_api_ms: ms(o2t_api), t2o_api_ms: ms(t2o_api) })
                            .await;
                    }
                    Some(enip::IoEvent::Data(first)) => {
                        // Latest-wins: collapse consecutive Data frames, carrying any following
                        // non-Data event so Up/Lost are never dropped.
                        let mut latest = first;
                        let mut carried: Option<enip::IoEvent> = None;
                        loop {
                            match handle.events().try_recv() {
                                Ok(enip::IoEvent::Data(n)) => latest = n,
                                Ok(other) => { carried = Some(other); break; }
                                Err(_) => break,
                            }
                        }
                        emit_data(
                            &in_layout, &in_fields, in_inst, &snapshot, &updates_tx, latest,
                        )
                        .await;
                        match carried {
                            Some(enip::IoEvent::Up { o2t_api, t2o_api }) => {
                                let _ = updates_tx
                                    .send(IoUpdate::Up { o2t_api_ms: ms(o2t_api), t2o_api_ms: ms(t2o_api) })
                                    .await;
                            }
                            Some(enip::IoEvent::Lost { reason }) => {
                                let _ = updates_tx
                                    .send(IoUpdate::Lost { error: map_lost_reason(reason) })
                                    .await;
                                break 'task;
                            }
                            _ => {}
                        }
                    }
                    Some(enip::IoEvent::Lost { reason }) => {
                        let _ = updates_tx.send(IoUpdate::Lost { error: map_lost_reason(reason) }).await;
                        break 'task;
                    }
                    None => break 'task,
                }
            }
            ctrl = control_rx.recv() => {
                match ctrl {
                    Some(PushControl::SetOutput(bytes, ack)) => do_output = Some((bytes, ack)),
                    Some(PushControl::Close(ack)) => do_close = Some(ack),
                    None => break 'task,
                }
            }
        }

        if let Some((bytes, ack)) = do_output {
            // The confirmed staging path (D-ENIP-20 / D-EIP-31): the I/O manager's own verdict —
            // `Ok` only when it holds the buffer for a live connection — travels back to the caller,
            // so `sb/write` can never report a success the producer buffer never took. A refusal is
            // resolved to a disposition first, so the caller is told *why* nothing was staged.
            let staged = stage_and_interpret(&mut handle, bytes).await;
            if let Err(e) = &staged.verdict {
                tracing::warn!(error = %e, "push: staging output frame failed");
            }
            let _ = ack.send(staged.verdict);
            if deliver_consulted_tail(
                &in_layout,
                &in_fields,
                in_inst,
                &snapshot,
                &updates_tx,
                staged.lost,
                staged.drained,
            )
            .await
            {
                break 'task;
            }
        }
        if let Some(ack) = do_close {
            let _ = handle.close(&client).await;
            io_manager.shutdown().await;
            client.close().await;
            let _ = ack.send(());
            return;
        }
    }

    // Terminal cleanup after a lost link / closed stream.
    let _ = handle.close(&client).await;
    io_manager.shutdown().await;
    client.close().await;
}

#[async_trait]
impl PushSession for EipPushSession {
    fn updates(&mut self) -> &mut mpsc::Receiver<IoUpdate> {
        &mut self.updates
    }

    fn last_input(&self) -> Option<InputSnapshot> {
        self.snapshot.lock().unwrap().clone()
    }

    fn io_stats(&self) -> Option<IoLinkStats> {
        Some(*self.stats.lock().unwrap())
    }

    async fn set_output(&mut self, field: &IoFieldSpec, value: &serde_json::Value) -> Result<()> {
        let layout = self
            .out_layout
            .as_ref()
            .ok_or(DeviceError::Unsupported("device has no output assembly"))?;
        // The layout key is the field's declaration index (build_layout enumerates output.signals).
        let key = self
            .out_fields
            .iter()
            .position(|f| {
                f.offset == field.offset && f.eip_type == field.eip_type && f.bit == field.bit
            })
            .ok_or_else(|| DeviceError::Permanent(anyhow::anyhow!("unknown output field")))?;
        let cip = super::types::encode_write(
            value,
            field.eip_type,
            field.scale,
            field.value_offset,
            field.array_count,
        )
        .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e.to_string())))?;
        layout
            .encode_into(&[(key, cip)], &mut self.out_buf)
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e.to_string())))?;
        // Result-bearing end to end (D-EIP-31): session ack ⇒ translator ⇒ I/O manager ack. `Ok(())`
        // here means the manager holds this buffer for a live connection, nothing weaker.
        let (ack_tx, ack_rx) = oneshot::channel();
        self.control
            .send(PushControl::SetOutput(self.out_buf.clone(), ack_tx))
            .await
            .map_err(|_| {
                DeviceError::Transient(anyhow::anyhow!(
                    "push session is closing; output not staged"
                ))
            })?;
        match tokio::time::timeout(self.ack_cap, ack_rx).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_gone)) => Err(DeviceError::Transient(anyhow::anyhow!(
                "push translator ended before the output was staged"
            ))),
            // Causal honesty, not a race: a translator wedged on a full update channel cannot
            // confirm, and a write must say so rather than hang or lie.
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "output staging was not confirmed within the request timeout"
            ))),
        }
    }

    async fn close(&mut self) {
        // The shutdown budget and this handoff share one number (§10.3, D-EIP-27).
        self.close_with_cap(crate::lifecycle::PUSH_CLOSE_HANDOFF_CAP)
            .await;
    }
}

#[cfg(test)]
mod tests {
    //! # Local-socket tests for the live seam (§12.2)
    //!
    //! Everything here runs against **loopback sockets bound to ephemeral ports** — no container, no
    //! device, no fixed port, no network peer — so the whole seam executes on Windows and Linux alike:
    //!
    //! * [`MockPlc`] is a scripted EtherNet/IP peer on a `tokio::net::TcpListener`. It answers
    //!   RegisterSession, the Phase-2a CIP Security posture reads (0x5D/0x5E/0x5F), the class-1
    //!   ForwardOpen (crafting the success reply the way `enip`'s own `io.rs` fixture does), and
    //!   ForwardClose. Given a `rustls::ServerConfig` it speaks the same protocol inside TLS, which is
    //!   how the CIP Security arm of `connect` is driven.
    //! * A test-owned `tokio::net::UdpSocket` is the class-1 target: it produces T→O frames into the
    //!   port the originator advertises in the ForwardOpen request, and receives the O→T frames the
    //!   reply's sockaddr item points at.
    //!
    //! **No test sleeps for a fixed span.** Every wait is either a bounded `tokio::time::timeout` on a
    //! real event or a retry loop with an attempt cap, so a slow scheduler makes a test slower, never
    //! red.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use enip::{
        Command, Cpf, CpfItem, EncapFrame, EncapHeader, ItemType, NetworkConnectionParams,
        SequencedAddress, SockAddrInfo,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use serde_json::json;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    use crate::config::GlobalConfig;
    use crate::device::Quality;

    /// `Get_Attribute_Single` (§7.5) — the service the posture reads ride.
    const GET_ATTRIBUTE_SINGLE: u8 = enip::cip::services::SERVICE_GET_ATTRIBUTE_SINGLE;

    // ---- config fixtures -------------------------------------------------------------------------

    fn timeouts() -> Timeouts {
        timeouts_of(2000)
    }

    /// The shipped `connectMs` with a caller-chosen `requestTimeoutMs` — which is also the bound on a
    /// push write's staging confirmation (D-EIP-31), so a test that must observe that bound elapse
    /// shortens it rather than waiting out the 2 s default.
    fn timeouts_of(request_timeout_ms: u64) -> Timeouts {
        GlobalConfig::from_value(&json!({
            "timeouts": { "connectMs": 4000, "requestTimeoutMs": request_timeout_ms }
        }))
        .unwrap()
        .timeouts
    }

    fn conn_of(v: serde_json::Value) -> ConnectionConfig {
        serde_json::from_value(v).unwrap()
    }

    /// The push `io` block used by the class-1 tests: an 8-byte T→O input (UDINT + REAL) and a 4-byte
    /// O→T output (one REAL). `rpiMs`/`o2tRpiMs` differ on purpose so the two `DirectionSpec`s cannot
    /// be confused for one another.
    fn io_of(rpi_ms: u64, o2t_rpi_ms: u64, multiplier: u32) -> IoConfig {
        serde_json::from_value(json!({
            "rpiMs": rpi_ms,
            "o2tRpiMs": o2t_rpi_ms,
            "timeoutMultiplier": multiplier,
            "assemblies": { "config": 151, "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 8,
                "realTimeFormat": "modeless",
                "signals": [
                    { "name": "din-word", "offset": 0, "type": "udint" },
                    { "name": "line-speed", "offset": 4, "type": "real" }
                ]
            },
            "output": {
                "sizeBytes": 4,
                "realTimeFormat": "header32",
                "signals": [ { "name": "setpoint", "offset": 0, "type": "real" } ]
            }
        }))
        .unwrap()
    }

    /// An 8-byte T→O input assembly: UDINT `din` at offset 0, REAL `speed` at offset 4.
    fn input_frame(din: u32, speed: f32) -> Vec<u8> {
        let mut v = din.to_le_bytes().to_vec();
        v.extend_from_slice(&speed.to_le_bytes());
        v
    }

    /// A whole class-1 T→O datagram (CPF: sequenced address + connected data) for `cid`, carrying a
    /// modeless frame (`[u16 sequence][data]`).
    fn t2o_datagram(cid: u32, encap_seq: u32, sequence: u16, data: &[u8]) -> Vec<u8> {
        let mut payload = sequence.to_le_bytes().to_vec();
        payload.extend_from_slice(data);
        Cpf::from_items(vec![
            CpfItem::new(
                ItemType::SequencedAddress,
                SequencedAddress {
                    connection_id: cid,
                    encap_sequence: encap_seq,
                }
                .encode(),
            ),
            CpfItem::connected_data(Bytes::from(payload)),
        ])
        .encode()
        .unwrap()
        .to_vec()
    }

    // ---- the scripted peer -----------------------------------------------------------------------

    /// What [`MockPlc`] answers. Every field is a *script*, never a timing knob. The default is a
    /// generic CIP device: no security objects, a ForwardOpen it accepts, no O→T redirect.
    #[derive(Clone, Default)]
    struct PlcScript {
        /// The CIP Security Object state (0x5D/1/1) the target reports. `None` ⇒ a generic CIP device
        /// that refuses every posture read with `0x05 path destination unknown`.
        posture_state: Option<u8>,
        /// CIP general status for the ForwardOpen reply (`0x00` = success).
        forward_open_status: u8,
        /// The UDP port named in the reply's O→T sockaddr item — the test's class-1 target socket.
        /// `sin_addr` is always `0.0.0.0`, so only the port is honoured (D-ENIP-17).
        o2t_port: Option<u16>,
        /// Actual packet intervals (µs) the reply names. `None` echoes the requested RPIs back, the
        /// way a well-behaved target does.
        apis_us: Option<(u32, u32)>,
        /// Answer RegisterSession with session handle `0` — a protocol violation the client refuses.
        bad_register: bool,
        /// Accept the TCP connection and hang up without answering anything.
        hang_up: bool,
        /// Answer RegisterSession, then hang up — the session opens and the very next request (the
        /// Phase-2a posture read) dies at the connection level.
        drop_after_register: bool,
        /// Speak TLS on the accepted socket (the CIP Security explicit path).
        tls: Option<Arc<rustls::ServerConfig>>,
    }

    impl PlcScript {
        /// A device implementing the CIP Security objects, reporting `state`.
        fn with_posture(mut self, state: u8) -> Self {
            self.posture_state = Some(state);
            self
        }
        /// A class-1 target that points its O→T stream at `port` (the test's UDP socket).
        fn with_io_target(mut self, port: u16) -> Self {
            self.o2t_port = Some(port);
            self
        }
        fn refusing_forward_open(mut self, status: u8) -> Self {
            self.forward_open_status = status;
            self
        }
    }

    /// The decoded class-1 ForwardOpen request the peer received (§8.2 field order).
    #[derive(Clone, Debug)]
    struct OpenRecord {
        service: u8,
        t2o_cid: u32,
        connection_serial: u16,
        vendor_id: u16,
        originator_serial: u32,
        timeout_multiplier_code: u8,
        o2t_rpi_us: u32,
        o2t_params: u16,
        t2o_rpi_us: u32,
        t2o_params: u16,
        transport_class_trigger: u8,
        connection_path: Vec<u8>,
        /// The UDP port the originator advertised for T→O frames (the request's `SockAddrTtoO` item).
        advertised_port: u16,
    }

    impl OpenRecord {
        fn parse(service: u8, data: &[u8], request_cpf: &Cpf) -> Option<Self> {
            fn u16at(data: &[u8], i: usize) -> Option<u16> {
                Some(u16::from_le_bytes([*data.get(i)?, *data.get(i + 1)?]))
            }
            fn u32at(data: &[u8], i: usize) -> Option<u32> {
                Some(u32::from_le_bytes([
                    *data.get(i)?,
                    *data.get(i + 1)?,
                    *data.get(i + 2)?,
                    *data.get(i + 3)?,
                ]))
            }
            let u16at = |i: usize| u16at(data, i);
            let u32at = |i: usize| u32at(data, i);
            let path_words = usize::from(*data.get(35)?);
            let advertised_port = request_cpf
                .find(ItemType::SockAddrTtoO)
                .and_then(|i| SockAddrInfo::decode(&i.data).ok())
                .map_or(0, |s| s.sin_port);
            Some(Self {
                service,
                t2o_cid: u32at(6)?,
                connection_serial: u16at(10)?,
                vendor_id: u16at(12)?,
                originator_serial: u32at(14)?,
                timeout_multiplier_code: *data.get(18)?,
                o2t_rpi_us: u32at(22)?,
                o2t_params: u16at(26)?,
                t2o_rpi_us: u32at(28)?,
                t2o_params: u16at(32)?,
                transport_class_trigger: *data.get(34)?,
                connection_path: data.get(36..36 + path_words * 2)?.to_vec(),
                advertised_port,
            })
        }
    }

    /// Everything the peer observed, readable from the test.
    #[derive(Clone, Default)]
    struct PlcLog {
        /// `(class, instance, attribute)` of every `Get_Attribute_Single` asked for.
        attribute_reads: Vec<(u16, u16, u16)>,
        /// Every CIP service code the peer answered, in order.
        services: Vec<u8>,
        /// The decoded class-1 ForwardOpen, once one arrives.
        open: Option<OpenRecord>,
        /// Whether the client sent UnRegisterSession.
        unregistered: bool,
        /// Whether the encapsulation session has ended at the peer — `serve` returned, because the
        /// stream yielded EOF (the originator's TCP socket was dropped) or the client unregistered.
        /// This is how a test observes that the adapter really let go of the transport, rather than
        /// inferring it from a `close()` that returned.
        disconnected: bool,
    }

    /// A scripted EtherNet/IP peer on `127.0.0.1:0`.
    struct MockPlc {
        addr: SocketAddr,
        log: Arc<Mutex<PlcLog>>,
        task: JoinHandle<()>,
    }

    impl Drop for MockPlc {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl MockPlc {
        async fn start(script: PlcScript) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let log = Arc::new(Mutex::new(PlcLog::default()));
            let task_log = Arc::clone(&log);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((tcp, _peer)) = listener.accept().await else {
                        return;
                    };
                    if script.hang_up {
                        drop(tcp);
                        continue;
                    }
                    match script.tls.clone() {
                        Some(cfg) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                            if let Ok(tls) = acceptor.accept(tcp).await {
                                serve(tls, &script, &task_log).await;
                            }
                        }
                        None => serve(tcp, &script, &task_log).await,
                    }
                    // `serve` returns only when the encapsulation session is over — every one of its
                    // exits is either EOF on the stream or an UnRegisterSession.
                    task_log.lock().unwrap().disconnected = true;
                }
            });
            Self { addr, log, task }
        }

        /// The `host:port` the adapter's `connection.endpoint` points at.
        fn endpoint(&self) -> String {
            self.addr.to_string()
        }

        fn log(&self) -> PlcLog {
            self.log.lock().unwrap().clone()
        }

        /// The `127.0.0.1:<port>` the originator advertised for T→O frames — where the test's UDP
        /// socket must produce.
        fn t2o_target(&self) -> SocketAddr {
            let port = self
                .log()
                .open
                .expect("a ForwardOpen was recorded")
                .advertised_port;
            assert_ne!(
                port, 0,
                "the ForwardOpen must advertise the originator's UDP receive port"
            );
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }

        /// The T→O connection id the target was told to stamp on the frames it produces.
        fn t2o_cid(&self) -> u32 {
            self.log().open.expect("a ForwardOpen was recorded").t2o_cid
        }

        /// Block until the peer records that the encapsulation session ended — the only way a test
        /// can tell that the originator really let go of the TCP transport, as opposed to a `close()`
        /// that merely returned. A bounded retry on a fact the peer writes, never a fixed sleep: a
        /// slow scheduler makes this slower, not red.
        async fn await_disconnect(&self, what: &str) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !self.log().disconnected {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{what}: the peer never saw the originator release the TCP session — something \
                     is still holding it"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Option<EncapFrame> {
        let mut header = [0u8; 24];
        s.read_exact(&mut header).await.ok()?;
        let h = EncapHeader::decode(&header).ok()?;
        let mut data = vec![0u8; h.length as usize];
        if !data.is_empty() {
            s.read_exact(&mut data).await.ok()?;
        }
        let mut whole = header.to_vec();
        whole.extend_from_slice(&data);
        EncapFrame::decode(&whole).ok()
    }

    async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, frame: &EncapFrame) -> Option<()> {
        let bytes = frame.encode().ok()?;
        s.write_all(&bytes).await.ok()?;
        s.flush().await.ok()
    }

    /// A Message-Router reply: `reply_service, reserved, status, ext_words(0), data`.
    fn mr_reply(service: u8, status: u8, data: &[u8]) -> Bytes {
        let mut v = vec![service | 0x80, 0x00, status, 0x00];
        v.extend_from_slice(data);
        Bytes::from(v)
    }

    /// Wrap a Message-Router reply in the `SendRRData` frame the client expects. The correlation
    /// context **and the session handle** are echoed from the request: the session actor discards a
    /// reply whose handle does not match the one it registered (§10.3).
    fn rr_frame(request: &EncapFrame, mr: Bytes, extra: Vec<CpfItem>) -> EncapFrame {
        let mut items = vec![CpfItem::null_address(), CpfItem::unconnected_data(mr)];
        items.extend(extra);
        let cpf = Cpf::from_items(items).encode().unwrap();
        let mut data = Vec::with_capacity(6 + cpf.len());
        data.extend_from_slice(&0u32.to_le_bytes()); // interface handle
        data.extend_from_slice(&0u16.to_le_bytes()); // timeout
        data.extend_from_slice(&cpf);
        EncapFrame::new(
            EncapHeader::request(
                Command::SendRRData,
                0,
                request.header.session_handle,
                request.header.sender_context,
            ),
            Bytes::from(data),
        )
    }

    /// The `(class, instance, attribute)` a `Get_Attribute_Single` EPATH addresses.
    fn parse_attr_path(path: &[u8]) -> (u16, u16, u16) {
        let (mut class, mut instance, mut attribute) = (0u16, 0u16, 0u16);
        let mut i = 0usize;
        while i < path.len() {
            match path[i] {
                0x20 => {
                    class = u16::from(path[i + 1]);
                    i += 2;
                }
                0x21 => {
                    class = u16::from_le_bytes([path[i + 2], path[i + 3]]);
                    i += 4;
                }
                0x24 => {
                    instance = u16::from(path[i + 1]);
                    i += 2;
                }
                0x25 => {
                    instance = u16::from_le_bytes([path[i + 2], path[i + 3]]);
                    i += 4;
                }
                0x30 => {
                    attribute = u16::from(path[i + 1]);
                    i += 2;
                }
                0x31 => {
                    attribute = u16::from_le_bytes([path[i + 2], path[i + 3]]);
                    i += 4;
                }
                other => panic!("unexpected EPATH segment 0x{other:02X}"),
            }
        }
        (class, instance, attribute)
    }

    /// The attribute bytes a CIP-Security-capable target answers, or `None` to refuse the read (which
    /// is what a generic CIP device does for every one of them).
    fn posture_attribute(state: u8, class: u16, instance: u16, attribute: u16) -> Option<Vec<u8>> {
        Some(match (class, instance, attribute) {
            // CIP Security Object (0x5D): state + supported/configured profile bitmaps.
            (0x5D, 1, 1) => vec![state],
            (0x5D, 1, 2) => 0x0003u16.to_le_bytes().to_vec(), // Integrity | Confidentiality
            (0x5D, 1, 3) => 0x0002u16.to_le_bytes().to_vec(), // Confidentiality
            // EtherNet/IP Security Object (0x5E).
            (0x5E, 1, 1) => vec![2],
            (0x5E, 1, 2) => 0x0000_0001u32.to_le_bytes().to_vec(),
            (0x5E, 1, 3) => vec![2, 0xC0, 0x2B, 0x13, 0x01], // available: ECDHE-GCM + TLS1.3
            (0x5E, 1, 4) => vec![1, 0xC0, 0x2B],             // allowed: ECDHE-GCM only
            (0x5E, 1, 9) => vec![1],                         // verifyClientCertificate
            (0x5E, 1, 10) => vec![1],                        // sendCertificateChain
            (0x5E, 1, 11) => vec![0],                        // checkExpiration
            // Certificate Management Object (0x5F).
            (0x5F, 0, 8) => 0x0000_0003u32.to_le_bytes().to_vec(), // push + pull
            (0x5F, 1, 1) => {
                let name = b"device-cert";
                let mut v = vec![name.len() as u8];
                v.extend_from_slice(name);
                v
            }
            (0x5F, 1, 2) => vec![3], // Verified
            (0x5F, 1, 5) => vec![0], // PEM
            _ => return None,
        })
    }

    /// The ForwardOpen success reply body (§8.2) — the same shape `enip`'s own `io.rs` fixture crafts.
    fn forward_open_success(rec: &OpenRecord, script: &PlcScript) -> (Vec<u8>, Vec<CpfItem>) {
        let (o2t_api, t2o_api) = script.apis_us.unwrap_or((rec.o2t_rpi_us, rec.t2o_rpi_us));
        let mut w = Vec::new();
        w.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes()); // O→T id: target-assigned
        w.extend_from_slice(&rec.t2o_cid.to_le_bytes());
        w.extend_from_slice(&rec.connection_serial.to_le_bytes());
        w.extend_from_slice(&rec.vendor_id.to_le_bytes());
        w.extend_from_slice(&rec.originator_serial.to_le_bytes());
        w.extend_from_slice(&o2t_api.to_le_bytes());
        w.extend_from_slice(&t2o_api.to_le_bytes());
        w.push(0); // application reply words
        w.push(0); // reserved
        let extra = script
            .o2t_port
            .map(|port| {
                vec![CpfItem::new(
                    ItemType::SockAddrOtoT,
                    SockAddrInfo::ipv4(0, port).encode(),
                )]
            })
            .unwrap_or_default();
        (w, extra)
    }

    /// Answer one `SendRRData`. `None` ends the connection (a request the script has no answer for).
    fn answer_rr(
        frame: &EncapFrame,
        script: &PlcScript,
        log: &Arc<Mutex<PlcLog>>,
    ) -> Option<EncapFrame> {
        let cpf = Cpf::decode(frame.data.get(6..)?).ok()?;
        let mr = cpf.find(ItemType::UnconnectedData)?.data.clone();
        let service = *mr.first()?;
        let path_end = 2 + usize::from(*mr.get(1)?) * 2;
        let path = mr.get(2..path_end)?.to_vec();
        let data = mr.get(path_end..)?.to_vec();
        log.lock().unwrap().services.push(service);

        let (status, body, extra) = match service {
            enip::cm::service::FORWARD_OPEN | enip::cm::service::LARGE_FORWARD_OPEN => {
                let rec = OpenRecord::parse(service, &data, &cpf)?;
                let answer = if script.forward_open_status == 0 {
                    let (body, extra) = forward_open_success(&rec, script);
                    (0u8, body, extra)
                } else {
                    // A refusal carries the ForwardRequestFail body: remaining path size + reserved.
                    (script.forward_open_status, vec![0u8, 0u8], Vec::new())
                };
                log.lock().unwrap().open = Some(rec);
                answer
            }
            enip::cm::service::FORWARD_CLOSE => {
                // §8.8 success reply: connection serial, vendor id, originator serial, echoed back.
                let mut w = Vec::new();
                w.extend_from_slice(data.get(2..10)?);
                w.push(0); // application reply words
                w.push(0); // reserved
                (0u8, w, Vec::new())
            }
            GET_ATTRIBUTE_SINGLE => {
                let (class, instance, attribute) = parse_attr_path(&path);
                log.lock()
                    .unwrap()
                    .attribute_reads
                    .push((class, instance, attribute));
                match script
                    .posture_state
                    .and_then(|s| posture_attribute(s, class, instance, attribute))
                {
                    Some(bytes) => (0u8, bytes, Vec::new()),
                    // 0x05 path destination unknown — what a device without the object answers.
                    None => (0x05u8, Vec::new(), Vec::new()),
                }
            }
            // 0x08 service not supported.
            _ => (0x08u8, Vec::new(), Vec::new()),
        };
        Some(rr_frame(frame, mr_reply(service, status, &body), extra))
    }

    /// Serve one encapsulation session (plaintext or inside TLS — the byte stream is all that differs).
    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        mut s: S,
        script: &PlcScript,
        log: &Arc<Mutex<PlcLog>>,
    ) {
        let Some(reg) = read_frame(&mut s).await else {
            return;
        };
        if !matches!(reg.header.command, Command::RegisterSession) {
            return;
        }
        let handle = if script.bad_register { 0 } else { 0x1234_5678 };
        let reply = EncapFrame::new(
            EncapHeader::request(
                Command::RegisterSession,
                0,
                handle,
                reg.header.sender_context,
            ),
            Bytes::from(vec![1, 0, 0, 0]), // protocol version 1, options 0
        );
        if write_frame(&mut s, &reply).await.is_none() || script.drop_after_register {
            return;
        }

        loop {
            let Some(frame) = read_frame(&mut s).await else {
                return;
            };
            match frame.header.command {
                Command::SendRRData => {
                    let Some(reply) = answer_rr(&frame, script, log) else {
                        return;
                    };
                    if write_frame(&mut s, &reply).await.is_none() {
                        return;
                    }
                }
                Command::UnRegisterSession => {
                    log.lock().unwrap().unregistered = true;
                    return;
                }
                _ => return,
            }
        }
    }

    // ---- throwaway PKI for the TLS arm -----------------------------------------------------------

    struct TestPki {
        ca_pem: String,
        ca_der: CertificateDer<'static>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_cert_pem: String,
        client_key_pem: String,
    }

    /// Mint a CA, a server leaf (CN `mock-plc`, IP SAN `127.0.0.1`) and a client identity — in memory,
    /// pure Rust, nothing on disk but the tempdir the adapter reads its PEMs from.
    fn mint_pki() -> TestPki {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose, SanType,
        };
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "eip local-socket test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut sp = CertificateParams::new(vec![]).unwrap();
        sp.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        sp.distinguished_name.push(DnType::CommonName, "mock-plc");
        let server_key = KeyPair::generate().unwrap();
        let server_cert = sp.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        let mut cp = CertificateParams::new(vec![]).unwrap();
        cp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        cp.distinguished_name
            .push(DnType::CommonName, "eip-originator");
        let client_key = KeyPair::generate().unwrap();
        let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            server_chain: vec![server_cert.der().clone()],
            server_key: PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    impl TestPki {
        /// A mutual-TLS server config: the device leaf, and a client verifier over the same CA — so
        /// the handshake only completes if the adapter really presented its client certificate.
        fn server_config(&self) -> Arc<rustls::ServerConfig> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut client_roots = rustls::RootCertStore::empty();
            client_roots.add(self.ca_der.clone()).unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_roots),
                provider.clone(),
            )
            .build()
            .unwrap();
            Arc::new(
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(self.server_chain.clone(), self.server_key.clone_key())
                    .unwrap(),
            )
        }
    }

    // ---- WARN capture ----------------------------------------------------------------------------

    /// A `tracing` subscriber that records WARN-level event messages on the current thread, so the
    /// §4.1 unprovisioned-device warning is asserted as a fact rather than assumed.
    #[derive(Clone, Default)]
    struct WarnLog(Arc<Mutex<Vec<String>>>);

    impl WarnLog {
        fn contains(&self, needle: &str) -> bool {
            self.0.lock().unwrap().iter().any(|m| m.contains(needle))
        }
        fn is_empty(&self) -> bool {
            self.0.lock().unwrap().is_empty()
        }
    }

    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for WarnLog {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            *meta.level() <= tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() > tracing::Level::WARN {
                return;
            }
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    // ---- shared drivers --------------------------------------------------------------------------

    /// Produce T→O frames from `peer` until the seam reports `Up`, returning the negotiated APIs and
    /// the sequence that got there. Deliberately a bounded retry, not a sleep: a datagram that lands
    /// before the connection is registered is dropped as unknown and nothing redelivers it, and that
    /// ordering is not part of the contract under test.
    async fn drive_up(
        session: &mut dyn PushSession,
        peer: &UdpSocket,
        target: SocketAddr,
        cid: u32,
        data: &[u8],
    ) -> (u32, u32, u16) {
        let mut seq: u16 = 0;
        loop {
            seq += 1;
            assert!(
                seq <= 60,
                "the seam never reported Up after {seq} T→O frames — the ForwardOpen did not arm the \
                 connection, or the translator is not running"
            );
            peer.send_to(&t2o_datagram(cid, u32::from(seq), seq, data), target)
                .await
                .unwrap();
            match tokio::time::timeout(Duration::from_millis(25), session.updates().recv()).await {
                Ok(Some(IoUpdate::Up {
                    o2t_api_ms,
                    t2o_api_ms,
                })) => return (o2t_api_ms, t2o_api_ms, seq),
                Ok(other) => panic!("expected Up as the first seam update, got {other:?}"),
                Err(_elapsed) => {}
            }
        }
    }

    /// The next `Data` update, or a panic naming what arrived instead.
    async fn next_data(session: &mut dyn PushSession) -> (Vec<crate::device::Reading>, u16, bool) {
        match tokio::time::timeout(Duration::from_secs(5), session.updates().recv()).await {
            Ok(Some(IoUpdate::Data {
                readings,
                sequence,
                run_mode,
                ..
            })) => (readings, sequence, run_mode),
            other => panic!("expected a Data update, got {other:?}"),
        }
    }

    /// A push session against a fresh scripted target: the peer socket the class-1 traffic flows
    /// over, the peer itself (for its request log), and the open session.
    async fn open_push_session(io: &IoConfig) -> (MockPlc, UdpSocket, Box<dyn PushSession>) {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = peer.local_addr().unwrap().port();
        let plc = MockPlc::start(PlcScript::default().with_io_target(port)).await;
        let backend = EipBackend::new(timeouts());
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        let session = backend.open_push(&conn, io).await.unwrap();
        (plc, peer, session)
    }

    /// The same thing unboxed: the tests that inject a close cap need the concrete session's
    /// inherent [`EipPushSession::close_with_cap`], which the trait object does not expose.
    async fn open_concrete_push_session(
        io: &IoConfig,
        timeouts: &Timeouts,
    ) -> (MockPlc, UdpSocket, EipPushSession) {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = peer.local_addr().unwrap().port();
        let plc = MockPlc::start(PlcScript::default().with_io_target(port)).await;
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        let session = EipPushSession::open(&conn, io, timeouts, VENDOR_ID)
            .await
            .unwrap();
        (plc, peer, session)
    }

    /// A live class-1 connection with **no translator**: the test owns the `IoConnectionHandle`, the
    /// client and the I/O manager, so it can drive the manager's own staging verdicts — and the
    /// disposition consult that reads them — directly, instead of through a `tokio::select!` whose
    /// branch order is deliberately random. Everything else is the production path: the same
    /// `io_spec`, the same `client_options`, the same `forward_open`.
    async fn open_bare_connection(
        io: &IoConfig,
    ) -> (
        MockPlc,
        UdpSocket,
        enip::EipClient,
        enip::IoManager,
        enip::IoConnectionHandle,
    ) {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = peer.local_addr().unwrap().port();
        let plc = MockPlc::start(PlcScript::default().with_io_target(port)).await;
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        let spec = io_spec(&conn, io, VENDOR_ID).unwrap();
        let client = enip::EipClient::connect(&conn.endpoint, client_options(&conn, &timeouts()))
            .await
            .unwrap();
        let manager = enip::IoManager::bind("0.0.0.0:0").await.unwrap();
        let handle = manager.forward_open(&client, spec).await.unwrap();
        (plc, peer, client, manager, handle)
    }

    /// The 4-byte O→T buffer the staging tests offer — a valid `setpoint` for [`io_of`]'s output
    /// assembly, so a refusal is always about the connection and never about the buffer.
    fn out_buf() -> Vec<u8> {
        12.5f32.to_le_bytes().to_vec()
    }

    /// Wedge the translator on a **full** seam update channel (16 slots) by producing T→O frames the
    /// test never consumes, and return once it is parked in `updates_tx.send`.
    ///
    /// Frames go one at a time, each confirmed through [`PushSession::last_input`] — the snapshot the
    /// translator writes immediately *before* it offers the update — so the frames are consumed one
    /// per loop iteration instead of being collapsed latest-wins into a single update. The first
    /// frame whose snapshot never lands is the causal signal that the translator stopped consuming:
    /// it is blocked offering the previous one. Everything is bounded; nothing races two timers.
    async fn wedge_translator(
        session: &EipPushSession,
        peer: &UdpSocket,
        target: SocketAddr,
        cid: u32,
    ) {
        for frame in 1..=40u16 {
            peer.send_to(
                &t2o_datagram(
                    cid,
                    u32::from(frame),
                    frame,
                    &input_frame(u32::from(frame), 0.0),
                ),
                target,
            )
            .await
            .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            let mut consumed = false;
            while tokio::time::Instant::now() < deadline {
                let landed = session.last_input().is_some_and(|s| {
                    s.readings
                        .first()
                        .is_some_and(|r| r.value == json!(u32::from(frame)))
                });
                if landed {
                    consumed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            if !consumed {
                return;
            }
        }
        panic!(
            "the translator consumed 40 unread frames without parking — the 16-slot update channel \
             did not fill, so this test would not be exercising a blocked translator"
        );
    }

    // ==== connect (poll) ==========================================================================

    /// A generic CIP device implements none of the 0x5D/0x5E/0x5F objects, so the Phase-2a posture
    /// read comes back refused — and `connect` must *still* succeed, handing back a bare plaintext
    /// session. A regression that let the refusal fail the connect would take every non-CIP-Security
    /// device offline.
    #[tokio::test]
    async fn connect_plaintext_without_posture_yields_a_bare_session() {
        let plc = MockPlc::start(PlcScript::default()).await;
        let backend = EipBackend::new(timeouts());
        assert_eq!(backend.kind(), "ethernet-ip");
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));

        let mut session = backend.connect(&conn).await.unwrap();
        assert!(
            session.security().is_none(),
            "no posture ⇒ the bare `EipSession::new` arm, reported as `{{\"mode\":\"plaintext\"}}`"
        );

        // Every object was probed and every refusal swallowed — the session survived all three, which
        // is what distinguishes "the device has no posture" from "the posture read broke the link".
        let reads = plc.log().attribute_reads;
        for probe in [(0x5D, 1, 1), (0x5E, 1, 1), (0x5F, 0, 8)] {
            assert!(
                reads.contains(&probe),
                "connect probes {probe:?}: {reads:?}"
            );
        }
        session.close().await;

        // The posture is a diagnostic surface, not a liveness gate: a read that dies at the
        // *connection* level is swallowed the same way, so a link hiccup during the probe can never
        // turn a reachable device into a failed connect.
        let plc = MockPlc::start(PlcScript {
            drop_after_register: true,
            ..PlcScript::default()
        })
        .await;
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        let session = backend.connect(&conn).await.unwrap();
        assert!(
            session.security().is_none(),
            "a broken posture read is swallowed, not surfaced"
        );
    }

    /// A CIP Security device's posture is decoded onto the seam type field for field, and a device
    /// found in `Factory Default` while being polled gets the §4.1 WARN — an unprovisioned device on
    /// a secured path is exactly the condition an operator must see.
    #[tokio::test]
    async fn connect_plaintext_with_posture_yields_secure_session_and_warns_on_factory_default() {
        let plc = MockPlc::start(PlcScript::default().with_posture(0)).await; // 0 = Factory Default
        let backend = EipBackend::new(timeouts());
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));

        let warns = WarnLog::default();
        let session = {
            let _guard = tracing::subscriber::set_default(warns.clone());
            backend.connect(&conn).await.unwrap()
        };

        let sec = session
            .security()
            .expect("a posture-carrying session reports security");
        assert!(
            !sec.tls,
            "the session is plaintext; only the target's posture was read"
        );
        let target = sec.target.expect("the target's posture");
        assert_eq!(target.state.as_deref(), Some("Factory Default"));
        assert_eq!(
            target.profiles,
            vec!["EtherNet/IP Integrity", "EtherNet/IP Confidentiality"]
        );
        assert_eq!(
            target.allowed_cipher_suites,
            vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]
        );
        assert_eq!(
            target.available_cipher_suites,
            vec![
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_AES_128_GCM_SHA256"
            ]
        );
        assert_eq!(target.verify_client, Some(true));
        assert_eq!(target.send_certificate_chain, Some(true));
        assert_eq!(target.check_expiration, Some(false));
        let cert = target
            .certificate
            .expect("the Certificate Management summary");
        assert_eq!(cert.name.as_deref(), Some("device-cert"));
        assert_eq!(cert.state.as_deref(), Some("Verified"));
        assert_eq!(cert.encoding.as_deref(), Some("PEM"));
        assert_eq!(cert.push_supported, Some(true));
        assert_eq!(cert.pull_supported, Some(true));
        assert!(
            warns.contains("Factory Default"),
            "an unprovisioned device must be warned about: {:?}",
            warns.0.lock().unwrap()
        );

        // The other polarity: a provisioned device reports the same surface without the warning.
        let plc = MockPlc::start(PlcScript::default().with_posture(2)).await; // 2 = Configured
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        let quiet = WarnLog::default();
        let session = {
            let _guard = tracing::subscriber::set_default(quiet.clone());
            backend.connect(&conn).await.unwrap()
        };
        let target = session.security().unwrap().target.unwrap();
        assert_eq!(target.state.as_deref(), Some("Configured"));
        assert!(quiet.is_empty(), "a provisioned device is not warned about");
    }

    /// The §10.1 classification on the open edge, both polarities and both entry points: a link that
    /// dies is `Transient` (reconnect), a peer that breaks the protocol shape is `Permanent` (back off
    /// at the ceiling rather than hammer a misconfiguration).
    #[tokio::test]
    async fn connect_refusal_maps_via_map_enip_error() {
        let backend = EipBackend::new(timeouts());

        // A peer that accepts the TCP connection and hangs up: a link-level failure ⇒ retry.
        let plc = MockPlc::start(PlcScript {
            hang_up: true,
            ..PlcScript::default()
        })
        .await;
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        match backend.connect(&conn).await.map(|_| ()) {
            Err(DeviceError::Transient(_)) => {}
            other => panic!("a dropped session must be transient, got {other:?}"),
        }

        // A peer that answers RegisterSession with session handle 0 — a protocol violation that will
        // repeat forever, so it must NOT be retried as if it were a hiccup.
        let plc = MockPlc::start(PlcScript {
            bad_register: true,
            ..PlcScript::default()
        })
        .await;
        let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
        match backend.connect(&conn).await.map(|_| ()) {
            Err(DeviceError::Permanent(_)) => {}
            other => panic!("a protocol violation must be permanent, got {other:?}"),
        }

        // The same table on the class-1 edge: a ForwardOpen refused for a resource reason is
        // transient, one refused as unsupported is permanent.
        let io = io_of(500, 20, 16);
        for (status, transient) in [(0x02u8, true), (0x08u8, false)] {
            let plc = MockPlc::start(PlcScript::default().refusing_forward_open(status)).await;
            let conn = conn_of(json!({ "endpoint": plc.endpoint() }));
            let outcome = backend.open_push(&conn, &io).await.map(|_| ());
            match (&outcome, transient) {
                (Err(DeviceError::Transient(_)), true)
                | (Err(DeviceError::Permanent(_)), false) => {}
                _ => panic!("forward-open status 0x{status:02X}: unexpected {outcome:?}"),
            }
        }
    }

    /// The CIP Security explicit path end to end over a loopback socket: the adapter builds its
    /// `ClientConfig` from file-sourced PEMs, negotiates mutual TLS against the scripted device (whose
    /// verifier rejects a client that does not present a certificate), reads the target's posture
    /// *inside* the TLS session, and reports the negotiated facts on the seam.
    #[tokio::test]
    async fn connect_tls_negotiates_and_reports_security_status() {
        let pki = mint_pki();
        let dir = tempfile::tempdir().unwrap();
        let cert_file = dir.path().join("client.pem");
        let key_file = dir.path().join("client.key");
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&cert_file, &pki.client_cert_pem).unwrap();
        std::fs::write(&key_file, &pki.client_key_pem).unwrap();
        std::fs::write(&ca_file, &pki.ca_pem).unwrap();

        let script = PlcScript {
            tls: Some(pki.server_config()),
            ..PlcScript::default()
        }
        .with_posture(2);
        let plc = MockPlc::start(script).await;
        let backend = EipBackend::new(timeouts());
        let conn = conn_of(json!({
            "endpoint": plc.endpoint(),
            "security": {
                "mode": "tls",
                "client": {
                    "certFile": cert_file.to_string_lossy(),
                    "keyFile": key_file.to_string_lossy()
                },
                "ca": { "file": ca_file.to_string_lossy() }
            }
        }));

        let session = backend.connect(&conn).await.unwrap();
        let sec = session
            .security()
            .expect("a TLS session reports its posture");
        assert!(sec.tls);
        assert_eq!(sec.tls_version.as_deref(), Some("1.3"));
        let suite = sec.cipher_suite.expect("a negotiated suite");
        assert!(suite.starts_with("TLS13_"), "negotiated suite: {suite}");
        assert!(
            sec.peer_verified,
            "verifyPeer defaults on and the chain verified"
        );
        assert!(
            sec.peer.as_deref().unwrap_or_default().contains("mock-plc"),
            "the peer identity is the device certificate subject: {:?}",
            sec.peer
        );
        assert!(
            sec.client_cert_not_after.is_some(),
            "our own leaf's expiry is surfaced"
        );
        assert!(sec.client_cert_serial.is_some());
        assert!(
            sec.client_cert_expiry_days.unwrap_or(-1) >= 0,
            "a freshly minted client cert is not expired"
        );
        assert_eq!(
            sec.trust_anchors.len(),
            1,
            "the managed trust store holds the one root"
        );
        assert!(
            sec.target.is_some(),
            "the Phase-2a posture read runs over the TLS session too"
        );

        // Both ways the security block can be wrong are permanent — a misconfiguration must park the
        // instance at the backoff ceiling, never be retried as if the device were merely unreachable.
        // Neither of these reaches a socket: they fail before the dial.
        let malformed = conn_of(json!({ "endpoint": "127.0.0.1:1", "security": { "bogus": 1 } }));
        match backend.connect(&malformed).await.map(|_| ()) {
            Err(DeviceError::Permanent(_)) => {}
            other => panic!("a malformed security block must be permanent, got {other:?}"),
        }
        let unsourceable = conn_of(json!({
            "endpoint": "127.0.0.1:1",
            "security": {
                "mode": "tls",
                "client": {
                    "certFile": dir.path().join("absent.pem").to_string_lossy(),
                    "keyFile": dir.path().join("absent.key").to_string_lossy()
                },
                "ca": { "file": ca_file.to_string_lossy() }
            }
        }));
        match backend.connect(&unsourceable).await.map(|_| ()) {
            Err(DeviceError::Permanent(_)) => {}
            other => panic!("unsourceable TLS material must be permanent, got {other:?}"),
        }
    }

    // ==== open_push (class-1) =====================================================================

    /// The ForwardOpen the `io` block builds, and the traffic it arms. The request is asserted field
    /// for field on the peer side — assembly path, both `DirectionSpec`s, the originator identity, the
    /// advertised UDP port — and the seam's `Up`/`Data` updates on the adapter side.
    #[tokio::test]
    async fn open_push_forward_open_up_and_data_flow() {
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;

        // ---- the request the target received (§4.6 → §8.2 mapping) ----
        let open = plc.log().open.expect("the peer recorded a ForwardOpen");
        assert_eq!(
            open.service,
            enip::cm::service::FORWARD_OPEN,
            "10-byte directions are not large"
        );
        assert_eq!(open.vendor_id, VENDOR_ID);
        assert_eq!(open.transport_class_trigger, enip::TRANSPORT_CLASS1_TRIGGER);
        assert_eq!(
            open.timeout_multiplier_code,
            enip::TimeoutMultiplier::X16.code()
        );
        assert_eq!(open.t2o_rpi_us, 500_000, "rpiMs is the T→O request");
        assert_eq!(open.o2t_rpi_us, 20_000, "o2tRpiMs is the O→T request");
        assert_eq!(
            open.connection_path,
            enip::io_connection_path(Some(151), 150, 100)
                .encode()
                .unwrap()
                .to_vec(),
            "config/output/input assemblies anchor the connection path"
        );
        let t2o = NetworkConnectionParams::decode_u16(open.t2o_params);
        assert_eq!(t2o.size, 10, "modeless T→O: 2 (sequence) + 8 (data)");
        assert_eq!(t2o.conn_type, enip::ConnType::P2P);
        assert_eq!(t2o.priority, enip::Priority::Scheduled);
        assert_eq!(t2o.variable, enip::VariableLength::Fixed);
        let o2t = NetworkConnectionParams::decode_u16(open.o2t_params);
        assert_eq!(
            o2t.size, 10,
            "header32 O→T: 2 (sequence) + 4 (run/idle) + 4 (data)"
        );
        assert_eq!(
            o2t.conn_type,
            enip::ConnType::P2P,
            "O→T is always point-to-point (§4.6)"
        );
        assert_ne!(
            open.advertised_port, 0,
            "the originator advertises its own UDP receive port"
        );
        assert_eq!(
            open.advertised_port,
            plc.t2o_target().port(),
            "and that is the port the target must produce into"
        );

        // ---- the traffic ----
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        let (o2t_api_ms, t2o_api_ms, _seq) =
            drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;
        assert_eq!(
            (o2t_api_ms, t2o_api_ms),
            (20, 500),
            "the negotiated APIs from the reply reach the seam in whole milliseconds"
        );

        let (readings, _sequence, run_mode) = next_data(session.as_mut()).await;
        assert!(
            run_mode,
            "a modeless frame carries no run/idle header ⇒ Run"
        );
        assert_eq!(readings.len(), 2);
        assert_eq!(readings[0].signal_id, "a100/0/udint");
        assert_eq!(readings[0].name.as_deref(), Some("din-word"));
        assert_eq!(readings[0].value, json!(7));
        assert_eq!(readings[0].quality, Quality::Good);
        assert_eq!(readings[1].signal_id, "a100/4/real");
        assert_eq!(readings[1].value, json!(55.5));
        assert_eq!(readings[1].quality, Quality::Good);

        session.close().await;
    }

    /// The translator's latest-wins collapse (§8.6): a burst of frames the consumer never drained must
    /// come back as a handful of updates ending at the newest sequence — never as the whole burst
    /// replayed — and a lifecycle transition sitting *behind* that burst must survive it. The second
    /// half is the one that bites: the collapse loop carries a following non-`Data` event, so a `Lost`
    /// queued behind an undrained burst is delivered rather than swallowed with the samples it
    /// overtook. A swallowed `Lost` leaves the engine reading a stream that will never speak again.
    #[tokio::test]
    async fn translator_latest_wins_collapses_a_burst_and_never_drops_up_or_lost() {
        const BURST: u16 = 400;
        let io = io_of(100, 100, 8); // 100 ms T→O API × 8 = an 800 ms watchdog
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        let (_o2t, _t2o, mut seq) =
            drive_up(session.as_mut(), &peer, target, cid, &input_frame(1, 1.0)).await;

        // Fill the seam channel first, one frame per scheduler turn: a lone queued sample gives the
        // translator nothing to collapse, so each wakeup costs a channel slot and the (undrained)
        // 16-deep channel fills. The translator then parks on its send.
        let produce =
            |seq: u16| t2o_datagram(cid, u32::from(seq), seq, &input_frame(u32::from(seq), 1.0));
        for _ in 0..120u16 {
            seq += 1;
            peer.send_to(&produce(seq), target).await.unwrap();
            tokio::task::yield_now().await;
        }
        // Now the burst proper: with the translator parked these pile up in the stack's event queue,
        // which is exactly the state the collapse loop has to get right.
        while seq < BURST {
            seq += 1;
            peer.send_to(&produce(seq), target).await.unwrap();
        }

        // Now go silent until the O→T stream stops. The produce scheduler and the inactivity watchdog
        // are the same task: production ends exactly when the watchdog removes the connection, so "no
        // O→T datagram for ten produce periods" is an *event* saying the `Lost` is now queued behind
        // the undrained burst. (Not a sleep: it waits on the peer's own socket.)
        let mut buf = vec![0u8; 2048];
        loop {
            match tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => panic!("the peer socket broke: {e}"),
                Err(_elapsed) => break,
            }
        }

        let mut ups = 0usize;
        let mut sequences: Vec<u16> = Vec::new();
        let mut lost = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), session.updates().recv()).await {
                Ok(Some(IoUpdate::Up { .. })) => ups += 1,
                Ok(Some(IoUpdate::Data { sequence, .. })) => {
                    assert_eq!(lost, 0, "a sample after the loss transition");
                    sequences.push(sequence);
                }
                Ok(Some(IoUpdate::Lost { error })) => {
                    assert!(error.is_transient());
                    lost += 1;
                }
                Ok(None) => break, // the translator ended after the loss
                Err(_elapsed) => panic!("the stream neither delivered a loss nor ended"),
            }
        }

        assert_eq!(
            ups, 0,
            "the one Up was already consumed by drive_up and never re-sent"
        );
        assert_eq!(
            lost, 1,
            "the loss queued behind the burst is delivered exactly once"
        );
        assert!(!sequences.is_empty(), "the burst produced samples");
        assert!(
            sequences.windows(2).all(|w| w[1] > w[0]),
            "a collapsed burst never delivers an older sample after a newer one: {sequences:?}"
        );
        assert!(
            sequences.len() <= 64,
            "the burst must collapse: {} updates for {BURST} frames (an uncollapsed translator \
             delivers hundreds)",
            sequences.len()
        );
        assert!(
            *sequences.last().unwrap() >= BURST / 2,
            "latest-wins keeps the NEWEST sample; last delivered was {:?}",
            sequences.last()
        );
        session.close().await;
    }

    /// Two things the push `sb/read` and the `EtherNetIpIo` metric emit stand on: the snapshot stays
    /// live independently of the engine's consumption, and the stack's counters reach the seam
    /// unshuffled.
    #[tokio::test]
    async fn last_input_snapshot_stays_live_and_io_stats_map() {
        // Field for field: a mis-wired mapping here silently reports one counter as another.
        let mapped = map_io_stats(enip::IoStats {
            frames_accepted: 1,
            frames_produced: 2,
            size_mismatch: 3,
            stale_frames: 4,
            sequence_gaps: 5,
            overflowed_events: 6,
            produce_overruns: 7,
            send_errors: 8,
            recv_errors: 9,
            malformed_frames: 10,
            unknown_connection: 11,
            refused_redirects: 12,
        });
        assert_eq!(
            mapped,
            IoLinkStats {
                frames_produced: 2,
                stale_frames: 4,
                size_mismatch: 3,
                sequence_gaps: 5,
                malformed_frames: 10,
                produce_overruns: 7,
                send_errors: 8,
                recv_errors: 9,
                refused_redirects: 12,
            }
        );

        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        assert!(session.last_input().is_none(), "no frame yet ⇒ no snapshot");
        let (_o2t, _t2o, mut seq) =
            drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;
        let (readings, _sequence, _run) = next_data(session.as_mut()).await;

        let snapshot = session
            .last_input()
            .expect("the snapshot is live after the first frame");
        assert_eq!(
            snapshot.readings, readings,
            "the snapshot IS the last accepted frame"
        );
        assert!(snapshot.run_mode);

        // A duplicate sequence is dropped by the signed-window rule and counted; the counters reach
        // the seam on the translator's next wakeup, which the advancing frame provides.
        let mut stale = 0;
        for attempt in 1..=40u16 {
            peer.send_to(
                &t2o_datagram(cid, u32::from(seq) + 500, seq, &input_frame(7, 55.5)),
                target,
            )
            .await
            .unwrap();
            seq += 1;
            peer.send_to(
                &t2o_datagram(cid, u32::from(seq), seq, &input_frame(8, 66.5)),
                target,
            )
            .await
            .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(50), session.updates().recv()).await;
            stale = session
                .io_stats()
                .expect("a class-1 session has counters")
                .stale_frames;
            if stale >= 1 {
                break;
            }
            assert!(
                attempt < 40,
                "the duplicate frame was never counted as stale"
            );
        }
        assert!(
            stale >= 1,
            "the duplicate T→O frame is counted, not silently accepted"
        );
        session.close().await;
    }

    /// The output path, end to end: a coerced value is encoded into the O→T assembly buffer and rides
    /// the next produced frame — observed as bytes at the target socket, not merely staged.
    ///
    /// Since D-EIP-31 the `Ok(())` itself carries that meaning: it is the I/O manager's own verdict,
    /// relayed session ⇒ translator ⇒ manager and back, so a write cannot report success against a
    /// connection that no longer exists. The wire assertion below now *confirms* the ack rather than
    /// substituting for it.
    #[tokio::test]
    async fn set_output_encodes_and_rides_the_next_o2t_frame() {
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;

        let field = &io.output.as_ref().unwrap().signals[0];
        session.set_output(field, &json!(12.5)).await.unwrap();

        let expected = 12.5f32.to_le_bytes();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut buf = vec![0u8; 2048];
        let mut seen_o2t = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the staged output never reached the wire (saw an O→T frame: {seen_o2t})"
            );
            let Ok(Ok((n, _src))) =
                tokio::time::timeout(Duration::from_millis(500), peer.recv_from(&mut buf)).await
            else {
                continue;
            };
            let Ok(cpf) = Cpf::decode(&buf[..n]) else {
                continue;
            };
            let Some(item) = cpf.find(ItemType::ConnectedData) else {
                continue;
            };
            let frame =
                enip::IoFrame::decode(enip::RealTimeFormat::Header32Bit, &item.data).unwrap();
            seen_o2t = true;
            assert_eq!(
                frame.run_mode,
                Some(true),
                "the O→T header carries the Run bit"
            );
            if frame.data.as_ref() == expected {
                break;
            }
        }

        // The refusal arms: a field the output assembly does not declare, and a value the field's CIP
        // type cannot hold, are both caller errors — never a silent no-op.
        let bogus: IoFieldSpec =
            serde_json::from_value(json!({ "name": "nope", "offset": 2, "type": "int" })).unwrap();
        assert!(
            matches!(
                session.set_output(&bogus, &json!(1)).await,
                Err(DeviceError::Permanent(_))
            ),
            "an unknown output field is a permanent error"
        );
        assert!(
            matches!(
                session.set_output(field, &json!("not a number")).await,
                Err(DeviceError::Permanent(_))
            ),
            "a value the CIP type cannot hold is a permanent error"
        );
        // A value that encodes cleanly but does not fit the declared assembly slot is caught by the
        // layout, not written past the field: the buffer the device consumes is never corrupted.
        let oversized: IoFieldSpec = serde_json::from_value(
            json!({ "name": "setpoint", "offset": 0, "type": "real", "arrayCount": 2 }),
        )
        .unwrap();
        assert!(
            matches!(
                session.set_output(&oversized, &json!([1.0, 2.0])).await,
                Err(DeviceError::Permanent(_))
            ),
            "a value too wide for its assembly slot is refused by the layout"
        );

        // A heartbeat connection (no output assembly) refuses writes as unsupported.
        let hb: IoConfig = serde_json::from_value(json!({
            "rpiMs": 500,
            "assemblies": { "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 8,
                "signals": [ { "name": "din-word", "offset": 0, "type": "udint" } ]
            }
        }))
        .unwrap();
        let (_hb_plc, _hb_peer, mut hb_session) = open_push_session(&hb).await;
        assert!(
            matches!(
                hb_session.set_output(field, &json!(1.0)).await,
                Err(DeviceError::Unsupported(_))
            ),
            "a device with no output assembly cannot be written to"
        );
        hb_session.close().await;
        session.close().await;
    }

    /// Count the ForwardCloses a peer answered.
    fn closes(plc: &MockPlc) -> usize {
        plc.log()
            .services
            .iter()
            .filter(|&&s| s == enip::cm::service::FORWARD_CLOSE)
            .count()
    }

    /// Teardown, both ways out: the graceful close issues the ForwardClose, unregisters the session,
    /// leaves the peer disconnected, and is idempotent; and a close whose translator has already died
    /// falls back to aborting the task instead of waiting out the whole handoff cap.
    #[tokio::test]
    async fn close_performs_forward_close_and_is_safe_twice() {
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;

        session.close().await;
        assert_eq!(
            closes(&plc),
            1,
            "the graceful close tears the class-1 connection down"
        );
        // The polite path survives the abort-and-join fix (D-EIP-31): a close that gets its ack still
        // sends every courtesy frame AND ends with the transport released.
        plc.await_disconnect("a clean close").await;
        assert!(
            plc.log().unregistered,
            "the clean close unregisters the encapsulation session"
        );
        session.close().await; // must be safe to call twice
        assert_eq!(
            closes(&plc),
            1,
            "the second close is a no-op, not a second ForwardClose"
        );

        // The other exit: the link is lost, the translator task ends, and its control receiver goes
        // with it — so `close` must take the abort fallback rather than park on the 5 s handoff cap.
        let io = io_of(100, 100, 8); // an 800 ms watchdog
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;
        let mut lost = false;
        loop {
            match tokio::time::timeout(Duration::from_secs(10), session.updates().recv()).await {
                Ok(Some(IoUpdate::Lost { .. })) => lost = true,
                Ok(Some(_)) => {}
                Ok(None) => break, // the translator returned; control_rx is gone
                Err(_elapsed) => panic!("the translator never ended after the link was lost"),
            }
        }
        assert!(
            lost,
            "the seam reported the lost link before ending the stream"
        );
        tokio::time::timeout(Duration::from_secs(2), session.close())
            .await
            .expect("close falls back to aborting the task, well inside PUSH_CLOSE_HANDOFF_CAP");
    }

    /// The third exit: an engine that simply drops the handle — an outer device task aborted at the
    /// stop budget, or a panic unwinding past it. The `Drop` guard aborts the translator and its
    /// transports go with it, so a dropped session never leaves a task holding the device's sockets
    /// (D-EIP-31). Regression guard: pinned so a future edit cannot reintroduce a detached task.
    #[tokio::test]
    async fn dropping_the_session_never_leaves_the_translator_running() {
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;
        assert!(!plc.log().disconnected, "nothing has been torn down yet");

        drop(session);

        plc.await_disconnect("a dropped session").await;
    }

    /// The P1-2 hole, closed: a translator that cannot service its control channel — parked offering
    /// an update nobody is reading — used to make `close()` fall through its ack timeout and **drop
    /// the join handle**, leaving a detached task holding the TCP session and the UDP I/O manager for
    /// the life of the process. Now the overrun aborts and joins, so `close()` returning means the
    /// translator has ended and the peer sees the transport released (D-EIP-31).
    ///
    /// The cap is injected (250 ms) rather than the production 5 s — that is what `close_with_cap`
    /// exists for; `close()` itself keeps the constant and is exercised by the clean-close test.
    #[tokio::test]
    async fn close_joins_a_blocked_translator_within_the_cap() {
        // A 500 ms T→O API × 16 is an 8 s watchdog: the wedge ends this test, not a timeout.
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_concrete_push_session(&io, &timeouts()).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        wedge_translator(&session, &peer, target, cid).await;
        assert!(
            !plc.log().disconnected,
            "the wedged translator is still holding the encapsulation session"
        );

        session.close_with_cap(Duration::from_millis(250)).await;

        // Nothing polite happened — an aborted translator skips the ForwardClose, by design — but the
        // transports are gone, which is the guarantee the abort buys.
        plc.await_disconnect("a close that aborted a wedged translator")
            .await;
    }

    /// The first link of the sb/write silent-success chain: a write handed to a control channel whose
    /// receiver is gone used to report `Ok(())`. It is a transient failure — the value was never
    /// staged and no frame will ever carry it (D-EIP-31).
    #[tokio::test]
    async fn set_output_after_close_is_an_error_not_a_silent_ok() {
        let io = io_of(500, 20, 16);
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;

        // `close` joins the translator, so its control receiver is provably gone on return — pure
        // channel causality, no timer beyond the bounded ack cap inside `set_output`.
        session.close().await;

        let field = &io.output.as_ref().unwrap().signals[0];
        let verdict = session.set_output(field, &json!(12.5)).await;
        assert!(
            matches!(verdict, Err(DeviceError::Transient(_))),
            "a write to a closed push session is refused, not silently accepted: {verdict:?}"
        );
    }

    /// The second link: a translator that is alive but wedged (parked offering an update nobody
    /// reads) can accept the control message and still never stage anything. The staging ack is
    /// bounded by the operator's `requestTimeoutMs`, and the elapsed bound is a refusal — `sb/write`
    /// neither hangs nor claims a value the producer buffer never took (D-EIP-31).
    ///
    /// One timer only: the wedge is permanent for the life of the test (nothing drains `updates()`),
    /// so the ack cap is not racing anything.
    #[tokio::test]
    async fn a_write_the_wedged_translator_cannot_confirm_is_refused() {
        let io = io_of(500, 20, 16);
        // 250 ms is ample for loopback CIP and keeps the unconfirmable write's bound short.
        let (plc, peer, mut session) = open_concrete_push_session(&io, &timeouts_of(250)).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        wedge_translator(&session, &peer, target, cid).await;

        let field = &io.output.as_ref().unwrap().signals[0];
        let verdict = session.set_output(field, &json!(12.5)).await;
        assert!(
            matches!(verdict, Err(DeviceError::Transient(_))),
            "an unconfirmable write is refused, not reported staged: {verdict:?}"
        );
    }

    /// **The third link, and the one the I/O manager cannot answer on its own.** `EnipError::Closed`
    /// is one word for three situations — the manager task is gone, the connection was removed
    /// because it was *lost*, or it was removed because it was *closed* — and its `Display` is the
    /// bare string `"closed"`. Here the watchdog expires a real connection on a real socket, and the
    /// refusal that follows names the loss, because the manager delivers `Lost` on this connection's
    /// stream before it can refuse the staging (D-EIP-31).
    ///
    /// It is also `Transient`: `enip` classifies `Closed` as permanent, which `map_enip_error` would
    /// have turned into a `DeviceError::Permanent` — a lost class-1 link is precisely what the
    /// reconnect ladder recovers.
    #[tokio::test]
    async fn a_staging_refusal_after_a_loss_names_the_loss_not_just_closed() {
        let io = io_of(100, 100, 8); // 100 ms T→O API × 8 = an 800 ms watchdog
        let (plc, peer, _client, manager, mut handle) = open_bare_connection(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        // One accepted frame arms the connection (and queues `Up` + `Data`); silence is then the only
        // thing that can end it.
        peer.send_to(&t2o_datagram(cid, 1, 1, &input_frame(7, 55.5)), target)
            .await
            .unwrap();

        // Stage against the connection until the manager refuses: a bounded retry on a fact the
        // watchdog changes, never a fixed wait for it to have changed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let staged = loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the watchdog never expired the connection, so no refusal was ever produced"
            );
            let staged = stage_and_interpret(&mut handle, out_buf()).await;
            if staged.verdict.is_err() {
                break staged;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert_eq!(
            staged.lost,
            Some(enip::LostReason::Timeout),
            "the disposition is read from the connection's own stream, not guessed"
        );
        let error = staged.verdict.unwrap_err();
        assert!(
            error.is_transient(),
            "a lost class-1 connection is what the reconnect ladder recovers: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("class-1 inactivity watchdog timeout"),
            "the refusal names the device fault an operator has to act on: {error}"
        );
        // Naming the disposition cost the seam nothing: the samples the consult had to read past are
        // handed back for delivery.
        assert!(
            staged
                .drained
                .iter()
                .any(|e| matches!(e, enip::IoEvent::Data(_))),
            "the frames queued ahead of the loss are carried out of the consult, not swallowed"
        );
        manager.shutdown().await;
    }

    /// The other disposition: a connection the adapter itself took down. `Closed` looks identical to
    /// the loss above from the I/O manager's side, and reads completely differently to an operator —
    /// an orderly stop, not a device fault (D-EIP-31). Deterministic by channel FIFO: the manager
    /// processes the `Remove` `close` sends before it reads the staging command behind it.
    #[tokio::test]
    async fn a_staging_refusal_after_a_deliberate_close_says_closed() {
        let io = io_of(500, 20, 16);
        let (_plc, _peer, client, manager, mut handle) = open_bare_connection(&io).await;

        handle.close(&client).await.unwrap();
        let staged = stage_and_interpret(&mut handle, out_buf()).await;

        assert_eq!(staged.lost, None, "nothing was lost — it was closed");
        let error = staged.verdict.unwrap_err();
        assert!(
            error.is_transient(),
            "a closed class-1 connection is reopened by the ladder, not parked at the ceiling: \
             {error:?}"
        );
        let text = error.to_string();
        assert!(
            text.contains("the class-1 connection was closed"),
            "an orderly stop says so: {text}"
        );
        assert!(
            !text.contains("lost"),
            "an orderly stop is never reported as a device fault: {text}"
        );
        manager.shutdown().await;
    }

    /// The third situation behind the same word: the I/O manager task itself is gone, so the staging
    /// command is dropped unserviced. Nothing was lost, so this reads as a close too (D-EIP-31).
    #[tokio::test]
    async fn a_staging_refusal_after_the_manager_is_gone_says_closed() {
        let io = io_of(500, 20, 16);
        let (_plc, _peer, _client, manager, mut handle) = open_bare_connection(&io).await;

        manager.shutdown().await;
        let staged = stage_and_interpret(&mut handle, out_buf()).await;

        assert_eq!(staged.lost, None);
        let error = staged.verdict.unwrap_err();
        assert!(error.is_transient(), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("the class-1 connection was closed"),
            "a manager that has gone away is a stop, not a device fault: {error}"
        );
    }

    /// A buffer the negotiated O→T size cannot hold is still the caller's error, not a disposition:
    /// everything that is not `Closed` keeps going through `map_enip_error` untouched (D-EIP-31).
    #[tokio::test]
    async fn a_staging_refusal_that_is_not_closed_keeps_its_own_classification() {
        let io = io_of(500, 20, 16);
        let (_plc, _peer, _client, manager, mut handle) = open_bare_connection(&io).await;

        let staged = stage_and_interpret(&mut handle, vec![1, 2]).await;

        assert_eq!(staged.lost, None);
        let error = staged.verdict.unwrap_err();
        assert!(
            matches!(error, DeviceError::Permanent(_)),
            "a mis-sized buffer will be mis-sized again: {error:?}"
        );
        assert!(
            error.to_string().contains("output size does not match"),
            "the protocol violation is reported verbatim: {error}"
        );
        manager.shutdown().await;
    }

    /// What the consult read to name a disposition is still owed to the consumer: the samples come
    /// out latest-wins (one `Up`, the freshest `Data`) and the loss follows them, so the seam learns
    /// the connection is over from a path that never reaches the translator's event arm (D-EIP-31).
    #[tokio::test]
    async fn a_consulted_tail_is_delivered_before_the_loss_that_ended_it() {
        let io = io_of(500, 20, 16);
        let layout = io.input_layout().unwrap();
        let fields = io.input.signals.clone();
        let snapshot: SharedSnapshot = Arc::new(Mutex::new(None));
        let (tx, mut rx) = mpsc::channel(16);

        fn sample(seq: u16, data: Vec<u8>) -> enip::IoEvent {
            enip::IoEvent::Data(enip::IoUpdate {
                data: Bytes::from(data),
                sequence: seq,
                encap_sequence: u32::from(seq),
                run_mode: true,
                received_at: tokio::time::Instant::now(),
            })
        }

        let ended = deliver_consulted_tail(
            &layout,
            &fields,
            io.assemblies.input,
            &snapshot,
            &tx,
            Some(enip::LostReason::Io),
            vec![
                enip::IoEvent::Up {
                    o2t_api: Duration::from_millis(20),
                    t2o_api: Duration::from_millis(500),
                },
                sample(1, input_frame(1, 1.0)),
                sample(2, input_frame(2, 2.0)),
            ],
        )
        .await;

        assert!(ended, "a consulted loss ends the translator");
        assert!(matches!(
            rx.recv().await,
            Some(IoUpdate::Up {
                o2t_api_ms: 20,
                t2o_api_ms: 500
            })
        ));
        match rx.recv().await {
            Some(IoUpdate::Data { sequence, .. }) => assert_eq!(
                sequence, 2,
                "latest-wins, exactly as the translator's event arm collapses a burst"
            ),
            other => panic!("expected the freshest drained sample, got {other:?}"),
        }
        match rx.recv().await {
            Some(IoUpdate::Lost { error }) => assert!(
                error.to_string().contains("class-1 socket error"),
                "the loss keeps its mapped reason: {error}"
            ),
            other => panic!("expected the loss last, got {other:?}"),
        }
        assert!(
            snapshot.lock().unwrap().is_some(),
            "the §7.2 snapshot push `sb/read` answers from is refreshed by the replay too"
        );
        // Nothing to deliver and nothing lost is a no-op that keeps the translator running.
        assert!(
            !deliver_consulted_tail(&layout, &fields, 0, &snapshot, &tx, None, Vec::new()).await
        );
    }

    /// The inactivity watchdog on a real socket: the target goes silent, the stack declares the
    /// class-1 connection lost, and the seam reports it as the transient error the engine reconnects
    /// on (§10.1 row 7) — never as a permanent one that would park the instance at the backoff ceiling.
    #[tokio::test]
    async fn watchdog_silence_maps_lost_reason() {
        let io = io_of(100, 100, 8); // 100 ms T→O API × 8 = an 800 ms watchdog
        let (plc, peer, mut session) = open_push_session(&io).await;
        let cid = plc.t2o_cid();
        let target = plc.t2o_target();
        drive_up(session.as_mut(), &peer, target, cid, &input_frame(7, 55.5)).await;

        // Silence. The watchdog is the only thing that can end this stream.
        let mut lost = None;
        while lost.is_none() {
            match tokio::time::timeout(Duration::from_secs(10), session.updates().recv()).await {
                Ok(Some(IoUpdate::Lost { error })) => lost = Some(error),
                Ok(Some(_)) => {}
                Ok(None) => panic!("the stream ended without reporting the loss"),
                Err(_elapsed) => panic!("the watchdog never fired"),
            }
        }
        let error = lost.unwrap();
        assert!(
            error.is_transient(),
            "a lost class-1 link is always retried"
        );
        assert!(
            error
                .to_string()
                .contains("class-1 inactivity watchdog timeout"),
            "the loss reason is mapped, not flattened: {error}"
        );
        session.close().await;
    }
}
