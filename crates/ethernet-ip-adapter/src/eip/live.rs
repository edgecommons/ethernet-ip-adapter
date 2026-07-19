//! # The EtherNet/IP live-socket drivers (§3.4, §4.6) — the live-infra seam (excluded, §12.2)
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
//! loss mapping ([`super::push::map_lost_reason`]) — are unit-tested in their home modules. This seam is
//! validated by the live OpENer/cpppo integration suites (§11) and the S9 deployed regression.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{IoConfig, IoFieldSpec, Timeouts};
use crate::device::{
    ConnectionConfig, DeviceBackend, DeviceError, DeviceSession, InputSnapshot, IoLinkStats, IoUpdate,
    PushSession, Result,
};

use super::push::{assembly_to_readings, map_lost_reason};
use super::{client_options, map_enip_error, EipBackend, VENDOR_ID};

#[async_trait]
impl DeviceBackend for EipBackend {
    fn kind(&self) -> &'static str {
        "ethernet-ip"
    }

    async fn connect(&self, conn: &ConnectionConfig) -> Result<Box<dyn DeviceSession>> {
        let opts = client_options(conn, self.timeouts());
        let request_timeout = opts.request_timeout;
        let client = enip::EipClient::connect(&conn.endpoint, opts)
            .await
            .map_err(map_enip_error)?;
        Ok(Box::new(super::session::EipSession::new(client, request_timeout)))
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

/// A control message from the session handle to its translator task.
enum PushControl {
    /// Stage a fully-encoded output-assembly buffer (rides the next O→T frame).
    SetOutput(Vec<u8>),
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

        // Build the ForwardOpen spec from the config's typed `to_enip` helpers (§4.6).
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
            // O→T is always point-to-point (§4.6).
            conn_type: enip::ConnType::P2P,
            priority: io.priority.to_enip(),
            variable: enip::VariableLength::Fixed,
        };
        let spec = enip::IoConnectionSpec {
            assembly,
            t2o,
            o2t,
            timeout_multiplier: io
                .timeout_multiplier_enip()
                .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?,
            trigger: enip::ProductionTrigger::Cyclic,
            vendor_id,
        };

        // Connect the TCP session (for CM/UCMM), bind the I/O socket, and ForwardOpen.
        let client = enip::EipClient::connect(&conn.endpoint, client_options(conn, timeouts))
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
        })
    }
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

        let mut do_output: Option<Vec<u8>> = None;
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
                        let readings = assembly_to_readings(
                            &in_layout, &in_fields, in_inst, &latest.data, latest.run_mode,
                        );
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
                    Some(PushControl::SetOutput(bytes)) => do_output = Some(bytes),
                    Some(PushControl::Close(ack)) => do_close = Some(ack),
                    None => break 'task,
                }
            }
        }

        if let Some(bytes) = do_output {
            if let Err(e) = handle.set_output(bytes) {
                tracing::warn!(error = %e, "push: staging output frame failed");
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
            .position(|f| f.offset == field.offset && f.eip_type == field.eip_type && f.bit == field.bit)
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
        let _ = self
            .control
            .send(PushControl::SetOutput(self.out_buf.clone()))
            .await;
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(task) = self.task.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            if self.control.send(PushControl::Close(ack_tx)).await.is_ok() {
                let _ = tokio::time::timeout(Duration::from_secs(5), ack_rx).await;
            } else {
                task.abort();
            }
        }
    }
}
