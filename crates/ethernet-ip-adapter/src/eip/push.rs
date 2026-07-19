//! # The push backend: [`EipPushSession`] over `enip::IoManager` (§3.4, §4.6)
//!
//! Class-1 implicit I/O. [`EipPushSession::open`] ForwardOpens the connection from the `io` block
//! (assemblies / RPIs / format / priority / watchdog via the config's `to_enip` helpers), then a
//! dedicated task consumes the `enip` [`enip::IoEvent`] stream and translates it into the seam's
//! [`IoUpdate`]s: `Up`, one `Data` per accepted input frame (each field decoded to a [`Reading`] per
//! §5 — Idle run/idle ⇒ UNCERTAIN), and a terminal `Lost` (§10.1 row 7). The event channel is drained
//! **promptly, latest-wins** (consecutive `Data` frames collapse to the freshest) so the P3
//! event-channel-overflow note does not bite.
//!
//! [`assembly_to_readings`] — the field-extraction → `Reading`s translation — is shared with the
//! simulator's push session so the sim exercises the same codec path with no OpENer.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{IoConfig, IoFieldSpec, Timeouts};
use crate::device::{
    ConnectionConfig, DeviceError, IoUpdate, PushSession, Quality, Reading, Result,
};

use super::map_enip_error;
use super::types::{self, Decoded};

/// Extract every configured input field from one accepted assembly frame and build one [`Reading`]
/// per field (§5, §5.4). GOOD on a fresh Run frame; UNCERTAIN (`IDLE`) when the peer signals Idle in
/// the run/idle header (values kept); UNCERTAIN (`NON_FINITE_AFTER_SCALE`) when scaling goes
/// non-finite; BAD on a codec type mismatch. A mis-sized/malformed frame is dropped+counted by the
/// stack, so `layout.decode` failing here yields **no samples** (never a panic).
pub(crate) fn assembly_to_readings(
    layout: &enip::AssemblyLayout,
    fields: &[IoFieldSpec],
    assembly_inst: u16,
    data: &[u8],
    run_mode: bool,
) -> Vec<Reading> {
    let Ok(decoded) = layout.decode(data) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(decoded.len());
    for (key, cipval) in decoded {
        let Some(field) = fields.get(key) else { continue };
        let (value, quality, quality_raw) =
            match types::decode_value(&cipval, field.eip_type, field.scale, field.value_offset) {
                Ok(Decoded { value, non_finite: false }) => {
                    if run_mode {
                        (value, Quality::Good, "0x00".to_string())
                    } else {
                        // Idle: values present, process not running (§5.4).
                        (value, Quality::Uncertain, "IDLE".to_string())
                    }
                }
                Ok(Decoded { non_finite: true, .. }) => (
                    serde_json::Value::Null,
                    Quality::Uncertain,
                    "NON_FINITE_AFTER_SCALE".to_string(),
                ),
                Err(e) => (serde_json::Value::Null, Quality::Bad, e.quality_raw()),
            };
        out.push(Reading {
            signal_id: field.signal_id(assembly_inst),
            name: Some(field.name.clone()),
            value,
            quality,
            quality_raw: Some(quality_raw),
        });
    }
    out
}

/// Map an `enip` class-1 loss reason to a seam error — always [`DeviceError::Transient`] (§10.1 row
/// 7): the push loop leaves and reconnects (ForwardClose best-effort first).
pub(crate) fn map_lost_reason(reason: enip::LostReason) -> DeviceError {
    let detail = match reason {
        enip::LostReason::Timeout => "class-1 inactivity watchdog timeout",
        enip::LostReason::ClosedByPeer => "peer closed the class-1 connection",
        enip::LostReason::Io => "class-1 socket error",
    };
    DeviceError::Transient(anyhow::anyhow!(detail))
}

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

/// A live push (class-1 I/O) session over the owned `enip` I/O manager. The [`IoConnectionHandle`],
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
        let client = enip::EipClient::connect(&conn.endpoint, super::client_options(conn, timeouts))
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
        let task = tokio::spawn(run_translator(
            handle, client, io_manager, in_layout, in_fields, in_inst, updates_tx, control_rx,
        ));

        Ok(Self {
            updates: updates_rx,
            control: control_tx,
            task: Some(task),
            out_layout,
            out_fields,
            out_buf: vec![0u8; out_size],
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
) {
    'task: loop {
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
                        let _ = updates_tx
                            .send(IoUpdate::Data {
                                readings,
                                sequence: latest.sequence,
                                run_mode: latest.run_mode,
                                received_at: latest.received_at.into_std(),
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
        let cip = types::encode_write(
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

#[cfg(test)]
mod tests {
    //! Push field-extraction: feed crafted assembly bytes through the input layout and assert the
    //! Readings (values, ids, quality) — no socket, no OpENer (§12.3).
    use super::*;
    use serde_json::json;

    fn io_config() -> IoConfig {
        serde_json::from_value(json!({
            "rpiMs": 100,
            "assemblies": { "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 8,
                "realTimeFormat": "modeless",
                "signals": [
                    { "name": "din-word", "offset": 0, "type": "udint" },
                    { "name": "motor-run", "offset": 0, "type": "bool", "bit": 0 },
                    { "name": "line-speed", "offset": 4, "type": "real" }
                ]
            }
        }))
        .unwrap()
    }

    /// An 8-byte assembly: UDINT=1 at offset 0 (so bit 0 = 1 ⇒ motor-run true), REAL 55.5 at offset 4.
    fn frame_bytes() -> Vec<u8> {
        let mut v = 1u32.to_le_bytes().to_vec();
        v.extend_from_slice(&55.5f32.to_le_bytes());
        v
    }

    #[test]
    fn extraction_decodes_fields_ids_and_quality_on_a_run_frame() {
        let io = io_config();
        let layout = io.input_layout().unwrap();
        let readings = assembly_to_readings(&layout, &io.input.signals, 100, &frame_bytes(), true);
        assert_eq!(readings.len(), 3);

        assert_eq!(readings[0].name.as_deref(), Some("din-word"));
        assert_eq!(readings[0].signal_id, "a100/0/udint");
        assert_eq!(readings[0].value, json!(1));
        assert_eq!(readings[0].quality, Quality::Good);

        assert_eq!(readings[1].signal_id, "a100/0/bool.0");
        assert_eq!(readings[1].value, json!(true));
        assert_eq!(readings[1].quality, Quality::Good);

        assert_eq!(readings[2].signal_id, "a100/4/real");
        assert_eq!(readings[2].value, json!(55.5));
        assert_eq!(readings[2].quality, Quality::Good);
    }

    #[test]
    fn an_idle_frame_marks_every_field_uncertain_but_keeps_the_value() {
        let io = io_config();
        let layout = io.input_layout().unwrap();
        let readings = assembly_to_readings(&layout, &io.input.signals, 100, &frame_bytes(), false);
        for r in &readings {
            assert_eq!(r.quality, Quality::Uncertain);
            assert_eq!(r.quality_raw.as_deref(), Some("IDLE"));
        }
        // Idle keeps the decoded value (process not running, values present, §5.4).
        assert_eq!(readings[2].value, json!(55.5));
    }

    #[test]
    fn a_mis_sized_frame_yields_no_samples() {
        let io = io_config();
        let layout = io.input_layout().unwrap();
        // 4 bytes for an 8-byte assembly → dropped, no samples (never a panic).
        assert!(assembly_to_readings(&layout, &io.input.signals, 100, &[0u8; 4], true).is_empty());
    }

    #[test]
    fn lost_reasons_map_to_transient() {
        for reason in [
            enip::LostReason::Timeout,
            enip::LostReason::ClosedByPeer,
            enip::LostReason::Io,
        ] {
            assert!(map_lost_reason(reason).is_transient());
        }
    }
}
