//! # The push backend's pure translators (§3.4, §4.6, §5)
//!
//! The class-1 field-extraction and loss-mapping the push backend uses, unit-tested with no socket
//! (§12.3). The live-socket driver — [`EipPushSession`](super::live::EipPushSession),
//! `open`/ForwardOpen, and the `enip::IoEvent` translator task — lives in the excluded live seam
//! [`super::live`]; it composes these pure pieces:
//!
//! * [`assembly_to_readings`] — one accepted assembly frame → one [`Reading`] per configured input
//!   field per §5 (Idle run/idle ⇒ UNCERTAIN; non-finite scale ⇒ UNCERTAIN; type mismatch ⇒ BAD). Also
//!   shared with the simulator's push session, so the sim exercises the same codec path with no OpENer.
//! * [`map_lost_reason`] — an `enip` class-1 loss reason → the seam's transient [`DeviceError`].

use crate::config::IoFieldSpec;
use crate::device::{DeviceError, Quality, Reading};

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

#[cfg(test)]
mod tests {
    //! Push field-extraction: feed crafted assembly bytes through the input layout and assert the
    //! Readings (values, ids, quality) — no socket, no OpENer (§12.3).
    use super::*;
    use crate::config::IoConfig;
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
