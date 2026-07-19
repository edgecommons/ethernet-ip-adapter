//! # The poll backend: [`EipSession`] over `enip::EipClient` (§3.4)
//!
//! One live explicit-messaging session to one device. `read_signals` issues one Read Tag per signal
//! (D-EIP-15) and decodes each reply through [`super::types`]; a per-tag CIP error or an isolated
//! request timeout becomes a **BAD [`Reading`]** (the session lives — one dead tag must not blind the
//! other ninety-nine, §5.4), while a connection-level failure returns `Err` so the supervisor
//! reconnects (§10.1). `write_signal` coerces + Write Tag (confirmed). `browse` pages Get Instance
//! Attribute List (`Unsupported` ⇒ `BROWSE_UNSUPPORTED`). `probe` is the cheapest real round-trip.
//!
//! **Defensive seam (the vetting mitigations).** Even though the `enip` stack is internally
//! deadline-bounded and panic-free, every op here is additionally wrapped in a generous
//! [`tokio::time::timeout`] backstop; if that backstop ever fires the session is treated as poisoned
//! and the caller reconnects. All `enip` errors are classified by [`super::map_enip_error`] (§10.1).

use std::time::Duration;

use async_trait::async_trait;

use crate::config::SignalSpec;
use crate::device::{
    BrowsePage, BrowsedTag, DeviceError, DeviceSession, Quality, Reading, Result,
};

use super::map_enip_error;
use super::types::{self, Decoded};

/// A live poll session over the owned `enip` client.
pub struct EipSession {
    client: enip::EipClient,
    /// The per-request deadline from `component.global.timeouts` (§4.1); the `enip` client enforces
    /// it internally, and the defensive backstop below is derived from it.
    request_timeout: Duration,
}

impl EipSession {
    /// Wrap a connected `enip` client as a poll session (used by [`super::EipBackend::connect`] and,
    /// via [`enip::EipClient::connect_over`], by the duplex unit tests).
    #[must_use]
    pub fn new(client: enip::EipClient, request_timeout: Duration) -> Self {
        Self { client, request_timeout }
    }

    /// The defensive backstop deadline: comfortably longer than the crate's own per-request deadline
    /// (which returns `Timeout`/`ConnectionLost` first), so this only fires on a true hang.
    fn defensive(&self) -> Duration {
        self.request_timeout
            .saturating_mul(4)
            .max(Duration::from_secs(2))
    }

    /// Read one signal into a [`Reading`]. `Err` means the **connection** is broken (poison the
    /// session); a per-tag failure comes back as `Ok(BAD Reading)`.
    async fn read_one(&self, spec: &SignalSpec) -> Result<Reading> {
        let addr = match enip::TagAddress::parse(&spec.tag_path) {
            Ok(a) => a,
            // A malformed tag path is a per-signal problem, not a link failure.
            Err(e) => return Ok(bad(spec, format!("DECODE bad tag path ({e})"))),
        };
        let elements = spec.array_count.unwrap_or(1).min(u32::from(u16::MAX)) as u16;

        let outcome = tokio::time::timeout(self.defensive(), self.client.read_tag(&addr, elements)).await;
        match outcome {
            Ok(Ok(result)) => {
                match types::decode_value(&result.value, spec.eip_type, spec.scale, spec.offset) {
                    Ok(Decoded { value, non_finite: false }) => Ok(good(spec, value)),
                    Ok(Decoded { non_finite: true, .. }) => Ok(uncertain(spec)),
                    Err(e) => Ok(bad(spec, e.quality_raw())),
                }
            }
            // A per-tag CIP error status: BAD sample, session lives (§5.4, §10.1).
            Ok(Err(enip::EnipError::Cip(status))) => Ok(bad(spec, status.to_string())),
            // An isolated request timeout: BAD sample. The crate declares the session lost after
            // three consecutive timeouts (returning ConnectionLost, handled below).
            Ok(Err(enip::EnipError::Timeout { .. })) => Ok(bad(spec, "TIMEOUT".to_string())),
            // Any other error is connection-level: poison the session.
            Ok(Err(e)) => Err(map_enip_error(e)),
            // The defensive backstop fired: treat the session as poisoned.
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "read exceeded the defensive request backstop"
            ))),
        }
    }
}

/// A GOOD reading of `value`.
fn good(spec: &SignalSpec, value: serde_json::Value) -> Reading {
    Reading {
        signal_id: spec.tag_path.clone(),
        name: Some(spec.name.clone()),
        value,
        quality: Quality::Good,
        quality_raw: Some("0x00".to_string()),
    }
}

/// An UNCERTAIN reading (scale/offset produced a non-finite number, §5.4).
fn uncertain(spec: &SignalSpec) -> Reading {
    Reading {
        signal_id: spec.tag_path.clone(),
        name: Some(spec.name.clone()),
        value: serde_json::Value::Null,
        quality: Quality::Uncertain,
        quality_raw: Some("NON_FINITE_AFTER_SCALE".to_string()),
    }
}

/// A BAD reading carrying the native status in `qualityRaw` (§5.4). Value is JSON `null`.
fn bad(spec: &SignalSpec, quality_raw: String) -> Reading {
    Reading {
        signal_id: spec.tag_path.clone(),
        name: Some(spec.name.clone()),
        value: serde_json::Value::Null,
        quality: Quality::Bad,
        quality_raw: Some(quality_raw),
    }
}

/// The CIP type name a browsed symbol reports, for `BrowsedTag.type_name` (§7.5). Structures and
/// STRING map to their marker names; the command layer maps the name to `supported: bool` (§5.1).
fn symbol_type_name(st: enip::SymbolType) -> String {
    if st.is_struct() {
        return "STRUCT".to_string();
    }
    match st.cip_type() {
        Some(ty) => cip_type_name(ty).to_string(),
        None => format!("0x{:04X}", st.0),
    }
}

/// The CIP elementary type's spelling (uppercase, as a Logix browse reports it).
fn cip_type_name(ty: enip::CipType) -> &'static str {
    match ty {
        enip::CipType::Bool => "BOOL",
        enip::CipType::Sint => "SINT",
        enip::CipType::Int => "INT",
        enip::CipType::Dint => "DINT",
        enip::CipType::Lint => "LINT",
        enip::CipType::Usint => "USINT",
        enip::CipType::Uint => "UINT",
        enip::CipType::Udint => "UDINT",
        enip::CipType::Ulint => "ULINT",
        enip::CipType::Real => "REAL",
        enip::CipType::Lreal => "LREAL",
        enip::CipType::Byte => "BYTE",
        enip::CipType::Word => "WORD",
        enip::CipType::Dword => "DWORD",
        enip::CipType::Lword => "LWORD",
        enip::CipType::String => "STRING",
        enip::CipType::Struct => "STRUCT",
        enip::CipType::Unknown(_) => "UNKNOWN",
        // `CipType` is `#[non_exhaustive]`: any future elementary code maps to a generic name.
        _ => "UNKNOWN",
    }
}

#[async_trait]
impl DeviceSession for EipSession {
    async fn read_signals(&mut self, signals: &[SignalSpec]) -> Result<Vec<Reading>> {
        let mut readings = Vec::with_capacity(signals.len());
        for spec in signals {
            readings.push(self.read_one(spec).await?);
        }
        Ok(readings)
    }

    async fn write_signal(&mut self, signal: &SignalSpec, value: &serde_json::Value) -> Result<()> {
        let cip = types::encode_write(
            value,
            signal.eip_type,
            signal.scale,
            signal.offset,
            signal.array_count,
        )
        .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e.to_string())))?;

        let addr = enip::TagAddress::parse(&signal.tag_path)
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!("bad tag path: {e}")))?;

        let write = self.client.write_tag(&addr, signal.eip_type.cip_type(), &cip);
        match tokio::time::timeout(self.defensive(), write).await {
            Ok(Ok(())) => Ok(()),
            // A rejected write (CIP error) is permanent for this value; the link is fine.
            Ok(Err(enip::EnipError::Cip(status))) => {
                Err(DeviceError::Permanent(anyhow::anyhow!("write rejected: {status}")))
            }
            Ok(Err(enip::EnipError::Timeout { .. })) => Err(DeviceError::Transient(anyhow::anyhow!(
                "write timed out"
            ))),
            Ok(Err(e)) => Err(map_enip_error(e)),
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "write exceeded the defensive request backstop"
            ))),
        }
    }

    async fn browse(&mut self, cursor: Option<String>, max: usize) -> Result<BrowsePage> {
        let start = cursor.as_deref().and_then(|c| c.parse::<u16>().ok()).unwrap_or(1);
        let list = self.client.list_tags(start, &enip::Scope::Controller);
        match tokio::time::timeout(self.defensive(), list).await {
            Ok(Ok((records, next))) => {
                let tags = records
                    .into_iter()
                    .take(max.max(1))
                    .map(|s| BrowsedTag {
                        name: s.name,
                        type_name: symbol_type_name(s.symbol_type),
                        array_dim: (s.symbol_type.dims() > 0).then_some(u32::from(s.symbol_type.dims())),
                        instance_id: s.instance_id,
                    })
                    .collect();
                Ok(BrowsePage {
                    tags,
                    next_cursor: next.map(|n| n.to_string()),
                })
            }
            // The tag-list service is not implemented by this device (§7.3, §10.1).
            Ok(Err(enip::EnipError::Cip(status)))
                if status.general == enip::GeneralStatus::ServiceNotSupported =>
            {
                Err(DeviceError::Unsupported("BROWSE_UNSUPPORTED"))
            }
            Ok(Err(e)) => Err(map_enip_error(e)),
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "browse exceeded the defensive request backstop"
            ))),
        }
    }

    async fn probe(&mut self) -> Result<()> {
        // The cheapest real round-trip that needs no configured tag: a ListIdentity over the session.
        match tokio::time::timeout(self.defensive(), self.client.identity()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(map_enip_error(e)),
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "probe exceeded the defensive request backstop"
            ))),
        }
    }

    async fn close(&mut self) {
        self.client.close().await;
    }
}

#[cfg(test)]
mod tests {
    //! The poll backend over a `tokio::io::duplex` fixture: `connect_over` + hand-crafted CIP replies,
    //! no socket, no PLC (§12.3). A tiny mock device answers RegisterSession then one crafted reply
    //! per Read/Write/GetInstanceAttributeList request, echoing the correlation context.
    use super::*;
    use bytes::Bytes;
    use enip::{Command, Cpf, CpfItem, EncapFrame, EncapHeader, ItemType};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn spec(name: &str, tag: &str, ty: &str, array: Option<u32>) -> SignalSpec {
        let mut v = json!({ "name": name, "tagPath": tag, "type": ty });
        if let Some(n) = array {
            v.as_object_mut().unwrap().insert("arrayCount".into(), json!(n));
        }
        serde_json::from_value(v).unwrap()
    }

    async fn read_frame(s: &mut DuplexStream) -> Option<EncapFrame> {
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

    async fn write_frame(s: &mut DuplexStream, frame: &EncapFrame) {
        let b = frame.encode().unwrap();
        s.write_all(&b).await.unwrap();
        s.flush().await.unwrap();
    }

    /// A Message-Router reply: `reply_service, reserved, status, ext_size(0), data`.
    fn mr_reply(service: u8, status: u8, data: &[u8]) -> Bytes {
        let mut v = vec![service | 0x80, 0x00, status, 0x00];
        v.extend_from_slice(data);
        Bytes::from(v)
    }

    /// Wrap an MR reply in a SendRRData frame echoing `ctx`.
    fn rr_reply(ctx: [u8; 8], mr: Bytes) -> EncapFrame {
        let cpf = Cpf::from_items(vec![CpfItem::null_address(), CpfItem::unconnected_data(mr)]);
        let cpf_bytes = cpf.encode().unwrap();
        let mut data = Vec::with_capacity(6 + cpf_bytes.len());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&cpf_bytes);
        EncapFrame::new(
            EncapHeader::request(Command::SendRRData, 0, 1, ctx),
            Bytes::from(data),
        )
    }

    /// A tagged REAL value reply payload: `u16 0xCA` + f32 LE.
    fn tagged_real(f: f32) -> Vec<u8> {
        let mut v = 0xCA_u16.to_le_bytes().to_vec();
        v.extend_from_slice(&f.to_le_bytes());
        v
    }

    /// One Get-Instance-Attribute-List record.
    fn tag_record(inst: u32, name: &str, sym: u16) -> Vec<u8> {
        let mut v = inst.to_le_bytes().to_vec();
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&sym.to_le_bytes());
        v
    }

    /// Spawn a mock device that answers RegisterSession then delegates each CIP request to `handler`
    /// `(call_index, service, mr_bytes) -> (status, reply_data)`.
    fn spawn_device<F>(mut s: DuplexStream, mut handler: F)
    where
        F: FnMut(u32, u8, &[u8]) -> (u8, Vec<u8>) + Send + 'static,
    {
        tokio::spawn(async move {
            let Some(reg) = read_frame(&mut s).await else { return };
            let reg_reply = EncapFrame::new(
                EncapHeader::request(Command::RegisterSession, 0, 1, reg.header.sender_context),
                Bytes::from(vec![1, 0, 0, 0]),
            );
            write_frame(&mut s, &reg_reply).await;

            let mut idx = 0u32;
            loop {
                let Some(frame) = read_frame(&mut s).await else { return };
                match frame.header.command {
                    Command::SendRRData => {
                        let cpf = Cpf::decode(&frame.data[6..]).unwrap();
                        let mr = cpf.find(ItemType::UnconnectedData).unwrap().data.clone();
                        let service = mr[0];
                        let (status, data) = handler(idx, service, &mr);
                        idx += 1;
                        let reply = rr_reply(frame.header.sender_context, mr_reply(service, status, &data));
                        write_frame(&mut s, &reply).await;
                    }
                    _ => return,
                }
            }
        });
    }

    async fn connect(client_half: DuplexStream) -> EipSession {
        let opts = enip::ClientOptions {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        };
        let client = enip::EipClient::connect_over(client_half, opts).await.unwrap();
        EipSession::new(client, Duration::from_millis(500))
    }

    #[tokio::test]
    async fn a_good_read_decodes_and_a_per_signal_cip_error_is_bad_not_swallowed() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |idx, service, _mr| {
            assert_eq!(service, 0x4C, "read tag");
            match idx {
                0 => (0x00, tagged_real(55.5)),
                _ => (0x04, Vec::new()), // path segment error → BAD, but the session lives
            }
        });
        let mut session = connect(client_half).await;

        let specs = vec![
            spec("line-speed", "LINE_SPEED", "real", None),
            spec("ghost", "NO_SUCH_TAG", "real", None),
        ];
        let readings = session.read_signals(&specs).await.unwrap();
        assert_eq!(readings.len(), 2);

        assert_eq!(readings[0].quality, Quality::Good);
        assert_eq!(readings[0].value, json!(55.5));
        assert_eq!(readings[0].quality_raw.as_deref(), Some("0x00"));

        assert_eq!(readings[1].quality, Quality::Bad, "one dead tag is BAD, not swallowed");
        assert_eq!(readings[1].value, serde_json::Value::Null);
        assert!(readings[1].quality_raw.as_deref().unwrap().contains("0x04"));
    }

    #[tokio::test]
    async fn a_connection_error_returns_err_so_the_supervisor_reconnects() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        // Answer RegisterSession, then drop the socket — the next read hits EOF (ConnectionLost).
        tokio::spawn(async move {
            let mut s = server_half;
            let reg = read_frame(&mut s).await.unwrap();
            let reg_reply = EncapFrame::new(
                EncapHeader::request(Command::RegisterSession, 0, 1, reg.header.sender_context),
                Bytes::from(vec![1, 0, 0, 0]),
            );
            write_frame(&mut s, &reg_reply).await;
            // drop `s` here → EOF
        });
        let mut session = connect(client_half).await;

        let specs = vec![spec("line-speed", "LINE_SPEED", "real", None)];
        let err = session.read_signals(&specs).await.unwrap_err();
        assert!(err.is_transient(), "a dropped link is transient (reconnect)");
    }

    #[tokio::test]
    async fn a_write_is_confirmed_on_the_device_ack() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x4D, "write tag");
            (0x00, Vec::new())
        });
        let mut session = connect(client_half).await;

        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        session.write_signal(&sp, &json!(55.5)).await.unwrap();
    }

    #[tokio::test]
    async fn browse_pages_the_tag_list() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x55, "get instance attribute list");
            let mut data = tag_record(1, "LINE_SPEED", 0x00CA); // REAL
            data.extend_from_slice(&tag_record(2, "PRODUCT_COUNT", 0x00C4)); // DINT
            (0x00, data)
        });
        let mut session = connect(client_half).await;

        let page = session.browse(None, 100).await.unwrap();
        assert_eq!(page.tags.len(), 2);
        assert_eq!(page.tags[0].name, "LINE_SPEED");
        assert_eq!(page.tags[0].type_name, "REAL");
        assert_eq!(page.tags[1].type_name, "DINT");
        assert!(page.next_cursor.is_none());
    }

    /// Browse over the full elementary-type spread plus a structure and an unknown code, exercising the
    /// `symbol_type_name` / `cip_type_name` mapping (§7.5, §5.1). A structure ⇒ "STRUCT"; an unrecognized
    /// code ⇒ its raw hex.
    #[tokio::test]
    async fn browse_maps_every_elementary_type_a_struct_and_an_unknown() {
        // (name, symbol type code, expected type_name).
        let rows: Vec<(&str, u16, &str)> = vec![
            ("B", 0x00C1, "BOOL"), ("SI", 0x00C2, "SINT"), ("I", 0x00C3, "INT"),
            ("DI", 0x00C4, "DINT"), ("LI", 0x00C5, "LINT"), ("USI", 0x00C6, "USINT"),
            ("UI", 0x00C7, "UINT"), ("UDI", 0x00C8, "UDINT"), ("ULI", 0x00C9, "ULINT"),
            ("R", 0x00CA, "REAL"), ("LR", 0x00CB, "LREAL"),
            ("UDT", 0x8100, "STRUCT"), ("MYSTERY", 0x00FF, "UNKNOWN"),
        ];
        let payload = rows.clone();
        let (client_half, server_half) = tokio::io::duplex(8192);
        spawn_device(server_half, move |_idx, service, _mr| {
            assert_eq!(service, 0x55);
            let mut data = Vec::new();
            for (i, (name, sym, _)) in payload.iter().enumerate() {
                data.extend_from_slice(&tag_record(i as u32 + 1, name, *sym));
            }
            (0x00, data)
        });
        let mut session = connect(client_half).await;

        let page = session.browse(None, 100).await.unwrap();
        assert_eq!(page.tags.len(), rows.len());
        for (got, (_, _, want)) in page.tags.iter().zip(rows.iter()) {
            assert_eq!(&got.type_name, want, "tag `{}` type name", got.name);
        }
    }

    #[tokio::test]
    async fn a_non_finite_after_scale_read_is_uncertain() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x4C);
            (0x00, tagged_real(1e30))
        });
        let mut session = connect(client_half).await;
        // scale 1e300 overflows the read value to a non-finite number ⇒ UNCERTAIN (§5.4).
        let sp: SignalSpec = serde_json::from_value(
            json!({ "name": "overflow", "tagPath": "OVERFLOW", "type": "real", "scale": 1e300 }),
        )
        .unwrap();
        let readings = session.read_signals(&[sp]).await.unwrap();
        assert_eq!(readings[0].quality, Quality::Uncertain);
        assert_eq!(readings[0].quality_raw.as_deref(), Some("NON_FINITE_AFTER_SCALE"));
    }

    #[tokio::test]
    async fn a_write_that_fails_to_encode_is_permanent_before_any_io() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        // The device would ack, but a non-numeric value never encodes, so no write is ever sent.
        spawn_device(server_half, |_idx, _service, _mr| (0x00, Vec::new()));
        let mut session = connect(client_half).await;
        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        let err = session.write_signal(&sp, &json!("not a number")).await.unwrap_err();
        assert!(!err.is_transient(), "a coercion failure is permanent, not a link error");
    }

    #[tokio::test]
    async fn a_device_rejected_write_is_permanent() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x4D, "write tag");
            (0x08, Vec::new()) // ServiceNotSupported-style CIP status ⇒ rejected write
        });
        let mut session = connect(client_half).await;
        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        let err = session.write_signal(&sp, &json!(55.5)).await.unwrap_err();
        assert!(!err.is_transient(), "a CIP-rejected write is permanent for this value");
    }

    #[tokio::test]
    async fn a_probe_against_a_dead_session_returns_err() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        // Answer RegisterSession, then drop the socket so the ListIdentity probe hits EOF.
        tokio::spawn(async move {
            let mut s = server_half;
            let reg = read_frame(&mut s).await.unwrap();
            let reply = EncapFrame::new(
                EncapHeader::request(Command::RegisterSession, 0, 1, reg.header.sender_context),
                Bytes::from(vec![1, 0, 0, 0]),
            );
            write_frame(&mut s, &reply).await;
        });
        let mut session = connect(client_half).await;
        assert!(session.probe().await.is_err(), "a probe over a dropped link fails");
    }
}
