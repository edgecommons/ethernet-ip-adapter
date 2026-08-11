//! # The poll backend: [`EipSession`] over `enip::EipClient` (§3.4)
//!
//! One live explicit-messaging session to one device. `read_signals` issues one Read Tag per signal
//! (D-EIP-15) and decodes each reply through [`super::types`]; a per-tag CIP error, an isolated
//! request timeout, or a reply whose element count is not the configured one
//! ([`cardinality_mismatch`], D-EIP-33) becomes a **BAD [`Reading`]** (the session lives — one dead
//! tag must not blind the other ninety-nine, and a malformed reply must not bounce the link, §5.4),
//! while a connection-level failure returns `Err` so the supervisor
//! reconnects (§10.1). `write_signal` coerces + Write Tag (confirmed). `browse` pages Get Instance
//! Attribute List, honouring `max` truthfully: an uncursored walk starts at symbol instance 0 so
//! nothing at the bottom of the instance space is skipped ([`parse_browse_cursor`]), a page cut
//! short resumes from the last record it actually returned ([`paginate_browse`]), and a cursor that
//! is not a symbol-instance id is a caller error, not a silent restart. A CIP `0x08` refusal of the
//! *first* page is a device with no tag-list service (`Unsupported` ⇒ `BROWSE_UNSUPPORTED`); the
//! same refusal of a **resume** is a failed page (`BROWSE_FAILED`), not a missing service.
//! `probe` is the cheapest real round-trip.
//!
//! **Defensive seam (the vetting mitigations).** Even though the `enip` stack is internally
//! deadline-bounded and panic-free, every op here is additionally wrapped in a generous
//! [`tokio::time::timeout`] backstop; if that backstop ever fires the session is treated as poisoned
//! and the caller reconnects. All `enip` errors are classified by [`super::map_enip_error`] (§10.1).

use std::time::Duration;

use async_trait::async_trait;

use crate::config::{EipType, SignalSpec};
use crate::device::{
    BrowsePage, BrowsedTag, DeviceError, DeviceIdentity, DeviceSession, Quality, Reading, Result,
    SecurityStatus,
};

use super::map_enip_error;
use super::types;

/// A live poll session over the owned `enip` client.
pub struct EipSession {
    client: enip::EipClient,
    /// The per-request deadline from `component.global.timeouts` (§4.1); the `enip` client enforces
    /// it internally, and the defensive backstop below is derived from it.
    request_timeout: Duration,
    /// The negotiated security posture (CIP Security Phase 1) — `Some` for a `mode: tls` session,
    /// `None` for a plaintext session (DESIGN-cip-security.md §3.4).
    security: Option<SecurityStatus>,
    /// What the device said it is, read once at connect (D-EIP-34). `None` when it refused the read.
    /// Captured, never re-read: a status query must not cost a device round-trip.
    identity: Option<DeviceIdentity>,
}

impl EipSession {
    /// Wrap a connected (plaintext) `enip` client as a poll session (used by
    /// [`super::EipBackend::connect`] and, via [`enip::EipClient::connect_over`], by the duplex unit
    /// tests).
    #[must_use]
    pub fn new(client: enip::EipClient, request_timeout: Duration) -> Self {
        Self {
            client,
            request_timeout,
            security: None,
            identity: None,
        }
    }

    /// Attach the identity read at connect (D-EIP-34). A builder step rather than a constructor
    /// argument because it is orthogonal to how the session was opened — plaintext or TLS, both
    /// carry one, and `None` (the device refused) is an ordinary outcome, not a variant.
    #[must_use]
    pub fn with_identity(mut self, identity: Option<DeviceIdentity>) -> Self {
        self.identity = identity;
        self
    }

    /// Wrap a connected TLS `enip` client as a poll session, carrying its negotiated security posture
    /// for the `sb/status`/state/metrics surface (DESIGN-cip-security.md §3.4).
    #[must_use]
    pub fn new_secure(
        client: enip::EipClient,
        request_timeout: Duration,
        security: SecurityStatus,
    ) -> Self {
        Self {
            client,
            request_timeout,
            security: Some(security),
            identity: None,
        }
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
        // Both paths that mint a `SignalSpec` bound `arrayCount` to `1..=MAX_ARRAY_COUNT` — config
        // validation (§4.4) and the `sb/read`/`sb/write` explicit ref (`BAD_ARGS`, §7.2) — so this
        // conversion is exact. It is written as a per-signal refusal rather than the clamp it
        // replaces because a silently narrowed element count asks the device for a different
        // contract than the configured one and then publishes the answer GOOD (D-EIP-33).
        let requested = spec.array_count.unwrap_or(1);
        let elements = match u16::try_from(requested) {
            Ok(n) if n >= 1 => n,
            _ => {
                return Ok(bad(
                    spec,
                    format!("DECODE arrayCount {requested} out of range (expected 1..=65535)"),
                ))
            }
        };

        let outcome =
            tokio::time::timeout(self.defensive(), self.client.read_tag(&addr, elements)).await;
        match outcome {
            Ok(Ok(result)) => {
                match types::decode_value(&result.value, spec.eip_type, spec.scale, spec.offset) {
                    Err(e) => Ok(bad(spec, decode_detail(spec, &e))),
                    // The element *type* matched; the element *count* is a separate promise, and it
                    // is checked here — on the shape the crate decoded — because only the adapter
                    // holds the configured cardinality (§5.1's "a JSON array of N elements").
                    Ok(decoded) => match cardinality_mismatch(&result.value, elements) {
                        Some(detail) => Ok(bad(spec, detail)),
                        None if decoded.non_finite => Ok(uncertain(spec)),
                        None => Ok(good(spec, decoded.value)),
                    },
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

/// The `qualityRaw` detail for a decode failure — [`types::DecodeError::quality_raw`], plus one hint
/// for the single mismatch shape an operator is most likely to hit and least likely to understand.
///
/// A configured BOOL **array** answered with `DWORD` is a Logix controller telling us its `BOOL[n]`
/// tag is packed (D-EIP-16): the adapter's BOOL-array encoding is byte-per-element, which this
/// device does not use. Config validation already warns about the signal at startup, but an operator
/// reading a BAD sample months later never saw that line, so the sample explains itself. Nothing
/// else is annotated — a hint on every mismatch would be noise, and the base detail already names
/// expected vs got.
fn decode_detail(spec: &SignalSpec, e: &types::DecodeError) -> String {
    let base = e.quality_raw();
    let bool_array_vs_dword = spec.eip_type == EipType::Bool
        && spec.array_count.is_some()
        && matches!(
            e,
            types::DecodeError::TypeMismatch {
                got: enip::CipType::Dword,
                ..
            }
        );
    if bool_array_vs_dword {
        return format!(
            "{base} - Logix packs BOOL arrays as DWORDs; BOOL-array support is experimental"
        );
    }
    base
}

/// How many elements a decoded reply actually carries. The protocol crate derives the count from the
/// reply length and **collapses a single element to a scalar** (`cip/types.rs`, PROTOCOL-DESIGN
/// §7.2), so a scalar is one element — which is also why a configured `arrayCount: 1` is satisfied by
/// a scalar reply.
fn returned_elements(v: &enip::CipValue) -> usize {
    match v {
        enip::CipValue::Array(_, elems) => elems.len(),
        _ => 1,
    }
}

/// The `qualityRaw` detail when a reply's element count is not the one the request asked for, or
/// `None` when it matches (D-EIP-33).
///
/// The requested count is sent on the wire and then has to be *checked*: a conforming Logix answers
/// exactly `requested` elements or errors, but nothing in the reply forces that, and the crate
/// deliberately derives the count from the payload length. Left unchecked, a nonconforming or
/// hostile peer turns a short reply into a GOOD array shorter than the configured contract, and a
/// one-element reply into a GOOD **scalar** where an array is configured — both silently wrong,
/// which is the failure mode D-EIP-1's threat model exists to refuse. It is a per-signal BAD sample,
/// never a connection-level error: a malformed reply must not bounce the session (§5.4).
fn cardinality_mismatch(v: &enip::CipValue, requested: u16) -> Option<String> {
    let got = returned_elements(v);
    let want = usize::from(requested);
    (got != want).then(|| format!("DECODE element count mismatch (expected {want}, got {got})"))
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

/// The resume instance for a browse request (§7.3). No cursor ⇒ **instance 0**: the symbol
/// enumeration is walked from the beginning of the instance space, because instance ids are the
/// device's to assign and starting at 1 skips any symbol that sits at instance 0 — silently, and
/// forever, which is the same defect class as a truncated page that returns the device's cursor.
/// Starting at 0 is also what a real `0x55` server wants: EthernetIPSharp serves its symbol table
/// only from the class-level start instance `0` and answers instance 1 with CIP `0x16`, so a walk
/// that began at 1 could not enumerate it at all (DESIGN §11.7). A cursor must be the decimal
/// symbol-instance id a previous page returned; anything else is a **caller error** — never a silent
/// restart at the beginning, which would re-serve (and duplicate) the whole walk.
///
/// Shared with the simulator backend ([`crate::sim`]) so both backends page identically and the sim
/// cannot mask an adapter paging bug.
///
/// # Errors
///
/// [`DeviceError::Permanent`] when `cursor` is not a decimal `u32` (the command layer surfaces it as
/// `BROWSE_FAILED` naming the offending cursor).
pub(crate) fn parse_browse_cursor(cursor: Option<&str>) -> Result<u32> {
    match cursor {
        None => Ok(0),
        Some(c) => c.trim().parse::<u32>().map_err(|_| {
            DeviceError::Permanent(anyhow::anyhow!(
                "invalid browse cursor `{c}` (expected the numeric cursor from the previous page)"
            ))
        }),
    }
}

/// Honour `max` truthfully (§7.3).
///
/// The device's own cursor follows the **last record of the page it sent**. When that page is longer
/// than `max`, everything past the cut is discarded and must be re-served, so the resume point is
/// the last record actually **returned** (`+1`) — passing the device's cursor through here would
/// skip the discarded records forever. An untruncated page keeps the device's cursor (it is the
/// authority on whether more records exist). `max == 0` clamps to 1 so a walk always progresses, and
/// a last record at `u32::MAX` ends the walk rather than wrapping.
///
/// Cutting at the last returned record is only exactly-once because the page is strictly ascending,
/// and that is the protocol crate's guarantee, not an assumption made here: `list_tags` walks each
/// decoded page and rejects an out-of-order or duplicated instance id as a `ProtocolViolation`
/// (PROTOCOL-DESIGN §7.3 / D-ENIP-19), so a page reaching this function cannot hide a record behind
/// the cut.
fn paginate_browse(
    mut records: Vec<enip::SymbolInfo>,
    device_next: Option<u32>,
    max: usize,
) -> (Vec<enip::SymbolInfo>, Option<u32>) {
    let max = max.max(1);
    if records.len() > max {
        records.truncate(max);
        let next = records.last().and_then(|s| s.instance_id.checked_add(1));
        (records, next)
    } else {
        (records, device_next)
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

        let write = self
            .client
            .write_tag(&addr, signal.eip_type.cip_type(), &cip);
        match tokio::time::timeout(self.defensive(), write).await {
            Ok(Ok(())) => Ok(()),
            // A rejected write (CIP error) is permanent for this value; the link is fine.
            Ok(Err(enip::EnipError::Cip(status))) => Err(DeviceError::Permanent(anyhow::anyhow!(
                "write rejected: {status}"
            ))),
            Ok(Err(enip::EnipError::Timeout { .. })) => {
                Err(DeviceError::Transient(anyhow::anyhow!("write timed out")))
            }
            Ok(Err(e)) => Err(map_enip_error(e)),
            Err(_elapsed) => Err(DeviceError::Transient(anyhow::anyhow!(
                "write exceeded the defensive request backstop"
            ))),
        }
    }

    async fn browse(&mut self, cursor: Option<String>, max: usize) -> Result<BrowsePage> {
        let start = parse_browse_cursor(cursor.as_deref())?;
        let list = self.client.list_tags(start, &enip::Scope::Controller);
        match tokio::time::timeout(self.defensive(), list).await {
            Ok(Ok((records, device_next))) => {
                let (page, next) = paginate_browse(records, device_next, max);
                let tags = page
                    .into_iter()
                    .map(|s| BrowsedTag {
                        name: s.name,
                        type_name: symbol_type_name(s.symbol_type),
                        array_dim: (s.symbol_type.dims() > 0)
                            .then_some(u32::from(s.symbol_type.dims())),
                        instance_id: s.instance_id,
                    })
                    .collect();
                Ok(BrowsePage {
                    tags,
                    next_cursor: next.map(|n| n.to_string()),
                })
            }
            // `ServiceNotSupported` (`0x08`) means two different things depending on where the walk
            // asked to start, and only one of them is "this device has no tag list" (§7.3, §10.1).
            //
            // At the bottom of the instance space the device is answering the enumeration itself:
            // there is no tag-list service here, which is the generic-CIP-device path ⇒
            // `BROWSE_UNSUPPORTED`.
            //
            // On a **resume** the device has already served a page (that is where the cursor came
            // from), so the service demonstrably exists and it is the mid-set *start instance* that
            // is refused — EthernetIPSharp answers `0x08` for every non-zero start instance, serving
            // its symbol table only from the class-level start (DESIGN §11.7). Reporting that as
            // `BROWSE_UNSUPPORTED` would tell a console the device cannot browse at all, right after
            // it browsed. It is a failure of this page, named as one: `BROWSE_FAILED`, permanent
            // because retrying the same cursor is refused identically.
            Ok(Err(enip::EnipError::Cip(status)))
                if status.general == enip::GeneralStatus::ServiceNotSupported =>
            {
                if start == 0 {
                    Err(DeviceError::Unsupported("BROWSE_UNSUPPORTED"))
                } else {
                    Err(DeviceError::Permanent(anyhow::anyhow!(
                        "device refused to resume the tag list at symbol instance {start} \
                         (CIP 0x08): it serves the enumeration only from the start of the \
                         instance space"
                    )))
                }
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

    fn security(&self) -> Option<SecurityStatus> {
        self.security.clone()
    }

    fn identity(&self) -> Option<DeviceIdentity> {
        self.identity.clone()
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn spec(name: &str, tag: &str, ty: &str, array: Option<u32>) -> SignalSpec {
        let mut v = json!({ "name": name, "tagPath": tag, "type": ty });
        if let Some(n) = array {
            v.as_object_mut()
                .unwrap()
                .insert("arrayCount".into(), json!(n));
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

    /// A tagged REAL **array** reply payload: `u16 0xCA` + one f32 LE per element. The crate derives
    /// the element count from the payload length, so this is how a device serves N of them — and how
    /// a test serves a number the request did not ask for.
    fn tagged_real_array(vals: &[f32]) -> Vec<u8> {
        let mut v = 0xCA_u16.to_le_bytes().to_vec();
        for f in vals {
            v.extend_from_slice(&f.to_le_bytes());
        }
        v
    }

    /// The element count a Read Tag request carried: a Message Request is
    /// `service, path_size_words, path…, data…`, and the Read Tag data is a single `u16` count.
    fn requested_elements(mr: &[u8]) -> u16 {
        let path_len = mr[1] as usize * 2;
        let off = 2 + path_len;
        u16::from_le_bytes([mr[off], mr[off + 1]])
    }

    /// One Get-Instance-Attribute-List record.
    fn tag_record(inst: u32, name: &str, sym: u16) -> Vec<u8> {
        let mut v = inst.to_le_bytes().to_vec();
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&sym.to_le_bytes());
        v
    }

    /// A synthetic [`enip::SymbolInfo`] for the pure paging unit tests.
    fn sym(instance_id: u32) -> enip::SymbolInfo {
        enip::SymbolInfo {
            instance_id,
            name: format!("TAG_{instance_id}"),
            symbol_type: enip::SymbolType(0x00CA), // REAL
        }
    }

    /// The start instance the mock device was asked to resume from, plus the EPATH logical-segment
    /// byte that carried it (`0x24` 8-bit / `0x25` 16-bit / `0x26` 32-bit) — so a test can assert the
    /// cursor reached the wire in the right width. `mr` is a Message Request:
    /// `service, path_size_words, path…, data…`.
    fn requested_instance(mr: &[u8]) -> (u32, u8) {
        let path_len = mr[1] as usize * 2;
        let path = &mr[2..2 + path_len];
        let mut i = 0usize;
        let mut found = (0u32, 0u8);
        while i < path.len() {
            match path[i] {
                0x20 => i += 2, // 8-bit class
                0x21 => i += 4, // 16-bit class
                0x24 => {
                    found = (u32::from(path[i + 1]), 0x24);
                    i += 2;
                }
                0x25 => {
                    found = (
                        u32::from(u16::from_le_bytes([path[i + 2], path[i + 3]])),
                        0x25,
                    );
                    i += 4;
                }
                0x26 => {
                    found = (
                        u32::from_le_bytes([path[i + 2], path[i + 3], path[i + 4], path[i + 5]]),
                        0x26,
                    );
                    i += 6;
                }
                other => panic!("unexpected EPATH segment 0x{other:02X}"),
            }
        }
        found
    }

    fn names(page: &BrowsePage) -> Vec<String> {
        page.tags.iter().map(|t| t.name.clone()).collect()
    }

    /// Spawn a mock device that answers RegisterSession then delegates each CIP request to `handler`
    /// `(call_index, service, mr_bytes) -> (status, reply_data)`.
    fn spawn_device<F>(mut s: DuplexStream, mut handler: F)
    where
        F: FnMut(u32, u8, &[u8]) -> (u8, Vec<u8>) + Send + 'static,
    {
        tokio::spawn(async move {
            let Some(reg) = read_frame(&mut s).await else {
                return;
            };
            let reg_reply = EncapFrame::new(
                EncapHeader::request(Command::RegisterSession, 0, 1, reg.header.sender_context),
                Bytes::from(vec![1, 0, 0, 0]),
            );
            write_frame(&mut s, &reg_reply).await;

            let mut idx = 0u32;
            loop {
                let Some(frame) = read_frame(&mut s).await else {
                    return;
                };
                match frame.header.command {
                    Command::SendRRData => {
                        let cpf = Cpf::decode(&frame.data[6..]).unwrap();
                        let mr = cpf.find(ItemType::UnconnectedData).unwrap().data.clone();
                        let service = mr[0];
                        let (status, data) = handler(idx, service, &mr);
                        idx += 1;
                        let reply = rr_reply(
                            frame.header.sender_context,
                            mr_reply(service, status, &data),
                        );
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
        let client = enip::EipClient::connect_over(client_half, opts)
            .await
            .unwrap();
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

        assert_eq!(
            readings[1].quality,
            Quality::Bad,
            "one dead tag is BAD, not swallowed"
        );
        assert_eq!(readings[1].value, serde_json::Value::Null);
        assert!(readings[1].quality_raw.as_deref().unwrap().contains("0x04"));
    }

    /// **The cardinality contract (D-EIP-33).** The requested element count is sent on the wire and
    /// must then be *checked*: nothing in a Read Tag reply forces the device to have honoured it, and
    /// the crate deliberately derives the count from the payload length. A reply carrying 3 of the 8
    /// elements asked for is a BAD sample naming both numbers — not a GOOD 3-element array short of
    /// the configured contract. The exact-N reply in the same test is the control: the check refuses
    /// only the mismatch.
    #[tokio::test]
    async fn a_short_array_reply_is_bad_naming_expected_and_got_while_exact_n_stays_good() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |idx, service, mr| {
            assert_eq!(service, 0x4C, "read tag");
            assert_eq!(requested_elements(mr), 8, "the request asks for all 8");
            match idx {
                0 => (0x00, tagged_real_array(&[1.0, 2.0, 3.0])), // three of eight
                _ => (
                    0x00,
                    tagged_real_array(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]),
                ),
            }
        });
        let mut session = connect(client_half).await;
        let sp = spec("zone-temps", "ZONE_TEMPS", "real", Some(8));

        let short = session
            .read_signals(std::slice::from_ref(&sp))
            .await
            .unwrap();
        assert_eq!(short[0].quality, Quality::Bad, "a short array is not GOOD");
        assert_eq!(short[0].value, serde_json::Value::Null);
        let raw = short[0].quality_raw.clone().unwrap_or_default();
        assert!(
            raw.contains("expected 8") && raw.contains("got 3"),
            "the detail names expected vs got: {raw}"
        );

        let full = session.read_signals(&[sp]).await.unwrap();
        assert_eq!(full[0].quality, Quality::Good, "exactly N is still GOOD");
        assert_eq!(
            full[0].value,
            json!([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
        );
    }

    /// The collapse case: the crate turns a one-element reply into a **scalar** (`cip/types.rs`), so
    /// an array-configured signal answered with one element published a GOOD scalar where §5.1
    /// promises a JSON array of N. That is the same defect wearing a different shape, and it is the
    /// same refusal.
    #[tokio::test]
    async fn a_scalar_reply_where_an_array_is_configured_is_bad_not_a_good_scalar() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x4C);
            (0x00, tagged_real(42.0)) // one element ⇒ the crate decodes a scalar
        });
        let mut session = connect(client_half).await;

        let r = session
            .read_signals(&[spec("zone-temps", "ZONE_TEMPS", "real", Some(4))])
            .await
            .unwrap();
        assert_eq!(r[0].quality, Quality::Bad);
        assert_eq!(r[0].value, serde_json::Value::Null);
        let raw = r[0].quality_raw.clone().unwrap_or_default();
        assert!(
            raw.contains("expected 4") && raw.contains("got 1"),
            "the detail names expected vs got: {raw}"
        );
    }

    /// The mirror image, and the reason the check is a count rather than a shape test: a *scalar*
    /// signal answered with several elements is equally out of contract. It is also why a configured
    /// `arrayCount: 1` is satisfied by the scalar the crate collapses a single element into — one
    /// element is one element, whichever shape carries it.
    #[tokio::test]
    async fn an_array_reply_where_a_scalar_is_configured_is_bad_and_array_count_one_accepts_a_scalar(
    ) {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |idx, service, _mr| {
            assert_eq!(service, 0x4C);
            match idx {
                0 => (0x00, tagged_real_array(&[1.0, 2.0, 3.0])),
                _ => (0x00, tagged_real(7.5)),
            }
        });
        let mut session = connect(client_half).await;

        let r = session
            .read_signals(&[spec("line-speed", "LINE_SPEED", "real", None)])
            .await
            .unwrap();
        assert_eq!(r[0].quality, Quality::Bad);
        let raw = r[0].quality_raw.clone().unwrap_or_default();
        assert!(
            raw.contains("expected 1") && raw.contains("got 3"),
            "a scalar signal answered with three elements: {raw}"
        );

        let one = session
            .read_signals(&[spec("one", "ONE", "real", Some(1))])
            .await
            .unwrap();
        assert_eq!(one[0].quality, Quality::Good, "arrayCount 1 is satisfiable");
        assert_eq!(one[0].value, json!(7.5));
    }

    /// **The clamp is gone (D-EIP-33).** `read_one` used to narrow the element count with
    /// `.min(u16::MAX)`, so a signal asking for 70 000 elements quietly requested 65 535 and
    /// published the device's answer GOOD — a different contract than the configured one, answered
    /// as if it were the configured one. Configuration now refuses that count outright; the seam
    /// keeps a non-panicking refusal for any spec that reaches it unvalidated, and issues **no
    /// request at all**.
    #[tokio::test]
    async fn an_unvalidated_out_of_range_array_count_is_refused_not_clamped() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        spawn_device(server_half, move |_idx, _service, _mr| {
            seen.fetch_add(1, Ordering::SeqCst);
            (0x00, tagged_real_array(&[1.0, 2.0]))
        });
        let mut session = connect(client_half).await;

        // `SignalSpec` deserializes without the §4.4 device validation, which is exactly the shape a
        // defensive conversion exists for.
        let r = session
            .read_signals(&[spec("huge", "HUGE", "real", Some(70_000))])
            .await
            .unwrap();
        assert_eq!(r[0].quality, Quality::Bad);
        let raw = r[0].quality_raw.clone().unwrap_or_default();
        assert!(
            raw.contains("70000") && raw.contains("1..=65535"),
            "the refusal names the count and the bound: {raw}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no truncated read is issued at all"
        );
    }

    /// **The BOOL-array experiment, both outcomes (D-EIP-16).** A byte-per-element peer answers the
    /// configured `BOOL[4]` and the signal reads GOOD — the feature is available, which is what
    /// "accepted, experimental" means. A Logix controller answers the same read with a packed
    /// `DWORD` array (`0x00D3`), which is a type mismatch ⇒ BAD; that BAD carries the hint, because
    /// an operator reading it months later never saw the startup warning and has no way to know
    /// from "expected bool, got Dword" that BOOL-array support is the thing at fault.
    #[tokio::test]
    async fn a_bool_array_reads_byte_per_element_and_a_dword_reply_is_bad_with_the_hint() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |idx, service, _mr| {
            assert_eq!(service, 0x4C);
            match idx {
                // Byte-per-element BOOL[4]: `u16 0xC1` + four bytes.
                0 => (0x00, vec![0xC1, 0x00, 1, 0, 1, 1]),
                // The Logix answer: a packed DWORD array (`u16 0xD3` + two 32-bit words).
                _ => (
                    0x00,
                    vec![0xD3, 0x00, 0x0F, 0, 0, 0, 0xF0, 0xFF, 0xFF, 0xFF],
                ),
            }
        });
        let mut session = connect(client_half).await;
        let sp = spec("alarms", "ALARMS", "bool", Some(4));

        let good = session
            .read_signals(std::slice::from_ref(&sp))
            .await
            .unwrap();
        assert_eq!(good[0].quality, Quality::Good);
        assert_eq!(good[0].value, json!([true, false, true, true]));

        let packed = session.read_signals(&[sp]).await.unwrap();
        assert_eq!(
            packed[0].quality,
            Quality::Bad,
            "a packed reply is loud, not silently reinterpreted"
        );
        let raw = packed[0].quality_raw.clone().unwrap_or_default();
        assert!(
            raw.contains("type mismatch") && raw.contains("Dword"),
            "the base detail still names expected vs got: {raw}"
        );
        assert!(
            raw.contains("Logix packs BOOL arrays as DWORDs")
                && raw.contains("BOOL-array support is experimental"),
            "the sample explains itself to an operator who never saw the startup log: {raw}"
        );
    }

    /// The hint is for that one mismatch shape only — every other decode mismatch keeps the bare
    /// detail, so the annotation stays a signal rather than noise.
    #[tokio::test]
    async fn the_bool_array_hint_is_not_appended_to_unrelated_mismatches() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |idx, service, _mr| {
            assert_eq!(service, 0x4C);
            match idx {
                // A REAL signal answered with a DINT: a mismatch, but nothing to do with BOOLs.
                0 => (0x00, vec![0xC4, 0x00, 1, 0, 0, 0]),
                // A *scalar* bool answered with a DWORD: still not the BOOL-array shape.
                _ => (0x00, vec![0xD3, 0x00, 0x0F, 0, 0, 0]),
            }
        });
        let mut session = connect(client_half).await;

        for sp in [
            spec("line-speed", "LINE_SPEED", "real", None),
            spec("motor-run", "MOTOR_RUN", "bool", None),
        ] {
            let r = session.read_signals(&[sp]).await.unwrap();
            assert_eq!(r[0].quality, Quality::Bad);
            let raw = r[0].quality_raw.clone().unwrap_or_default();
            assert!(
                !raw.contains("experimental"),
                "no BOOL-array hint on an unrelated mismatch: {raw}"
            );
        }
    }

    /// The counterpart of the clamp removal on the wire: the count the operator configured is the
    /// count the request carries, right up to the `u16` ceiling this bound exists to respect. (The
    /// device answers a CIP status rather than 256 KB of REALs — the assertion is about the
    /// *request*; a reply that large does not fit one unfragmented CPF item anyway.)
    #[tokio::test]
    async fn the_configured_element_count_reaches_the_wire_verbatim() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        let asked = Arc::new(Mutex::new(Vec::<u16>::new()));
        let record = Arc::clone(&asked);
        spawn_device(server_half, move |_idx, service, mr| {
            assert_eq!(service, 0x4C);
            record.lock().unwrap().push(requested_elements(mr));
            (0x13, Vec::new()) // not enough data — a per-tag CIP status, session lives
        });
        let mut session = connect(client_half).await;

        let r = session
            .read_signals(&[spec("max", "MAX_ARR", "real", Some(65_535))])
            .await
            .unwrap();
        assert_eq!(r[0].quality, Quality::Bad, "the device refused this one");
        assert_eq!(
            asked.lock().unwrap().as_slice(),
            [65_535],
            "the configured count rides the wire unnarrowed"
        );
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
        assert!(
            err.is_transient(),
            "a dropped link is transient (reconnect)"
        );
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

    /// The F7 headline (§4.1/§4.3): when `max` cuts a device page short, the returned cursor must
    /// resume from the last record **actually returned** — not the device's own cursor, which follows
    /// the last record of the FULL page and would skip everything discarded by the cut. The mock is a
    /// device that never pages itself: every reply carries the whole tag set from the requested
    /// instance onward with status `0x00`, so all truncation is the adapter's. Its symbols occupy
    /// instances 1..=5, so the uncursored start (instance 0, one below the first symbol) simply
    /// yields the whole set.
    #[tokio::test]
    async fn browse_truncation_resumes_from_the_last_returned_record() {
        let (client_half, server_half) = tokio::io::duplex(8192);
        spawn_device(server_half, |_idx, service, mr| {
            assert_eq!(service, 0x55, "get instance attribute list");
            let (start, _seg) = requested_instance(mr);
            let mut data = Vec::new();
            for inst in start.max(1)..=5 {
                data.extend_from_slice(&tag_record(inst, &format!("TAG_{inst}"), 0x00CA));
            }
            (0x00, data)
        });
        let mut session = connect(client_half).await;

        let p1 = session.browse(None, 2).await.unwrap();
        assert_eq!(names(&p1), ["TAG_1", "TAG_2"]);
        assert_eq!(
            p1.next_cursor.as_deref(),
            Some("3"),
            "resume after the last RETURNED record, not after the device's page"
        );

        let p2 = session.browse(p1.next_cursor.clone(), 2).await.unwrap();
        assert_eq!(names(&p2), ["TAG_3", "TAG_4"]);
        assert_eq!(p2.next_cursor.as_deref(), Some("5"));

        let p3 = session.browse(p2.next_cursor.clone(), 2).await.unwrap();
        assert_eq!(names(&p3), ["TAG_5"]);
        assert!(
            p3.next_cursor.is_none(),
            "the last, untruncated page ends the walk"
        );

        // Exactly-once: the union across the pages is the whole set, with no repeats and no skips.
        let walked: Vec<String> = [p1, p2, p3].iter().flat_map(names).collect();
        assert_eq!(walked, ["TAG_1", "TAG_2", "TAG_3", "TAG_4", "TAG_5"]);
    }

    /// A cursor the adapter cannot read is the caller's error (§4.3) — restarting the walk at the
    /// bottom of the instance space would silently re-serve every tag already delivered. No request
    /// reaches the device.
    #[tokio::test]
    async fn browse_invalid_cursor_is_an_error_not_a_restart() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        spawn_device(server_half, move |_idx, _service, _mr| {
            seen.fetch_add(1, Ordering::SeqCst);
            (0x00, Vec::new())
        });
        let mut session = connect(client_half).await;

        let err = session
            .browse(Some("banana".to_string()), 10)
            .await
            .unwrap_err();
        assert!(
            !err.is_transient(),
            "a corrupt cursor never fixes itself by reconnecting"
        );
        assert!(
            err.to_string().contains("invalid browse cursor"),
            "the error names the cause: {err}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no tag-list request is issued at all"
        );
    }

    /// A symbol instance above the 16-bit space survives the round trip: the cursor is reported
    /// verbatim and rides back to the device as a 32-bit (`0x26`) logical instance segment.
    #[tokio::test]
    async fn browse_passes_the_32bit_cursor_through() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        let asked = Arc::new(Mutex::new(Vec::<(u32, u8)>::new()));
        let record = Arc::clone(&asked);
        spawn_device(server_half, move |idx, service, mr| {
            assert_eq!(service, 0x55);
            record.lock().unwrap().push(requested_instance(mr));
            match idx {
                // `0x06` = more data: one record whose instance id is past 0xFFFF.
                0 => (0x06, tag_record(0x0001_0000, "BIG_TAG", 0x00CA)),
                _ => (0x00, Vec::new()),
            }
        });
        let mut session = connect(client_half).await;

        let page = session.browse(None, 100).await.unwrap();
        assert_eq!(page.tags[0].instance_id, 0x0001_0000);
        assert_eq!(
            page.next_cursor.as_deref(),
            Some("65537"),
            "no 16-bit mask, no wrap"
        );

        let next = session.browse(page.next_cursor.clone(), 100).await.unwrap();
        assert!(next.tags.is_empty());
        assert!(next.next_cursor.is_none());

        let asked = asked.lock().unwrap().clone();
        assert_eq!(
            asked[0],
            (0, 0x24),
            "the first page starts at instance 0, 8-bit form"
        );
        assert_eq!(
            asked[1],
            (65_537, 0x26),
            "a 32-bit cursor rides the 0x26 segment"
        );
    }

    /// The regression guard for the start of the walk: an uncursored `sb/browse` enumerates from
    /// symbol instance **0**, so a device whose first symbol sits there has it returned on the first
    /// page. Starting at 1 — as the paging spec originally pinned — drops that record silently and
    /// forever, the same defect class as a truncated page that returns the device's own cursor. The
    /// mock is a device that serves every symbol from the requested instance onward: with a start of
    /// 0 it answers `TAG_0`, with a start of 1 it cannot.
    #[tokio::test]
    async fn an_uncursored_browse_starts_at_instance_zero() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        let asked = Arc::new(Mutex::new(Vec::<(u32, u8)>::new()));
        let record = Arc::clone(&asked);
        spawn_device(server_half, move |_idx, service, mr| {
            assert_eq!(service, 0x55, "get instance attribute list");
            let (start, seg) = requested_instance(mr);
            record.lock().unwrap().push((start, seg));
            let mut data = Vec::new();
            for inst in start..=2 {
                data.extend_from_slice(&tag_record(inst, &format!("TAG_{inst}"), 0x00CA));
            }
            (0x00, data)
        });
        let mut session = connect(client_half).await;

        let page = session.browse(None, 100).await.unwrap();
        assert_eq!(
            names(&page),
            ["TAG_0", "TAG_1", "TAG_2"],
            "a symbol at instance 0 is part of the enumeration, never skipped"
        );
        assert_eq!(page.tags[0].instance_id, 0);
        assert_eq!(
            asked.lock().unwrap().as_slice(),
            [(0, 0x24)],
            "the uncursored walk asks the device to start at instance 0"
        );
    }

    /// A device that answers the very first page with `ServiceNotSupported` has no tag list at all —
    /// the generic-CIP-device path (§10.1). That, and only that, is `BROWSE_UNSUPPORTED`.
    #[tokio::test]
    async fn browse_refused_at_the_first_page_is_an_unsupported_device() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        spawn_device(server_half, |_idx, service, _mr| {
            assert_eq!(service, 0x55);
            (0x08, Vec::new()) // ServiceNotSupported
        });
        let mut session = connect(client_half).await;

        let err = session.browse(None, 100).await.unwrap_err();
        assert!(
            matches!(err, DeviceError::Unsupported("BROWSE_UNSUPPORTED")),
            "no tag-list service at the bottom of the instance space: {err}"
        );
    }

    /// The same CIP `0x08` answering a **resume** is a different fact and must not be reported as the
    /// same one: the device already served a page (that is where the cursor came from), so it plainly
    /// has the service — what it refuses is the mid-set start instance. This mock is the measured
    /// EthernetIPSharp shape (DESIGN §11.7): the whole symbol table from the class-level start
    /// instance 0, `ServiceNotSupported` for every non-zero start. Page 1 at `max: 2` succeeds; the
    /// resume is a failed page (`BROWSE_FAILED`, permanent) naming the instance that was refused —
    /// never `BROWSE_UNSUPPORTED`, which would tell a console the device cannot browse at all
    /// immediately after it browsed.
    #[tokio::test]
    async fn browse_refused_on_a_resume_is_a_failed_page_not_an_unsupported_device() {
        let (client_half, server_half) = tokio::io::duplex(8192);
        spawn_device(server_half, |_idx, service, mr| {
            assert_eq!(service, 0x55);
            let (start, _seg) = requested_instance(mr);
            if start != 0 {
                return (0x08, Vec::new()); // ServiceNotSupported — resume refused
            }
            let mut data = Vec::new();
            for (inst, name) in [(2u32, "LINE_SPEED"), (3, "FILL_TEMP"), (4, "PRODUCT_COUNT")] {
                data.extend_from_slice(&tag_record(inst, name, 0x00CA));
            }
            (0x00, data)
        });
        let mut session = connect(client_half).await;

        let p1 = session.browse(None, 2).await.unwrap();
        assert_eq!(names(&p1), ["LINE_SPEED", "FILL_TEMP"]);
        assert_eq!(p1.next_cursor.as_deref(), Some("4"));

        let err = session.browse(p1.next_cursor.clone(), 2).await.unwrap_err();
        assert!(
            !matches!(err, DeviceError::Unsupported(_)),
            "the service exists — page 1 came from it: {err}"
        );
        assert!(
            !err.is_transient(),
            "the same cursor is refused identically on retry"
        );
        assert!(
            err.to_string()
                .contains("refused to resume the tag list at symbol instance 4"),
            "the failure names what was refused: {err}"
        );
    }

    #[test]
    fn parse_browse_cursor_defaults_to_zero_and_rejects_garbage() {
        assert_eq!(
            parse_browse_cursor(None).unwrap(),
            0,
            "an uncursored browse walks from the start of the instance space, not from 1"
        );
        assert_eq!(parse_browse_cursor(Some("0")).unwrap(), 0);
        assert_eq!(parse_browse_cursor(Some("42")).unwrap(), 42);
        assert_eq!(parse_browse_cursor(Some("  65537  ")).unwrap(), 65_537);
        assert_eq!(parse_browse_cursor(Some("4294967295")).unwrap(), u32::MAX);
        for bad in ["banana", "-1", "4294967296", "", "3.5", "0x10"] {
            let err = parse_browse_cursor(Some(bad)).unwrap_err();
            assert!(!err.is_transient(), "cursor `{bad}` is a caller error");
            assert!(
                err.to_string().contains("invalid browse cursor"),
                "cursor `{bad}`"
            );
        }
    }

    #[test]
    fn paginate_browse_resumes_from_the_last_returned_record_only_when_truncated() {
        let recs = |ids: &[u32]| ids.iter().copied().map(sym).collect::<Vec<_>>();

        // Truncated: the device's cursor (14) is discarded — records 12, 13 must be re-served.
        let (page, next) = paginate_browse(recs(&[10, 11, 12, 13]), Some(14), 2);
        assert_eq!(page.len(), 2);
        assert_eq!(next, Some(12));

        // `max == 0` clamps to 1, so a walk still progresses instead of standing still.
        let (page, next) = paginate_browse(recs(&[10, 11]), Some(12), 0);
        assert_eq!(page.len(), 1);
        assert_eq!(next, Some(11));

        // `len == max` is NOT a truncation: the device is the authority on what follows.
        let (page, next) = paginate_browse(recs(&[10, 11]), Some(99), 2);
        assert_eq!(page.len(), 2);
        assert_eq!(next, Some(99));

        // A short page, and an empty one, pass the device's verdict through unchanged.
        let (page, next) = paginate_browse(recs(&[10]), None, 5);
        assert_eq!(page.len(), 1);
        assert_eq!(next, None);
        let (page, next) = paginate_browse(recs(&[]), Some(7), 5);
        assert!(page.is_empty());
        assert_eq!(next, Some(7));

        // End of the instance space: the walk ends rather than wrapping to 0.
        let (page, next) = paginate_browse(recs(&[u32::MAX, 7]), Some(8), 1);
        assert_eq!(page.len(), 1);
        assert_eq!(next, None);
    }

    /// Browse over the full elementary-type spread plus a structure and an unknown code, exercising the
    /// `symbol_type_name` / `cip_type_name` mapping (§7.5, §5.1). A structure ⇒ "STRUCT"; an unrecognized
    /// code ⇒ its raw hex.
    #[tokio::test]
    async fn browse_maps_every_elementary_type_a_struct_and_an_unknown() {
        // (name, symbol type code, expected type_name).
        let rows: Vec<(&str, u16, &str)> = vec![
            ("B", 0x00C1, "BOOL"),
            ("SI", 0x00C2, "SINT"),
            ("I", 0x00C3, "INT"),
            ("DI", 0x00C4, "DINT"),
            ("LI", 0x00C5, "LINT"),
            ("USI", 0x00C6, "USINT"),
            ("UI", 0x00C7, "UINT"),
            ("UDI", 0x00C8, "UDINT"),
            ("ULI", 0x00C9, "ULINT"),
            ("R", 0x00CA, "REAL"),
            ("LR", 0x00CB, "LREAL"),
            ("UDT", 0x8100, "STRUCT"),
            ("MYSTERY", 0x00FF, "UNKNOWN"),
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
        assert_eq!(
            readings[0].quality_raw.as_deref(),
            Some("NON_FINITE_AFTER_SCALE")
        );
    }

    #[tokio::test]
    async fn a_write_that_fails_to_encode_is_permanent_before_any_io() {
        let (client_half, server_half) = tokio::io::duplex(4096);
        // The device would ack, but a non-numeric value never encodes, so no write is ever sent.
        spawn_device(server_half, |_idx, _service, _mr| (0x00, Vec::new()));
        let mut session = connect(client_half).await;
        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        let err = session
            .write_signal(&sp, &json!("not a number"))
            .await
            .unwrap_err();
        assert!(
            !err.is_transient(),
            "a coercion failure is permanent, not a link error"
        );
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
        assert!(
            !err.is_transient(),
            "a CIP-rejected write is permanent for this value"
        );
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
        assert!(
            session.probe().await.is_err(),
            "a probe over a dropped link fails"
        );
    }
}
