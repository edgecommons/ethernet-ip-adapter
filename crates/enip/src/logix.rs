//! Allen-Bradley Logix tag services (PROTOCOL-DESIGN §7.2–§7.4).
//!
//! Read Tag (`0x4C`) / Write Tag (`0x4D`) with **auto-fragmentation** (`0x52`/`0x53`, D-ENIP-12),
//! Get Instance Attribute List (`0x55`) tag enumeration with paging, and the [`SymbolType`] word
//! decode. The Symbol-object service codes live here and never cross into [`crate::cm`] (where
//! `0x52`/`0x4E` mean Unconnected_Send / Forward_Close against the Connection Manager, §7.2).
//!
//! The pure encoders/decoders (`SymbolType`, [`SymbolInfo`] record parsing) carry no I/O. The
//! request-driving methods hang off [`EipClient`] and reassemble fragmented transfers so the caller
//! asks for a tag and gets the whole value or a typed error — never a fragment.

use crate::cip::epath::{EPath, TagAddress};
use crate::cip::message::MessageRequest;
use crate::cip::types::{CipType, CipValue};
use crate::client::EipClient;
use crate::error::{EnipError, Result, WireError};
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "logix";

/// Read Tag service (§7.2).
pub const SERVICE_READ_TAG: u8 = 0x4C;
/// Write Tag service (§7.2).
pub const SERVICE_WRITE_TAG: u8 = 0x4D;
/// Read Tag Fragmented service (§7.2).
pub const SERVICE_READ_TAG_FRAGMENTED: u8 = 0x52;
/// Write Tag Fragmented service (§7.2).
pub const SERVICE_WRITE_TAG_FRAGMENTED: u8 = 0x53;
/// Get Instance Attribute List service (§7.3).
pub const SERVICE_GET_INSTANCE_ATTRIBUTE_LIST: u8 = 0x55;
/// The Symbol object class (§7.3).
pub const CLASS_SYMBOL: u16 = 0x6B;

/// The decoded symbol-type word (§7.4). `bit 15` structure flag, `bits 13–14` array dims (0–3);
/// atomic `bits 0–7` type code (bool adds `bits 8–10` bit position); structure `bits 0–11` template
/// instance (`> 0xEFF` ⇒ system-predefined).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolType(pub u16);

impl SymbolType {
    /// Whether the symbol is a structure (bit 15).
    #[must_use]
    pub fn is_struct(self) -> bool {
        self.0 & (1 << 15) != 0
    }

    /// Whether the symbol is an atomic elementary type (not a structure).
    #[must_use]
    pub fn is_atomic(self) -> bool {
        !self.is_struct()
    }

    /// Array dimensionality (0–3), `bits 13–14`.
    #[must_use]
    pub fn dims(self) -> u8 {
        ((self.0 >> 13) & 0b11) as u8
    }

    /// The atomic CIP type code (`bits 0–7`), or `None` for a structure.
    #[must_use]
    pub fn type_code(self) -> Option<u8> {
        if self.is_struct() {
            None
        } else {
            Some((self.0 & 0xFF) as u8)
        }
    }

    /// The atomic type as a [`CipType`], or `None` for a structure.
    #[must_use]
    pub fn cip_type(self) -> Option<CipType> {
        self.type_code().map(|c| CipType::from_code(u16::from(c)))
    }

    /// Whether the atomic type is BOOL (`0xC1`), so [`SymbolType::bit_position`] applies.
    #[must_use]
    pub fn is_bool(self) -> bool {
        self.type_code() == Some(0xC1)
    }

    /// The bit position (0–7) for a BOOL symbol (`bits 8–10`), or `None` otherwise.
    #[must_use]
    pub fn bit_position(self) -> Option<u8> {
        if self.is_bool() {
            Some(((self.0 >> 8) & 0b111) as u8)
        } else {
            None
        }
    }

    /// The template instance id for a structure (`bits 0–11`), or `None` for an atomic type.
    #[must_use]
    pub fn template_instance(self) -> Option<u16> {
        if self.is_struct() {
            Some(self.0 & 0x0FFF)
        } else {
            None
        }
    }

    /// Whether a structure is a system-predefined template (`template instance > 0xEFF`).
    #[must_use]
    pub fn is_system_predefined(self) -> bool {
        self.template_instance().is_some_and(|v| v > 0xEFF)
    }

    /// Whether the crate can decode this symbol's *value* — an atomic, non-array elementary type.
    /// Structures, strings, and multi-dimensional tags are reported but not value-decoded (§1
    /// non-goals); the adapter marks them `supported: false`.
    #[must_use]
    pub fn is_value_supported(self) -> bool {
        !self.is_struct()
            && self.dims() == 0
            && self.cip_type().is_some_and(CipType::is_elementary)
    }
}

/// One symbol instance from a Get Instance Attribute List page (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The symbol instance id.
    pub instance_id: u32,
    /// The tag name (checked UTF-8 — the `from_utf8_unchecked` fix, §4 invariant 4).
    pub name: String,
    /// The symbol type word.
    pub symbol_type: SymbolType,
}

impl SymbolInfo {
    /// Decode one Get-Instance-Attribute-List record from the cursor (§7.3): `u32 instance_id,
    /// u16 name_length, name bytes (checked UTF-8), u16 symbol_type`.
    fn decode(r: &mut WireReader<'_>) -> core::result::Result<Self, WireError> {
        let instance_id = r.u32()?;
        let name_len = r.u16()? as usize;
        let name_bytes = r.take(name_len)?;
        let name = core::str::from_utf8(name_bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8 { context: CONTEXT })?;
        let symbol_type = SymbolType(r.u16()?);
        Ok(Self {
            instance_id,
            name,
            symbol_type,
        })
    }
}

/// The scope a tag enumeration runs in (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Controller-scoped tags.
    Controller,
    /// Program-scoped tags (`Program:<name>`), prefixed as a symbolic segment before the class path.
    Program(String),
}

/// The result of a Read Tag (§7.2): the decoded value, the wire-declared type (D-ENIP-4), and
/// whether the crate had to fragment the transfer to assemble it.
#[derive(Debug, Clone, PartialEq)]
pub struct TagReadResult {
    /// The decoded value.
    pub value: CipValue,
    /// The type code the reply declared.
    pub wire_type: CipType,
    /// Whether the value was reassembled from `0x52` fragments.
    pub fragmented: bool,
}

impl EipClient {
    /// Read a tag (§7.2). Issues Read Tag (`0x4C`) for `elements` elements; on a partial transfer
    /// (`0x06`) or reply-too-large (`0x11`) it transparently switches to fragmented reads (`0x52`),
    /// reassembling up to `max_value_bytes` (D-ENIP-12) before decoding. A per-tag CIP error is
    /// returned as `Err(Cip(..))` for the adapter to map to a BAD sample.
    pub async fn read_tag(&self, tag: &TagAddress, elements: u16) -> Result<TagReadResult> {
        let mut req_data = WireWriter::with_capacity(2);
        req_data.u16(elements);
        let mr = MessageRequest::new(SERVICE_READ_TAG, tag.path().clone(), req_data.into_bytes());
        let reply = self.send_cip(mr, "read_tag").await?;
        reply.expect_service(SERVICE_READ_TAG)?;

        if reply.status.is_ok() {
            let (wire_type, value) = CipValue::decode_tagged(&reply.data)?;
            return Ok(TagReadResult {
                value,
                wire_type,
                fragmented: false,
            });
        }

        // Partial transfer or reply-too-large ⇒ drive the fragmented read (D-ENIP-12).
        if reply.status.has_more()
            || matches!(
                reply.status.general,
                crate::cip::status::GeneralStatus::ReplyDataTooLarge
            )
        {
            return self.read_tag_fragmented(tag, elements).await;
        }

        Err(EnipError::Cip(reply.status))
    }

    /// The fragmented read loop (§7.2, D-ENIP-12): re-reads from offset 0 with `0x52`, accumulating
    /// each fragment's value bytes until a final `status 0`, capped by `max_value_bytes`.
    async fn read_tag_fragmented(
        &self,
        tag: &TagAddress,
        elements: u16,
    ) -> Result<TagReadResult> {
        let cap = self.max_value_bytes();
        let mut offset: u32 = 0;
        let mut acc: Vec<u8> = Vec::new();
        let mut wire_type: Option<CipType> = None;
        let mut struct_handle: Option<u16> = None;

        loop {
            let mut req_data = WireWriter::with_capacity(6);
            req_data.u16(elements);
            req_data.u32(offset);
            let mr = MessageRequest::new(
                SERVICE_READ_TAG_FRAGMENTED,
                tag.path().clone(),
                req_data.into_bytes(),
            );
            let reply = self.send_cip(mr, "read_tag_fragmented").await?;
            reply.expect_service(SERVICE_READ_TAG_FRAGMENTED)?;

            let more = reply.status.has_more();
            if !reply.status.is_ok() && !more {
                return Err(EnipError::Cip(reply.status));
            }

            // Each fragment repeats the leading type code (+ handle for a struct).
            let mut r = WireReader::with_context(&reply.data, CONTEXT);
            let code = r.u16()?;
            let ty = *wire_type.get_or_insert(CipType::from_code(code));
            if matches!(ty, CipType::Struct) {
                let handle = r.u16()?;
                struct_handle.get_or_insert(handle);
            }
            let value_bytes = r.take_rest();

            let new_len = acc
                .len()
                .checked_add(value_bytes.len())
                .ok_or(EnipError::TooLarge { limit: cap })?;
            if new_len > cap {
                return Err(EnipError::TooLarge { limit: cap });
            }
            acc.extend_from_slice(value_bytes);
            let advance = u32::try_from(value_bytes.len()).map_err(|_| EnipError::TooLarge { limit: cap })?;
            offset = offset.checked_add(advance).ok_or(EnipError::TooLarge { limit: cap })?;

            if !more {
                break;
            }
            // Defend against a peer that keeps replying `0x06` with no forward progress.
            if value_bytes.is_empty() {
                return Err(EnipError::ProtocolViolation {
                    detail: "fragmented read made no progress",
                });
            }
        }

        let ty = wire_type.unwrap_or(CipType::Unknown(0));
        let value = build_fragment_value(ty, struct_handle, &acc)?;
        Ok(TagReadResult {
            value,
            wire_type: ty,
            fragmented: true,
        })
    }

    /// Write a tag (§7.2). Encodes the value and issues Write Tag (`0x4D`); if the encoded request
    /// would exceed the session's usable request size it chunks via Write Tag Fragmented (`0x53`) on
    /// element boundaries (D-ENIP-12). Structures/strings cannot be written (`Unsupported`).
    pub async fn write_tag(&self, tag: &TagAddress, ty: CipType, value: &CipValue) -> Result<()> {
        let element_size = ty.element_size().ok_or(EnipError::Unsupported {
            what: "write of non-elementary type",
        })?;
        let mut value_buf = WireWriter::new();
        value
            .encode_value(&mut value_buf)
            .map_err(EnipError::Malformed)?;
        let value_bytes = value_buf.into_bytes();
        let element_count = u16::try_from(value.element_count()).map_err(|_| EnipError::TooLarge { limit: u16::MAX as usize })?;

        // Single-packet write when the value fits comfortably in the usable request size.
        let usable = self.max_request_bytes();
        // header for 0x4D: type(2) + count(2); fragmented 0x53: type(2)+count(2)+offset(4).
        if value_bytes.len().saturating_add(8) <= usable {
            let mut data = WireWriter::with_capacity(value_bytes.len().saturating_add(4));
            data.u16(ty.code());
            data.u16(element_count);
            data.put_slice(&value_bytes);
            let mr = MessageRequest::new(SERVICE_WRITE_TAG, tag.path().clone(), data.into_bytes());
            let reply = self.send_cip(mr, "write_tag").await?;
            reply.expect_service(SERVICE_WRITE_TAG)?;
            if reply.status.is_ok() {
                return Ok(());
            }
            return Err(EnipError::Cip(reply.status));
        }

        // Fragmented write: chunk on element boundaries so no partial element is split.
        let chunk_elems = usable.saturating_sub(12).checked_div(element_size).unwrap_or(0).max(1);
        let chunk_bytes = chunk_elems.checked_mul(element_size).unwrap_or(element_size);
        let mut offset: u32 = 0;
        let mut sent = 0usize;
        while sent < value_bytes.len() {
            let end = sent.checked_add(chunk_bytes).unwrap_or(value_bytes.len()).min(value_bytes.len());
            let chunk = value_bytes.get(sent..end).unwrap_or(&[]);
            let mut data = WireWriter::with_capacity(chunk.len().saturating_add(8));
            data.u16(ty.code());
            data.u16(element_count);
            data.u32(offset);
            data.put_slice(chunk);
            let mr = MessageRequest::new(
                SERVICE_WRITE_TAG_FRAGMENTED,
                tag.path().clone(),
                data.into_bytes(),
            );
            let reply = self.send_cip(mr, "write_tag_fragmented").await?;
            reply.expect_service(SERVICE_WRITE_TAG_FRAGMENTED)?;
            if !reply.status.is_ok() && !reply.status.has_more() {
                return Err(EnipError::Cip(reply.status));
            }
            let advance = u32::try_from(chunk.len()).map_err(|_| EnipError::TooLarge { limit: u32::MAX as usize })?;
            offset = offset.checked_add(advance).ok_or(EnipError::TooLarge { limit: u32::MAX as usize })?;
            sent = end;
        }
        Ok(())
    }

    /// Enumerate one page of tags (§7.3): Get Instance Attribute List (`0x55`) starting at
    /// `start_instance`. Returns the page's [`SymbolInfo`] records and, when the reply signalled more
    /// (`0x06`), the next start instance (`last_id + 1`). Paging policy stays with the caller.
    pub async fn list_tags(
        &self,
        start_instance: u16,
        scope: &Scope,
    ) -> Result<(Vec<SymbolInfo>, Option<u16>)> {
        let mut path = match scope {
            Scope::Controller => EPath::new(),
            Scope::Program(name) => EPath::new().symbol(format!("Program:{name}")),
        };
        path = path.class(CLASS_SYMBOL).instance(start_instance);

        let mut data = WireWriter::with_capacity(6);
        data.u16(2); // attribute count
        data.u16(1); // attribute 1 — symbol name
        data.u16(2); // attribute 2 — symbol type
        let mr = MessageRequest::new(SERVICE_GET_INSTANCE_ATTRIBUTE_LIST, path, data.into_bytes());
        let reply = self.send_cip(mr, "list_tags").await?;
        reply.expect_service(SERVICE_GET_INSTANCE_ATTRIBUTE_LIST)?;

        let more = reply.status.has_more();
        if !reply.status.is_ok() && !more {
            return Err(EnipError::Cip(reply.status));
        }

        let mut r = WireReader::with_context(&reply.data, CONTEXT);
        let mut records = Vec::new();
        while r.remaining() > 0 {
            // A record that fails to decode fails the whole page (never a silent partial, §7.3).
            records.push(SymbolInfo::decode(&mut r)?);
        }

        let next = if more {
            records
                .last()
                .map(|s| s.instance_id)
                .and_then(|id| u16::try_from(id & 0xFFFF).ok())
                .and_then(|id| id.checked_add(1))
        } else {
            None
        };
        Ok((records, next))
    }
}

/// Build the final [`CipValue`] from a reassembled fragmented read's bytes.
fn build_fragment_value(
    ty: CipType,
    struct_handle: Option<u16>,
    acc: &[u8],
) -> Result<CipValue> {
    match ty {
        CipType::Struct => Ok(CipValue::Struct {
            handle: struct_handle.unwrap_or(0),
            bytes_len: acc.len(),
        }),
        CipType::String | CipType::Unknown(_) => Ok(CipValue::Unsupported {
            type_code: ty.code(),
            bytes_len: acc.len(),
        }),
        elementary => CipValue::decode(elementary, acc).map_err(EnipError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn symbol_type_atomic_dint() {
        // DINT (0xC4), no dims, atomic.
        let st = SymbolType(0x00C4);
        assert!(st.is_atomic());
        assert!(!st.is_struct());
        assert_eq!(st.dims(), 0);
        assert_eq!(st.type_code(), Some(0xC4));
        assert_eq!(st.cip_type(), Some(CipType::Dint));
        assert!(st.is_value_supported());
        assert_eq!(st.bit_position(), None);
    }

    #[test]
    fn symbol_type_bool_bit_position() {
        // BOOL (0xC1) at bit position 5: bits 8-10 = 5.
        let st = SymbolType((5 << 8) | 0xC1);
        assert!(st.is_bool());
        assert_eq!(st.bit_position(), Some(5));
        assert!(st.is_value_supported());
    }

    #[test]
    fn symbol_type_struct_and_array_unsupported() {
        // struct flag set, template 0x0104.
        let st = SymbolType((1 << 15) | 0x0104);
        assert!(st.is_struct());
        assert_eq!(st.template_instance(), Some(0x0104));
        assert!(!st.is_value_supported());
        assert!(!st.is_system_predefined());

        // system-predefined struct.
        let sys = SymbolType((1 << 15) | 0x0F01);
        assert!(sys.is_system_predefined());

        // atomic but 1-D array → value not decoded here.
        let arr = SymbolType((1 << 13) | 0x00C4);
        assert_eq!(arr.dims(), 1);
        assert!(!arr.is_value_supported());
    }

    #[test]
    fn symbol_info_record_decodes_checked_utf8() {
        let mut w = WireWriter::new();
        w.u32(0x0001_0000); // instance
        w.u16(4); // name length
        w.put_slice(b"Tag1");
        w.u16(0x00C4); // DINT
        let mut r = WireReader::new(w.as_slice());
        let info = SymbolInfo::decode(&mut r).unwrap();
        assert_eq!(info.instance_id, 0x0001_0000);
        assert_eq!(info.name, "Tag1");
        assert_eq!(info.symbol_type.cip_type(), Some(CipType::Dint));

        // Bad UTF-8 in the name is rejected, not UB.
        let mut bad = WireWriter::new();
        bad.u32(1);
        bad.u16(1);
        bad.put_slice(&[0xFF]);
        bad.u16(0x00C4);
        let mut r = WireReader::new(bad.as_slice());
        assert!(matches!(
            SymbolInfo::decode(&mut r),
            Err(WireError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn build_fragment_value_decodes_dint_array() {
        let mut w = WireWriter::new();
        for v in [1i32, 2, 3] {
            w.i32(v);
        }
        let v = build_fragment_value(CipType::Dint, None, w.as_slice()).unwrap();
        assert_eq!(
            v,
            CipValue::Array(
                CipType::Dint,
                vec![CipValue::Dint(1), CipValue::Dint(2), CipValue::Dint(3)]
            )
        );
    }
}
