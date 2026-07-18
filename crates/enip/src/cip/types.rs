//! CIP elementary data types (PROTOCOL-DESIGN §6.3).
//!
//! [`CipType`] is the wire type-code set (elementary scalars, the bit-string aliases, the STRING
//! and structure markers) with a total [`CipType::from_code`] — an unknown code becomes
//! [`CipType::Unknown`] (invariant 5 of §4). [`CipValue`] is the crate's value type: one variant
//! per supported scalar, plus `Array`, the opaque `Struct` marker, and `Unsupported` for
//! STRING/unknown types (decode-by-wire-declared-type, D-ENIP-4 — a type we cannot interpret
//! becomes *data*, not a decode error). Value decode/encode is checked end-to-end via
//! [`crate::wire`].

use crate::error::WireError;
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "cip value";

/// A CIP elementary data-type code (§6.3). `#[non_exhaustive]`; unknown codes are
/// [`CipType::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipType {
    /// `0xC1` BOOL — wire `u8`, 0 = false, non-zero = true; write emits `0xFF`/`0x00`.
    Bool,
    /// `0xC2` SINT — `i8`.
    Sint,
    /// `0xC3` INT — `i16`.
    Int,
    /// `0xC4` DINT — `i32`.
    Dint,
    /// `0xC5` LINT — `i64`.
    Lint,
    /// `0xC6` USINT — `u8`.
    Usint,
    /// `0xC7` UINT — `u16`.
    Uint,
    /// `0xC8` UDINT — `u32`.
    Udint,
    /// `0xC9` ULINT — `u64`.
    Ulint,
    /// `0xCA` REAL — `f32`.
    Real,
    /// `0xCB` LREAL — `f64`.
    Lreal,
    /// `0xD1` BYTE — bit-string alias of `u8`.
    Byte,
    /// `0xD2` WORD — bit-string alias of `u16`.
    Word,
    /// `0xD3` DWORD — bit-string alias of `u32`.
    Dword,
    /// `0xD4` LWORD — bit-string alias of `u64`.
    Lword,
    /// `0xD0` STRING — not decoded (surfaced as [`CipValue::Unsupported`]).
    String,
    /// `0x02A0` structure marker — the following `u16` is the template handle; not decoded.
    Struct,
    /// Any other type code (§4 invariant 5).
    Unknown(u16),
}

impl CipType {
    /// Decode from a wire type code — total.
    #[must_use]
    pub fn from_code(code: u16) -> Self {
        match code {
            0xC1 => Self::Bool,
            0xC2 => Self::Sint,
            0xC3 => Self::Int,
            0xC4 => Self::Dint,
            0xC5 => Self::Lint,
            0xC6 => Self::Usint,
            0xC7 => Self::Uint,
            0xC8 => Self::Udint,
            0xC9 => Self::Ulint,
            0xCA => Self::Real,
            0xCB => Self::Lreal,
            0xD1 => Self::Byte,
            0xD2 => Self::Word,
            0xD3 => Self::Dword,
            0xD4 => Self::Lword,
            0xD0 => Self::String,
            0x02A0 => Self::Struct,
            other => Self::Unknown(other),
        }
    }

    /// The wire type code.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Bool => 0xC1,
            Self::Sint => 0xC2,
            Self::Int => 0xC3,
            Self::Dint => 0xC4,
            Self::Lint => 0xC5,
            Self::Usint => 0xC6,
            Self::Uint => 0xC7,
            Self::Udint => 0xC8,
            Self::Ulint => 0xC9,
            Self::Real => 0xCA,
            Self::Lreal => 0xCB,
            Self::Byte => 0xD1,
            Self::Word => 0xD2,
            Self::Dword => 0xD3,
            Self::Lword => 0xD4,
            Self::String => 0xD0,
            Self::Struct => 0x02A0,
            Self::Unknown(v) => v,
        }
    }

    /// The fixed on-wire size in bytes of one element, for the elementary types. STRING, the
    /// structure marker, and unknown types have no fixed element size (`None`).
    #[must_use]
    pub fn element_size(self) -> Option<usize> {
        Some(match self {
            Self::Bool | Self::Sint | Self::Usint | Self::Byte => 1,
            Self::Int | Self::Uint | Self::Word => 2,
            Self::Dint | Self::Udint | Self::Real | Self::Dword => 4,
            Self::Lint | Self::Ulint | Self::Lreal | Self::Lword => 8,
            Self::String | Self::Struct | Self::Unknown(_) => return None,
        })
    }

    /// Whether this is a decodable elementary scalar (has a fixed element size).
    #[must_use]
    pub fn is_elementary(self) -> bool {
        self.element_size().is_some()
    }
}

/// A decoded CIP value (§6.3). One variant per supported scalar, plus a contiguous `Array`, the
/// opaque `Struct` marker, and `Unsupported` for STRING/unknown types. The adapter owns any
/// JSON conversion at its `device.rs` seam.
#[derive(Debug, Clone, PartialEq)]
pub enum CipValue {
    /// BOOL.
    Bool(bool),
    /// SINT.
    Sint(i8),
    /// INT.
    Int(i16),
    /// DINT.
    Dint(i32),
    /// LINT.
    Lint(i64),
    /// USINT.
    Usint(u8),
    /// UINT.
    Uint(u16),
    /// UDINT.
    Udint(u32),
    /// ULINT.
    Ulint(u64),
    /// REAL.
    Real(f32),
    /// LREAL.
    Lreal(f64),
    /// BYTE.
    Byte(u8),
    /// WORD.
    Word(u16),
    /// DWORD.
    Dword(u32),
    /// LWORD.
    Lword(u64),
    /// A contiguous array of `N` elements of the given elementary type.
    Array(CipType, Vec<CipValue>),
    /// A structure value — detected, not decoded (§1 non-goals): the template handle plus the raw
    /// byte length that followed the marker.
    Struct {
        /// The template instance handle from the `0x02A0` marker.
        handle: u16,
        /// The number of value bytes that followed (not interpreted).
        bytes_len: usize,
    },
    /// A STRING or unknown-typed value the crate does not interpret — carried as data so a type
    /// mismatch becomes a BAD sample at the adapter, not a decode error (D-ENIP-4).
    Unsupported {
        /// The wire type code that was declared.
        type_code: u16,
        /// The number of value bytes that followed.
        bytes_len: usize,
    },
}

impl CipValue {
    /// The wire type of this value (the element type for an array; `Struct`/`Unknown` markers for
    /// the opaque variants).
    #[must_use]
    pub fn wire_type(&self) -> CipType {
        match self {
            Self::Bool(_) => CipType::Bool,
            Self::Sint(_) => CipType::Sint,
            Self::Int(_) => CipType::Int,
            Self::Dint(_) => CipType::Dint,
            Self::Lint(_) => CipType::Lint,
            Self::Usint(_) => CipType::Usint,
            Self::Uint(_) => CipType::Uint,
            Self::Udint(_) => CipType::Udint,
            Self::Ulint(_) => CipType::Ulint,
            Self::Real(_) => CipType::Real,
            Self::Lreal(_) => CipType::Lreal,
            Self::Byte(_) => CipType::Byte,
            Self::Word(_) => CipType::Word,
            Self::Dword(_) => CipType::Dword,
            Self::Lword(_) => CipType::Lword,
            Self::Array(ty, _) => *ty,
            Self::Struct { .. } => CipType::Struct,
            Self::Unsupported { type_code, .. } => CipType::from_code(*type_code),
        }
    }

    /// Decode one elementary scalar of `ty` from the cursor. `ty` must be elementary (callers pass
    /// only elementary types here).
    fn decode_scalar(ty: CipType, r: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(match ty {
            CipType::Bool => Self::Bool(r.u8()? != 0),
            CipType::Sint => Self::Sint(r.i8()?),
            CipType::Int => Self::Int(r.i16()?),
            CipType::Dint => Self::Dint(r.i32()?),
            CipType::Lint => Self::Lint(r.i64()?),
            CipType::Usint => Self::Usint(r.u8()?),
            CipType::Uint => Self::Uint(r.u16()?),
            CipType::Udint => Self::Udint(r.u32()?),
            CipType::Ulint => Self::Ulint(r.u64()?),
            CipType::Real => Self::Real(r.f32()?),
            CipType::Lreal => Self::Lreal(r.f64()?),
            CipType::Byte => Self::Byte(r.u8()?),
            CipType::Word => Self::Word(r.u16()?),
            CipType::Dword => Self::Dword(r.u32()?),
            CipType::Lword => Self::Lword(r.u64()?),
            // Non-elementary types never reach here.
            CipType::String | CipType::Struct | CipType::Unknown(_) => {
                return Err(WireError::Malformed {
                    context: CONTEXT,
                    detail: "non-elementary type in scalar decode",
                })
            }
        })
    }

    /// Decode a value of a wire-declared elementary type from `data`, deriving the element count
    /// from `data.len() / element_size` (a non-integral division is `Malformed`, invariant 2). One
    /// element yields a scalar; more yield an [`CipValue::Array`]. Callers use
    /// [`CipValue::decode_tagged`] when the buffer still carries the leading type code.
    pub fn decode(ty: CipType, data: &[u8]) -> Result<Self, WireError> {
        let size = match ty.element_size() {
            Some(s) => s,
            None => {
                return Err(WireError::Malformed {
                    context: CONTEXT,
                    detail: "type has no fixed element size",
                })
            }
        };
        let count = data.len().checked_div(size).ok_or(WireError::Overflow { context: CONTEXT })?;
        let rem = data.len().checked_rem(size).ok_or(WireError::Overflow { context: CONTEXT })?;
        if rem != 0 {
            return Err(WireError::Malformed {
                context: CONTEXT,
                detail: "value length not a multiple of element size",
            });
        }
        if count == 0 {
            return Err(WireError::Truncated {
                needed: size,
                remaining: 0,
                context: CONTEXT,
            });
        }
        let mut r = WireReader::with_context(data, CONTEXT);
        if count == 1 {
            let v = Self::decode_scalar(ty, &mut r)?;
            r.expect_end()?;
            return Ok(v);
        }
        // `count` is bounded by `data.len()` (each element is >= 1 byte), so the reservation is
        // bounded by the input (invariant 3).
        let mut elems = Vec::with_capacity(count);
        for _ in 0..count {
            elems.push(Self::decode_scalar(ty, &mut r)?);
        }
        r.expect_end()?;
        Ok(Self::Array(ty, elems))
    }

    /// Decode a *tagged* value: a leading `u16` type code (plus the `u16` handle for the structure
    /// marker) followed by the value bytes — the Read-Tag reply data shape (§7.2). STRING and
    /// unknown types are surfaced as [`CipValue::Unsupported`] carrying the raw byte length.
    /// Returns the declared [`CipType`] alongside the value.
    pub fn decode_tagged(data: &[u8]) -> Result<(CipType, Self), WireError> {
        let mut r = WireReader::with_context(data, CONTEXT);
        let code = r.u16()?;
        let ty = CipType::from_code(code);
        match ty {
            CipType::Struct => {
                let handle = r.u16()?;
                let bytes_len = r.remaining();
                let _ = r.take_rest();
                Ok((ty, Self::Struct { handle, bytes_len }))
            }
            CipType::String | CipType::Unknown(_) => {
                let bytes_len = r.remaining();
                let _ = r.take_rest();
                Ok((
                    ty,
                    Self::Unsupported {
                        type_code: code,
                        bytes_len,
                    },
                ))
            }
            elementary => {
                let rest = r.take_rest();
                let value = Self::decode(elementary, rest)?;
                Ok((elementary, value))
            }
        }
    }

    /// Encode the raw value bytes (no type prefix). BOOL emits `0xFF`/`0x00` per §6.3. `Struct`,
    /// `Unsupported`, and arrays of non-elementary types cannot be encoded (write is unsupported).
    pub fn encode_value(&self, w: &mut WireWriter) -> Result<(), WireError> {
        match self {
            Self::Bool(v) => w.u8(if *v { 0xFF } else { 0x00 }),
            Self::Sint(v) => w.i8(*v),
            Self::Int(v) => w.i16(*v),
            Self::Dint(v) => w.i32(*v),
            Self::Lint(v) => w.i64(*v),
            Self::Usint(v) => w.u8(*v),
            Self::Uint(v) => w.u16(*v),
            Self::Udint(v) => w.u32(*v),
            Self::Ulint(v) => w.u64(*v),
            Self::Real(v) => w.f32(*v),
            Self::Lreal(v) => w.f64(*v),
            Self::Byte(v) => w.u8(*v),
            Self::Word(v) => w.u16(*v),
            Self::Dword(v) => w.u32(*v),
            Self::Lword(v) => w.u64(*v),
            Self::Array(_, elems) => {
                for e in elems {
                    e.encode_value(w)?;
                }
            }
            Self::Struct { .. } | Self::Unsupported { .. } => {
                return Err(WireError::Malformed {
                    context: CONTEXT,
                    detail: "cannot encode struct/unsupported value",
                })
            }
        }
        Ok(())
    }

    /// The number of elements this value represents on the wire (arrays report their length; the
    /// opaque markers report 1).
    #[must_use]
    pub fn element_count(&self) -> usize {
        match self {
            Self::Array(_, elems) => elems.len(),
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn type_code_roundtrips() {
        for code in [
            0xC1u16, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xD0, 0xD1, 0xD2,
            0xD3, 0xD4, 0x02A0,
        ] {
            assert_eq!(CipType::from_code(code).code(), code);
        }
    }

    #[test]
    fn unknown_type_is_total() {
        assert_eq!(CipType::from_code(0x00AB), CipType::Unknown(0x00AB));
        assert_eq!(CipType::from_code(0x00AB).element_size(), None);
    }

    #[test]
    fn scalar_roundtrip_each_type() {
        let cases = [
            CipValue::Bool(true),
            CipValue::Sint(-5),
            CipValue::Int(-1234),
            CipValue::Dint(-123456),
            CipValue::Lint(-1_000_000_000_000),
            CipValue::Usint(200),
            CipValue::Uint(50000),
            CipValue::Udint(4_000_000_000),
            CipValue::Ulint(18_000_000_000_000_000_000),
            CipValue::Real(3.5),
            CipValue::Lreal(2.5),
            CipValue::Byte(0xAB),
            CipValue::Word(0xBEEF),
            CipValue::Dword(0xDEAD_BEEF),
            CipValue::Lword(0x0102_0304_0506_0708),
        ];
        for original in cases {
            let mut w = WireWriter::new();
            original.encode_value(&mut w).unwrap();
            let decoded = CipValue::decode(original.wire_type(), w.as_slice()).unwrap();
            // BOOL roundtrips true<->0xFF; equality holds because decode maps non-zero to true.
            assert_eq!(decoded, original, "type {:?}", original.wire_type());
        }
    }

    #[test]
    fn array_decode_and_count() {
        // Four DINTs: 1, 2, 3, 4.
        let mut w = WireWriter::new();
        for v in [1i32, 2, 3, 4] {
            w.i32(v);
        }
        let v = CipValue::decode(CipType::Dint, w.as_slice()).unwrap();
        assert_eq!(
            v,
            CipValue::Array(
                CipType::Dint,
                vec![
                    CipValue::Dint(1),
                    CipValue::Dint(2),
                    CipValue::Dint(3),
                    CipValue::Dint(4)
                ]
            )
        );
        assert_eq!(v.element_count(), 4);
    }

    #[test]
    fn non_integral_length_is_malformed() {
        // 5 bytes is not a multiple of 4 (DINT).
        let data = [0u8; 5];
        assert!(matches!(
            CipValue::decode(CipType::Dint, &data),
            Err(WireError::Malformed { .. })
        ));
    }

    #[test]
    fn tagged_struct_is_detected_not_decoded() {
        // 0x02A0 marker, handle 0x1234, then 6 opaque bytes.
        let mut w = WireWriter::new();
        w.u16(0x02A0);
        w.u16(0x1234);
        w.put_slice(&[0, 1, 2, 3, 4, 5]);
        let (ty, v) = CipValue::decode_tagged(w.as_slice()).unwrap();
        assert_eq!(ty, CipType::Struct);
        assert_eq!(
            v,
            CipValue::Struct {
                handle: 0x1234,
                bytes_len: 6
            }
        );
    }

    #[test]
    fn tagged_string_is_unsupported_not_error() {
        let mut w = WireWriter::new();
        w.u16(0xD0); // STRING
        w.put_slice(&[0xAA, 0xBB]);
        let (ty, v) = CipValue::decode_tagged(w.as_slice()).unwrap();
        assert_eq!(ty, CipType::String);
        assert!(matches!(v, CipValue::Unsupported { type_code: 0xD0, bytes_len: 2 }));
    }
}
