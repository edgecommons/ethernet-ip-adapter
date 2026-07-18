//! Assembly layout mapping (PROTOCOL-DESIGN §9, D-ENIP-11).
//!
//! [`AssemblyLayout`]: bounds-checked extraction/insertion of typed fields (offset/type/bit) from
//! raw assembly bytes. Field *naming and configuration* stays in the adapter; only the byte math
//! lives here, inside the fuzz boundary (§12.3). The layout is **validated at construction** so
//! runtime [`AssemblyLayout::decode`] / [`AssemblyLayout::encode_into`] cannot go out of bounds *by
//! construction* — every field is proven to fit `data_size` before any wire byte is touched.
//!
//! The crate never sees signal names, UNS channels, scaling, or deadbands — those are adapter
//! concerns applied to the `(key, CipValue)` pairs (D-ENIP-11).

use crate::cip::types::{CipType, CipValue};
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "assembly";

/// One field within an assembly (§9). `key` is a caller-supplied index the adapter maps back to a
/// signal — the crate never interprets it. Elementary types only; `bit` selects a single bit within
/// the byte at `offset` (packed booleans); `count` > 1 is a contiguous array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    /// Caller-supplied field index (opaque to the crate).
    pub key: usize,
    /// Byte offset into the assembly data.
    pub offset: usize,
    /// The elementary CIP type of each element.
    pub ty: CipType,
    /// For a packed boolean: the bit (0–7) within the byte at `offset`. `Some` requires
    /// [`CipType::Bool`] and `count == 1`.
    pub bit: Option<u8>,
    /// Element count: `1` = scalar, `N` = a contiguous array of `N` elements.
    pub count: usize,
}

impl FieldSpec {
    /// A scalar field of `ty` at `offset` mapped to `key`.
    #[must_use]
    pub fn scalar(key: usize, offset: usize, ty: CipType) -> Self {
        Self { key, offset, ty, bit: None, count: 1 }
    }

    /// An `count`-element array field of `ty` at `offset` mapped to `key`.
    #[must_use]
    pub fn array(key: usize, offset: usize, ty: CipType, count: usize) -> Self {
        Self { key, offset, ty, bit: None, count }
    }

    /// A packed-boolean field: `bit` (0–7) within the byte at `offset`, mapped to `key`.
    #[must_use]
    pub fn boolean(key: usize, offset: usize, bit: u8) -> Self {
        Self { key, offset, ty: CipType::Bool, bit: Some(bit), count: 1 }
    }
}

/// A layout validation / runtime error (§9). The adapter turns [`AssemblyError`] from
/// [`AssemblyLayout::new`] into a config-validation failure at startup; the runtime variants are
/// returned by [`AssemblyLayout::decode`] / [`AssemblyLayout::encode_into`] and are never panics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblyError {
    /// A field's `offset + size × count` exceeds `data_size` (construction check).
    FieldOutOfBounds {
        /// The offending field's key.
        key: usize,
    },
    /// A field's `count` was zero (construction check).
    ZeroCount {
        /// The offending field's key.
        key: usize,
    },
    /// A `bit` selector was used with a non-BOOL type, a bit index `> 7`, or `count != 1`
    /// (construction check).
    InvalidBitField {
        /// The offending field's key.
        key: usize,
    },
    /// A field's type is not an elementary scalar (STRING / structure / unknown — construction
    /// check).
    NonElementaryType {
        /// The offending field's key.
        key: usize,
    },
    /// A runtime buffer whose length did not equal the layout's `data_size`.
    DataSizeMismatch {
        /// The `data_size` the layout was built for.
        expected: usize,
        /// The buffer length actually supplied.
        actual: usize,
    },
    /// An unknown field key was supplied to [`AssemblyLayout::encode_into`].
    UnknownField {
        /// The key that was not in the layout.
        key: usize,
    },
    /// A value handed to [`AssemblyLayout::encode_into`] did not match its field's type/shape.
    ValueTypeMismatch {
        /// The field key whose value was wrong.
        key: usize,
    },
}

impl core::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FieldOutOfBounds { key } => write!(f, "assembly field {key} out of bounds"),
            Self::ZeroCount { key } => write!(f, "assembly field {key} has zero count"),
            Self::InvalidBitField { key } => write!(f, "assembly field {key} has an invalid bit selector"),
            Self::NonElementaryType { key } => write!(f, "assembly field {key} is not an elementary type"),
            Self::DataSizeMismatch { expected, actual } => {
                write!(f, "assembly data size mismatch: expected {expected}, got {actual}")
            }
            Self::UnknownField { key } => write!(f, "unknown assembly field {key}"),
            Self::ValueTypeMismatch { key } => write!(f, "value type mismatch for assembly field {key}"),
        }
    }
}

impl std::error::Error for AssemblyError {}

/// A validated, bounds-checked mapping between raw assembly bytes and typed fields (§9, D-ENIP-11).
/// Construction proves every field fits, so [`decode`](Self::decode) / [`encode_into`](Self::encode_into)
/// are total — no runtime bounds violation is reachable. Overlapping fields are permitted (a status
/// word plus its individual bits): the layout is data, not a partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyLayout {
    fields: Vec<FieldSpec>,
    data_size: usize,
}

impl AssemblyLayout {
    /// Validate `fields` against `data_size` and build the layout (§9). Every field must have a
    /// non-zero count, an elementary type, a valid bit selector (BOOL + bit ≤ 7 + count 1), and must
    /// fit: `offset + element_size × count ≤ data_size` (checked arithmetic). Otherwise a typed
    /// [`AssemblyError`] the adapter surfaces as a startup config failure.
    pub fn new(fields: Vec<FieldSpec>, data_size: usize) -> Result<Self, AssemblyError> {
        for field in &fields {
            let key = field.key;
            if field.count == 0 {
                return Err(AssemblyError::ZeroCount { key });
            }
            let elem_size = field
                .ty
                .element_size()
                .ok_or(AssemblyError::NonElementaryType { key })?;

            if let Some(bit) = field.bit {
                // A packed boolean lives in the byte at `offset`: BOOL only, bit 0–7, single element.
                if field.ty != CipType::Bool || bit > 7 || field.count != 1 {
                    return Err(AssemblyError::InvalidBitField { key });
                }
            }

            // offset + elem_size * count <= data_size, all checked.
            let span = elem_size
                .checked_mul(field.count)
                .ok_or(AssemblyError::FieldOutOfBounds { key })?;
            let end = field
                .offset
                .checked_add(span)
                .ok_or(AssemblyError::FieldOutOfBounds { key })?;
            if end > data_size {
                return Err(AssemblyError::FieldOutOfBounds { key });
            }
        }
        Ok(Self { fields, data_size })
    }

    /// The assembly's fixed data size in bytes.
    #[must_use]
    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// The field specifications, in declaration order.
    #[must_use]
    pub fn fields(&self) -> &[FieldSpec] {
        &self.fields
    }

    /// Extract every field from `data` as `(key, CipValue)` pairs (§9). Rechecks
    /// `data.len() == data_size`, then reads each field through [`WireReader`] — total, no panics,
    /// even against hostile bytes (fuzzed, §12.3). Because construction proved every field fits, the
    /// only reachable error here is the length recheck.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<(usize, CipValue)>, AssemblyError> {
        if data.len() != self.data_size {
            return Err(AssemblyError::DataSizeMismatch {
                expected: self.data_size,
                actual: data.len(),
            });
        }
        let mut out = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            out.push((field.key, self.extract_field(field, data)?));
        }
        Ok(out)
    }

    /// Extract one field, reading through a fresh cursor positioned at `field.offset`.
    fn extract_field(&self, field: &FieldSpec, data: &[u8]) -> Result<CipValue, AssemblyError> {
        // A cursor into the validated buffer; `skip`/reads are bounds-checked, but construction has
        // already proven the field fits, so these cannot fail on a correctly-sized buffer.
        let mut r = WireReader::with_context(data, CONTEXT);
        r.skip(field.offset).map_err(|_| AssemblyError::FieldOutOfBounds { key: field.key })?;

        if let Some(bit) = field.bit {
            let byte = r.u8().map_err(|_| AssemblyError::FieldOutOfBounds { key: field.key })?;
            let mask = 1u8.checked_shl(u32::from(bit)).unwrap_or(0);
            return Ok(CipValue::Bool(byte & mask != 0));
        }

        // Elementary scalar or array: the byte span is `element_size × count`, already validated.
        let elem_size = field
            .ty
            .element_size()
            .ok_or(AssemblyError::NonElementaryType { key: field.key })?;
        let span = elem_size
            .checked_mul(field.count)
            .ok_or(AssemblyError::FieldOutOfBounds { key: field.key })?;
        let bytes = r
            .take(span)
            .map_err(|_| AssemblyError::FieldOutOfBounds { key: field.key })?;
        CipValue::decode(field.ty, bytes).map_err(|_| AssemblyError::FieldOutOfBounds { key: field.key })
    }

    /// Insert values into `buf`, the write-side inverse used by the output assembly (§9). `buf` must
    /// be `data_size` bytes; **unset fields keep their previous bytes** (the layout is not a
    /// partition). Each `(key, value)` must name a field in the layout and carry a value matching the
    /// field's type and shape, else a typed [`AssemblyError`] — never a panic or an out-of-range
    /// write.
    pub fn encode_into(
        &self,
        values: &[(usize, CipValue)],
        buf: &mut [u8],
    ) -> Result<(), AssemblyError> {
        if buf.len() != self.data_size {
            return Err(AssemblyError::DataSizeMismatch {
                expected: self.data_size,
                actual: buf.len(),
            });
        }
        for (key, value) in values {
            let field = self
                .fields
                .iter()
                .find(|f| f.key == *key)
                .ok_or(AssemblyError::UnknownField { key: *key })?;
            self.insert_field(field, value, buf)?;
        }
        Ok(())
    }

    /// Insert one field's value into `buf` at `field.offset`, preserving surrounding bytes.
    fn insert_field(
        &self,
        field: &FieldSpec,
        value: &CipValue,
        buf: &mut [u8],
    ) -> Result<(), AssemblyError> {
        let key = field.key;
        if let Some(bit) = field.bit {
            let CipValue::Bool(set) = value else {
                return Err(AssemblyError::ValueTypeMismatch { key });
            };
            let slot = buf.get_mut(field.offset).ok_or(AssemblyError::FieldOutOfBounds { key })?;
            let mask = 1u8.checked_shl(u32::from(bit)).unwrap_or(0);
            if *set {
                *slot |= mask;
            } else {
                *slot &= !mask;
            }
            return Ok(());
        }

        // Reject a value whose element type does not match the field.
        if value.wire_type() != field.ty {
            return Err(AssemblyError::ValueTypeMismatch { key });
        }
        if value.element_count() != field.count {
            return Err(AssemblyError::ValueTypeMismatch { key });
        }

        // Encode the value bytes into a scratch buffer, then copy into the target span (checked).
        let mut w = WireWriter::new();
        value.encode_value(&mut w).map_err(|_| AssemblyError::ValueTypeMismatch { key })?;
        let bytes = w.into_bytes();
        let end = field
            .offset
            .checked_add(bytes.len())
            .ok_or(AssemblyError::FieldOutOfBounds { key })?;
        let slot = buf
            .get_mut(field.offset..end)
            .ok_or(AssemblyError::FieldOutOfBounds { key })?;
        slot.copy_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    fn sample_layout() -> AssemblyLayout {
        // 12-byte assembly: DINT count @0, REAL temp @4, status byte @8 (bit 0 = running, bit 3 =
        // fault), INT[1] spare @10 (overlaps nothing).
        AssemblyLayout::new(
            vec![
                FieldSpec::scalar(0, 0, CipType::Dint),
                FieldSpec::scalar(1, 4, CipType::Real),
                FieldSpec::scalar(2, 8, CipType::Byte),   // whole status byte
                FieldSpec::boolean(3, 8, 0),               // running bit — overlaps the status byte
                FieldSpec::boolean(4, 8, 3),               // fault bit — overlaps too
                FieldSpec::scalar(5, 10, CipType::Int),
            ],
            12,
        )
        .unwrap()
    }

    #[test]
    fn decode_extracts_scalars_bits_and_overlaps() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&42i32.to_le_bytes());
        data[4..8].copy_from_slice(&55.5f32.to_le_bytes());
        data[8] = 0b0000_1001; // bit 0 and bit 3 set
        data[10..12].copy_from_slice(&(-7i16).to_le_bytes());

        let fields = sample_layout().decode(&data).unwrap();
        assert_eq!(fields[0], (0, CipValue::Dint(42)));
        assert_eq!(fields[1], (1, CipValue::Real(55.5)));
        assert_eq!(fields[2], (2, CipValue::Byte(0b0000_1001)));
        assert_eq!(fields[3], (3, CipValue::Bool(true)));  // running
        assert_eq!(fields[4], (4, CipValue::Bool(true)));  // fault
        assert_eq!(fields[5], (5, CipValue::Int(-7)));
    }

    #[test]
    fn array_field_roundtrip() {
        // 8-byte assembly: INT[4].
        let layout = AssemblyLayout::new(vec![FieldSpec::array(0, 0, CipType::Int, 4)], 8).unwrap();
        let mut buf = vec![0u8; 8];
        let value = CipValue::Array(
            CipType::Int,
            vec![CipValue::Int(1), CipValue::Int(2), CipValue::Int(3), CipValue::Int(4)],
        );
        layout.encode_into(&[(0, value.clone())], &mut buf).unwrap();
        let decoded = layout.decode(&buf).unwrap();
        assert_eq!(decoded, vec![(0, value)]);
    }

    #[test]
    fn encode_into_preserves_unset_bytes_and_sets_bits() {
        let layout = sample_layout();
        let mut buf = vec![0xFFu8; 12]; // start all-ones so "preserve" is observable
        // Set only the DINT and clear the fault bit, set running bit.
        layout
            .encode_into(
                &[
                    (0, CipValue::Dint(0x0102_0304)),
                    (3, CipValue::Bool(true)),
                    (4, CipValue::Bool(false)),
                ],
                &mut buf,
            )
            .unwrap();
        assert_eq!(&buf[0..4], &0x0102_0304i32.to_le_bytes()); // DINT written
        assert_eq!(&buf[4..8], &[0xFF, 0xFF, 0xFF, 0xFF]);      // REAL bytes preserved
        assert_eq!(buf[8] & 0b0000_0001, 0b0000_0001);          // running set
        assert_eq!(buf[8] & 0b0000_1000, 0);                    // fault cleared
        assert_eq!(&buf[10..12], &[0xFF, 0xFF]);                // spare INT preserved
    }

    #[test]
    fn construction_rejects_out_of_bounds_field() {
        // A DINT at offset 10 needs bytes 10..14 but data_size is 12.
        let err = AssemblyLayout::new(vec![FieldSpec::scalar(9, 10, CipType::Dint)], 12).unwrap_err();
        assert_eq!(err, AssemblyError::FieldOutOfBounds { key: 9 });
    }

    #[test]
    fn construction_rejects_array_overflow_via_checked_mul() {
        // count × element_size overflows usize — must be a typed error, never a wrap/panic.
        let err = AssemblyLayout::new(
            vec![FieldSpec::array(7, 0, CipType::Lint, usize::MAX)],
            16,
        )
        .unwrap_err();
        assert_eq!(err, AssemblyError::FieldOutOfBounds { key: 7 });
    }

    #[test]
    fn construction_rejects_bad_bit_and_zero_count_and_bad_type() {
        // bit on a non-BOOL type
        assert_eq!(
            AssemblyLayout::new(vec![FieldSpec { key: 1, offset: 0, ty: CipType::Int, bit: Some(0), count: 1 }], 4)
                .unwrap_err(),
            AssemblyError::InvalidBitField { key: 1 }
        );
        // bit index > 7
        assert_eq!(
            AssemblyLayout::new(vec![FieldSpec { key: 2, offset: 0, ty: CipType::Bool, bit: Some(8), count: 1 }], 4)
                .unwrap_err(),
            AssemblyError::InvalidBitField { key: 2 }
        );
        // zero count
        assert_eq!(
            AssemblyLayout::new(vec![FieldSpec::array(3, 0, CipType::Int, 0)], 4).unwrap_err(),
            AssemblyError::ZeroCount { key: 3 }
        );
        // non-elementary type (STRING)
        assert_eq!(
            AssemblyLayout::new(vec![FieldSpec::scalar(4, 0, CipType::String)], 4).unwrap_err(),
            AssemblyError::NonElementaryType { key: 4 }
        );
    }

    #[test]
    fn decode_rejects_wrong_size_buffer_no_panic() {
        let layout = sample_layout();
        assert_eq!(
            layout.decode(&[0u8; 11]).unwrap_err(),
            AssemblyError::DataSizeMismatch { expected: 12, actual: 11 }
        );
        assert_eq!(
            layout.decode(&[0u8; 13]).unwrap_err(),
            AssemblyError::DataSizeMismatch { expected: 12, actual: 13 }
        );
    }

    #[test]
    fn decode_truncation_sweep_never_panics() {
        // Every prefix of a valid buffer must decode to a typed error, never a panic.
        let layout = sample_layout();
        let full = [0xABu8; 12];
        for n in 0..=full.len() {
            let prefix = &full[..n];
            let res = layout.decode(prefix);
            if n == 12 {
                assert!(res.is_ok());
            } else {
                assert!(matches!(res, Err(AssemblyError::DataSizeMismatch { .. })));
            }
        }
    }

    #[test]
    fn encode_into_rejects_unknown_field_and_type_mismatch() {
        let layout = sample_layout();
        let mut buf = vec![0u8; 12];
        assert_eq!(
            layout.encode_into(&[(99, CipValue::Dint(1))], &mut buf).unwrap_err(),
            AssemblyError::UnknownField { key: 99 }
        );
        // field 0 is a DINT; a REAL value is a type mismatch.
        assert_eq!(
            layout.encode_into(&[(0, CipValue::Real(1.0))], &mut buf).unwrap_err(),
            AssemblyError::ValueTypeMismatch { key: 0 }
        );
        // wrong-length buffer
        let mut small = vec![0u8; 4];
        assert_eq!(
            layout.encode_into(&[], &mut small).unwrap_err(),
            AssemblyError::DataSizeMismatch { expected: 12, actual: 4 }
        );
    }
}
