//! `WireReader` / `WireWriter` — the ONLY way wire bytes are read or written (PROTOCOL-DESIGN §4).
//!
//! [`WireReader`] is a checked little-endian cursor: every read validates `remaining()` first and
//! returns [`WireError::Truncated`] rather than indexing or wrapping. This is where the no-panic
//! invariant is made mechanical — nothing here indexes a slice (`.get(..)` only) or does unchecked
//! arithmetic on wire-supplied numbers, which the crate-wide `clippy::indexing_slicing` /
//! `arithmetic_side_effects` denials enforce. [`WireWriter`] is the append-only encode side over a
//! [`bytes::BytesMut`].

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::WireError;

/// A checked little-endian cursor over one wire buffer — the ONLY decode primitive (§4).
///
/// All integer reads are little-endian (CIP byte order). The single big-endian exception —
/// sockaddr-info family/port/address (§5.4) — is handled explicitly by [`crate::cpf`] via
/// [`WireReader::u16_be`] / [`WireReader::u32_be`] / [`WireReader::i16_be`]. A `context` label
/// travels with the cursor so a truncation error names the layer that failed; decoders set it with
/// [`WireReader::at`] as they descend into a sub-structure.
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
    context: &'static str,
}

impl<'a> WireReader<'a> {
    /// A reader over `buf` with a generic context label.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            context: "wire",
        }
    }

    /// A reader over `buf` labelled with the layer name it decodes.
    #[must_use]
    pub fn with_context(buf: &'a [u8], context: &'static str) -> Self {
        Self {
            buf,
            pos: 0,
            context,
        }
    }

    /// Set the context label used by subsequent truncation errors. Chainable.
    pub fn at(&mut self, context: &'static str) -> &mut Self {
        self.context = context;
        self
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        // `pos` is only ever advanced by `take`, which caps it at `buf.len()`, so this never
        // underflows; `saturating_sub` keeps it total regardless.
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the whole buffer has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Assert the buffer is fully consumed — a trailing-garbage guard for exact layouts (§4).
    pub fn expect_end(&self) -> Result<(), WireError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(WireError::Malformed {
                context: self.context,
                detail: "trailing bytes after expected end",
            })
        }
    }

    /// Borrow the next `n` bytes, advancing past them. `n` is checked against `remaining()` first.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Overflow {
            context: self.context,
        })?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated {
            needed: n,
            remaining: self.remaining(),
            context: self.context,
        })?;
        self.pos = end;
        Ok(slice)
    }

    /// Skip `n` bytes (checked).
    pub fn skip(&mut self, n: usize) -> Result<(), WireError> {
        self.take(n).map(|_| ())
    }

    /// Borrow all remaining bytes, consuming them.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        rest
    }

    /// Peek the next byte without consuming (used to branch on a type/tag byte).
    #[must_use]
    pub fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let slice = self.take(N)?;
        let mut arr = [0u8; N];
        // `slice` is exactly N bytes (guaranteed by `take`), so this copy is total.
        arr.copy_from_slice(slice);
        Ok(arr)
    }

    /// Read a `u8`.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_array::<1>()?[0])
    }

    /// Read an `i8`.
    pub fn i8(&mut self) -> Result<i8, WireError> {
        Ok(self.u8()? as i8)
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take_array::<2>()?))
    }

    /// Read a little-endian `i16`.
    pub fn i16(&mut self) -> Result<i16, WireError> {
        Ok(i16::from_le_bytes(self.take_array::<2>()?))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Read a little-endian `i32`.
    pub fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take_array::<8>()?))
    }

    /// Read a little-endian `i64`.
    pub fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_le_bytes(self.take_array::<8>()?))
    }

    /// Read a little-endian `f32`.
    pub fn f32(&mut self) -> Result<f32, WireError> {
        Ok(f32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Read a little-endian `f64`.
    pub fn f64(&mut self) -> Result<f64, WireError> {
        Ok(f64::from_le_bytes(self.take_array::<8>()?))
    }

    /// Read a big-endian `i16` — the sockaddr-info exception only (§5.4).
    pub fn i16_be(&mut self) -> Result<i16, WireError> {
        Ok(i16::from_be_bytes(self.take_array::<2>()?))
    }

    /// Read a big-endian `u16` — the sockaddr-info exception only (§5.4).
    pub fn u16_be(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take_array::<2>()?))
    }

    /// Read a big-endian `u32` — the sockaddr-info exception only (§5.4).
    pub fn u32_be(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }

    /// Read a CIP `SHORT_STRING` (u8 length + that many UTF-8 bytes, no padding, §5.3). Invalid
    /// UTF-8 is [`WireError::InvalidUtf8`] (invariant 4).
    pub fn short_string(&mut self) -> Result<String, WireError> {
        let len = self.u8()? as usize;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8 {
                context: self.context,
            })
    }
}

/// The append-only encode side: a thin, panic-free wrapper over [`bytes::BytesMut`] that writes
/// little-endian (with explicit `*_be` helpers for the sockaddr exception). Encoding *our own*
/// values cannot overflow the buffer; callers that derive a length from untrusted input validate it
/// before calling (invariant 3), so nothing here needs to fail.
#[derive(Debug, Default, Clone)]
pub struct WireWriter {
    buf: BytesMut,
}

impl WireWriter {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A writer with reserved capacity.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(cap),
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The written bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume into an immutable [`Bytes`].
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.buf.freeze()
    }

    /// Consume into the underlying [`BytesMut`].
    #[must_use]
    pub fn into_inner(self) -> BytesMut {
        self.buf
    }

    /// Append a raw byte slice.
    pub fn put_slice(&mut self, bytes: &[u8]) {
        self.buf.put_slice(bytes);
    }

    /// Append a `u8`.
    pub fn u8(&mut self, v: u8) {
        self.buf.put_u8(v);
    }

    /// Append an `i8`.
    pub fn i8(&mut self, v: i8) {
        self.buf.put_i8(v);
    }

    /// Append a little-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.put_u16_le(v);
    }

    /// Append a little-endian `i16`.
    pub fn i16(&mut self, v: i16) {
        self.buf.put_i16_le(v);
    }

    /// Append a little-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.buf.put_u32_le(v);
    }

    /// Append a little-endian `i32`.
    pub fn i32(&mut self, v: i32) {
        self.buf.put_i32_le(v);
    }

    /// Append a little-endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.buf.put_u64_le(v);
    }

    /// Append a little-endian `i64`.
    pub fn i64(&mut self, v: i64) {
        self.buf.put_i64_le(v);
    }

    /// Append a little-endian `f32`.
    pub fn f32(&mut self, v: f32) {
        self.buf.put_f32_le(v);
    }

    /// Append a little-endian `f64`.
    pub fn f64(&mut self, v: f64) {
        self.buf.put_f64_le(v);
    }

    /// Append a big-endian `i16` — the sockaddr-info exception only (§5.4).
    pub fn i16_be(&mut self, v: i16) {
        self.buf.put_i16(v);
    }

    /// Append a big-endian `u16` — the sockaddr-info exception only (§5.4).
    pub fn u16_be(&mut self, v: u16) {
        self.buf.put_u16(v);
    }

    /// Append a big-endian `u32` — the sockaddr-info exception only (§5.4).
    pub fn u32_be(&mut self, v: u32) {
        self.buf.put_u32(v);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reads_little_endian_scalars() {
        let bytes = [
            0x01u8, // u8
            0x02, 0x01, // u16 = 0x0102
            0x04, 0x03, 0x02, 0x01, // u32 = 0x01020304
        ];
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert_eq!(r.u32().unwrap(), 0x0102_0304);
        assert_eq!(r.remaining(), 0);
        r.expect_end().unwrap();
    }

    #[test]
    fn truncation_is_typed_not_panic() {
        let bytes = [0x01u8, 0x02];
        let mut r = WireReader::with_context(&bytes, "test");
        assert_eq!(r.u16().unwrap(), 0x0201);
        // Only two bytes; the next u32 read must be Truncated, never a panic.
        match r.u32() {
            Err(WireError::Truncated {
                needed,
                remaining,
                context,
            }) => {
                assert_eq!(needed, 4);
                assert_eq!(remaining, 0);
                assert_eq!(context, "test");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn expect_end_detects_trailing_bytes() {
        let bytes = [0xAAu8, 0xBB];
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0xAA);
        assert!(matches!(r.expect_end(), Err(WireError::Malformed { .. })));
    }

    #[test]
    fn short_string_roundtrips_and_rejects_bad_utf8() {
        let mut w = WireWriter::new();
        w.u8(3);
        w.put_slice(b"abc");
        let bytes = w.into_bytes();
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.short_string().unwrap(), "abc");

        let bad = [0x01u8, 0xFF]; // length 1, then an invalid UTF-8 byte
        let mut r = WireReader::new(&bad);
        assert!(matches!(
            r.short_string(),
            Err(WireError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn big_endian_helpers() {
        let bytes = [0x00u8, 0x02, 0x08, 0xAE]; // family=2, port=0x08AE big-endian
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.u16_be().unwrap(), 0x0002);
        assert_eq!(r.u16_be().unwrap(), 0x08AE);
    }

    #[test]
    fn writer_scalars_match_le_layout() {
        let mut w = WireWriter::with_capacity(8);
        w.u16(0x0102);
        w.u32(0x0304_0506);
        assert_eq!(w.as_slice(), &[0x02, 0x01, 0x06, 0x05, 0x04, 0x03]);
    }
}
