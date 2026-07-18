//! TCP framing codec for the encapsulation layer (PROTOCOL-DESIGN §5.1).
//!
//! A [`tokio_util::codec`] [`Decoder`]/[`Encoder`] over the byte stream: read the 24-byte header,
//! cap `length <= MAX_DATA_LEN` **before** buffering the data (a hostile length cannot force an
//! over-allocation), skip `NOP` frames (never surfaced), and treat a partial frame at EOF as
//! [`EnipError::ConnectionLost`]. The output is a fully-parsed [`EncapFrame`].

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::encap::{Command, EncapFrame, HEADER_LEN, MAX_DATA_LEN};
use crate::error::EnipError;

/// The framed codec (PROTOCOL-DESIGN §5.1). Stateless — one per `TcpStream`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EncapCodec;

impl EncapCodec {
    /// A new codec.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for EncapCodec {
    type Item = EncapFrame;
    type Error = EnipError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<EncapFrame>, EnipError> {
        loop {
            // Need the whole 24-byte header before we can learn the data length.
            let header_bytes = match src.get(0..HEADER_LEN) {
                Some(h) => h,
                None => {
                    src.reserve(HEADER_LEN.saturating_sub(src.len()));
                    return Ok(None);
                }
            };

            // Peek command + declared length from the header (checked read, no indexing).
            let mut peek = crate::wire::WireReader::with_context(header_bytes, "encap header");
            let command = Command::from_code(peek.u16()?);
            let length = peek.u16()? as usize;

            // Cap BEFORE buffering: a length above the protocol maximum is rejected outright so a
            // hostile peer cannot make us reserve a huge buffer.
            if length > MAX_DATA_LEN {
                return Err(EnipError::Malformed(crate::error::WireError::Malformed {
                    context: "encap codec",
                    detail: "declared length exceeds protocol maximum",
                }));
            }

            let total = HEADER_LEN
                .checked_add(length)
                .ok_or(EnipError::Malformed(crate::error::WireError::Overflow {
                    context: "encap codec",
                }))?;

            if src.len() < total {
                src.reserve(total.saturating_sub(src.len()));
                return Ok(None);
            }

            // A full frame is buffered — consume exactly `total` bytes and parse it.
            let frame_bytes = src.split_to(total);
            let frame = EncapFrame::decode(&frame_bytes)?;

            // NOP frames are keepalive filler: consumed above, never surfaced. Loop for the next.
            if matches!(command, Command::Nop) {
                tracing::trace!("skipping NOP encapsulation frame");
                continue;
            }
            return Ok(Some(frame));
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<EncapFrame>, EnipError> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if src.is_empty() {
                    Ok(None)
                } else {
                    // Bytes remain that cannot complete a frame: the peer went away mid-frame.
                    Err(EnipError::ConnectionLost {
                        context: "encap frame truncated at eof",
                    })
                }
            }
        }
    }
}

impl Encoder<EncapFrame> for EncapCodec {
    type Error = EnipError;

    fn encode(&mut self, item: EncapFrame, dst: &mut BytesMut) -> Result<(), EnipError> {
        let bytes = item.encode()?;
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;
    use crate::encap::{EncapHeader, EncapStatus};
    use bytes::{Bytes, BytesMut};

    fn register_reply_frame() -> EncapFrame {
        let mut h = EncapHeader::request(Command::RegisterSession, 4, 0x0000_1234, [9; 8]);
        h.status = EncapStatus::Success;
        EncapFrame::new(h, Bytes::from_static(&[0x01, 0x00, 0x00, 0x00]))
    }

    #[test]
    fn encode_then_decode_one_frame() {
        let frame = register_reply_frame();
        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frame_yields_none_then_completes() {
        let frame = register_reply_frame();
        let full = frame.encode().unwrap();
        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();

        // Feed only the first 20 bytes (mid-header): must ask for more, not panic.
        buf.extend_from_slice(&full[..20]);
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Feed the rest: now it decodes.
        buf.extend_from_slice(&full[20..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), frame);
    }

    #[test]
    fn nop_frame_is_skipped() {
        let nop = EncapFrame::new(
            EncapHeader::request(Command::Nop, 0, 0, [0; 8]),
            Bytes::new(),
        );
        let real = register_reply_frame();
        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&nop.encode().unwrap());
        buf.extend_from_slice(&real.encode().unwrap());
        // The NOP is consumed silently; the first surfaced frame is the real one.
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), real);
    }

    #[test]
    fn eof_mid_frame_is_connection_lost() {
        let full = register_reply_frame().encode().unwrap();
        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&full[..25]); // header + 1 data byte, short of the declared 4
        assert!(matches!(
            codec.decode_eof(&mut buf),
            Err(EnipError::ConnectionLost { .. })
        ));
    }

    #[test]
    fn oversized_length_rejected_before_buffering() {
        // Hand-build a header claiming a length above the protocol max.
        let mut buf = BytesMut::new();
        let mut w = crate::wire::WireWriter::new();
        w.u16(Command::SendRRData.code());
        w.u16(0xFFFF); // 65535 > MAX_DATA_LEN (65511)
        w.u32(0);
        w.u32(0);
        w.put_slice(&[0u8; 8]);
        w.u32(0);
        buf.extend_from_slice(w.as_slice());
        let mut codec = EncapCodec::new();
        assert!(matches!(codec.decode(&mut buf), Err(EnipError::Malformed(_))));
    }
}
