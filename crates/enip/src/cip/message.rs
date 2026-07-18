//! CIP Message Router request/reply (PROTOCOL-DESIGN §6.1).
//!
//! [`MessageRequest`] encodes `service · path-size-in-words · padded EPATH · data`.
//! [`MessageReply`] decodes `reply-service · reserved · general-status · ext-size · ext-words ·
//! data` — **entirely through the cursor**. This is the rseip `SendRRData` fix (invariant 6 of §4):
//! a short reply is [`crate::error::WireError::Truncated`], never an index into `data[0..4]`; and a
//! non-zero status does **not** discard the service data (a `0x06` partial-transfer reply keeps its
//! bytes, D-ENIP-12), unlike rseip's decoder which erred out.

use bytes::Bytes;

use crate::cip::epath::EPath;
use crate::cip::status::{CipStatus, GeneralStatus};
use crate::error::{EnipError, WireError};
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "cip reply";

/// The reply-service bit OR-ed onto a request service code in the reply (§6.1).
pub const REPLY_MASK: u8 = 0x80;

/// A CIP Message Router request (§6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRequest {
    /// The service code.
    pub service: u8,
    /// The request path (EPATH).
    pub path: EPath,
    /// The service-specific request data.
    pub data: Bytes,
}

impl MessageRequest {
    /// A request for `service` against `path` with `data`.
    #[must_use]
    pub fn new(service: u8, path: EPath, data: Bytes) -> Self {
        Self {
            service,
            path,
            data,
        }
    }

    /// Encode the request: `service`, path size in words, the padded EPATH, then the data (§6.1).
    pub fn encode(&self) -> Result<Bytes, EnipError> {
        let path_bytes = self.path.encode()?;
        // `EPath::encode` already guarantees even length and `<= 255` words.
        let words = path_bytes.len().checked_div(2).unwrap_or(0);
        let words = u8::try_from(words).map_err(|_| EnipError::TooLarge { limit: 255 })?;
        let mut w = WireWriter::with_capacity(2usize.saturating_add(path_bytes.len()).saturating_add(self.data.len()));
        w.u8(self.service);
        w.u8(words);
        w.put_slice(&path_bytes);
        w.put_slice(&self.data);
        Ok(w.into_bytes())
    }
}

/// A CIP Message Router reply (§6.1). The status is kept typed and the service data is retained
/// regardless of status; the caller decides whether a non-zero status is an error or data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReply {
    /// The reply service code (`request | 0x80`).
    pub reply_service: u8,
    /// The typed CIP status (general + extended words).
    pub status: CipStatus,
    /// The service-specific reply data (present even for some non-zero statuses, e.g. `0x06`).
    pub data: Bytes,
}

impl MessageReply {
    /// Decode a Message Router reply — every field read through the cursor (invariant 6 of §4).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(buf, CONTEXT);
        // Header: reply service, reserved, general status, additional-status size (all checked).
        let reply_service = r.u8()?;
        let _reserved = r.u8()?;
        let general = GeneralStatus::from_code(r.u8()?);
        let ext_size = r.u8()? as usize; // in 16-bit words

        // Checked multiply of the wire-supplied extended-status size (invariant 2): a lie about the
        // size becomes Truncated, never an over-read or a wrap.
        let ext_bytes = ext_size
            .checked_mul(2)
            .ok_or(WireError::Overflow { context: CONTEXT })?;
        if r.remaining() < ext_bytes {
            return Err(WireError::Truncated {
                needed: ext_bytes,
                remaining: r.remaining(),
                context: CONTEXT,
            });
        }
        let mut extended = Vec::with_capacity(ext_size);
        for _ in 0..ext_size {
            extended.push(r.u16()?);
        }

        let data = Bytes::copy_from_slice(r.take_rest());
        Ok(Self {
            reply_service,
            status: CipStatus::with_extended(general, extended),
            data,
        })
    }

    /// Confirm the reply service matches `request_service | 0x80` (§6.1); otherwise
    /// [`EnipError::ProtocolViolation`].
    pub fn expect_service(&self, request_service: u8) -> Result<(), EnipError> {
        if self.reply_service == (request_service | REPLY_MASK) {
            Ok(())
        } else {
            Err(EnipError::ProtocolViolation {
                detail: "reply service does not match request | 0x80",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn request_encode_matches_layout() {
        // Unconnected_Send-style: service 0x52, path [class 0x06, instance 0x01], data [0x10,0x00].
        let req = MessageRequest::new(
            0x52,
            EPath::new().class(0x06).instance(0x01),
            Bytes::from_static(&[0x10, 0x00]),
        );
        let bytes = req.encode().unwrap();
        assert_eq!(
            bytes.as_ref(),
            &[0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x10, 0x00]
        );
    }

    #[test]
    fn read_tag_success_reply_decodes() {
        // reply service 0xCC (0x4C|0x80), reserved 0, status 0, ext 0, then type 0xC4 + DINT 42.
        let buf = [0xCC, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x2A, 0x00, 0x00, 0x00];
        let reply = MessageReply::decode(&buf).unwrap();
        assert_eq!(reply.reply_service, 0xCC);
        assert!(reply.status.is_ok());
        reply.expect_service(0x4C).unwrap();
        assert_eq!(reply.data.as_ref(), &[0xC4, 0x00, 0x2A, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn error_status_reply_keeps_extended_words() {
        // reply service 0xCC, status 0xFF (extended error), ext size 1, ext word 0x2107.
        let buf = [0xCC, 0x00, 0xFF, 0x01, 0x07, 0x21];
        let reply = MessageReply::decode(&buf).unwrap();
        assert_eq!(reply.status.general, GeneralStatus::ExtendedError);
        assert_eq!(reply.status.primary_extended(), Some(0x2107));
        assert!(reply.data.is_empty());
    }

    #[test]
    fn partial_transfer_status_retains_data() {
        // status 0x06 (partial transfer) but data still present — the rseip regression.
        let buf = [0xD2, 0x00, 0x06, 0x00, 0xC4, 0x00, 0x01, 0x02, 0x03, 0x04];
        let reply = MessageReply::decode(&buf).unwrap();
        assert!(reply.status.has_more());
        assert_eq!(reply.data.len(), 6);
    }

    #[test]
    fn short_reply_is_truncated_not_panic() {
        // Only 3 bytes: the 4-byte header cannot be read — Truncated, never an index panic.
        assert!(matches!(
            MessageReply::decode(&[0xCC, 0x00, 0x00]),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn lying_extended_size_is_truncated() {
        // ext size says 4 words (8 bytes) but none follow.
        assert!(matches!(
            MessageReply::decode(&[0xCC, 0x00, 0xFF, 0x04]),
            Err(WireError::Truncated { .. })
        ));
    }
}
