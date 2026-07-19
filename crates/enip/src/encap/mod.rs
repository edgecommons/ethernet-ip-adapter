//! Encapsulation layer (PROTOCOL-DESIGN §5).
//!
//! The 24-byte [`EncapHeader`] (§5.1, exact offsets), the [`Command`] set (§5.2, total with
//! [`Command::Unknown`]), the session lifecycle constants (§5.5), and the typed [`EncapStatus`]
//! codes (§5.6). Multi-byte fields are little-endian; the sockaddr-info big-endian exception lives
//! in [`crate::cpf`]. The TCP framing that turns a byte stream into [`EncapFrame`]s is
//! [`crate::encap::codec`].

pub mod codec;

use bytes::Bytes;

use crate::error::WireError;
use crate::wire::{WireReader, WireWriter};

/// The 24-byte encapsulation header length (§5.1).
pub const HEADER_LEN: usize = 24;

/// The maximum data length after the header (`u16::MAX - 24`, §5.1). A `length` above this is
/// rejected before buffering by the framed codec.
pub const MAX_DATA_LEN: usize = (u16::MAX as usize) - HEADER_LEN;

/// The default EtherNet/IP TCP port (0xAF12).
pub const DEFAULT_TCP_PORT: u16 = 44818;

/// The default EtherNet/IP-over-TLS TCP port (CIP Security, Vol 8 — explicit messaging inside TLS).
/// A secure connection is addressed by dialing this port and speaking TLS on it; there is no in-band
/// STARTTLS upgrade on 44818 (DESIGN-cip-security.md §2.1).
pub const DEFAULT_TLS_PORT: u16 = 2221;

/// The default EtherNet/IP UDP port for class-0/1 I/O and discovery (0x08AE).
pub const DEFAULT_UDP_PORT: u16 = 2222;

/// The encapsulation protocol version RegisterSession negotiates (§5.5).
pub const PROTOCOL_VERSION: u16 = 1;

/// An encapsulation command code (§5.2). Total — an unrecognized code is [`Command::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// `0x0000` NOP — keepalive filler, never replied.
    Nop,
    /// `0x0004` ListServices — capability discovery.
    ListServices,
    /// `0x0063` ListIdentity — device discovery (§5.3).
    ListIdentity,
    /// `0x0064` ListInterfaces — optional interface discovery.
    ListInterfaces,
    /// `0x0065` RegisterSession — opens the session (§5.5).
    RegisterSession,
    /// `0x0066` UnRegisterSession — graceful close, no reply.
    UnRegisterSession,
    /// `0x006F` SendRRData — unconnected CIP (UCMM).
    SendRRData,
    /// `0x0070` SendUnitData — connected class-3 CIP.
    SendUnitData,
    /// Any other command code (§4 invariant 5).
    Unknown(u16),
}

impl Command {
    /// Decode from a wire command code — total.
    #[must_use]
    pub fn from_code(code: u16) -> Self {
        match code {
            0x0000 => Self::Nop,
            0x0004 => Self::ListServices,
            0x0063 => Self::ListIdentity,
            0x0064 => Self::ListInterfaces,
            0x0065 => Self::RegisterSession,
            0x0066 => Self::UnRegisterSession,
            0x006F => Self::SendRRData,
            0x0070 => Self::SendUnitData,
            other => Self::Unknown(other),
        }
    }

    /// The wire command code.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Nop => 0x0000,
            Self::ListServices => 0x0004,
            Self::ListIdentity => 0x0063,
            Self::ListInterfaces => 0x0064,
            Self::RegisterSession => 0x0065,
            Self::UnRegisterSession => 0x0066,
            Self::SendRRData => 0x006F,
            Self::SendUnitData => 0x0070,
            Self::Unknown(v) => v,
        }
    }
}

/// A typed encapsulation status (§5.6). Total — an unrecognized code is [`EncapStatus::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncapStatus {
    /// `0x0000` success.
    Success,
    /// `0x0001` unsupported command.
    UnsupportedCommand,
    /// `0x0002` insufficient memory (transient).
    InsufficientMemory,
    /// `0x0003` incorrect data.
    IncorrectData,
    /// `0x0064` invalid session handle — additionally poisons the session (reconnect).
    InvalidSessionHandle,
    /// `0x0065` invalid length.
    InvalidLength,
    /// `0x0069` unsupported protocol version.
    UnsupportedProtocolVersion,
    /// Any other status code.
    Unknown(u32),
}

impl EncapStatus {
    /// Decode from a wire status word — total.
    #[must_use]
    pub fn from_code(code: u32) -> Self {
        match code {
            0x0000 => Self::Success,
            0x0001 => Self::UnsupportedCommand,
            0x0002 => Self::InsufficientMemory,
            0x0003 => Self::IncorrectData,
            0x0064 => Self::InvalidSessionHandle,
            0x0065 => Self::InvalidLength,
            0x0069 => Self::UnsupportedProtocolVersion,
            other => Self::Unknown(other),
        }
    }

    /// The wire status word.
    #[must_use]
    pub fn code(self) -> u32 {
        match self {
            Self::Success => 0x0000,
            Self::UnsupportedCommand => 0x0001,
            Self::InsufficientMemory => 0x0002,
            Self::IncorrectData => 0x0003,
            Self::InvalidSessionHandle => 0x0064,
            Self::InvalidLength => 0x0065,
            Self::UnsupportedProtocolVersion => 0x0069,
            Self::Unknown(v) => v,
        }
    }

    /// Whether the status is success.
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Whether the session handle is gone and the session must be re-established (`0x0064`).
    #[must_use]
    pub fn poisons_session(self) -> bool {
        matches!(self, Self::InvalidSessionHandle)
    }
}

impl core::fmt::Display for EncapStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let desc = match self {
            Self::Success => "success",
            Self::UnsupportedCommand => "unsupported command",
            Self::InsufficientMemory => "insufficient memory",
            Self::IncorrectData => "incorrect data",
            Self::InvalidSessionHandle => "invalid session handle",
            Self::InvalidLength => "invalid length",
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::Unknown(_) => "unknown status",
        };
        write!(f, "0x{:04X} ({desc})", self.code())
    }
}

/// The decoded 24-byte encapsulation header (§5.1). `command` and `status` are typed; `length` is
/// the raw byte length of the data that follows (needed by the framed codec to know how much to
/// read); `sender_context` is the 8-byte correlation key (§10.3), opaque to the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapHeader {
    /// The command (offset 0).
    pub command: Command,
    /// The data length that follows the header (offset 2).
    pub length: u16,
    /// The session handle (offset 4).
    pub session_handle: u32,
    /// The typed status (offset 8).
    pub status: EncapStatus,
    /// The 8-byte sender context (offset 12) — echoed verbatim in the reply.
    pub sender_context: [u8; 8],
    /// The options field (offset 20) — always 0; a received non-zero value is discarded per spec.
    pub options: u32,
}

impl EncapHeader {
    /// A request header for `command` with `data_len` bytes of data, the given session handle and
    /// sender context. Status/options are 0.
    #[must_use]
    pub fn request(
        command: Command,
        data_len: u16,
        session_handle: u32,
        sender_context: [u8; 8],
    ) -> Self {
        Self {
            command,
            length: data_len,
            session_handle,
            status: EncapStatus::Success,
            sender_context,
            options: 0,
        }
    }

    /// Decode exactly the 24-byte header from the front of `buf` (§5.1). The header is read through
    /// the checked cursor — a short buffer is [`WireError::Truncated`], never an index panic.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(buf, "encap header");
        Self::decode_from(&mut r)
    }

    /// Decode the header from a cursor (leaves the cursor positioned at the data portion).
    pub fn decode_from(r: &mut WireReader<'_>) -> Result<Self, WireError> {
        r.at("encap header");
        let command = Command::from_code(r.u16()?);
        let length = r.u16()?;
        let session_handle = r.u32()?;
        let status = EncapStatus::from_code(r.u32()?);
        let mut sender_context = [0u8; 8];
        sender_context.copy_from_slice(r.take(8)?);
        let options = r.u32()?;
        Ok(Self {
            command,
            length,
            session_handle,
            status,
            sender_context,
            options,
        })
    }

    /// Write the 24-byte header (using `self.length` verbatim).
    pub fn write(&self, w: &mut WireWriter) {
        w.u16(self.command.code());
        w.u16(self.length);
        w.u32(self.session_handle);
        w.u32(self.status.code());
        w.put_slice(&self.sender_context);
        w.u32(self.options);
    }
}

/// A whole encapsulation frame: the header plus its data portion (§5). Encoding stamps
/// `header.length` from the data length; decoding validates that the data portion matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapFrame {
    /// The header.
    pub header: EncapHeader,
    /// The data portion (CPF, RegisterSession data, etc.).
    pub data: Bytes,
}

impl EncapFrame {
    /// A frame carrying `data` under `header` (the header's length is overwritten from the data).
    #[must_use]
    pub fn new(mut header: EncapHeader, data: Bytes) -> Self {
        header.length = u16::try_from(data.len()).unwrap_or(u16::MAX);
        Self { header, data }
    }

    /// Encode the whole frame (header + data). Fails with [`WireError::Overflow`] if the data
    /// exceeds [`MAX_DATA_LEN`] (our own value; the length field cannot represent it).
    pub fn encode(&self) -> Result<Bytes, WireError> {
        if self.data.len() > MAX_DATA_LEN {
            return Err(WireError::Overflow {
                context: "encap frame",
            });
        }
        let mut w = WireWriter::with_capacity(HEADER_LEN.saturating_add(self.data.len()));
        let mut header = self.header.clone();
        // Length is authoritative from the data (guarded above to fit u16).
        header.length = self.data.len() as u16;
        header.write(&mut w);
        w.put_slice(&self.data);
        Ok(w.into_bytes())
    }

    /// Decode a whole frame from `buf`: the 24-byte header then exactly `header.length` data bytes.
    /// Trailing bytes beyond the declared length are [`WireError::Malformed`].
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(buf, "encap frame");
        let header = EncapHeader::decode_from(&mut r)?;
        let data = r.take(header.length as usize)?;
        let frame = Self {
            header,
            data: Bytes::copy_from_slice(data),
        };
        r.expect_end()?;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn command_and_status_are_total_and_roundtrip() {
        for code in [0x0000u16, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070, 0x1234] {
            assert_eq!(Command::from_code(code).code(), code);
        }
        assert_eq!(Command::from_code(0x1234), Command::Unknown(0x1234));
        for code in [0x0000u32, 0x0001, 0x0002, 0x0003, 0x0064, 0x0065, 0x0069, 0xDEAD] {
            assert_eq!(EncapStatus::from_code(code).code(), code);
        }
        assert_eq!(EncapStatus::from_code(0xDEAD), EncapStatus::Unknown(0xDEAD));
    }

    #[test]
    fn header_roundtrip() {
        let h = EncapHeader::request(Command::RegisterSession, 4, 0, [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut w = WireWriter::new();
        h.write(&mut w);
        assert_eq!(w.len(), HEADER_LEN);
        let decoded = EncapHeader::decode(w.as_slice()).expect("decode");
        assert_eq!(decoded, h);
    }

    #[test]
    fn frame_roundtrip_stamps_length() {
        let h = EncapHeader::request(Command::SendRRData, 0, 42, [0; 8]);
        let frame = EncapFrame::new(h, Bytes::from_static(&[0xAA, 0xBB, 0xCC]));
        assert_eq!(frame.header.length, 3);
        let bytes = frame.encode().expect("encode");
        let decoded = EncapFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn truncated_header_is_typed() {
        assert!(matches!(
            EncapHeader::decode(&[0u8; 10]),
            Err(WireError::Truncated { .. })
        ));
    }
}
