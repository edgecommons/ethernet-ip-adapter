//! Error & failure model (PROTOCOL-DESIGN §10).
//!
//! [`WireError`] is the decode-layer error: every decoder is a total function
//! `&[u8] -> Result<T, WireError>` that never panics, never indexes, and never wraps arithmetic on
//! wire-supplied numbers (§4). [`EnipError`] is the session/connection/CIP-status-carrying error
//! the public API surfaces (§10.1); it wraps `WireError` for hostile/broken peers and carries the
//! typed encapsulation ([`crate::encap::EncapStatus`]) and CIP ([`crate::cip::status::CipStatus`])
//! status values — no stringly-typed status anywhere.

use crate::cip::status::CipStatus;
use crate::encap::EncapStatus;

/// A decode failure. Produced only by [`crate::wire::WireReader`] and the decoders built on it.
///
/// Every variant names the `context` — the layer that failed — so a truncated frame reads as
/// `Truncated { needed: 4, remaining: 2, context: "encap header" }` rather than an opaque panic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// The buffer ended before a read of `needed` bytes could complete (only `remaining` were
    /// left). This is invariant 1/6 of §4: a short buffer is `Truncated`, never an index panic.
    Truncated {
        /// Bytes the read required.
        needed: usize,
        /// Bytes actually left in the buffer.
        remaining: usize,
        /// The layer that attempted the read.
        context: &'static str,
    },
    /// A structurally invalid field: a count/length that cannot be satisfied, an odd size where the
    /// spec requires words, a reserved field with an illegal value, an item shape that violates the
    /// spec. `detail` is a fixed diagnostic string (never device bytes).
    Malformed {
        /// The layer that rejected the bytes.
        context: &'static str,
        /// A fixed description of what was wrong.
        detail: &'static str,
    },
    /// Arithmetic on a wire-supplied length/count would overflow `usize` (invariant 2 of §4): the
    /// checked multiply/add returned `None`. Treated as malformed input, never a wrap.
    Overflow {
        /// The layer that computed the length.
        context: &'static str,
    },
    /// A string field (tag/symbol name) was not valid UTF-8 (invariant 4 of §4). The offending
    /// bytes are not retained; the lossy rendering, if any, lives only in log diagnostics.
    InvalidUtf8 {
        /// The layer that decoded the string.
        context: &'static str,
    },
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated {
                needed,
                remaining,
                context,
            } => write!(
                f,
                "truncated at {context}: needed {needed} bytes, {remaining} remaining"
            ),
            Self::Malformed { context, detail } => write!(f, "malformed {context}: {detail}"),
            Self::Overflow { context } => write!(f, "length overflow at {context}"),
            Self::InvalidUtf8 { context } => write!(f, "invalid utf-8 at {context}"),
        }
    }
}

impl std::error::Error for WireError {}

/// The public error type (PROTOCOL-DESIGN §10.1). `#[non_exhaustive]` — the adapter matches with a
/// wildcard arm and keys its reconnect classification on [`EnipError::is_transient`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnipError {
    /// A socket-level failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The TCP stream ended or framing broke mid-session (unrecoverable stream position).
    #[error("connection lost: {context}")]
    ConnectionLost {
        /// Where the stream broke.
        context: &'static str,
    },
    /// A caller-supplied deadline elapsed (D-ENIP-6).
    #[error("timeout during {op}")]
    Timeout {
        /// The operation that timed out.
        op: &'static str,
    },
    /// A reply carried a non-zero encapsulation status (§5.6).
    #[error("encapsulation status: {0}")]
    Encap(EncapStatus),
    /// A reply carried a non-zero CIP general status (§6.4). To the adapter these are usually
    /// per-tag *values* (BAD samples), not session failures.
    #[error("cip status: {0}")]
    Cip(CipStatus),
    /// A `ForwardOpen` was rejected by the target (§8.2).
    #[error("forward open rejected: {status}")]
    ForwardOpenRejected {
        /// The CIP status from the rejection.
        status: CipStatus,
        /// The remaining route-path size, when the rejection is a routing error.
        remaining_path_size: Option<u8>,
    },
    /// A decode failed — a hostile or broken peer (§4).
    #[error("malformed frame: {0}")]
    Malformed(#[from] WireError),
    /// A reply violated the protocol shape (wrong reply service, unexpected CPF layout).
    #[error("protocol violation: {detail}")]
    ProtocolViolation {
        /// A fixed description of the violation.
        detail: &'static str,
    },
    /// A feature the crate deliberately does not support (§1 non-goals): struct/STRING values, a
    /// route port > 14 (D-ENIP-13), etc.
    #[error("unsupported: {what}")]
    Unsupported {
        /// What was unsupported.
        what: &'static str,
    },
    /// The session or connection is already closed.
    #[error("closed")]
    Closed,
    /// A caller value or a wire-supplied reassembly size exceeded a configured cap
    /// (`max_value_bytes`, request-size limits — invariant 3 of §4).
    #[error("too large (limit {limit})")]
    TooLarge {
        /// The cap that was exceeded.
        limit: usize,
    },
}

impl EnipError {
    /// The adapter's reconnect classification default (§10.1): transport hiccups, timeouts, and
    /// resource/routing CIP errors are transient; a peer that breaks the protocol shape will keep
    /// breaking it, so those are not.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Io(_) | Self::ConnectionLost { .. } | Self::Timeout { .. } => true,
            Self::Encap(status) => matches!(status, EncapStatus::InsufficientMemory),
            Self::Cip(status) | Self::ForwardOpenRejected { status, .. } => {
                status.is_routing_error() || status.is_resource_error()
            }
            Self::Malformed(_)
            | Self::ProtocolViolation { .. }
            | Self::Unsupported { .. }
            | Self::TooLarge { .. }
            | Self::Closed => false,
        }
    }
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, EnipError>;
