//! # The EtherNet/IP backend (`eip/`) — the only module that imports the `enip` crate
//!
//! This is the protocol side of the `device.rs` seam (§3.4): it turns the owned `enip` stack
//! ([`enip::EipClient`] for poll, [`enip::IoManager`] for push) into the [`DeviceBackend`] /
//! [`DeviceSession`] / [`PushSession`] the supervisor drives. Everything above the seam speaks
//! [`Reading`](crate::device::Reading)s and [`crate::device::IoUpdate`]s; the `enip` types
//! (`CipValue`, `EnipError`, `IoEvent`, `AssemblyLayout`) never cross it.
//!
//! * [`types`] — the pure JSON ⇄ `CipValue` codec (§5.1, fully unit-tested).
//! * [`session`] — [`EipSession`]: the poll [`DeviceSession`] over `EipClient` (read/write/browse/probe).
//! * [`push`] — [`push::EipPushSession`]: the [`PushSession`] over `IoManager` (class-1 implicit I/O).
//!
//! **Error classification (§10.1).** [`map_enip_error`] implements the normative `EnipError →
//! DeviceError` table: `EnipError::is_transient()` is the default, overridden per row (a peer that
//! breaks the protocol shape is `Permanent`; an invalid session handle is `Transient` because
//! reconnecting re-registers it). Per-tag CIP statuses and isolated request timeouts are **not**
//! mapped here — they become BAD samples in [`session`] (§5.4); only connection-level failures reach
//! this function.

use std::time::Duration;

use async_trait::async_trait;

use crate::config::{IoConfig, Timeouts};
use crate::device::{
    ConnectionConfig, DeviceBackend, DeviceError, DeviceSession, PushSession, Result,
};

pub mod push;
pub mod session;
pub mod types;

/// The originator vendor id stamped into ForwardOpen / class-1 opens (matches the `enip` default).
const VENDOR_ID: u16 = 0x1337;

/// Opens sessions over the owned `enip` EtherNet/IP stack (kind `"ethernet-ip"`, §3.4). Holds the
/// configured connection timeouts (the [`DeviceBackend::connect`] signature carries only the
/// connection, but the `enip` client needs the connect/request deadlines from `component.global`).
pub struct EipBackend {
    timeouts: Timeouts,
}

impl EipBackend {
    /// A backend with the given connection timeouts (from `component.global.timeouts`, §4.1).
    #[must_use]
    pub fn new(timeouts: Timeouts) -> Self {
        Self { timeouts }
    }
}

/// Build the `enip` client options from the connection config + timeouts (§3.4): slot ⇒ backplane
/// route, `connected` ⇒ connected class-3 messaging, deadlines from `timeouts`.
fn client_options(conn: &ConnectionConfig, timeouts: &Timeouts) -> enip::ClientOptions {
    enip::ClientOptions {
        route: conn.slot.map(enip::RoutePath::backplane_slot),
        connect_timeout: Duration::from_millis(timeouts.connect_ms.max(1)),
        request_timeout: Duration::from_millis(timeouts.request_timeout_ms.max(1)),
        connected_messaging: conn.connected,
        vendor_id: VENDOR_ID,
        ..Default::default()
    }
}

#[async_trait]
impl DeviceBackend for EipBackend {
    fn kind(&self) -> &'static str {
        "ethernet-ip"
    }

    async fn connect(&self, conn: &ConnectionConfig) -> Result<Box<dyn DeviceSession>> {
        let opts = client_options(conn, &self.timeouts);
        let request_timeout = opts.request_timeout;
        let client = enip::EipClient::connect(&conn.endpoint, opts)
            .await
            .map_err(map_enip_error)?;
        Ok(Box::new(session::EipSession::new(client, request_timeout)))
    }

    async fn open_push(
        &self,
        conn: &ConnectionConfig,
        io: &IoConfig,
    ) -> Result<Box<dyn PushSession>> {
        let session = push::EipPushSession::open(conn, io, &self.timeouts, VENDOR_ID).await?;
        Ok(Box::new(session))
    }
}

/// Classify an `enip` error into the seam's [`DeviceError`] per the §10.1 table (the adapter's
/// normative reconnect behavior). Only connection-level failures reach here — per-tag CIP statuses
/// and isolated timeouts are handled as BAD samples in [`session`] before this is called.
///
/// The default is [`enip::EnipError::is_transient`]; the overrides: a malformed/hostile peer or a
/// caller-size violation is `Permanent` (it will keep failing); an invalid session handle is
/// `Transient` (reconnect re-registers); an `Unsupported` feature maps to [`DeviceError::Unsupported`].
pub(crate) fn map_enip_error(e: enip::EnipError) -> DeviceError {
    // `Unsupported` carries a static reason string, not a source error.
    if let enip::EnipError::Unsupported { what } = e {
        return DeviceError::Unsupported(what);
    }
    let transient = match &e {
        // A peer that breaks the protocol shape, or a size-cap violation, will not fix itself.
        enip::EnipError::Malformed(_)
        | enip::EnipError::ProtocolViolation { .. }
        | enip::EnipError::TooLarge { .. } => false,
        // An invalid session handle poisons the session but reconnecting re-registers it.
        enip::EnipError::Encap(status) if status.poisons_session() => true,
        // Everything else follows the crate's own transient/permanent classification.
        other => other.is_transient(),
    };
    if transient {
        DeviceError::Transient(anyhow::Error::new(e))
    } else {
        DeviceError::Permanent(anyhow::Error::new(e))
    }
}

#[cfg(test)]
mod tests {
    //! One test per §10.1 classification row (transient vs permanent vs unsupported).
    use super::map_enip_error;
    use crate::device::DeviceError;
    use enip::{CipStatus, EnipError, GeneralStatus, WireError};

    fn is_transient(e: EnipError) -> bool {
        matches!(map_enip_error(e), DeviceError::Transient(_))
    }
    fn is_permanent(e: EnipError) -> bool {
        matches!(map_enip_error(e), DeviceError::Permanent(_))
    }

    #[test]
    fn row_tcp_io_error_is_transient() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(is_transient(EnipError::Io(io)));
    }

    #[test]
    fn row_connection_lost_is_transient() {
        assert!(is_transient(EnipError::ConnectionLost { context: "session eof" }));
    }

    #[test]
    fn row_request_timeout_is_transient() {
        // A single timeout is a BAD sample (handled in session); when mapped it is transient.
        assert!(is_transient(EnipError::Timeout { op: "request" }));
    }

    #[test]
    fn row_cip_resource_error_is_transient() {
        // Resource-unavailable (target busy / out of connections) is a transient reconnect class.
        let status = CipStatus::new(GeneralStatus::ResourceUnavailable);
        assert!(is_transient(EnipError::Cip(status)));
    }

    #[test]
    fn row_cip_permanent_status_is_permanent() {
        // A non-routing, non-resource CIP status reaching the connection level is permanent.
        let status = CipStatus::new(GeneralStatus::ServiceNotSupported);
        assert!(is_permanent(EnipError::Cip(status)));
    }

    #[test]
    fn row_forward_open_rejected_is_transient() {
        let status = CipStatus::new(GeneralStatus::ResourceUnavailable);
        assert!(is_transient(EnipError::ForwardOpenRejected {
            status,
            remaining_path_size: None,
        }));
    }

    #[test]
    fn row_malformed_peer_is_permanent() {
        assert!(is_permanent(EnipError::Malformed(WireError::Malformed {
            context: "test",
            detail: "bad",
        })));
    }

    #[test]
    fn row_protocol_violation_is_permanent() {
        assert!(is_permanent(EnipError::ProtocolViolation { detail: "bad reply" }));
    }

    #[test]
    fn row_too_large_is_permanent() {
        assert!(is_permanent(EnipError::TooLarge { limit: 1024 }));
    }

    #[test]
    fn row_invalid_session_handle_is_transient() {
        assert!(is_transient(EnipError::Encap(
            enip::EncapStatus::InvalidSessionHandle
        )));
    }

    #[test]
    fn row_unsupported_maps_to_unsupported() {
        let mapped = map_enip_error(EnipError::Unsupported { what: "struct value" });
        assert!(matches!(mapped, DeviceError::Unsupported("struct value")));
    }
}
