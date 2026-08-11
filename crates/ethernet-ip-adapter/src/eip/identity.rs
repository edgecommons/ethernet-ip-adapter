//! # Identity at connect (D-EIP-34) — the EtherNet/IP side
//!
//! Two reads, both diagnostics, both entirely inside the backend:
//!
//! * [`read_identity`] — one CIP Identity Object `Get_Attributes_All` over a **freshly established
//!   session**, mapped across the seam as [`DeviceIdentity`]. A device that refuses it costs one
//!   WARN and nothing else; the connect proceeds and `identity` is simply absent.
//! * [`identity_of_unregisterable_peer`] — the **registration-failure** diagnostic. When a target
//!   accepts TCP and then refuses to open a session, the ordinary error text says only that the
//!   handshake failed. One bounded encapsulation `ListIdentity` (`0x0063`) — the one question a
//!   target answers without a session — turns "RegisterSession refused" into "the 1756-L71/B at
//!   10.0.0.5 refused RegisterSession", which is the difference between a wrong address and a
//!   device that is out of sessions.
//!
//! **The invariant both obey: identity informs, wire facts decide.** Nothing here feeds a decision.
//! No value read by this module selects a code path, a service, or a decode; it lands in a log, an
//! event context, and `sb/status`, and nowhere else. That is deliberate — the identity is asserted by
//! the device and proven by nothing (the cpppo bench peer claims to be a Rockwell `1756-L61/B
//! LOGIX5561`), so a quirk table keyed on it would be a correctness argument resting on an
//! unauthenticated string.
//!
//! **ListIdentity has exactly one role**, and it is this one. It is not a discovery verb, it is not
//! a fallback for the Identity Object read, and it never runs on a healthy connect.

use std::time::Duration;

use crate::device::{ConnectionConfig, DeviceIdentity};

/// The share of the connect budget the registration-failure diagnostic may spend
/// ([`identity_of_unregisterable_peer`]). Deliberately small: the probe is a nicety on a path that
/// has already failed, and the connect ladder is waiting to back off. Whatever is left of the
/// caller's own budget caps it further, so a connect that already burned its allowance probes for
/// (almost) nothing rather than extending the failure.
pub(crate) const LIST_IDENTITY_BUDGET: Duration = Duration::from_secs(1);

/// Map the protocol crate's Identity Object into the seam type, rendering the vendor and device-type
/// names through the crate's known-values table so nothing above the seam needs it.
fn to_seam(id: &enip::IdentityObject) -> DeviceIdentity {
    DeviceIdentity {
        vendor_id: id.vendor.0,
        vendor_name: id.vendor.name().map(str::to_owned),
        device_type: id.device_type.0,
        device_type_name: id.device_type.name().map(str::to_owned),
        product_code: id.product_code,
        revision_major: id.revision_major,
        revision_minor: id.revision_minor,
        serial_number: id.serial_number,
        product_name: id.product_name.clone(),
    }
}

/// The same mapping for the encapsulation `ListIdentity` item, which carries the same nameplate
/// fields wrapped in a socket address and a state byte (§5.3).
fn list_identity_to_seam(id: &enip::DeviceIdentity) -> DeviceIdentity {
    DeviceIdentity {
        vendor_id: id.vendor.0,
        vendor_name: id.vendor.name().map(str::to_owned),
        device_type: id.device_type.0,
        device_type_name: id.device_type.name().map(str::to_owned),
        product_code: id.product_code,
        revision_major: id.revision_major,
        revision_minor: id.revision_minor,
        serial_number: id.serial_number,
        product_name: id.product_name.clone(),
    }
}

/// Read the CIP Identity Object over an established session (D-EIP-34), best-effort.
///
/// **Never fatal.** Identity is CIP-mandatory, and a device is still entitled to refuse: the
/// libplctag `ab_server` bench peer answers `Service_Not_Supported` to every Identity service it is
/// asked for, GAA and singles alike, and it is a perfectly good poll target. A refusal — or any
/// other failure — costs one WARN and yields `None`; the caller connects regardless.
///
/// One round trip, budgeted by the client's own `requestTimeoutMs` like every other request.
pub(crate) async fn read_identity(
    client: &enip::EipClient,
    endpoint: &str,
) -> Option<DeviceIdentity> {
    match client.read_identity().await {
        Ok(id) => Some(to_seam(&id)),
        Err(e) => {
            tracing::warn!(
                endpoint = %endpoint,
                error = %e,
                "the device did not answer the CIP Identity Object read; connecting without an \
                 identity (status, events and logs will report it as unknown)"
            );
            None
        }
    }
}

/// Whether a failed [`enip::EipClient::connect`] failed **after** the TCP connection was
/// established — i.e. in the RegisterSession handshake — and is therefore worth a ListIdentity
/// probe (D-EIP-34).
///
/// The distinction is the whole point of the diagnostic. A refused TCP connect says the address is
/// wrong or nothing is listening, and dialling it a second time to ask its name is pure noise. A
/// *handshake* failure says something answered and then would not open a session, which is exactly
/// when knowing what answered is worth a round trip.
///
/// Only variants whose provenance is unambiguous count. `Io` is excluded on purpose: it is what a
/// refused connect looks like, and also what a mid-handshake socket error looks like, and a probe
/// fired on the first is worse than a probe missed on the second.
pub(crate) fn is_registration_failure(e: &enip::EnipError) -> bool {
    match e {
        // The target answered RegisterSession with an encapsulation error status.
        enip::EnipError::Encap(_) => true,
        // It answered with something that is not a conforming RegisterSession reply, or with a
        // protocol generation this crate does not speak. Either way, it answered.
        enip::EnipError::ProtocolViolation { .. } | enip::EnipError::Unsupported { .. } => true,
        // The handshake — not the connect — ran out of budget, or the peer closed mid-handshake.
        // `EipClient::connect` labels the two phases distinctly, which is what makes this readable.
        enip::EnipError::Timeout { op } => *op == "register",
        enip::EnipError::ConnectionLost { .. } => true,
        _ => false,
    }
}

/// The registration-failure diagnostic: one bounded `ListIdentity` against a target that accepted
/// TCP and then refused to open a session (D-EIP-34).
///
/// Opens its own short-lived TCP connection — the failed handshake's stream is gone, consumed and
/// dropped inside the crate — sends `ListIdentity` pre-registration, and returns whatever it yields.
/// `None` for every failure mode: the connect has already failed, and the diagnostic must never turn
/// one failure into two or delay the backoff. The whole attempt (connect + exchange) shares ONE
/// absolute budget, the smaller of [`LIST_IDENTITY_BUDGET`] and whatever the caller has left.
pub(crate) async fn identity_of_unregisterable_peer(
    conn: &ConnectionConfig,
    port: u16,
    remaining: Duration,
) -> Option<DeviceIdentity> {
    let budget = LIST_IDENTITY_BUDGET.min(remaining);
    if budget.is_zero() {
        return None;
    }
    let deadline = tokio::time::Instant::now() + budget;
    let target = if conn.endpoint.contains(':') {
        conn.endpoint.clone()
    } else {
        format!("{}:{port}", conn.endpoint)
    };

    let connect = tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(&target));
    let mut stream = match connect.await {
        Ok(Ok(s)) => s,
        // The peer that just answered a handshake is not answering TCP now: nothing to learn, and
        // nothing to say about it that the connect failure has not already said.
        Ok(Err(_)) | Err(_) => return None,
    };
    match enip::list_identity_over(&mut stream, deadline).await {
        Ok(id) => Some(list_identity_to_seam(&id)),
        Err(e) => {
            tracing::debug!(
                endpoint = %conn.endpoint,
                error = %e,
                "the ListIdentity diagnostic did not answer either"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_post_tcp_handshake_failures_earn_a_probe() {
        // Answered, and said no — probe.
        assert!(is_registration_failure(&enip::EnipError::Encap(
            enip::EncapStatus::InvalidSessionHandle
        )));
        assert!(is_registration_failure(
            &enip::EnipError::ProtocolViolation {
                detail: "register reply context mismatch"
            }
        ));
        assert!(is_registration_failure(&enip::EnipError::Unsupported {
            what: "encapsulation protocol version"
        }));
        assert!(is_registration_failure(&enip::EnipError::Timeout {
            op: "register"
        }));
        assert!(is_registration_failure(&enip::EnipError::ConnectionLost {
            context: "eof during handshake"
        }));

        // Never answered — no probe. A refused/timed-out TCP connect is an address problem, and
        // dialling it again to ask its name would be noise on a path that already knows the answer.
        assert!(!is_registration_failure(&enip::EnipError::Timeout {
            op: "connect"
        }));
        assert!(!is_registration_failure(&enip::EnipError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused")
        )));
    }

    /// A budget already spent buys no probe: the ladder backs off instead of waiting on a nicety.
    #[tokio::test]
    async fn a_spent_budget_skips_the_probe_entirely() {
        let conn: ConnectionConfig =
            serde_json::from_value(serde_json::json!({ "endpoint": "203.0.113.1" })).unwrap();
        let started = tokio::time::Instant::now();
        let out = identity_of_unregisterable_peer(&conn, 44818, Duration::ZERO).await;
        assert!(out.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a zero budget must not dial at all"
        );
    }

    /// The seam mapping renders the crate's known-values table into plain strings, and leaves an
    /// unregistered vendor as an id with no name rather than inventing one.
    #[test]
    fn the_seam_mapping_carries_names_and_admits_ignorance() {
        let known = enip::IdentityObject {
            vendor: enip::VendorId(1),
            device_type: enip::DeviceType(0x0E),
            product_code: 0x37,
            revision_major: 20,
            revision_minor: 11,
            status: 0x60,
            serial_number: 0x1234_5678,
            product_name: "1756-L71/B".to_string(),
        };
        let mapped = to_seam(&known);
        assert_eq!(
            mapped.vendor_name.as_deref(),
            Some("Rockwell Automation/Allen-Bradley")
        );
        assert_eq!(
            mapped.device_type_name.as_deref(),
            Some("Programmable Logic Controller")
        );
        assert_eq!(mapped.revision(), "20.11");
        assert_eq!(mapped.summary(), "1756-L71/B rev 20.11");

        let unknown = enip::IdentityObject {
            vendor: enip::VendorId(0x9999),
            device_type: enip::DeviceType(0x4242),
            ..known
        };
        let mapped = to_seam(&unknown);
        assert_eq!(mapped.vendor_id, 0x9999);
        assert!(mapped.vendor_name.is_none(), "no name is invented");
        assert!(mapped.device_type_name.is_none());
    }

    /// The `ListIdentity` item maps to the same seam shape as the Identity Object — the two reads
    /// answer the same question from two layers, and a consumer must not be able to tell which one
    /// answered by the shape of what it gets.
    #[test]
    fn the_list_identity_item_maps_to_the_same_seam_shape() {
        let item = enip::DeviceIdentity {
            protocol_version: 1,
            socket_addr: enip::SockAddrInfo::ipv4(0xC0A8_0132, 44818),
            vendor: enip::VendorId(1),
            device_type: enip::DeviceType(0x0E),
            product_code: 0x37,
            revision_major: 20,
            revision_minor: 11,
            status: 0x60,
            serial_number: 0x1234_5678,
            product_name: "1756-L71/B".to_string(),
            state: 3,
        };
        let obj = enip::IdentityObject {
            vendor: enip::VendorId(1),
            device_type: enip::DeviceType(0x0E),
            product_code: 0x37,
            revision_major: 20,
            revision_minor: 11,
            status: 0x60,
            serial_number: 0x1234_5678,
            product_name: "1756-L71/B".to_string(),
        };
        assert_eq!(list_identity_to_seam(&item), to_seam(&obj));
    }
}
