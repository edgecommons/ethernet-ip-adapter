//! The identity surface (D-ENIP-26), proven over in-memory [`tokio::io::duplex`] fixtures.
//!
//! Two reads, two layers, and they are deliberately tested apart:
//!
//! * [`enip::EipClient::read_identity`] — the **CIP Identity Object** (class `0x01`, instance 1) via
//!   one `Get_Attributes_All` over an established session. Here the fixture proves the request that
//!   actually lands on the wire (service `0x01`, the Identity path, no attribute segment), the
//!   decode of a real mandatory attribute block, tolerance of a device that appends optional
//!   attributes, and that a device which **refuses** the service produces a typed CIP error rather
//!   than a panic or a bogus identity.
//! * [`enip::list_identity_over`] — the **encapsulation** `ListIdentity` (`0x0063`) over a connected
//!   but *unregistered* stream: the registration-failure diagnostic. The fixture proves the exchange
//!   is correlated (the context echo is required), bounded by the caller's absolute deadline, and
//!   that a peer which says nothing fails typed instead of hanging.
//!
//! There is no embedded server: each test spawns a mock peer on the server half of a duplex that
//! decodes the client's frames with the crate's own decoders and writes exact crafted bytes back.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use enip::encap::{Command, EncapFrame, EncapHeader, EncapStatus};
use enip::{
    ClientOptions, Cpf, CpfItem, EipClient, EnipError, GeneralStatus, IdentityObject, ItemType,
    SockAddrInfo, VendorId, WireWriter,
};

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

// ---------------------------------------------------------------------------
// mock peer
// ---------------------------------------------------------------------------

struct MockPeer {
    stream: DuplexStream,
    buf: BytesMut,
}

impl MockPeer {
    fn new(stream: DuplexStream) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
        }
    }

    async fn recv(&mut self) -> Option<EncapFrame> {
        loop {
            if self.buf.len() >= 24 {
                let header = EncapHeader::decode(&self.buf[..24]).unwrap();
                let total = 24 + header.length as usize;
                if self.buf.len() >= total {
                    let frame_bytes = self.buf.split_to(total);
                    return Some(EncapFrame::decode(&frame_bytes).unwrap());
                }
            }
            let n = self.stream.read_buf(&mut self.buf).await.unwrap();
            if n == 0 {
                return None;
            }
        }
    }

    async fn send(&mut self, frame: &EncapFrame) {
        let bytes = frame.encode().unwrap();
        self.stream.write_all(&bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    async fn handle_register(&mut self) {
        let req = self.recv().await.expect("register request");
        assert_eq!(req.header.command, Command::RegisterSession);
        self.send(&EncapFrame::new(
            EncapHeader::request(
                Command::RegisterSession,
                0,
                SESSION_HANDLE,
                req.header.sender_context,
            ),
            Bytes::from(vec![0x01, 0x00, 0x00, 0x00]),
        ))
        .await;
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// The mandatory Identity Object attribute block (attributes 1–7, in order) — what a compliant
/// `Get_Attributes_All` reply carries.
fn identity_attribute_block() -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u16(0x0001); // 1 vendor: Rockwell
    w.u16(0x000E); // 2 device type: PLC
    w.u16(0x0037); // 3 product code
    w.u8(20); // 4 revision major
    w.u8(11); // 4 revision minor
    w.u16(0x0060); // 5 status
    w.u32(0x1234_5678); // 6 serial
    w.u8(10); // 7 product name (SHORT_STRING)
    w.put_slice(b"1756-L71/B");
    w.into_inner().to_vec()
}

/// A ListIdentity CPF Identity item (§5.3) — the encapsulation-layer shape.
fn list_identity_item() -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u16(1); // protocol version
    w.put_slice(&SockAddrInfo::ipv4(0xC0A8_0132, 44818).encode());
    w.u16(0x0001); // vendor
    w.u16(0x000E); // device type
    w.u16(0x0037); // product code
    w.u8(20);
    w.u8(11);
    w.u16(0x0060); // status
    w.u32(0x1234_5678); // serial
    w.u8(10);
    w.put_slice(b"1756-L71/B");
    w.u8(0x03); // state
    w.into_inner().to_vec()
}

fn list_identity_reply(ctx: [u8; 8]) -> EncapFrame {
    let cpf = Cpf::from_items(vec![CpfItem::new(
        ItemType::Identity,
        Bytes::from(list_identity_item()),
    )]);
    EncapFrame::new(
        EncapHeader::request(Command::ListIdentity, 0, 0, ctx),
        cpf.encode().unwrap(),
    )
}

/// A Message Router reply: `reply-service · reserved · status · ext-size · data`.
fn mr_reply(service: u8, status: u8, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(status);
    w.u8(0);
    w.put_slice(data);
    w.into_bytes().to_vec()
}

fn rrdata_reply(ctx: [u8; 8], mr: &[u8]) -> EncapFrame {
    let cpf = Cpf::from_items(vec![
        CpfItem::null_address(),
        CpfItem::unconnected_data(Bytes::copy_from_slice(mr)),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(0); // interface handle
    w.u16(0); // timeout
    w.put_slice(&cpf_bytes);
    EncapFrame::new(
        EncapHeader::request(Command::SendRRData, 0, SESSION_HANDLE, ctx),
        w.into_bytes(),
    )
}

fn opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// EipClient::read_identity — the CIP Identity Object over an established session
// ---------------------------------------------------------------------------

/// The happy path, and the **request** as much as the reply: one `Get_Attributes_All` (`0x01`) to
/// the Identity Object path `[0x20 0x01 0x24 0x01]` — a class/instance path with **no** attribute
/// segment — and the mandatory attribute block decoded field by field.
#[tokio::test]
async fn read_identity_issues_one_get_attributes_all_and_decodes_the_block() {
    let (client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        peer.handle_register().await;
        let req = peer.recv().await.expect("the identity request");
        assert_eq!(req.header.command, Command::SendRRData);
        // Skip the 6-byte interface-handle/timeout prefix and the CPF framing to reach the MR.
        let cpf = Cpf::decode(&req.data[6..]).unwrap();
        let mr = cpf.expect_explicit_data().unwrap();
        // `service · path-size(words) · path…`
        assert_eq!(mr[0], 0x01, "Get_Attributes_All, not six singles");
        assert_eq!(mr[1], 2, "a two-word path: class + instance");
        assert_eq!(
            &mr[2..6],
            &[0x20, 0x01, 0x24, 0x01],
            "class 0x01 instance 1, and NO attribute segment"
        );
        assert_eq!(mr.len(), 6, "no request data rides a Get_Attributes_All");
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x01, 0x00, &identity_attribute_block()),
        ))
        .await;
        peer
    });

    let client = EipClient::connect_over(client_half, opts()).await.unwrap();
    let id = client.read_identity().await.expect("the identity block");
    assert_eq!(id.vendor, VendorId(1));
    assert_eq!(
        id.vendor.name(),
        Some("Rockwell Automation/Allen-Bradley"),
        "the vendor renders through the known-values table"
    );
    assert_eq!(id.device_type.0, 0x000E);
    assert_eq!(id.product_code, 0x0037);
    assert_eq!(id.revision(), "20.11");
    assert_eq!(id.status, 0x0060);
    assert_eq!(id.serial_number, 0x1234_5678);
    assert_eq!(id.product_name, "1756-L71/B");
    assert_eq!(
        id.to_string(),
        "1756-L71/B rev 20.11 (Rockwell Automation/Allen-Bradley (0x0001), serial 0x12345678)"
    );
    peer.await.unwrap();
}

/// A device that serves **more** than the mandatory set is not malformed: the optional attributes a
/// real controller appends after the product name (state, config consistency, heartbeat) are
/// ignored, not refused. Reading them as a decode failure would make the identity of every
/// well-equipped device unavailable.
#[tokio::test]
async fn trailing_optional_attributes_are_ignored_not_refused() {
    let mut block = identity_attribute_block();
    block.extend_from_slice(&[0x03, 0xAB, 0xCD, 0xEF]); // state + whatever else the device adds
    let id = IdentityObject::parse_get_attributes_all(&block).expect("the mandatory block decodes");
    assert_eq!(id.product_name, "1756-L71/B");
    assert_eq!(id.revision(), "20.11");
}

/// A block that ends before the mandatory set is complete is a typed truncation, never a panic and
/// never a half-populated identity.
#[test]
fn a_runt_attribute_block_is_truncated() {
    let full = identity_attribute_block();
    for cut in 0..full.len() {
        assert!(
            IdentityObject::parse_get_attributes_all(&full[..cut]).is_err(),
            "a block cut at {cut} bytes must not decode"
        );
    }
    assert!(IdentityObject::parse_get_attributes_all(&full).is_ok());
}

/// **Refusal is a device's prerogative.** Identity is CIP-mandatory, but a target that answers
/// `Service_Not_Supported` must produce a typed CIP error the caller can tolerate — not an
/// `Ok` with an invented identity, and not a connection-level failure that would take the session
/// down with it.
#[tokio::test]
async fn a_device_that_refuses_the_service_yields_a_typed_cip_error() {
    let (client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        peer.handle_register().await;
        let req = peer.recv().await.expect("the identity request");
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x01, 0x08, &[]), // 0x08 Service_Not_Supported
        ))
        .await;
        peer
    });

    let client = EipClient::connect_over(client_half, opts()).await.unwrap();
    let err = client.read_identity().await.expect_err("a refusal");
    match err {
        EnipError::Cip(status) => assert_eq!(status.general, GeneralStatus::ServiceNotSupported),
        other => panic!("a refused service must surface as a CIP status, got {other:?}"),
    }
    // The session is untouched: the refusal was one request's verdict, not the link's.
    assert_eq!(client.stats().timeouts, 0);
    peer.await.unwrap();
}

// ---------------------------------------------------------------------------
// list_identity_over — the pre-registration diagnostic
// ---------------------------------------------------------------------------

/// The diagnostic exchange on a stream that has **never registered a session**: one `ListIdentity`
/// request out, one Identity item back, decoded. This is the shape the adapter uses when a target
/// accepts TCP and then refuses to open a session.
#[tokio::test]
async fn list_identity_over_an_unregistered_stream_round_trips() {
    let (mut client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        let req = peer.recv().await.expect("the ListIdentity request");
        assert_eq!(req.header.command, Command::ListIdentity);
        assert_eq!(
            req.header.session_handle, 0,
            "the probe runs before a session exists, so it carries no handle"
        );
        assert!(
            req.data.is_empty(),
            "ListIdentity is a bare command with no data portion"
        );
        assert_eq!(
            req.header.sender_context,
            enip::LIST_IDENTITY_CONTEXT,
            "the request stamps the correlation tag the reply must echo"
        );
        peer.send(&list_identity_reply(req.header.sender_context))
            .await;
        peer
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let id = enip::list_identity_over(&mut client_half, deadline)
        .await
        .expect("the identity of a peer that will not register");
    assert_eq!(id.vendor, VendorId(1));
    assert_eq!(id.product_name, "1756-L71/B");
    assert_eq!(id.revision_major, 20);
    assert_eq!(id.revision_minor, 11);
    assert_eq!(id.serial_number, 0x1234_5678);
    peer.await.unwrap();
}

/// The exchange is **correlated**: a reply that does not echo the request's context is not our
/// identity, whatever else it looks like, and is refused as a protocol violation rather than
/// adopted.
#[tokio::test]
async fn a_reply_with_a_foreign_context_is_refused() {
    let (mut client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        let _req = peer.recv().await.expect("the ListIdentity request");
        peer.send(&list_identity_reply(*b"SOMEBODY")).await;
        peer
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let err = enip::list_identity_over(&mut client_half, deadline)
        .await
        .expect_err("a foreign context must not be adopted");
    assert!(
        matches!(err, EnipError::ProtocolViolation { .. }),
        "got {err:?}"
    );
    peer.await.unwrap();
}

/// An encapsulation error status on the reply is surfaced as such — the peer answered, and said no.
#[tokio::test]
async fn an_encapsulation_error_status_is_surfaced() {
    let (mut client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        let req = peer.recv().await.expect("the ListIdentity request");
        let mut header =
            EncapHeader::request(Command::ListIdentity, 0, 0, req.header.sender_context);
        header.status = EncapStatus::UnsupportedCommand;
        peer.send(&EncapFrame::new(header, Bytes::new())).await;
        peer
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let err = enip::list_identity_over(&mut client_half, deadline)
        .await
        .expect_err("an error status is not an identity");
    assert!(
        matches!(err, EnipError::Encap(EncapStatus::UnsupportedCommand)),
        "got {err:?}"
    );
    peer.await.unwrap();
}

/// **Bounded, always.** A peer that accepts the request and then goes quiet — the very peer this
/// diagnostic exists for — must end the probe on the caller's absolute deadline with a typed
/// timeout, not park the connect ladder behind it.
#[tokio::test(start_paused = true)]
async fn a_silent_peer_ends_on_the_callers_deadline() {
    let (mut client_half, server_half) = tokio::io::duplex(4096);
    // Held open and never answered: dropping it would give an EOF instead of the silence under test.
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        let _req = peer.recv().await;
        std::future::pending::<()>().await;
    });

    let budget = Duration::from_millis(900);
    let started = tokio::time::Instant::now();
    let deadline = started + budget;
    let err = enip::list_identity_over(&mut client_half, deadline)
        .await
        .expect_err("silence is not an identity");
    assert!(
        matches!(
            err,
            EnipError::Timeout {
                op: "list_identity"
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        started.elapsed(),
        budget,
        "the probe ends ON the deadline it was given"
    );
    peer.abort();
}

/// A peer that closes the stream instead of answering is a lost connection, typed — the failure the
/// adapter then reports beside the registration failure that sent it here.
#[tokio::test]
async fn a_peer_that_closes_yields_connection_lost() {
    let (mut client_half, server_half) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_half);
        let _req = peer.recv().await;
        drop(peer);
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let err = enip::list_identity_over(&mut client_half, deadline)
        .await
        .expect_err("an EOF is not an identity");
    assert!(
        matches!(err, EnipError::ConnectionLost { .. }),
        "got {err:?}"
    );
    peer.await.unwrap();
}
