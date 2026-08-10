//! Connected class-3 ForwardOpen **reply verification** (PROTOCOL-DESIGN §7.6, §8.2, D-ENIP-16).
//!
//! The class-3 open adopts the target-assigned O→T connection id from a ForwardOpen success reply.
//! If that reply is not verified to echo our originator identity, a crossed or hostile reply binds
//! the whole explicit path to somebody else's connection — every subsequent request would be
//! addressed to it. These tests drive `open_class3` over an in-memory [`tokio::io::duplex`]
//! byte-stream fixture (D-ENIP-14 — no embedded server) and prove the check both rejects a corrupt
//! echo (with a best-effort ForwardClose behind it) and leaves a faithful reply alone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use enip::encap::{Command, EncapFrame, EncapHeader};
use enip::{ClientOptions, Cpf, CpfItem, EipClient, EnipError, WireReader, WireWriter};

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

/// Connection Manager service codes (§8.2, §8.8).
const FORWARD_OPEN: u8 = 0x54;
const FORWARD_CLOSE: u8 = 0x4E;

// ---------------------------------------------------------------------------
// mock peer over the server half of a duplex — crafts exact response bytes
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

    /// Read the next full request frame, or `None` at EOF (client dropped).
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
        let reply = mk_frame(
            Command::RegisterSession,
            SESSION_HANDLE,
            req.header.sender_context,
            vec![0x01, 0x00, 0x00, 0x00],
        );
        self.send(&reply).await;
    }
}

// ---------------------------------------------------------------------------
// frame / reply builders — the reply must echo the request's sender context, reuse the SAME
// encapsulation command, and carry the registered session handle (§5.1, §10.3).
// ---------------------------------------------------------------------------

fn mk_frame(command: Command, handle: u32, ctx: [u8; 8], data: Vec<u8>) -> EncapFrame {
    EncapFrame::new(
        EncapHeader::request(command, 0, handle, ctx),
        Bytes::from(data),
    )
}

/// A Message Router reply: `reply-service · reserved · status · ext-words · data`.
fn mr_reply(service: u8, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(0); // success
    w.u8(0); // no extended-status words
    w.put_slice(data);
    w.into_bytes().to_vec()
}

/// Wrap MR bytes in a `SendRRData` reply frame (UCMM CPF `[null, unconnected-data]`).
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
    mk_frame(
        Command::SendRRData,
        SESSION_HANDLE,
        ctx,
        w.into_bytes().to_vec(),
    )
}

/// Split a UCMM (`SendRRData`) request frame into `(service, service-data)`.
fn parse_ucmm_request(frame: &EncapFrame) -> (u8, Vec<u8>) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap(); // interface handle
    r.u16().unwrap(); // timeout
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let mr = cpf.expect_explicit_data().unwrap();
    let mut mr_r = WireReader::new(mr);
    let service = mr_r.u8().unwrap();
    let path_words = mr_r.u8().unwrap() as usize;
    mr_r.skip(path_words * 2).unwrap();
    (service, mr_r.take_rest().to_vec())
}

/// The originator identity a ForwardOpen request carries (§8.2 fields 4–7).
struct OpenIdentity {
    t_o_connection_id: u32,
    connection_serial: u16,
    vendor_id: u16,
    originator_serial: u32,
}

fn parse_open_identity(data: &[u8]) -> OpenIdentity {
    let mut r = WireReader::new(data);
    r.u8().unwrap(); // priority/time tick
    r.u8().unwrap(); // timeout ticks
    r.u32().unwrap(); // O→T id (0 — the target assigns it)
    OpenIdentity {
        t_o_connection_id: r.u32().unwrap(),
        connection_serial: r.u16().unwrap(),
        vendor_id: r.u16().unwrap(),
        originator_serial: r.u32().unwrap(),
    }
}

/// A ForwardOpen success reply body (§8.2) built from an identity plus 2 s APIs.
fn forward_open_success(id: &OpenIdentity) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u32(0xAABB_CCDD); // O→T id, target-assigned
    w.u32(id.t_o_connection_id);
    w.u16(id.connection_serial);
    w.u16(id.vendor_id);
    w.u32(id.originator_serial);
    // Class-3 consults the reply O→T API only for the keepalive window (§7.6): 2 s × the default ×16
    // multiplier is a 32 s inactivity window, so no probe falls due inside these tests.
    w.u32(2_000_000); // O→T API (µs)
    w.u32(2_000_000); // T→O API (µs)
    w.u8(0); // application reply words
    w.u8(0); // reserved
    w.into_bytes().to_vec()
}

/// A ForwardClose success reply body (§8.8).
fn forward_close_success(id: &OpenIdentity) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u16(id.connection_serial);
    w.u16(id.vendor_id);
    w.u32(id.originator_serial);
    w.into_bytes().to_vec()
}

fn connected_opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_millis(500),
        connected_messaging: true,
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// **F10 regression (`client/connected.rs`).** A class-3 ForwardOpen reply that does not echo the
/// request's connection serial is refused: `connect_over` fails with a typed `ProtocolViolation`
/// rather than adopting the target-assigned O→T id, and a best-effort ForwardClose (`0x4E`) goes out
/// so the target does not keep a connection we will never drive.
#[tokio::test]
async fn class3_open_rejects_echo_mismatch() {
    let (client_side, server_side) = tokio::io::duplex(8192);

    let peer = tokio::spawn(async move {
        let mut mock = MockPeer::new(server_side);
        mock.handle_register().await;

        let open_frame = mock.recv().await.expect("forward open request");
        let (service, data) = parse_ucmm_request(&open_frame);
        assert_eq!(service, FORWARD_OPEN);
        let id = parse_open_identity(&data);
        let requested_serial = id.connection_serial;

        // Echo everything faithfully EXCEPT the connection serial.
        let corrupted = OpenIdentity {
            connection_serial: requested_serial ^ 1,
            ..id
        };
        let mr = mr_reply(FORWARD_OPEN, &forward_open_success(&corrupted));
        mock.send(&rrdata_reply(open_frame.header.sender_context, &mr))
            .await;

        // The refusal must be followed by a best-effort ForwardClose carrying the OPEN's serial
        // (§8.8 body: priority · ticks · serial · vendor · originator serial · …).
        let close_frame = mock.recv().await.expect("best-effort forward close");
        let (close_service, close_data) = parse_ucmm_request(&close_frame);
        assert_eq!(
            close_service, FORWARD_CLOSE,
            "the target is told to drop the connection"
        );
        assert_eq!(
            &close_data[2..4],
            &requested_serial.to_le_bytes(),
            "the close carries the open's own serial, not the corrupted echo"
        );
        let mr = mr_reply(FORWARD_CLOSE, &forward_close_success(&corrupted));
        mock.send(&rrdata_reply(close_frame.header.sender_context, &mr))
            .await;
        true
    });

    match EipClient::connect_over(client_side, connected_opts()).await {
        Err(EnipError::ProtocolViolation { detail }) => {
            assert_eq!(detail, "forward-open reply connection serial mismatch");
        }
        other => panic!(
            "expected a protocol violation, got {:?}",
            other.map(|_| "Ok(client)")
        ),
    }
    assert!(peer.await.unwrap());
}

/// The guard against over-tightening: a faithful echo still opens the class-3 path.
#[tokio::test]
async fn class3_open_still_succeeds_on_faithful_echo() {
    let (client_side, server_side) = tokio::io::duplex(8192);

    let peer = tokio::spawn(async move {
        let mut mock = MockPeer::new(server_side);
        mock.handle_register().await;

        let open_frame = mock.recv().await.expect("forward open request");
        let (service, data) = parse_ucmm_request(&open_frame);
        assert_eq!(service, FORWARD_OPEN);
        let id = parse_open_identity(&data);
        let mr = mr_reply(FORWARD_OPEN, &forward_open_success(&id));
        mock.send(&rrdata_reply(open_frame.header.sender_context, &mr))
            .await;

        // Nothing else should arrive: no ForwardClose on the happy path. The client is dropped at
        // the end of the test, so the next read is EOF.
        mock.recv().await.is_none()
    });

    let client = EipClient::connect_over(client_side, connected_opts())
        .await
        .expect("a faithful reply opens the class-3 path");
    assert!(client.is_connected_messaging());
    drop(client);
    assert!(
        peer.await.unwrap(),
        "no ForwardClose followed a faithful reply"
    );
}
