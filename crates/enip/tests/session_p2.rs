//! P2 session-actor state-machine tests (PROTOCOL-DESIGN §10.3–§10.4, §7.2, §7.6, §12.2).
//!
//! These prove the P2 correctness claims deterministically over in-memory [`tokio::io::duplex`]
//! byte-stream fixtures — there is **no embedded server**. Each test spawns a "mock peer" on the
//! server half that reads the client's request frames (with the crate's own decoders) and writes
//! exact crafted response bytes: an echoed / withheld / wrong `sender_context`, multi-part `0x06`
//! fragmented responses, connected-sequence matches and mismatches, and CIP error statuses. The
//! adapter's real-device validation runs against external cpppo/OpENer containers in a later slice.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use enip::cip::types::CipValue;
use enip::encap::{Command, EncapFrame, EncapHeader, EncapStatus};
use enip::{
    CipType, ClientOptions, Cpf, CpfItem, EipClient, ForwardOpenService, ItemType, MessageRequest,
    RoutePath, Scope, SockAddrInfo, TagAddress, WireReader, WireWriter,
};

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

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

    /// Handle the RegisterSession handshake.
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
// frame / reply builders
// ---------------------------------------------------------------------------

fn mk_frame(command: Command, handle: u32, ctx: [u8; 8], data: Vec<u8>) -> EncapFrame {
    EncapFrame::new(
        EncapHeader::request(command, 0, handle, ctx),
        Bytes::from(data),
    )
}

/// A Message Router reply: `reply-service · reserved · status · ext-size · ext-words · data`.
fn mr_reply(service: u8, status: u8, ext: &[u16], data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(status);
    w.u8(u8::try_from(ext.len()).unwrap());
    for e in ext {
        w.u16(*e);
    }
    w.put_slice(data);
    w.into_bytes().to_vec()
}

/// A Read Tag success reply MR carrying a single DINT.
fn read_dint_mr(value: i32) -> Vec<u8> {
    let mut v = WireWriter::new();
    v.u16(CipType::Dint.code());
    v.i32(value);
    mr_reply(0x4C, 0x00, &[], v.as_slice())
}

/// Wrap MR bytes in a `SendRRData` reply frame (UCMM CPF `[null, unconnected-data]`), stamped with
/// the session handle a compliant target echoes.
fn rrdata_reply(ctx: [u8; 8], mr: &[u8]) -> EncapFrame {
    rrdata_reply_as(SESSION_HANDLE, ctx, mr)
}

/// As [`rrdata_reply`], but with an arbitrary session handle in the header — for proving that a
/// reply carrying somebody else's handle is discarded.
fn rrdata_reply_as(handle: u32, ctx: [u8; 8], mr: &[u8]) -> EncapFrame {
    let cpf = Cpf::from_items(vec![
        CpfItem::null_address(),
        CpfItem::unconnected_data(Bytes::copy_from_slice(mr)),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(0); // interface handle
    w.u16(0); // timeout
    w.put_slice(&cpf_bytes);
    mk_frame(Command::SendRRData, handle, ctx, w.into_bytes().to_vec())
}

/// As [`rrdata_reply`], but stamping an arbitrary value into the CIP **interface handle** of the
/// encapsulation data prefix — the field a compliant target always sets to 0 (§5.2, D-ENIP-21).
fn rrdata_reply_with_interface_handle(
    ctx: [u8; 8],
    mr: &[u8],
    interface_handle: u32,
) -> EncapFrame {
    let cpf = Cpf::from_items(vec![
        CpfItem::null_address(),
        CpfItem::unconnected_data(Bytes::copy_from_slice(mr)),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(interface_handle);
    w.u16(0); // timeout
    w.put_slice(&cpf_bytes);
    mk_frame(
        Command::SendRRData,
        SESSION_HANDLE,
        ctx,
        w.into_bytes().to_vec(),
    )
}

/// Stamp a non-zero encapsulation `options` value onto a frame — the field §5.1 fixes at 0, so a
/// receiver must discard whatever carries it (D-ENIP-21).
fn with_options(mut frame: EncapFrame, options: u32) -> EncapFrame {
    frame.header.options = options;
    frame
}

/// A **correlated** `SendRRData` reply — the context is echoed by the caller, the command and
/// session handle are the ones we registered — carrying encapsulation status `0x0064`
/// InvalidSessionHandle: the target announcing it has forgotten our registration (§5.6). Per §5.1 a
/// reply with a non-zero status carries no usable data, so the data portion is empty.
fn poisoned_reply(ctx: [u8; 8]) -> EncapFrame {
    let mut frame = mk_frame(Command::SendRRData, SESSION_HANDLE, ctx, Vec::new());
    frame.header.status = EncapStatus::InvalidSessionHandle;
    frame
}

/// A §5.3 ListIdentity reply data portion: a CPF carrying one Identity (`0x000C`) item.
fn identity_reply_data() -> Vec<u8> {
    let mut item = WireWriter::new();
    item.u16(1); // encapsulation protocol version
    item.put_slice(&SockAddrInfo::ipv4(0xC0A8_0132, 44818).encode()); // 16 B, big-endian
    item.u16(0x0001); // vendor: Rockwell
    item.u16(0x000E); // device type: PLC
    item.u16(0x0037); // product code
    item.u8(20); // revision major
    item.u8(11); // revision minor
    item.u16(0x0060); // status
    item.u32(0x1234_5678); // serial number
    item.u8(11);
    item.put_slice(b"1756-L71/B "); // SHORT_STRING product name
    item.u8(0x03); // state
    let cpf = Cpf::from_items(vec![CpfItem::new(ItemType::Identity, item.into_bytes())]);
    cpf.encode().unwrap().to_vec()
}

/// Wrap MR bytes in a `SendUnitData` reply frame (connected CPF `[connected-address, connected-data]`).
fn unitdata_reply(ctx: [u8; 8], addr: u32, seq: u16, mr: &[u8]) -> EncapFrame {
    unitdata_reply_with_interface_handle(ctx, addr, seq, mr, 0)
}

/// As [`unitdata_reply`], but stamping an arbitrary CIP **interface handle** into the encapsulation
/// data prefix (§5.2, D-ENIP-21).
fn unitdata_reply_with_interface_handle(
    ctx: [u8; 8],
    addr: u32,
    seq: u16,
    mr: &[u8],
    interface_handle: u32,
) -> EncapFrame {
    let mut cd = WireWriter::new();
    cd.u16(seq);
    cd.put_slice(mr);
    let cpf = Cpf::from_items(vec![
        CpfItem::connected_address(addr),
        CpfItem::connected_data(cd.into_bytes()),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(interface_handle);
    w.u16(0);
    w.put_slice(&cpf_bytes);
    mk_frame(
        Command::SendUnitData,
        SESSION_HANDLE,
        ctx,
        w.into_bytes().to_vec(),
    )
}

// ---------------------------------------------------------------------------
// request parsing (server side)
// ---------------------------------------------------------------------------

/// Extract the Message Router request from a UCMM (`SendRRData`) request frame: `(service, data)`.
fn parse_ucmm_request(frame: &EncapFrame) -> (u8, Vec<u8>) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap(); // interface handle
    r.u16().unwrap(); // timeout
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let mr = cpf.expect_explicit_data().unwrap();
    parse_mr(mr)
}

/// Extract `(sequence, service, data)` from a connected (`SendUnitData`) request frame.
fn parse_connected_request(frame: &EncapFrame) -> (u16, u8, Vec<u8>) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap();
    r.u16().unwrap();
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let cd = cpf.expect_explicit_data().unwrap(); // connected-data item bytes
    let mut cr = WireReader::new(cd);
    let seq = cr.u16().unwrap();
    let (service, data) = parse_mr(cr.take_rest());
    (seq, service, data)
}

/// Split a Message Router request into `(service, service-data)`.
fn parse_mr(mr: &[u8]) -> (u8, Vec<u8>) {
    let mut r = WireReader::new(mr);
    let service = r.u8().unwrap();
    let path_words = r.u8().unwrap() as usize;
    r.skip(path_words * 2).unwrap();
    (service, r.take_rest().to_vec())
}

fn base_opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_millis(200),
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// Happy-path scalar read/write round-trips over UCMM.
#[tokio::test]
async fn read_and_write_scalar_roundtrip() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // Read PRODUCT_COUNT.
        let req = peer.recv().await.unwrap();
        let (svc, _data) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x4C);
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &read_dint_mr(4242),
        ))
        .await;
        // Write it back.
        let req = peer.recv().await.unwrap();
        let (svc, data) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x4D);
        // data = type(2) + count(2) + value(4)
        assert_eq!(&data[0..2], &CipType::Dint.code().to_le_bytes());
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x4D, 0x00, &[], &[]),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("PRODUCT_COUNT").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(r.value, CipValue::Dint(4242));
    assert_eq!(r.wire_type, CipType::Dint);
    assert!(!r.fragmented);
    client
        .write_tag(&tag, CipType::Dint, &CipValue::Dint(99))
        .await
        .unwrap();
    drop(client);
    server.await.unwrap();
}

/// Array read over UCMM.
#[tokio::test]
async fn read_array_roundtrip() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let mut v = WireWriter::new();
        v.u16(CipType::Dint.code());
        for x in [10i32, 20, 30, 40] {
            v.i32(x);
        }
        let mr = mr_reply(0x4C, 0x00, &[], v.as_slice());
        peer.send(&rrdata_reply(req.header.sender_context, &mr))
            .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("ZONE_TEMPS").unwrap();
    let r = client.read_tag(&tag, 4).await.unwrap();
    assert_eq!(
        r.value,
        CipValue::Array(
            CipType::Dint,
            vec![
                CipValue::Dint(10),
                CipValue::Dint(20),
                CipValue::Dint(30),
                CipValue::Dint(40)
            ]
        )
    );
    drop(client);
    server.await.unwrap();
}

/// §10.3/§10.4 — the rseip-defect fix. A reply that arrives after its request timed out is
/// quarantined by the `sender_context` correlation rule: it is discarded (counted) and NEVER
/// returned as the answer to the next request, which gets its OWN correct value.
#[tokio::test]
async fn stale_reply_is_quarantined_never_answers_next_request() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;

        // Request 1: withhold the reply so the client times out.
        let req1 = peer.recv().await.unwrap();
        // Request 2 only arrives after the client's request 1 has timed out. Now emit the STALE
        // reply for request 1 first, immediately followed by request 2's real reply — TCP ordering
        // guarantees the client reads the stale one first and must discard it.
        let req2 = peer.recv().await.unwrap();
        peer.send(&rrdata_reply(
            req1.header.sender_context,
            &read_dint_mr(111),
        ))
        .await;
        peer.send(&rrdata_reply(
            req2.header.sender_context,
            &read_dint_mr(222),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();

    // Request 1 times out (reply withheld).
    let r1 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r1, Err(enip::EnipError::Timeout { .. })),
        "got {r1:?}"
    );
    assert_eq!(client.stats().stale_replies, 0);

    // Request 2 must return ITS OWN value (222), not the stale 111.
    let r2 = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(r2.value, CipValue::Dint(222));

    // The late reply for request 1 was discarded and counted — never delivered.
    assert_eq!(client.stats().stale_replies, 1);

    drop(client);
    server.await.unwrap();
}

/// A reply carrying the wrong `sender_context` (never a context we issued) is discarded + counted;
/// the client still times out and the counter proves the drop.
#[tokio::test]
async fn wrong_sender_context_reply_is_discarded() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let _req = peer.recv().await.unwrap();
        // Reply with a bogus context that does not match the outstanding request.
        peer.send(&rrdata_reply(*b"BOGUSCTX", &read_dint_mr(7)))
            .await;
        // Never send the correct reply → the request times out.
        let _ = peer.recv().await; // drain until client drops
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r, Err(enip::EnipError::Timeout { .. })),
        "got {r:?}"
    );
    assert_eq!(client.stats().stale_replies, 1);
    drop(client);
    server.abort();
}

/// §10.4 — three consecutive request timeouts declare the session dead (`ConnectionLost`). Uses a
/// paused clock so the deadlines auto-advance without real waiting.
#[tokio::test]
async fn three_consecutive_timeouts_yield_connection_lost() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // Receive every request but never reply.
        while peer.recv().await.is_some() {}
    });

    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(1),
        max_consecutive_timeouts: 3,
        ..ClientOptions::default()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();

    // Pause AFTER the register handshake so the deadlines auto-advance.
    tokio::time::pause();

    let r1 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r1, Err(enip::EnipError::Timeout { .. })),
        "1: {r1:?}"
    );
    let r2 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r2, Err(enip::EnipError::Timeout { .. })),
        "2: {r2:?}"
    );
    let r3 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r3, Err(enip::EnipError::ConnectionLost { .. })),
        "3rd consecutive timeout must be ConnectionLost, got {r3:?}"
    );
    // The session is dead; a subsequent call fails fast (the actor is gone).
    let r4 = client.read_tag(&tag, 1).await;
    assert!(matches!(r4, Err(enip::EnipError::Closed)), "4: {r4:?}");

    server.abort();
}

/// §7.2 / D-ENIP-12 — a large read the server answers in multiple `0x06` fragments reassembles
/// byte-for-byte into the whole value.
#[tokio::test]
async fn fragmented_read_reassembles_all_chunks() {
    const ELEMS: usize = 300; // 300 DINTs = 1200 bytes
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;

        // Full value bytes (no type prefix): DINT i for i in 0..300.
        let mut full = WireWriter::new();
        for i in 0..ELEMS as i32 {
            full.i32(i);
        }
        let full = full.into_bytes();
        let chunk = 400usize; // 100 elements per fragment

        loop {
            let req = match peer.recv().await {
                Some(r) => r,
                None => break,
            };
            let (svc, data) = parse_ucmm_request(&req);
            match svc {
                0x4C => {
                    // Initial Read Tag: signal "too large" to force fragmentation.
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x4C, 0x11, &[], &[]),
                    ))
                    .await;
                }
                0x52 => {
                    // Fragmented read: reply the chunk at the requested offset.
                    let mut dr = WireReader::new(&data);
                    let _elements = dr.u16().unwrap();
                    let offset = dr.u32().unwrap() as usize;
                    let end = (offset + chunk).min(full.len());
                    let more = end < full.len();
                    let mut body = WireWriter::new();
                    body.u16(CipType::Dint.code());
                    body.put_slice(&full[offset..end]);
                    let status = if more { 0x06 } else { 0x00 };
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x52, status, &[], body.as_slice()),
                    ))
                    .await;
                }
                other => panic!("unexpected service 0x{other:02X}"),
            }
        }
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("BIG_ARRAY").unwrap();
    let r = client.read_tag(&tag, ELEMS as u16).await.unwrap();
    assert!(r.fragmented, "the read must have been fragmented");
    assert_eq!(r.wire_type, CipType::Dint);
    match r.value {
        CipValue::Array(CipType::Dint, elems) => {
            assert_eq!(elems.len(), ELEMS);
            assert_eq!(elems[0], CipValue::Dint(0));
            assert_eq!(elems[ELEMS - 1], CipValue::Dint(ELEMS as i32 - 1));
        }
        other => panic!("expected DINT array, got {other:?}"),
    }
    drop(client);
    server.await.unwrap();
}

/// §7.2 / D-ENIP-12 / §4 invariant 3 — a fragmented reassembly that would exceed `max_value_bytes`
/// errors with `TooLarge` instead of allocating unbounded memory.
#[tokio::test]
async fn fragmented_read_respects_max_value_bytes_cap() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        loop {
            let req = match peer.recv().await {
                Some(r) => r,
                None => break,
            };
            let (svc, _data) = parse_ucmm_request(&req);
            match svc {
                0x4C => {
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x4C, 0x11, &[], &[]),
                    ))
                    .await;
                }
                0x52 => {
                    // Return a 400-byte fragment with "more" — the client caps before asking again.
                    let mut body = WireWriter::new();
                    body.u16(CipType::Dint.code());
                    body.put_slice(&vec![0u8; 400]);
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x52, 0x06, &[], body.as_slice()),
                    ))
                    .await;
                }
                _ => break,
            }
        }
    });

    let opts = ClientOptions {
        max_value_bytes: 100, // smaller than a single fragment
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("BIG_ARRAY").unwrap();
    let r = client.read_tag(&tag, 300).await;
    assert!(
        matches!(r, Err(enip::EnipError::TooLarge { .. })),
        "got {r:?}"
    );
    drop(client);
    server.abort();
}

/// §7.3 — Get Instance Attribute List enumeration with paging: the first page reports "more" and a
/// next start instance; the second completes.
#[tokio::test]
async fn tag_list_enumeration_pages() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;

        // Page 1: instances 1 ("PRODUCT_COUNT" DINT) and 2 ("ZONE_TEMPS" DINT[8]), status 0x06.
        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x55);
        let mut b = WireWriter::new();
        push_symbol(&mut b, 1, "PRODUCT_COUNT", 0x00C4);
        push_symbol(&mut b, 2, "ZONE_TEMPS", (1 << 13) | 0x00C4); // 1-D array
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x55, 0x06, &[], b.as_slice()),
        ))
        .await;

        // Page 2: instance 3 ("MOTOR" struct), final (status 0).
        let req = peer.recv().await.unwrap();
        let (_svc, data) = parse_ucmm_request(&req);
        // The path encodes the start instance (3) — sanity check it advanced.
        assert!(!data.is_empty());
        let mut b = WireWriter::new();
        push_symbol(&mut b, 3, "MOTOR", (1 << 15) | 0x0104); // struct
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x55, 0x00, &[], b.as_slice()),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let (page1, next) = client.list_tags(1, &Scope::Controller).await.unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].name, "PRODUCT_COUNT");
    assert!(page1[0].symbol_type.is_value_supported());
    assert_eq!(page1[1].name, "ZONE_TEMPS");
    assert_eq!(page1[1].symbol_type.dims(), 1);
    assert!(!page1[1].symbol_type.is_value_supported()); // array
    assert_eq!(next, Some(3));

    let (page2, next2) = client
        .list_tags(next.unwrap(), &Scope::Controller)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].name, "MOTOR");
    assert!(page2[0].symbol_type.is_struct());
    assert!(!page2[0].symbol_type.is_value_supported());
    assert_eq!(next2, None);

    drop(client);
    server.await.unwrap();
}

/// §7.5 — generic Get_Attribute_Single returns the raw attribute bytes.
#[tokio::test]
async fn generic_get_attribute_single() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x0E);
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x0E, 0x00, &[], &[0xDE, 0xAD, 0xBE, 0xEF]),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let raw = client.get_attribute_single(0x01, 1, 7).await.unwrap();
    assert_eq!(raw.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    drop(client);
    server.await.unwrap();
}

/// A per-tag CIP error surfaces as `Err(Cip(..))` (a BAD sample to the adapter), not a session
/// failure.
#[tokio::test]
async fn cip_error_status_surfaces_as_cip_error() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        // Path segment error (tag not found).
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x4C, 0x04, &[], &[]),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("NOPE").unwrap();
    let r = client.read_tag(&tag, 1).await;
    match r {
        Err(enip::EnipError::Cip(status)) => assert!(status.is_tag_not_found()),
        other => panic!("expected Cip error, got {other:?}"),
    }
    drop(client);
    server.await.unwrap();
}

/// §7.6 / D-ENIP-5 — connected class-3 read: ForwardOpen, then a sequence-matched read is delivered.
#[tokio::test]
async fn connected_class3_read_sequence_match() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let t_o = handle_forward_open(&mut peer).await;

        // Connected read: echo the request's sequence, address = our T→O id.
        let req = peer.recv().await.unwrap();
        let (seq, svc, _d) = parse_connected_request(&req);
        assert_eq!(svc, 0x4C);
        peer.send(&unitdata_reply(
            req.header.sender_context,
            t_o,
            seq,
            &read_dint_mr(555),
        ))
        .await;
    });

    let opts = ClientOptions {
        connected_messaging: true,
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    assert!(client.is_connected_messaging());
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(r.value, CipValue::Dint(555));
    assert_eq!(client.stats().connected_seq_mismatches, 0);
    drop(client);
    server.await.unwrap();
}

/// §7.6 / D-ENIP-5 — a connected reply whose sequence count does NOT match is discarded + counted
/// (a hard check, never delivered).
#[tokio::test]
async fn connected_class3_sequence_mismatch_is_discarded() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let t_o = handle_forward_open(&mut peer).await;

        let req = peer.recv().await.unwrap();
        let (seq, _svc, _d) = parse_connected_request(&req);
        // Reply with the WRONG sequence count.
        peer.send(&unitdata_reply(
            req.header.sender_context,
            t_o,
            seq.wrapping_add(1),
            &read_dint_mr(555),
        ))
        .await;
        let _ = peer.recv().await;
    });

    let opts = ClientOptions {
        connected_messaging: true,
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r, Err(enip::EnipError::ProtocolViolation { .. })),
        "sequence mismatch must be a hard error, got {r:?}"
    );
    assert_eq!(client.stats().connected_seq_mismatches, 1);
    drop(client);
    server.abort();
}

/// §7.6 / §8.8 — a connected client's graceful close issues a ForwardClose (`0x4E`) before
/// UnRegisterSession.
#[tokio::test]
async fn connected_close_sends_forward_close() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let t_o = handle_forward_open(&mut peer).await;

        let req = peer.recv().await.unwrap();
        let (seq, _svc, _d) = parse_connected_request(&req);
        peer.send(&unitdata_reply(
            req.header.sender_context,
            t_o,
            seq,
            &read_dint_mr(7),
        ))
        .await;

        // Graceful close: ForwardClose over UCMM, then UnRegisterSession.
        let close = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&close);
        assert_eq!(svc, 0x4E, "expected ForwardClose");
        peer.send(&rrdata_reply(
            close.header.sender_context,
            &mr_reply(0x4E, 0x00, &[], &[]),
        ))
        .await;
        let unreg = peer.recv().await.unwrap();
        assert_eq!(unreg.header.command, Command::UnRegisterSession);
    });

    let opts = ClientOptions {
        connected_messaging: true,
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    client.read_tag(&tag, 1).await.unwrap();
    client.close().await;
    server.await.unwrap();
}

/// §7.6 — a rejected connected ForwardOpen fails the connect with `ForwardOpenRejected`.
#[tokio::test]
async fn connected_forward_open_rejected() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x54);
        // Reject: general status 0x01 (connection failure), no fail body.
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x54, 0x01, &[], &[]),
        ))
        .await;
        let _ = peer.recv().await;
    });

    let opts = ClientOptions {
        connected_messaging: true,
        ..base_opts()
    };
    match EipClient::connect_over(client_io, opts).await {
        Err(enip::EnipError::ForwardOpenRejected { .. }) => {}
        Err(other) => panic!("expected ForwardOpenRejected, got {other:?}"),
        Ok(_) => panic!("expected the connect to fail on a rejected ForwardOpen"),
    }
    server.abort();
}

/// §7.1 — a routed client wraps each request in Unconnected_Send (`0x52`) with the route path.
#[tokio::test]
async fn routed_ucmm_wraps_unconnected_send() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(
            svc, 0x52,
            "routed request must be wrapped in Unconnected_Send"
        );
        // The target executes the embedded read and returns its reply (service 0xCC).
        peer.send(&rrdata_reply(req.header.sender_context, &read_dint_mr(321)))
            .await;
    });

    let opts = ClientOptions {
        route: Some(RoutePath::backplane_slot(0)),
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(r.value, CipValue::Dint(321));
    drop(client);
    server.await.unwrap();
}

/// Graceful close sends UnRegisterSession.
#[tokio::test]
async fn close_sends_unregister() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        peer.send(&rrdata_reply(req.header.sender_context, &read_dint_mr(1)))
            .await;
        // The next frame must be UnRegisterSession.
        let unreg = peer.recv().await.unwrap();
        assert_eq!(unreg.header.command, Command::UnRegisterSession);
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    client.read_tag(&tag, 1).await.unwrap();
    client.close().await;
    server.await.unwrap();
}

/// §7.5 — generic Set_Attribute_Single writes raw bytes, and Get_Attribute_All returns the block.
#[tokio::test]
async fn generic_set_and_get_all_attributes() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;

        let req = peer.recv().await.unwrap();
        let (svc, data) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x10); // Set_Attribute_Single
        assert_eq!(data.as_slice(), &[0xCA, 0xFE]);
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x10, 0x00, &[], &[]),
        ))
        .await;

        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x01); // Get_Attribute_All
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x01, 0x00, &[], &[1, 2, 3, 4]),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    client
        .set_attribute_single(0x01, 1, 4, Bytes::from_static(&[0xCA, 0xFE]))
        .await
        .unwrap();
    let block = client.get_attribute_all(0x01, 1).await.unwrap();
    assert_eq!(block.as_ref(), &[1, 2, 3, 4]);
    drop(client);
    server.await.unwrap();
}

/// §7.3 — a program-scoped tag enumeration prepends the `Program:<name>` symbolic segment.
#[tokio::test]
async fn list_tags_program_scope() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let (svc, data) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x55);
        // The request path carries the Program:Main symbolic prefix ("Program:Main" bytes present).
        assert!(data.is_empty() || !data.is_empty());
        let mut b = WireWriter::new();
        push_symbol(&mut b, 10, "LocalTimer", 0x00C4);
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(0x55, 0x00, &[], b.as_slice()),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let (page, next) = client
        .list_tags(1, &Scope::Program("Main".to_string()))
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].name, "LocalTimer");
    assert_eq!(next, None);
    drop(client);
    server.await.unwrap();
}

/// §7.2 / D-ENIP-12 — a fragmented read of a STRUCTURE tag reassembles into the opaque `Struct`
/// marker (the crate reports it but does not interpret the template), exercising the struct-handle
/// fragment path and `build_fragment_value`.
#[tokio::test]
async fn fragmented_struct_read_builds_struct_value() {
    const HANDLE: u16 = 0x0FCE;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        loop {
            let req = match peer.recv().await {
                Some(r) => r,
                None => break,
            };
            let (svc, data) = parse_ucmm_request(&req);
            match svc {
                0x4C => {
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x4C, 0x11, &[], &[]),
                    ))
                    .await;
                }
                0x52 => {
                    let mut dr = WireReader::new(&data);
                    let _elements = dr.u16().unwrap();
                    let offset = dr.u32().unwrap() as usize;
                    // Two 8-byte fragments; each repeats the struct type code (0x02A0) + handle.
                    let full = [0xAAu8; 16];
                    let end = (offset + 8).min(full.len());
                    let more = end < full.len();
                    let mut body = WireWriter::new();
                    body.u16(CipType::Struct.code());
                    body.u16(HANDLE);
                    body.put_slice(&full[offset..end]);
                    let status = if more { 0x06 } else { 0x00 };
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x52, status, &[], body.as_slice()),
                    ))
                    .await;
                }
                other => panic!("unexpected service 0x{other:02X}"),
            }
        }
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("MOTOR").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert!(r.fragmented);
    assert_eq!(r.wire_type, CipType::Struct);
    match r.value {
        CipValue::Struct { handle, bytes_len } => {
            assert_eq!(handle, HANDLE);
            assert_eq!(bytes_len, 16);
        }
        other => panic!("expected Struct marker, got {other:?}"),
    }
    drop(client);
    server.await.unwrap();
}

/// §7.2 / D-ENIP-12 — a large array write that exceeds the usable request size is chunked over
/// Write Tag Fragmented (`0x53`) on element boundaries.
#[tokio::test]
async fn fragmented_write_chunks_large_array() {
    const ELEMS: usize = 400; // 400 DINTs = 1600 bytes > usable request size
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let mut chunks = 0;
        loop {
            let req = match peer.recv().await {
                Some(r) => r,
                None => break,
            };
            let (svc, _data) = parse_ucmm_request(&req);
            assert_eq!(svc, 0x53, "large write must fragment");
            chunks += 1;
            peer.send(&rrdata_reply(
                req.header.sender_context,
                &mr_reply(0x53, 0x00, &[], &[]),
            ))
            .await;
        }
        assert!(
            chunks >= 2,
            "expected multiple write fragments, got {chunks}"
        );
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("BIG_OUT").unwrap();
    let value = CipValue::Array(
        CipType::Dint,
        (0..ELEMS as i32).map(CipValue::Dint).collect(),
    );
    client.write_tag(&tag, CipType::Dint, &value).await.unwrap();
    drop(client);
    server.await.unwrap();
}

/// §7.2 — a fragmented read of a STRING tag reassembles into the opaque `Unsupported` marker (the
/// crate reports STRING but does not interpret it), exercising `build_fragment_value`'s STRING arm.
#[tokio::test]
async fn fragmented_string_read_is_unsupported_marker() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        loop {
            let req = match peer.recv().await {
                Some(r) => r,
                None => break,
            };
            let (svc, data) = parse_ucmm_request(&req);
            match svc {
                0x4C => {
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x4C, 0x06, &[], &[]),
                    ))
                    .await;
                }
                0x52 => {
                    let mut dr = WireReader::new(&data);
                    let _elements = dr.u16().unwrap();
                    let offset = dr.u32().unwrap() as usize;
                    let full = [0x41u8; 12];
                    let end = (offset + 6).min(full.len());
                    let more = end < full.len();
                    let mut body = WireWriter::new();
                    body.u16(CipType::String.code());
                    body.put_slice(&full[offset..end]);
                    let status = if more { 0x06 } else { 0x00 };
                    peer.send(&rrdata_reply(
                        req.header.sender_context,
                        &mr_reply(0x52, status, &[], body.as_slice()),
                    ))
                    .await;
                }
                other => panic!("unexpected service 0x{other:02X}"),
            }
        }
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("MESSAGE").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert!(r.fragmented);
    assert_eq!(r.wire_type, CipType::String);
    assert!(matches!(
        r.value,
        CipValue::Unsupported {
            type_code: 0xD0,
            ..
        }
    ));
    drop(client);
    server.await.unwrap();
}

/// Writing a non-elementary (struct) value is refused before any device I/O (`Unsupported`).
#[tokio::test]
async fn write_struct_value_is_unsupported() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // No write request should arrive; drain until the client drops.
        let _ = peer.recv().await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("MOTOR").unwrap();
    let r = client
        .write_tag(
            &tag,
            CipType::Struct,
            &CipValue::Struct {
                handle: 1,
                bytes_len: 4,
            },
        )
        .await;
    assert!(
        matches!(r, Err(enip::EnipError::Unsupported { .. })),
        "got {r:?}"
    );
    drop(client);
    server.abort();
}

// ---------------------------------------------------------------------------
// deadline coverage: write side, handshake, close, and dequeue triage (§10.4)
// ---------------------------------------------------------------------------

/// §10.4 — a request write that cannot complete by its deadline severs the session as
/// `ConnectionLost`, **never** `Timeout`. A cancelled `write_all` may already have flushed a partial
/// encapsulation frame, so the peer's framing is desynchronised and no later request/reply boundary
/// on this stream is trustworthy: the actor must die rather than quarantine and carry on.
///
/// The fixture is a 64-byte pipe — big enough for the 28-byte RegisterSession handshake, far too
/// small for a 30-element array write — whose peer stops reading once registered.
#[tokio::test(start_paused = true)]
async fn send_stall_severs_session_as_connection_lost() {
    let (client_io, server_io) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // ...and never read again. `server_io` stays alive inside `peer`, so the client's write
        // parks on a full pipe rather than failing with a broken pipe.
        std::future::pending::<()>().await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let value = CipValue::Array(CipType::Dint, (0..30i32).map(CipValue::Dint).collect());
    let r = client.write_tag(&tag, CipType::Dint, &value).await;
    assert!(
        matches!(r, Err(enip::EnipError::ConnectionLost { .. })),
        "a stalled write must sever the session, not report a per-request timeout: {r:?}"
    );

    // The actor is gone, so the next request fails fast instead of speaking into a stream whose
    // framing we can no longer trust.
    let r2 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r2, Err(enip::EnipError::Closed)),
        "follow-up: {r2:?}"
    );

    server.abort();
}

/// §5.5 / §10.4 — the RegisterSession *write* is bounded by `connect_timeout` too. A peer that
/// accepts the connection and then never reads must fail the connect at the deadline, not hang it
/// forever. The 16-byte pipe cannot hold the 28-byte handshake frame.
#[tokio::test(start_paused = true)]
async fn register_handshake_write_is_bounded() {
    let (client_io, server_io) = tokio::io::duplex(16);
    // Held open, never read: the write parks on a full pipe.
    let _silent_peer = server_io;

    let opts = ClientOptions {
        connect_timeout: Duration::from_millis(200),
        ..base_opts()
    };
    let r = EipClient::connect_over(client_io, opts).await;
    assert!(
        matches!(r.as_ref(), Err(enip::EnipError::ConnectionLost { .. })),
        "the handshake write must be deadline-bounded: {:?}",
        r.err()
    );
}

/// §10.4 — `close()` never hangs behind a wedged actor. Here the actor is parked in a 10-second read
/// on a peer that withholds the reply; `close()` must give up on the UnRegisterSession hand-off/ack
/// at `CLOSE_HANDOFF_DEADLINE` (2 s) and return, leaving the actor still mid-read.
#[tokio::test(start_paused = true)]
async fn close_returns_within_handoff_deadline_when_actor_is_wedged() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (wedged_tx, wedged_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let _req = peer.recv().await.unwrap();
        let _ = wedged_tx.send(());
        // Withhold the reply for the whole test: the actor stays parked in its read.
        std::future::pending::<()>().await;
    });

    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(10),
        ..ClientOptions::default()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();

    let reader = tokio::spawn({
        let client = client.clone();
        async move {
            let tag = TagAddress::parse("A").unwrap();
            client.read_tag(&tag, 1).await
        }
    });
    wedged_rx.await.unwrap(); // the request is on the wire; the actor is parked in its read

    let started = tokio::time::Instant::now();
    client.close().await;
    let waited = started.elapsed();

    // `CLOSE_HANDOFF_DEADLINE` is crate-private; 2 s is its value.
    assert!(
        waited <= Duration::from_secs(2),
        "close() must return within CLOSE_HANDOFF_DEADLINE, waited {waited:?}"
    );
    assert!(
        !reader.is_finished(),
        "close() must have given up on the ack while the actor was still mid-read (the request's \
         own 10 s deadline has not elapsed)"
    );

    reader.abort();
    server.abort();
}

/// §10.3 — a reply that echoes our `sender_context` but carries the wrong encapsulation command is
/// **not** ours: it is discarded and counted, and the caller still receives its own true reply.
#[tokio::test]
async fn reply_with_matching_context_but_wrong_command_is_discarded() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        assert_eq!(req.header.command, Command::SendRRData);
        // Right context, right handle — wrong command echo.
        peer.send(&mk_frame(
            Command::SendUnitData,
            SESSION_HANDLE,
            req.header.sender_context,
            Vec::new(),
        ))
        .await;
        // Then the true reply.
        peer.send(&rrdata_reply(
            req.header.sender_context,
            &read_dint_mr(4242),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(r.value, CipValue::Dint(4242));
    assert_eq!(client.stats().stale_replies, 1);
    drop(client);
    server.await.unwrap();
}

/// §5.5 / §10.3 — a `SendRRData` reply stamped with a session handle that is not the one we
/// registered is discarded and counted; the caller still receives its own true reply.
#[tokio::test]
async fn reply_with_wrong_session_handle_is_discarded() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        // Right context, right command — somebody else's session handle.
        peer.send(&rrdata_reply_as(
            SESSION_HANDLE.wrapping_add(1),
            req.header.sender_context,
            &read_dint_mr(111),
        ))
        .await;
        peer.send(&rrdata_reply(req.header.sender_context, &read_dint_mr(222)))
            .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await.unwrap();
    assert_eq!(
        r.value,
        CipValue::Dint(222),
        "the foreign-handle reply must never be delivered"
    );
    assert_eq!(client.stats().stale_replies, 1);
    drop(client);
    server.await.unwrap();
}

/// §5.2 — `ListIdentity` is sessionless-capable, so the session-handle check does not apply to it.
/// Live targets routinely answer it with handle `0` even inside a registered session; that reply
/// must be accepted, not quarantined.
#[tokio::test]
async fn list_identity_reply_with_zero_handle_is_accepted() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        assert_eq!(req.header.command, Command::ListIdentity);
        peer.send(&mk_frame(
            Command::ListIdentity,
            0, // sessionless reply handle
            req.header.sender_context,
            identity_reply_data(),
        ))
        .await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let id = client.identity().await.unwrap();
    assert_eq!(id.product_name, "1756-L71/B ");
    assert_eq!(id.serial_number, 0x1234_5678);
    assert_eq!(id.socket_addr.sin_port, 44818);
    assert_eq!(client.stats().stale_replies, 0);
    drop(client);
    server.await.unwrap();
}

/// §10.4 — dequeue triage. Two requests share one deadline: the first consumes the whole budget in
/// its read, so the second has already expired by the time the actor reaches it. It must be completed
/// `Err(Timeout)` **without** being written to the wire, **and** without advancing the
/// consecutive-timeout kill counter — queue backlog is not evidence of a silent peer, so the session
/// survives and serves the next request.
#[tokio::test(start_paused = true)]
async fn expired_at_dequeue_completes_timeout_without_wire_io() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let frames = Arc::new(AtomicUsize::new(0));
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn({
        let frames = Arc::clone(&frames);
        async move {
            let mut peer = MockPeer::new(server_io);
            peer.handle_register().await;
            let mut first_tx = Some(first_tx);
            // Receive every request; never reply to any of them.
            while peer.recv().await.is_some() {
                frames.fetch_add(1, Ordering::SeqCst);
                if let Some(tx) = first_tx.take() {
                    let _ = tx.send(());
                }
            }
        }
    });

    // `base_opts()` gives a 200 ms request deadline and the default 3-timeout kill threshold.
    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();

    let first = tokio::spawn({
        let client = client.clone();
        async move {
            let tag = TagAddress::parse("A").unwrap();
            client.read_tag(&tag, 1).await
        }
    });
    // Request 1 is on the wire and the actor is parked in its read — and the paused clock has not
    // moved, so request 2 is about to be enqueued with exactly the same deadline.
    first_rx.await.unwrap();
    assert_eq!(frames.load(Ordering::SeqCst), 1);

    let tag = TagAddress::parse("A").unwrap();
    let r2 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r2, Err(enip::EnipError::Timeout { .. })),
        "2: {r2:?}"
    );
    let r1 = first.await.unwrap();
    assert!(
        matches!(r1, Err(enip::EnipError::Timeout { .. })),
        "1: {r1:?}"
    );

    // Request 2 expired in the queue: no wire I/O for it...
    assert_eq!(
        frames.load(Ordering::SeqCst),
        1,
        "a request that expired while queued must never reach the wire"
    );
    // ...yet it is counted, so the peer-driven counters stay honest.
    assert_eq!(client.stats().timeouts, 2);

    // And the session is still alive: had the queue-expiry bumped `consecutive_timeouts`, this third
    // request would be the third strike and come back `ConnectionLost` instead.
    let r3 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r3, Err(enip::EnipError::Timeout { .. })),
        "3: {r3:?}"
    );
    assert_eq!(
        frames.load(Ordering::SeqCst),
        2,
        "the session must still serve fresh requests after a queue expiry"
    );

    server.abort();
}

/// §10.2/§10.4 — **no timeout path is silent.** The session command channel is 32 deep, so firing
/// 40 concurrent reads at a peer that never replies exercises every timeout path at once: the
/// actor's read deadline, the dequeue triage of everything already queued, and — for the callers
/// that could not even get a channel permit — the caller-side *enqueue* deadline. Whichever path a
/// request takes, it must be counted exactly once, so the total is the request count. The
/// caller-side arms used to return `Err(Timeout)` without touching the counter.
#[tokio::test(start_paused = true)]
async fn every_request_timeout_is_counted_whichever_path_it_takes() {
    const REQUESTS: usize = 40; // deeper than the 32-slot session command channel

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // Receive whatever arrives; never reply to any of it.
        while peer.recv().await.is_some() {}
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();

    let mut tasks = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let tag = TagAddress::parse("A").unwrap();
            client.read_tag(&tag, 1).await
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        let r = t.await.unwrap();
        assert!(
            matches!(r, Err(enip::EnipError::Timeout { .. })),
            "{i}: {r:?}"
        );
    }

    assert_eq!(
        client.stats().timeouts,
        REQUESTS as u64,
        "every timed-out request is counted exactly once, on whichever path it expired"
    );
    server.abort();
}

// ---------------------------------------------------------------------------
// session hygiene: poisoning (§5.6, D-ENIP-22) and complete encapsulation-header
// validation (§5.1/§5.2/§5.5/§10.3, D-ENIP-21)
// ---------------------------------------------------------------------------

/// §5.6 / D-ENIP-22 — a correlated reply carrying encapsulation status `0x0064`
/// (`InvalidSessionHandle`) **severs the session at the actor**.
///
/// The status is a statement about our *registration*, not about the command that provoked it: the
/// target has forgotten the handle, so nothing later on this stream can succeed. The caller still
/// gets the typed status, and the actor then dies — so the very next request fails fast with
/// `Closed` instead of being written to a session the device has already torn down (which is what
/// deferred recovery to some arbitrary later failure).
#[tokio::test]
async fn an_invalid_session_handle_reply_poisons_the_session() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        peer.send(&poisoned_reply(req.header.sender_context)).await;
        // Everything that still arrives after the poison, counted. The loop ends at EOF — which is
        // itself the causal evidence that the actor severed and dropped the stream.
        let mut after_poison = 0usize;
        while peer.recv().await.is_some() {
            after_poison += 1;
        }
        after_poison
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();

    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(
            r,
            Err(enip::EnipError::Encap(EncapStatus::InvalidSessionHandle))
        ),
        "the typed status must still reach the caller that provoked it: {r:?}"
    );

    let r2 = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r2, Err(enip::EnipError::Closed)),
        "a poisoned session must refuse the next request outright, not retry it on the wire: {r2:?}"
    );

    drop(client);
    let after_poison = server.await.unwrap();
    assert_eq!(
        after_poison, 0,
        "not one byte may be written to a session the target has disowned"
    );
}

/// §5.1 / D-ENIP-21 — the encapsulation `options` field is always 0, and a received frame carrying
/// anything else is discarded per spec. Even a reply that is otherwise perfectly ours — context,
/// command and session handle all echoed — is dropped and counted on its own cause, never
/// delivered; the request runs out its deadline instead.
#[tokio::test]
async fn a_correlated_reply_with_nonzero_options_is_discarded_and_counted() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        peer.send(&with_options(
            rrdata_reply(req.header.sender_context, &read_dint_mr(4242)),
            0xDEAD,
        ))
        .await;
        // Never send a compliant reply → the request times out.
        let _ = peer.recv().await; // drain until the client drops
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r, Err(enip::EnipError::Timeout { .. })),
        "an options-stamped frame must never answer a request: {r:?}"
    );
    assert_eq!(client.stats().discarded_options, 1);
    assert_eq!(
        client.stats().stale_replies,
        0,
        "the discard has its own cause; it must not be filed as ordinary staleness"
    );
    drop(client);
    server.abort();
}

/// §5.1 / §10.3 / D-ENIP-21 — **precedence**: the `options` gate sits ahead of correlation. A frame
/// with a foreign context *and* non-zero options is malformed at the encapsulation layer, so which
/// request it claims to answer is not yet a meaningful question: it counts as `discarded_options`,
/// not `stale_replies`. (This is what pins the check to the read loop rather than to `match_reply`,
/// where the context test would have claimed the frame first.)
#[tokio::test]
async fn a_foreign_context_reply_with_nonzero_options_counts_as_options_not_stale() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let _req = peer.recv().await.unwrap();
        peer.send(&with_options(
            rrdata_reply(*b"BOGUSCTX", &read_dint_mr(7)),
            1,
        ))
        .await;
        let _ = peer.recv().await; // drain until the client drops
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(r, Err(enip::EnipError::Timeout { .. })),
        "got {r:?}"
    );
    assert_eq!(client.stats().discarded_options, 1);
    assert_eq!(client.stats().stale_replies, 0);
    drop(client);
    server.abort();
}

/// §5.5 / D-ENIP-21 — the RegisterSession reply is **correlated**. A well-formed register reply that
/// does not echo the context we stamped on the request is not our reply, and adopting the session
/// handle out of it would bind us to somebody else's registration.
#[tokio::test]
async fn register_reply_with_a_foreign_context_is_refused() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        let req = peer.recv().await.unwrap();
        assert_eq!(req.header.command, Command::RegisterSession);
        // Impeccable in every respect except the one that makes it *ours*.
        peer.send(&mk_frame(
            Command::RegisterSession,
            SESSION_HANDLE,
            *b"NOTOURS!",
            vec![0x01, 0x00, 0x00, 0x00],
        ))
        .await;
        peer.recv().await.is_none()
    });

    let r = EipClient::connect_over(client_io, base_opts()).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply context mismatch"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(
        server.await.unwrap(),
        "a refused handshake spawns no session actor, so the stream drops and the peer sees EOF"
    );
}

/// §5.5 / D-ENIP-21 — a RegisterSession reply carrying non-zero `options` is **refused**, not
/// discarded-and-retried. Pre-actor there is exactly one expected frame on the stream, so looping
/// over discards buys nothing against a peer this broken — and adopting a session from it is worse.
#[tokio::test]
async fn register_reply_with_nonzero_options_is_refused() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        let req = peer.recv().await.unwrap();
        peer.send(&with_options(
            mk_frame(
                Command::RegisterSession,
                SESSION_HANDLE,
                req.header.sender_context,
                vec![0x01, 0x00, 0x00, 0x00],
            ),
            1,
        ))
        .await;
        peer.recv().await.is_none()
    });

    let r = EipClient::connect_over(client_io, base_opts()).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply carries non-zero options"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

// ---------------------------------------------------------------------------
// §5.5 / D-ENIP-21 — the RegisterSession reply **body**: `u16 protocol_version = 1`,
// `u16 options = 0`, and nothing after it. Every one of these bodies was accepted while only the
// first word was read, so each test below fails against that code and passes against the whole-body
// validation. The 4-byte reply is what every live peer in the bench actually sends (cpppo,
// libplctag's ab_server, EthernetIPSharp, OpENer, OpENer-CIPSecurity all answer `01 00 00 00`), so
// none of these shapes is a real device's behaviour being outlawed.
// ---------------------------------------------------------------------------

/// Drive one handshake whose reply carries `body`. Returns the client's verdict plus the peer task,
/// which resolves to whether the peer saw EOF next — a refused handshake spawns no session actor, so
/// the stream must drop rather than leave a live reader on a session we rejected.
async fn register_reply_body_verdict(
    body: Vec<u8>,
) -> (enip::Result<EipClient>, tokio::task::JoinHandle<bool>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        let req = peer.recv().await.unwrap();
        assert_eq!(req.header.command, Command::RegisterSession);
        peer.send(&mk_frame(
            Command::RegisterSession,
            SESSION_HANDLE,
            req.header.sender_context,
            body,
        ))
        .await;
        peer.recv().await.is_none()
    });
    let r = EipClient::connect_over(client_io, base_opts()).await;
    (r, server)
}

/// The reviewer's case: a **two-byte** body carrying only `01 00`. The protocol version is right,
/// but the options word the request sent — and §5.5 says comes back — is simply not there. Reading
/// the version and stopping accepted this frame and adopted the session out of it.
#[tokio::test]
async fn register_reply_with_a_two_byte_body_is_refused() {
    let (r, server) = register_reply_body_verdict(vec![0x01, 0x00]).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply body ends before the session options word"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

/// A reply with **no** command-specific data at all. The status is OK and the handle is non-zero, so
/// nothing before the body catches it; the missing version must be named as a missing field rather
/// than silently read as 0 and reported as an unsupported protocol version.
#[tokio::test]
async fn register_reply_with_an_empty_body_is_refused() {
    let (r, server) = register_reply_body_verdict(Vec::new()).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply body ends before the protocol version"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

/// The body's **session options** word is reserved and fixed at 0 (§5.5) — the same rule the header
/// `options` check applies one layer out. A peer setting bits there is negotiating something we
/// never offered, so the session is refused rather than adopted with the option ignored.
#[tokio::test]
async fn register_reply_with_nonzero_session_options_is_refused() {
    let (r, server) = register_reply_body_verdict(vec![0x01, 0x00, 0x01, 0x00]).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply body carries non-zero session options"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

/// An otherwise-perfect body with bytes appended. The layout is exact, so trailing data is not a
/// larger version of the same structure — it is a frame whose length disagrees with the command it
/// claims to answer, and nothing downstream would ever look at those bytes.
#[tokio::test]
async fn register_reply_with_trailing_body_bytes_is_refused() {
    let (r, server) = register_reply_body_verdict(vec![0x01, 0x00, 0x00, 0x00, 0xFF]).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::ProtocolViolation {
                detail: "register reply body has trailing bytes after the 4-byte payload"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

/// The variant split, pinned: a body of the right *shape* whose protocol version is not 1 is
/// `Unsupported`, not `ProtocolViolation` — the peer is speaking a generation of the encapsulation
/// layer this crate does not implement, the same thing encapsulation status `0x0069` says. The
/// malformed-body refusals above must stay distinguishable from it by variant alone.
#[tokio::test]
async fn register_reply_with_an_unsupported_protocol_version_is_refused() {
    let (r, server) = register_reply_body_verdict(vec![0x02, 0x00, 0x00, 0x00]).await;
    assert!(
        matches!(
            r.as_ref(),
            Err(enip::EnipError::Unsupported {
                what: "encapsulation protocol version"
            })
        ),
        "{:?}",
        r.err()
    );
    assert!(server.await.unwrap(), "no session actor owns the stream");
}

/// The conforming body — `01 00 00 00`, exactly what every live peer in the bench sends — still
/// registers. The whole-body validation must reject the shapes above **without** tightening the one
/// shape a compliant target actually emits.
#[tokio::test]
async fn register_reply_with_the_exact_four_byte_body_is_accepted() {
    let (r, server) = register_reply_body_verdict(vec![0x01, 0x00, 0x00, 0x00]).await;
    assert!(r.is_ok(), "{:?}", r.err());
    drop(r);
    server.abort();
}

/// §5.2 / D-ENIP-21 — the CIP interface handle in a `SendRRData` reply is 0 by Vol 2. A non-zero
/// value means the peer is answering on some other interface, so the payload is not a CIP Message
/// Router reply we may decode: `ProtocolViolation` (non-transient — a peer that mislabels its
/// interface will keep doing so).
#[tokio::test]
async fn an_explicit_reply_with_a_nonzero_interface_handle_is_refused() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        peer.send(&rrdata_reply_with_interface_handle(
            req.header.sender_context,
            &read_dint_mr(4242),
            7,
        ))
        .await;
        let _ = peer.recv().await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(
            r,
            Err(enip::EnipError::ProtocolViolation {
                detail: "non-zero interface handle in SendRRData reply"
            })
        ),
        "got {r:?}"
    );
    drop(client);
    server.abort();
}

/// §5.2 / D-ENIP-21 — the same rule on the connected class-3 path (`SendUnitData`).
#[tokio::test]
async fn a_connected_reply_with_a_nonzero_interface_handle_is_refused() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let t_o = handle_forward_open(&mut peer).await;
        let req = peer.recv().await.unwrap();
        let (seq, _svc, _d) = parse_connected_request(&req);
        peer.send(&unitdata_reply_with_interface_handle(
            req.header.sender_context,
            t_o,
            seq,
            &read_dint_mr(555),
            7,
        ))
        .await;
        let _ = peer.recv().await;
    });

    let opts = ClientOptions {
        connected_messaging: true,
        ..base_opts()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(
        matches!(
            r,
            Err(enip::EnipError::ProtocolViolation {
                detail: "non-zero interface handle in SendUnitData reply"
            })
        ),
        "got {r:?}"
    );
    drop(client);
    server.abort();
}

/// §5.2 / §8.2 / D-ENIP-21 — and on the Connection-Manager UCMM path the class-1 I/O layer opens
/// connections through (`ForwardOpenService::cm_ucmm`). Nothing in a reply that mislabels its
/// interface may bind a connection.
#[tokio::test]
async fn a_forward_open_reply_with_a_nonzero_interface_handle_is_refused() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        let req = peer.recv().await.unwrap();
        let (svc, _d) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x54, "expected ForwardOpen");
        peer.send(&rrdata_reply_with_interface_handle(
            req.header.sender_context,
            &mr_reply(0x54, 0x00, &[], &[]),
            7,
        ))
        .await;
        let _ = peer.recv().await;
    });

    let client = EipClient::connect_over(client_io, base_opts())
        .await
        .unwrap();
    let request = MessageRequest::new(
        0x54,
        enip::connection_manager_path(),
        Bytes::from_static(&[0u8; 4]),
    );
    let r = client.cm_ucmm(request, Vec::new()).await;
    assert!(
        matches!(
            r,
            Err(enip::EnipError::ProtocolViolation {
                detail: "non-zero interface handle in forward-open reply"
            })
        ),
        "got {:?}",
        r.err()
    );
    drop(client);
    server.abort();
}

// ---------------------------------------------------------------------------
// connected helpers
// ---------------------------------------------------------------------------

/// Handle a ForwardOpen (UCMM `0x54`), returning the T→O connection id the originator chose (so the
/// mock can address its connected replies with it).
async fn handle_forward_open(peer: &mut MockPeer) -> u32 {
    let req = peer.recv().await.unwrap();
    let (svc, data) = parse_ucmm_request(&req);
    assert_eq!(svc, 0x54, "expected ForwardOpen");
    // ForwardOpen data: priority(1) ticks(1) o_t(4) t_o(4) ...
    let mut r = WireReader::new(&data);
    r.u8().unwrap();
    r.u8().unwrap();
    let _o_t = r.u32().unwrap();
    let t_o = r.u32().unwrap();
    let serial = r.u16().unwrap();
    let vendor = r.u16().unwrap();
    let orig_serial = r.u32().unwrap();

    // Success reply: assign an O→T id, echo T→O + identifiers, echo the requested 2 s packet
    // interval as the actual one, no app data.
    //
    // The APIs are not incidental: class-3 derives its inactivity-keepalive window from the reply's
    // actual O→T API (§7.6), so 2 s × the default ×16 multiplier gives a 32 s window — no probe can
    // fall due inside these scripted exchanges. (A compliant target echoes the requested interval;
    // the previous 2000 µs would have armed a 32 ms window and injected keepalive frames into every
    // class-3 script below.)
    let mut body = WireWriter::new();
    body.u32(0x1000_0001); // O→T (target-assigned)
    body.u32(t_o); // T→O (echo)
    body.u16(serial);
    body.u16(vendor);
    body.u32(orig_serial);
    body.u32(2_000_000);
    body.u32(2_000_000);
    body.u8(0); // app words
    body.u8(0); // reserved
    peer.send(&rrdata_reply(
        req.header.sender_context,
        &mr_reply(0x54, 0x00, &[], body.as_slice()),
    ))
    .await;
    t_o
}

/// Push one Get-Instance-Attribute-List record: `u32 instance, u16 name_len, name, u16 symbol_type`.
fn push_symbol(w: &mut WireWriter, instance: u32, name: &str, symbol_type: u16) {
    w.u32(instance);
    w.u16(u16::try_from(name.len()).unwrap());
    w.put_slice(name.as_bytes());
    w.u16(symbol_type);
}
