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

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use enip::cip::types::CipValue;
use enip::encap::{Command, EncapFrame, EncapHeader};
use enip::{
    CipType, ClientOptions, Cpf, CpfItem, EipClient, Scope, TagAddress, WireReader, WireWriter,
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
    mk_frame(Command::SendRRData, SESSION_HANDLE, ctx, w.into_bytes().to_vec())
}

/// Wrap MR bytes in a `SendUnitData` reply frame (connected CPF `[connected-address, connected-data]`).
fn unitdata_reply(ctx: [u8; 8], addr: u32, seq: u16, mr: &[u8]) -> EncapFrame {
    let mut cd = WireWriter::new();
    cd.u16(seq);
    cd.put_slice(mr);
    let cpf = Cpf::from_items(vec![
        CpfItem::connected_address(addr),
        CpfItem::connected_data(cd.into_bytes()),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(0);
    w.u16(0);
    w.put_slice(&cpf_bytes);
    mk_frame(Command::SendUnitData, SESSION_HANDLE, ctx, w.into_bytes().to_vec())
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
        peer.send(&rrdata_reply(req.header.sender_context, &read_dint_mr(4242)))
            .await;
        // Write it back.
        let req = peer.recv().await.unwrap();
        let (svc, data) = parse_ucmm_request(&req);
        assert_eq!(svc, 0x4D);
        // data = type(2) + count(2) + value(4)
        assert_eq!(&data[0..2], &CipType::Dint.code().to_le_bytes());
        peer.send(&rrdata_reply(req.header.sender_context, &mr_reply(0x4D, 0x00, &[], &[])))
            .await;
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
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
        peer.send(&rrdata_reply(req.header.sender_context, &mr)).await;
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
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
        peer.send(&rrdata_reply(req1.header.sender_context, &read_dint_mr(111)))
            .await;
        peer.send(&rrdata_reply(req2.header.sender_context, &read_dint_mr(222)))
            .await;
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();

    // Request 1 times out (reply withheld).
    let r1 = client.read_tag(&tag, 1).await;
    assert!(matches!(r1, Err(enip::EnipError::Timeout { .. })), "got {r1:?}");
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await;
    assert!(matches!(r, Err(enip::EnipError::Timeout { .. })), "got {r:?}");
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
    assert!(matches!(r1, Err(enip::EnipError::Timeout { .. })), "1: {r1:?}");
    let r2 = client.read_tag(&tag, 1).await;
    assert!(matches!(r2, Err(enip::EnipError::Timeout { .. })), "2: {r2:?}");
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
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
    assert!(matches!(r, Err(enip::EnipError::TooLarge { .. })), "got {r:?}");
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let (page1, next) = client.list_tags(1, &Scope::Controller).await.unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].name, "PRODUCT_COUNT");
    assert!(page1[0].symbol_type.is_value_supported());
    assert_eq!(page1[1].name, "ZONE_TEMPS");
    assert_eq!(page1[1].symbol_type.dims(), 1);
    assert!(!page1[1].symbol_type.is_value_supported()); // array
    assert_eq!(next, Some(3));

    let (page2, next2) = client.list_tags(next.unwrap(), &Scope::Controller).await.unwrap();
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
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
        peer.send(&unitdata_reply(req.header.sender_context, t_o, seq, &read_dint_mr(555)))
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

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let tag = TagAddress::parse("A").unwrap();
    client.read_tag(&tag, 1).await.unwrap();
    client.close().await;
    server.await.unwrap();
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

    // Success reply: assign an O→T id, echo T→O + identifiers, APIs = 2000µs, no app data.
    let mut body = WireWriter::new();
    body.u32(0x1000_0001); // O→T (target-assigned)
    body.u32(t_o); // T→O (echo)
    body.u16(serial);
    body.u16(vendor);
    body.u32(orig_serial);
    body.u32(2000);
    body.u32(2000);
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
