//! Tag-enumeration paging over 32-bit symbol-instance cursors (PROTOCOL-DESIGN §7.3, §12.2).
//!
//! `list_tags` carries a full `u32` cursor end to end: a Logix controller routinely serves symbol
//! instances above `0xFFFF`, and a cursor that masks them wraps a browse walk back toward instance 1
//! — an endless loop for any caller that pages to completion. These tests drive the real client over
//! an in-memory [`tokio::io::duplex`] byte-stream fixture (D-ENIP-14 — no embedded server), scripting
//! a `0x55` reply per case, and pin the three cursor rules: the cursor crosses the 16-bit boundary
//! intact (and is emitted as the 32-bit logical instance segment on the wire), a page that does not
//! advance is a [`enip::EnipError::ProtocolViolation`] rather than a loop, and the end of the
//! instance space ends the enumeration rather than wrapping.

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
use enip::{ClientOptions, Cpf, CpfItem, EipClient, EnipError, Scope, WireReader, WireWriter};

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

/// Get Instance Attribute List (§7.3).
const SERVICE_TAG_LIST: u8 = 0x55;

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

    /// Answer the next `0x55` request with one record and the given CIP status, returning the
    /// request path bytes the client actually put on the wire.
    async fn answer_tag_list(&mut self, status: u8, instance: u32, name: &str) -> Vec<u8> {
        self.answer_tag_list_page(status, &[(instance, name)]).await
    }

    /// Answer the next `0x55` request with a whole page of records (in the order given — a peer is
    /// free to send them in any order, which is exactly what the ordering guard is for) and the
    /// given CIP status, returning the request path bytes the client actually put on the wire.
    async fn answer_tag_list_page(&mut self, status: u8, records: &[(u32, &str)]) -> Vec<u8> {
        let req = self.recv().await.expect("tag list request");
        let (service, path, _data) = parse_ucmm_request(&req);
        assert_eq!(service, SERVICE_TAG_LIST);
        let mut b = WireWriter::new();
        for (instance, name) in records {
            push_symbol(&mut b, *instance, name, 0x00C4); // DINT
        }
        self.send(&rrdata_reply(
            req.header.sender_context,
            &mr_reply(SERVICE_TAG_LIST, status, b.as_slice()),
        ))
        .await;
        path
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

/// A Message Router reply: `reply-service · reserved · status · ext-size · data` (§6.1).
fn mr_reply(service: u8, status: u8, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(status);
    w.u8(0); // no extended status words
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
    mk_frame(Command::SendRRData, SESSION_HANDLE, ctx, w.into_bytes().to_vec())
}

/// One `0x55` record: `u32 instance · u16 name length · name · u16 symbol type` (§7.3).
fn push_symbol(w: &mut WireWriter, instance: u32, name: &str, symbol_type: u16) {
    w.u32(instance);
    w.u16(u16::try_from(name.len()).unwrap());
    w.put_slice(name.as_bytes());
    w.u16(symbol_type);
}

/// Split a UCMM (`SendRRData`) request frame into `(service, request path bytes, service data)`.
fn parse_ucmm_request(frame: &EncapFrame) -> (u8, Vec<u8>, Vec<u8>) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap(); // interface handle
    r.u16().unwrap(); // timeout
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let mr = cpf.expect_explicit_data().unwrap();
    let mut mr_r = WireReader::new(mr);
    let service = mr_r.u8().unwrap();
    let path_words = mr_r.u8().unwrap() as usize;
    let path = mr_r.take(path_words * 2).unwrap().to_vec();
    (service, path, mr_r.take_rest().to_vec())
}

fn base_opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_millis(500),
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// §7.3 — the resume cursor is a full `u32`: a symbol instance above `0xFFFF` produces a cursor
/// above `0xFFFF`, and the request that carried the high start instance used the 32-bit logical
/// instance segment (`0x26`, §6.2).
#[tokio::test]
async fn list_tags_next_cursor_crosses_the_u16_boundary() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // status 0x06 — "more data", so a next cursor is derived.
        peer.answer_tag_list(0x06, 0x0001_0005, "HIGH_INSTANCE_TAG").await
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let (page, next) = client
        .list_tags(0x0001_0000, &Scope::Controller)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].instance_id, 0x0001_0005);
    // Masking the instance id to 16 bits would yield Some(6) — a cursor that walks the enumeration
    // back into pages it already served, forever.
    assert_eq!(next, Some(0x0001_0006));

    drop(client);
    let path = server.await.unwrap();
    // class 0x6B in the 8-bit form, then the 32-bit instance segment for 0x0001_0000.
    assert_eq!(path, vec![0x20, 0x6B, 0x26, 0x00, 0x00, 0x00, 0x01, 0x00]);
}

/// §7.3 — a `0x06` page whose resume point does not advance past the requested start is a
/// [`EnipError::ProtocolViolation`], not a loop the caller has to detect.
#[tokio::test]
async fn list_tags_rejects_a_non_advancing_page() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        // Asked to resume at 500, the peer answers with a record from before that point.
        peer.answer_tag_list(0x06, 100, "BACKWARDS").await
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let err = client
        .list_tags(500, &Scope::Controller)
        .await
        .expect_err("a non-advancing page is a protocol violation");
    assert!(
        matches!(
            err,
            EnipError::ProtocolViolation {
                detail: "tag list page did not advance"
            }
        ),
        "got {err:?}"
    );

    drop(client);
    server.await.unwrap();
}

/// §7.3 — a page whose records are **not strictly ascending** is a [`EnipError::ProtocolViolation`].
///
/// The resume point is derived from the page's *last* record, so an out-of-order page is a silent
/// skip waiting to happen: a caller that cuts the page to its own `max` (the adapter's `sb/browse`
/// does exactly that) returns only the head of the page and resumes past everything behind it.
/// `[10, 2, 3]` cut to one record returns `TAG_10` and resumes at 11 — instances 2 and 3 are never
/// served again, silently and forever.
#[tokio::test]
async fn list_tags_rejects_an_out_of_order_page() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        peer.answer_tag_list_page(0x06, &[(10, "TAG_10"), (2, "TAG_2"), (3, "TAG_3")])
            .await
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let err = client
        .list_tags(0, &Scope::Controller)
        .await
        .expect_err("an out-of-order page is a protocol violation");
    // The last record (3) still derives a cursor that advances past start 0, so the advance guard
    // alone never sees this page: only the intra-page ordering pass catches it.
    assert!(
        matches!(
            err,
            EnipError::ProtocolViolation {
                detail: "tag list page is not in ascending instance order"
            }
        ),
        "got {err:?}"
    );

    drop(client);
    server.await.unwrap();
}

/// §7.3 — a repeated instance id inside one page is the same defect and the same typed error, and
/// the guard is not gated on `0x06`: this page is a **final** page (status `0`) whose duplicate
/// would still be dropped by a `max`-truncating caller resuming from the last record.
#[tokio::test]
async fn list_tags_rejects_a_duplicated_instance_id() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        peer.answer_tag_list_page(0x00, &[(2, "TAG_2"), (2, "TAG_2_AGAIN"), (3, "TAG_3")])
            .await
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let err = client
        .list_tags(0, &Scope::Controller)
        .await
        .expect_err("a duplicated instance id is a protocol violation");
    assert!(
        matches!(
            err,
            EnipError::ProtocolViolation {
                detail: "tag list page is not in ascending instance order"
            }
        ),
        "got {err:?}"
    );

    drop(client);
    server.await.unwrap();
}

/// §7.3 — a page whose last record sits at the top of the instance space ends the enumeration
/// instead of wrapping to a cursor the walk already visited.
#[tokio::test]
async fn list_tags_end_of_instance_space_ends_the_walk() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        peer.answer_tag_list(0x06, u32::MAX, "LAST").await
    });

    let client = EipClient::connect_over(client_io, base_opts()).await.unwrap();
    let (page, next) = client
        .list_tags(0xFFFF_0000, &Scope::Controller)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].instance_id, u32::MAX);
    // `u32::MAX + 1` has no representable resume point, so the walk ends here.
    assert_eq!(next, None);

    drop(client);
    server.await.unwrap();
}
