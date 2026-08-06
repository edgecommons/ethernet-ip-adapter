//! Class-3 inactivity keepalive (PROTOCOL-DESIGN §7.6, D-ENIP-18).
//!
//! A class-3 ForwardOpen arms an inactivity watchdog **on the target**: `multiplier × O→T API`. A
//! session that goes quiet for longer than that — a paused instance, or any poll group slower than
//! the window — loses its connection, and every later request on it fails until the adapter
//! reconnects. The connection's owner is this crate, so the crate keeps it alive: at ¾ of the
//! negotiated window with no traffic, the session reads Identity attribute 4 (Revision) over the
//! connected path.
//!
//! These tests drive the whole mechanism over an in-memory [`tokio::io::duplex`] byte-stream fixture
//! under `start_paused` virtual time (D-ENIP-14 — no embedded server, no sockets, no wall clock):
//! the keepalive's exact frame, its cadence, its derivation from the *negotiated* API, the deferral
//! by ordinary traffic, its tolerance of a CIP error reply, and — the leak class — that the task and
//! the session actor both die with the client.

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
use enip::cm::TimeoutMultiplier;
use enip::encap::{Command, EncapFrame, EncapHeader};
use enip::{CipType, ClientOptions, Cpf, CpfItem, EipClient, ItemType, TagAddress, WireReader, WireWriter};

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

/// Connection Manager service codes (§8.2, §8.8).
const FORWARD_OPEN: u8 = 0x54;
const FORWARD_CLOSE: u8 = 0x4E;
/// `Get_Attribute_Single` — the §7.6 keepalive service.
const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
/// `Read Tag` — ordinary traffic in these tests.
const READ_TAG: u8 = 0x4C;

/// The O→T connection id the fixture assigns; every connected request must be addressed to it.
const ASSIGNED_O_T_ID: u32 = 0xAABB_CCDD;

/// The Identity-revision path the keepalive must carry: class `0x01`, instance `1`, attribute `4`.
const IDENTITY_REVISION_PATH: [u8; 6] = [0x20, 0x01, 0x24, 0x01, 0x30, 0x04];

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

    /// The next full request frame, or `None` at EOF (the session actor exited).
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
            req.header.sender_context,
            vec![0x01, 0x00, 0x00, 0x00],
        );
        self.send(&reply).await;
    }
}

// ---------------------------------------------------------------------------
// frame / reply builders
// ---------------------------------------------------------------------------

fn mk_frame(command: Command, ctx: [u8; 8], data: Vec<u8>) -> EncapFrame {
    EncapFrame::new(
        EncapHeader::request(command, 0, SESSION_HANDLE, ctx),
        Bytes::from(data),
    )
}

/// A Message Router reply: `reply-service · reserved · status · ext-words · data`.
fn mr_reply(service: u8, status: u8, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(status);
    w.u8(0);
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
    w.u32(0);
    w.u16(0);
    w.put_slice(&cpf_bytes);
    mk_frame(Command::SendRRData, ctx, w.into_bytes().to_vec())
}

/// Wrap MR bytes in a `SendUnitData` reply frame (connected CPF `[address, data]`), carrying the
/// sequence the request used and the originator's T→O connection id (both are hard-checked).
fn unitdata_reply(ctx: [u8; 8], t_o_id: u32, seq: u16, mr: &[u8]) -> EncapFrame {
    let mut cd = WireWriter::new();
    cd.u16(seq);
    cd.put_slice(mr);
    let cpf = Cpf::from_items(vec![
        CpfItem::connected_address(t_o_id),
        CpfItem::connected_data(cd.into_bytes()),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(0);
    w.u16(0);
    w.put_slice(&cpf_bytes);
    mk_frame(Command::SendUnitData, ctx, w.into_bytes().to_vec())
}

/// Split a UCMM (`SendRRData`) request frame into `(service, service-data)`.
fn parse_ucmm_request(frame: &EncapFrame) -> (u8, Vec<u8>) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap();
    r.u16().unwrap();
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let mr = cpf.expect_explicit_data().unwrap();
    let mut mr_r = WireReader::new(mr);
    let service = mr_r.u8().unwrap();
    let path_words = mr_r.u8().unwrap() as usize;
    mr_r.skip(path_words * 2).unwrap();
    (service, mr_r.take_rest().to_vec())
}

/// One connected (`SendUnitData`) request as the target sees it.
struct ConnectedRequest {
    /// The connected-address item — must be the O→T id the fixture assigned.
    address: u32,
    /// The connected-data sequence count (§7.6, never 0).
    sequence: u16,
    /// The Message Router service code.
    service: u8,
    /// The Message Router request path bytes.
    path: Vec<u8>,
}

fn parse_connected_request(frame: &EncapFrame) -> ConnectedRequest {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap();
    r.u16().unwrap();
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let addr_item = cpf.find(ItemType::ConnectedAddress).expect("connected address item");
    let data_item = cpf.find(ItemType::ConnectedData).expect("connected data item");
    let mut ar = WireReader::new(&addr_item.data);
    let address = ar.u32().unwrap();
    let mut dr = WireReader::new(&data_item.data);
    let sequence = dr.u16().unwrap();
    let mut mr_r = WireReader::new(dr.take_rest());
    let service = mr_r.u8().unwrap();
    let path_words = mr_r.u8().unwrap() as usize;
    let path = mr_r.take(path_words * 2).unwrap().to_vec();
    ConnectedRequest {
        address,
        sequence,
        service,
        path,
    }
}

/// The originator identity a ForwardOpen request carries (§8.2 fields 4–7), plus the requested
/// timing fields the keepalive window is derived from.
struct OpenRequest {
    t_o_connection_id: u32,
    connection_serial: u16,
    vendor_id: u16,
    originator_serial: u32,
    timeout_multiplier_code: u8,
    o_t_rpi: u32,
    t_o_rpi: u32,
}

fn parse_open_request(data: &[u8]) -> OpenRequest {
    let mut r = WireReader::new(data);
    r.u8().unwrap(); // priority / time tick
    r.u8().unwrap(); // timeout ticks
    r.u32().unwrap(); // O→T id (0 — the target assigns it)
    let t_o_connection_id = r.u32().unwrap();
    let connection_serial = r.u16().unwrap();
    let vendor_id = r.u16().unwrap();
    let originator_serial = r.u32().unwrap();
    let timeout_multiplier_code = r.u8().unwrap();
    r.skip(3).unwrap(); // reserved
    let o_t_rpi = r.u32().unwrap();
    r.u16().unwrap(); // O→T NCP
    let t_o_rpi = r.u32().unwrap();
    OpenRequest {
        t_o_connection_id,
        connection_serial,
        vendor_id,
        originator_serial,
        timeout_multiplier_code,
        o_t_rpi,
        t_o_rpi,
    }
}

/// A ForwardOpen success reply body (§8.2) echoing the originator quad, assigning
/// [`ASSIGNED_O_T_ID`], and naming `api` µs as the **actual** packet interval in both directions.
fn forward_open_success(open: &OpenRequest, api: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u32(ASSIGNED_O_T_ID);
    w.u32(open.t_o_connection_id);
    w.u16(open.connection_serial);
    w.u16(open.vendor_id);
    w.u32(open.originator_serial);
    w.u32(api); // O→T API (µs) — the value the keepalive window is derived from
    w.u32(api); // T→O API (µs)
    w.u8(0); // application reply words
    w.u8(0); // reserved
    w.into_bytes().to_vec()
}

/// A ForwardClose success reply body (§8.8).
fn forward_close_success(open: &OpenRequest) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u16(open.connection_serial);
    w.u16(open.vendor_id);
    w.u32(open.originator_serial);
    w.into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// the scripted peer
// ---------------------------------------------------------------------------

/// Everything the target observed, returned when the client's session actor closes the stream.
#[derive(Default, Debug)]
struct Observed {
    /// The ForwardOpen's requested O→T RPI, T→O RPI, and timeout-multiplier code.
    requested_rpis: (u32, u32),
    requested_multiplier_code: u8,
    /// One entry per connected request, in order: its Message Router service code.
    connected_services: Vec<u8>,
    /// The address, sequence and path of every keepalive (service `0x0E`) request.
    keepalive_addresses: Vec<u32>,
    keepalive_sequences: Vec<u16>,
    keepalive_paths: Vec<Vec<u8>>,
    /// One entry per UCMM request after the open: its service code (a ForwardClose, in practice).
    ucmm_services: Vec<u8>,
    /// Whether an UnRegisterSession arrived.
    unregistered: bool,
}

impl Observed {
    fn keepalives(&self) -> usize {
        self.connected_services
            .iter()
            .filter(|s| **s == GET_ATTRIBUTE_SINGLE)
            .count()
    }
}

/// Serve one class-3 session until the client's actor closes the stream: register, ForwardOpen
/// (echoing `api` as the actual packet interval), then answer every request — keepalive reads with
/// `keepalive_status`, tag reads with a DINT, ForwardClose with a success body.
async fn serve(server_side: DuplexStream, api: u32, keepalive_status: u8) -> Observed {
    let mut mock = MockPeer::new(server_side);
    let mut obs = Observed::default();
    mock.handle_register().await;

    let open_frame = mock.recv().await.expect("forward open request");
    let (service, data) = parse_ucmm_request(&open_frame);
    assert_eq!(service, FORWARD_OPEN);
    let open = parse_open_request(&data);
    obs.requested_rpis = (open.o_t_rpi, open.t_o_rpi);
    obs.requested_multiplier_code = open.timeout_multiplier_code;
    let body = forward_open_success(&open, api);
    mock.send(&rrdata_reply(
        open_frame.header.sender_context,
        &mr_reply(FORWARD_OPEN, 0x00, &body),
    ))
    .await;

    while let Some(frame) = mock.recv().await {
        match frame.header.command {
            Command::UnRegisterSession => obs.unregistered = true,
            Command::SendUnitData => {
                let req = parse_connected_request(&frame);
                obs.connected_services.push(req.service);
                let mr = match req.service {
                    GET_ATTRIBUTE_SINGLE => {
                        obs.keepalive_addresses.push(req.address);
                        obs.keepalive_sequences.push(req.sequence);
                        obs.keepalive_paths.push(req.path.clone());
                        // Identity revision: major, minor.
                        mr_reply(GET_ATTRIBUTE_SINGLE, keepalive_status, &[0x01, 0x02])
                    }
                    READ_TAG => {
                        let mut v = WireWriter::new();
                        v.u16(CipType::Dint.code());
                        v.i32(555);
                        mr_reply(READ_TAG, 0x00, v.as_slice())
                    }
                    other => panic!("unexpected connected service {other:#04X}"),
                };
                mock.send(&unitdata_reply(
                    frame.header.sender_context,
                    open.t_o_connection_id,
                    req.sequence,
                    &mr,
                ))
                .await;
            }
            Command::SendRRData => {
                let (service, _data) = parse_ucmm_request(&frame);
                obs.ucmm_services.push(service);
                assert_eq!(service, FORWARD_CLOSE, "the only UCMM traffic after the open");
                mock.send(&rrdata_reply(
                    frame.header.sender_context,
                    &mr_reply(FORWARD_CLOSE, 0x00, &forward_close_success(&open)),
                ))
                .await;
            }
            other => panic!("unexpected encapsulation command {other:?}"),
        }
    }
    obs
}

/// Class-3 options with an explicit window: `rpi × multiplier` is the target-side inactivity
/// window, so the keepalive is due at ¾ of it.
fn opts(rpi: Duration, multiplier: TimeoutMultiplier) -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_millis(500),
        connected_messaging: true,
        class3_rpi: rpi,
        class3_timeout_multiplier: multiplier,
        ..ClientOptions::default()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// **K1.** The headline: an idle class-3 session sends a keepalive at ¾ of the negotiated window,
/// and the frame is exactly the §7.6 one — a connected `SendUnitData` addressed to the
/// target-assigned O→T id, carrying a non-zero connected-data sequence and a
/// `Get_Attribute_Single` of Identity (class `0x01`) instance 1 attribute 4 (Revision).
///
/// Requested 400 ms × ×4 and the target echoes the same API ⇒ a 1.6 s window, due at 1.2 s. Two
/// windows of idle time must produce **exactly two** probes — the cadence is one per ¾-window, not a
/// storm.
#[tokio::test(start_paused = true)]
async fn idle_class3_session_sends_identity_keepalive_at_three_quarters_window() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(serve(server_side, 400_000, 0x00));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_millis(400), TimeoutMultiplier::X4),
    )
    .await
    .expect("the class-3 open succeeds");
    assert!(client.is_connected_messaging());

    // Two windows of pure idleness: probes fall due at 1.2 s and 2.4 s, the next at 3.6 s.
    tokio::time::sleep(Duration::from_millis(3_200)).await;
    assert_eq!(
        client.stats().keepalives_sent,
        2,
        "exactly one probe per ¾-window — no storm, no starvation"
    );

    drop(client);
    let obs = peer.await.unwrap();
    assert_eq!(obs.requested_rpis, (400_000, 400_000), "both RPIs carry the option");
    assert_eq!(obs.requested_multiplier_code, TimeoutMultiplier::X4.code());
    assert_eq!(obs.connected_services, vec![GET_ATTRIBUTE_SINGLE; 2]);
    assert_eq!(obs.keepalive_addresses, vec![ASSIGNED_O_T_ID; 2]);
    for path in &obs.keepalive_paths {
        assert_eq!(path.as_slice(), &IDENTITY_REVISION_PATH);
    }
    for seq in &obs.keepalive_sequences {
        assert_ne!(*seq, 0, "the connected-data sequence never uses 0 (§7.6)");
    }
    assert_eq!(
        obs.keepalive_sequences[1],
        obs.keepalive_sequences[0] + 1,
        "the probe rides the ordinary connected path, so it consumes the next sequence"
    );
}

/// **K2.** Ordinary request traffic defers the keepalive: every completed class-3 exchange refreshes
/// the activity clock, so a session polled faster than ¾ of the window never probes at all.
#[tokio::test(start_paused = true)]
async fn request_traffic_defers_the_keepalive() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(serve(server_side, 400_000, 0x00));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_millis(400), TimeoutMultiplier::X4),
    )
    .await
    .expect("the class-3 open succeeds");

    // Window 1.6 s ⇒ due at 1.2 s. Read every 0.9 s across four windows (7.2 s).
    let tag = TagAddress::parse("A").unwrap();
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(900)).await;
        let r = client.read_tag(&tag, 1).await.unwrap();
        assert_eq!(r.value, CipValue::Dint(555));
    }
    assert_eq!(
        client.stats().keepalives_sent,
        0,
        "traffic inside ¾ of the window must keep the probe from ever falling due"
    );

    drop(client);
    let obs = peer.await.unwrap();
    assert_eq!(obs.connected_services, vec![READ_TAG; 8]);
    assert_eq!(obs.keepalives(), 0);
}

/// **K3.** The window is derived from the **negotiated** interval, not the requested one: the target
/// answers the 400 ms request with a 100 ms actual API, so the window is 100 ms × ×4 = 400 ms and the
/// probe is due at 300 ms — long before the 1.2 s the requested RPI would have implied.
#[tokio::test(start_paused = true)]
async fn keepalive_window_prefers_the_reply_api() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(serve(server_side, 100_000, 0x00));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_millis(400), TimeoutMultiplier::X4),
    )
    .await
    .expect("the class-3 open succeeds");

    // Just past the API-derived due time (300 ms) and far short of the requested-RPI one (1.2 s).
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        client.stats().keepalives_sent,
        1,
        "the reply's actual O→T API sets the window"
    );

    drop(client);
    let obs = peer.await.unwrap();
    assert_eq!(obs.keepalives(), 1);
    assert_eq!(
        obs.requested_rpis.0, 400_000,
        "the request still carries what we asked for"
    );
}

/// **K5.** The leak class: the keepalive task holds nothing strong. Dropping the last client handle
/// closes the session actor's stream at once, and no probe is ever sent afterwards.
///
/// **Promptness is the property, not just eventual exit.** The task's channel sender is a
/// [`tokio::sync::mpsc::WeakSender`], so dropping the client takes the actor's *last strong* sender
/// with it and the actor exits immediately. Were it a strong `Sender`, the actor would linger until
/// the task's next wake — up to `KEEPALIVE_MAX_SLEEP` (60 s), and here the 24 s ¾-window point of the
/// default 32 s window — holding the socket open long past the caller's `drop`. So the EOF is
/// asserted **before** virtual time can reach that first due point: under `start_paused` a lingering
/// actor leaves every task idle, the clock auto-advances to the bound, and this times out.
///
/// The yield before the drop is load-bearing, not cosmetic: on a current-thread runtime the keepalive
/// task is not polled at all between `connect_over` returning and the next `.await`, so without it
/// the task would still be sitting at its first poll — where it exits through the failed `Weak`
/// upgrade whatever kind of sender it holds, and the drop would look prompt either way. Letting it
/// reach its sleep first is what makes the sender's strength observable.
#[tokio::test(start_paused = true)]
async fn dropping_the_last_client_stops_keepalive_and_actor() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(serve(server_side, 2_000_000, 0x00));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_secs(2), TimeoutMultiplier::X16),
    )
    .await
    .expect("the class-3 open succeeds");
    assert!(client.is_connected_messaging());

    // Let the keepalive task run up to its sleep. Window 32 s ⇒ the first probe is due at 24 s, so a
    // second of idling parks the task without waking it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(client.stats().keepalives_sent, 0, "far too early for a probe");

    // Five seconds is comfortably short of both the 24 s due point and the 60 s liveness re-check.
    let dropped_at = tokio::time::Instant::now();
    drop(client);
    let obs = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .expect(
            "the session actor must exit the moment the last client drops — it is still alive, so \
             something other than the client is holding a strong sender (a strong `Sender` in the \
             keepalive task would keep it up until the task's next wake)",
        )
        .unwrap();
    let lingered = tokio::time::Instant::now().saturating_duration_since(dropped_at);
    assert!(
        lingered < Duration::from_secs(24),
        "the actor lingered {lingered:?} after the drop — past the first keepalive due point"
    );

    // The peer's read side saw EOF, and nothing at all arrived after the open.
    assert!(obs.connected_services.is_empty(), "{obs:?}");
    assert!(obs.ucmm_services.is_empty(), "{obs:?}");
    assert!(!obs.unregistered, "a dropped client sends no courtesy unregister");
}

/// **K6.** A graceful `close()` stops the keepalive too: the target sees the ForwardClose and the
/// UnRegisterSession, then nothing — three windows later there is still no probe, because the task's
/// next probe finds the session closed and returns.
#[tokio::test(start_paused = true)]
async fn close_stops_the_keepalive() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(serve(server_side, 400_000, 0x00));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_millis(400), TimeoutMultiplier::X4),
    )
    .await
    .expect("the class-3 open succeeds");
    client.close().await;

    // Three windows (4.8 s) past the close — a live session would have probed four times.
    tokio::time::sleep(Duration::from_millis(4_800)).await;
    assert_eq!(client.stats().keepalives_sent, 0);

    drop(client);
    let obs = peer.await.unwrap();
    assert_eq!(obs.ucmm_services, vec![FORWARD_CLOSE]);
    assert!(obs.unregistered, "close() sends the courtesy UnRegisterSession");
    assert_eq!(obs.keepalives(), 0, "no probe after the session closed");
}

/// **K7.** A target that refuses the attribute read must not wedge or kill the session: a CIP error
/// reply still proves the exchange flowed both ways (which is exactly what the target's watchdog
/// measures), so it counts as a keepalive, and the connection keeps serving requests.
#[tokio::test(start_paused = true)]
async fn keepalive_counts_a_cip_error_reply_as_sent() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    // 0x08 = Service Not Supported.
    let peer = tokio::spawn(serve(server_side, 400_000, 0x08));

    let client = EipClient::connect_over(
        client_side,
        opts(Duration::from_millis(400), TimeoutMultiplier::X4),
    )
    .await
    .expect("the class-3 open succeeds");

    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(client.stats().keepalives_sent, 1);

    let tag = TagAddress::parse("A").unwrap();
    let r = client.read_tag(&tag, 1).await.expect("the session still serves reads");
    assert_eq!(r.value, CipValue::Dint(555));
    assert_eq!(client.stats().connected_seq_mismatches, 0);

    drop(client);
    let obs = peer.await.unwrap();
    assert_eq!(obs.connected_services, vec![GET_ATTRIBUTE_SINGLE, READ_TAG]);
}
