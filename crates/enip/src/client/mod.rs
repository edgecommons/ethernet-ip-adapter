//! The explicit-messaging client (PROTOCOL-DESIGN §11).
//!
//! [`EipClient`] is the caller-facing handle — connect, read/write tag, list tags, get/set
//! attribute, identity, close — a cheap clone around the session actor's command channel. All calls
//! are deadline-bounded and go through the one-in-flight session actor ([`session`]). [`ClientOptions`]
//! selects port, routing, timeouts, the `max_value_bytes` reassembly cap, and connected-vs-unconnected
//! messaging.
//!
//! The client is generic over the byte stream only at [`EipClient::connect_over`]: production uses
//! [`EipClient::connect`] (a real `TcpStream`); tests inject a [`tokio::io::duplex`] half so the P2
//! correctness claims are proven deterministically without any embedded server.

pub mod connected;
pub mod io_service;
// The class-3 inactivity keepalive (§7.6) — internal machinery, not part of the crate's surface; its
// observable face is `ClientStats::keepalives_sent`.
pub(crate) mod keepalive;
pub mod session;
// TLS transport (CIP Security Phase 1) — off by default; adds `connect_tls`/`TlsOptions` over the
// transport-generic session actor (DESIGN-cip-security.md §3.1).
#[cfg(feature = "tls")]
pub mod tls;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::cip::epath::{EPath, PortSegment};
use crate::cip::message::MessageRequest;
use crate::cpf::{Cpf, CpfItem};
use crate::discovery::DeviceIdentity;
use crate::encap::codec::EncapCodec;
use crate::encap::{Command, EncapFrame, EncapHeader, PROTOCOL_VERSION};
use crate::error::{EnipError, Result};
use crate::wire::{WireReader, WireWriter};

use connected::ConnectedState;
use session::{
    deadline_from, recv_frame, send_frame_by, spawn_session, SessionCommand, SessionStats,
    Transaction,
};

/// Bounds [`EipClient::close`]'s hand-off to the session actor plus its done-ack (§10.4), so a
/// graceful shutdown can never hang behind a wedged actor (one parked mid-read on a silent peer, or
/// one whose queue is still draining). On elapse `close()` returns anyway: the courtesy
/// UnRegisterSession is best-effort, and dropping the last handle tears the session down regardless.
pub(crate) const CLOSE_HANDOFF_DEADLINE: Duration = Duration::from_secs(2);

/// Grace added to the caller-side reply backstop, on top of the request deadline (§10.4).
///
/// The session actor is the **authority** on a request's outcome: it alone knows whether an elapsed
/// deadline is an ordinary per-request `Timeout`, the third consecutive strike (`ConnectionLost`), or
/// a write that stalled mid-frame and desynchronised the stream (`ConnectionLost`). The caller's
/// `timeout_at` on the reply channel is only a *liveness backstop* for an actor that never answers at
/// all — so it must fire strictly AFTER the actor's own deadline. Were the two the same instant, the
/// caller's timer (registered first, and therefore fired first) would pre-empt the actor at every
/// deadline and collapse every failure class into a bare `Timeout`.
pub(crate) const REPLY_BACKSTOP_GRACE: Duration = Duration::from_millis(50);

/// The Connection Manager object path `[0x20 0x06 0x24 0x01]` as an [`EPath`] (§7.1).
pub(crate) fn connection_manager_path() -> EPath {
    EPath::new().class(0x06).instance(0x01)
}

/// A routed path to the target (§6.2, D-ENIP-13) — one or more port segments (backplane slot, etc.).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePath {
    segments: Vec<PortSegment>,
}

impl RoutePath {
    /// A single backplane hop to `slot` (port 1, link `[slot]`) — the common CompactLogix/rack path.
    #[must_use]
    pub fn backplane_slot(slot: u8) -> Self {
        Self {
            segments: vec![PortSegment::backplane_slot(slot)],
        }
    }

    /// A route from explicit port segments.
    #[must_use]
    pub fn from_segments(segments: Vec<PortSegment>) -> Self {
        Self { segments }
    }

    /// Whether the route is empty (direct / no routing).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Build an [`EPath`] of just the route's port segments.
    fn to_epath(&self) -> EPath {
        let mut p = EPath::new();
        for seg in &self.segments {
            p = p.port(seg.clone());
        }
        p
    }

    /// Prefix the route's port segments onto `base` (for the connected-class-3 connection path).
    fn prefixed(&self, base: EPath) -> EPath {
        if self.segments.is_empty() {
            return base;
        }
        let mut segs: Vec<_> = self.segments.iter().cloned().map(crate::cip::epath::Segment::Port).collect();
        segs.extend(base.segments().iter().cloned());
        EPath::from_segments(segs)
    }
}

/// Options for [`EipClient::connect`] (§11.2).
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// TCP port (default `44818`).
    pub port: u16,
    /// Optional route path (`None` for cpppo / CompactLogix-direct).
    pub route: Option<RoutePath>,
    /// Deadline for **each phase** of opening a session: the TCP connect, then the RegisterSession
    /// handshake (its request write and its reply read together). Each phase gets the full value.
    pub connect_timeout: Duration,
    /// Per-request deadline (§10.4).
    pub request_timeout: Duration,
    /// Reassembly cap for fragmented reads (default 1 MiB, D-ENIP-12).
    pub max_value_bytes: usize,
    /// Whether to open a connected class-3 path at connect time (§7.6).
    pub connected_messaging: bool,
    /// Consecutive timeouts that declare the session dead (default 3, §10.4).
    pub max_consecutive_timeouts: u32,
    /// The originator vendor id stamped into ForwardOpen (§8.2).
    pub vendor_id: u16,
    /// Class-3 requested packet interval, used for **both** the O→T and T→O RPI of the class-3
    /// ForwardOpen (§7.6). Clamped to `[MIN_REPLY_API, MAX_REPLY_API]` at open time. Only read when
    /// `connected_messaging` is true.
    ///
    /// Together with [`ClientOptions::class3_timeout_multiplier`] this sets the target's inactivity
    /// watchdog on the connection, and therefore the cadence of the keepalive that keeps the
    /// connection off it — the client probes at ¾ of the negotiated window.
    ///
    /// # Keep `request_timeout` well inside a quarter of the window
    ///
    /// The client's idle clock is stamped when a request **completes**, while the target re-arms its
    /// watchdog when a request **arrives**: the client's notion of "idle since" therefore lags the
    /// target's by roughly one request latency, and the ¾ rule leaves only a quarter of the window to
    /// absorb that lag. Keep
    ///
    /// ```text
    /// request_timeout  ≪  (class3_timeout_multiplier × negotiated interval) / 4
    /// ```
    ///
    /// At the defaults there is no contest — a 32 s window leaves 8 s of margin against a 3 s
    /// worst-case request. It becomes reachable two ways: setting a small `class3_rpi`, and a target
    /// that echoes an actual O→T API far below what was requested (the window follows the
    /// **negotiated** value, so a 100 ms echo at ×16 is a 1.6 s window — a quarter of which is
    /// already under the 3 s default `request_timeout`). The client warns once at open when the
    /// derived window lands implausibly low; a window that small means the target claims a watchdog
    /// too tight for the round trips it is answering.
    pub class3_rpi: Duration,
    /// Class-3 connection timeout-multiplier code (§8.2 field 8). Only read when
    /// `connected_messaging` is true.
    ///
    /// This is the other half of the inactivity window (`multiplier × negotiated O→T interval`), so
    /// lowering it tightens the keepalive margin exactly as lowering [`ClientOptions::class3_rpi`]
    /// does — see that field for the `request_timeout` relationship an operator must respect.
    pub class3_timeout_multiplier: crate::cm::TimeoutMultiplier,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            port: crate::encap::DEFAULT_TCP_PORT,
            route: None,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(3),
            max_value_bytes: 1 << 20,
            connected_messaging: false,
            max_consecutive_timeouts: 3,
            vendor_id: 0x1337,
            class3_rpi: Duration::from_secs(2),
            class3_timeout_multiplier: crate::cm::TimeoutMultiplier::X16,
        }
    }
}

struct Inner {
    route: Option<RoutePath>,
    request_timeout: Duration,
    max_value_bytes: usize,
    stats: Arc<SessionStats>,
    connected: Option<ConnectedState>,
}

/// A snapshot of the session's peer-driven counters (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientStats {
    /// Replies discarded for a `sender_context` mismatch (the stale-reply / quarantine counter).
    pub stale_replies: u64,
    /// Requests that hit their deadline.
    pub timeouts: u64,
    /// Connected class-3 replies discarded for a sequence-count mismatch (D-ENIP-5).
    pub connected_seq_mismatches: u64,
    /// Class-3 inactivity keepalives that completed an exchange with the target (§7.6, D-ENIP-18).
    pub keepalives_sent: u64,
}

/// The explicit-messaging client handle (§11.2). Cheap to clone.
#[derive(Clone)]
pub struct EipClient {
    tx: tokio::sync::mpsc::Sender<SessionCommand>,
    inner: Arc<Inner>,
    /// The TCP peer address, captured at [`EipClient::connect`]. Used by the class-1 I/O layer as the
    /// default O→T transmit target (§8.2); `None` for an injected byte-stream fixture.
    pub(crate) peer_addr: Option<SocketAddr>,
    /// The negotiated TLS session facts, set by [`EipClient::connect_tls`] (feature `tls`); `None`
    /// for a plaintext client. Read via [`EipClient::tls_session_info`].
    #[cfg(feature = "tls")]
    pub(crate) tls_info: Option<tls::TlsSessionInfo>,
}

impl EipClient {
    /// Connect to `addr` (host or `host:port`) and open a session (§5.5). Bounds the TCP connect +
    /// RegisterSession by `connect_timeout`.
    pub async fn connect(addr: &str, opts: ClientOptions) -> Result<Self> {
        let target = if addr.contains(':') {
            addr.to_owned()
        } else {
            format!("{addr}:{}", opts.port)
        };
        let connect = TcpStream::connect(target);
        let stream = match tokio::time::timeout(opts.connect_timeout, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(EnipError::Io(e)),
            Err(_elapsed) => return Err(EnipError::Timeout { op: "connect" }),
        };
        stream.set_nodelay(true).ok();
        let peer_addr = stream.peer_addr().ok();
        let mut client = Self::connect_over(stream, opts).await?;
        client.peer_addr = peer_addr;
        Ok(client)
    }

    /// Register a session over an already-connected byte stream and spawn the session actor. This is
    /// the stream-injection entry point: production goes through [`EipClient::connect`]; tests pass a
    /// [`tokio::io::duplex`] half so the actor's correlation/timeout/fragmentation behaviour is proven
    /// without a socket or an embedded server.
    pub async fn connect_over<S>(mut stream: S, opts: ClientOptions) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // RegisterSession handshake (§5.5), synchronous before the actor owns the stream. ONE
        // absolute deadline bounds the whole handshake — write and read alike — so a peer that
        // accepts the TCP connection and then stops reading cannot park us forever on the write.
        let handshake_deadline = deadline_from(opts.connect_timeout);
        let mut reg_data = WireWriter::with_capacity(4);
        reg_data.u16(PROTOCOL_VERSION);
        reg_data.u16(0); // options
        let reg_frame = EncapFrame::new(
            EncapHeader::request(Command::RegisterSession, 0, 0, *b"ECREGIST"),
            reg_data.into_bytes(),
        );
        send_frame_by(&mut stream, &reg_frame, handshake_deadline).await?;

        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();
        let reply =
            recv_frame(&mut stream, &mut buf, &mut codec, handshake_deadline, "register").await?;

        if !matches!(reply.header.command, Command::RegisterSession) {
            return Err(EnipError::ProtocolViolation { detail: "register reply command mismatch" });
        }
        if !reply.header.status.is_ok() {
            return Err(EnipError::Encap(reply.header.status));
        }
        let session_handle = reply.header.session_handle;
        if session_handle == 0 {
            return Err(EnipError::ProtocolViolation { detail: "register assigned session handle 0" });
        }
        // Reply protocol version must be 1 (§5.5).
        let mut vr = WireReader::with_context(&reply.data, "register reply");
        let version = vr.u16().unwrap_or(0);
        if version != PROTOCOL_VERSION {
            return Err(EnipError::Unsupported { what: "encapsulation protocol version" });
        }

        let stats = Arc::new(SessionStats::default());
        let tx = spawn_session(
            stream,
            buf,
            session_handle,
            opts.max_consecutive_timeouts,
            stats.clone(),
        );

        // A provisional (unconnected) handle to run the ForwardOpen over UCMM if requested.
        let provisional = Self {
            tx: tx.clone(),
            inner: Arc::new(Inner {
                route: opts.route.clone(),
                request_timeout: opts.request_timeout,
                max_value_bytes: opts.max_value_bytes,
                stats: stats.clone(),
                connected: None,
            }),
            peer_addr: None,
            #[cfg(feature = "tls")]
            tls_info: None,
        };

        let connected = if opts.connected_messaging {
            Some(provisional.open_class3(&opts).await?)
        } else {
            None
        };

        let client = Self {
            tx,
            inner: Arc::new(Inner {
                route: opts.route,
                request_timeout: opts.request_timeout,
                max_value_bytes: opts.max_value_bytes,
                stats,
                connected,
            }),
            peer_addr: None,
            #[cfg(feature = "tls")]
            tls_info: None,
        };
        // A class-3 connection carries a target-side inactivity watchdog, so the session must keep
        // itself alive (§7.6). The task holds nothing strong — it dies with the client.
        if client.inner.connected.is_some() {
            keepalive::spawn(client.tx.clone(), Arc::downgrade(&client.inner));
        }
        Ok(client)
    }

    /// The `max_value_bytes` reassembly cap (D-ENIP-12).
    pub(crate) fn max_value_bytes(&self) -> usize {
        self.inner.max_value_bytes
    }

    /// The usable request-payload size for write chunking (§7.2). A conservative UCMM ceiling.
    pub(crate) fn max_request_bytes(&self) -> usize {
        480
    }

    /// A snapshot of the peer-driven counters (§10.2).
    #[must_use]
    pub fn stats(&self) -> ClientStats {
        ClientStats {
            stale_replies: self.inner.stats.stale_replies.load(Ordering::Relaxed),
            timeouts: self.inner.stats.timeouts.load(Ordering::Relaxed),
            connected_seq_mismatches: self.inner.stats.connected_seq_mismatches.load(Ordering::Relaxed),
            keepalives_sent: self.inner.stats.keepalives_sent.load(Ordering::Relaxed),
        }
    }

    /// Whether this client sends over a connected class-3 path (§7.6).
    #[must_use]
    pub fn is_connected_messaging(&self) -> bool {
        self.inner.connected.is_some()
    }

    /// Send a CIP Message Router request and return the decoded reply (§7). Routes over the connected
    /// class-3 path when open, else over UCMM (wrapping in Unconnected_Send when a route is set).
    pub(crate) async fn send_cip(&self, mr: MessageRequest, op: &'static str) -> Result<crate::cip::message::MessageReply> {
        if let Some(conn) = &self.inner.connected {
            self.send_connected(conn, mr, op).await
        } else {
            self.send_unconnected(mr, op).await
        }
    }

    /// Run one encapsulation transaction through the session actor.
    ///
    /// The deadline is absolute and computed HERE, before the request is handed to the actor (§10.4),
    /// so every phase the caller waits through — queueing behind another in-flight request, the
    /// actor's write, the actor's read — is charged to the one `request_timeout` budget. Both waits
    /// this side of the actor are bounded: a full command channel cannot park the caller past its
    /// deadline, and neither can an actor that never answers.
    ///
    /// The reply wait is bounded at `deadline + REPLY_BACKSTOP_GRACE` rather than at `deadline`
    /// itself, because the actor — which shares this exact deadline — is the authority on *which*
    /// failure occurred (see [`REPLY_BACKSTOP_GRACE`]). The caller's bound exists only so a wedged or
    /// vanished actor cannot park the caller forever.
    ///
    /// Both caller-side bounds count their elapse as a timeout (§10.2, never silent): the actor
    /// never saw a request that expired queueing for it, and by definition produced no verdict for
    /// one that tripped the backstop, so neither would otherwise appear on `stats().timeouts`.
    async fn transaction(&self, command: Command, data: Bytes, op: &'static str) -> Result<EncapFrame> {
        let deadline = deadline_from(self.inner.request_timeout);
        let (reply_tx, reply_rx) = oneshot::channel();
        let t = Transaction {
            command,
            data,
            deadline,
            reply_tx,
        };
        match tokio::time::timeout_at(deadline, self.tx.send(SessionCommand::Transact(t))).await {
            Ok(Ok(())) => {}
            Ok(Err(_send_failed)) => return Err(EnipError::Closed),
            Err(_elapsed) => {
                // The budget was spent queueing for the actor, so the actor never saw this request
                // and cannot count it — but no timeout path is silent (§10.2).
                self.inner.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(EnipError::Timeout { op });
            }
        }
        let backstop = deadline
            .checked_add(REPLY_BACKSTOP_GRACE)
            .unwrap_or(deadline);
        match tokio::time::timeout_at(backstop, reply_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_closed)) => Err(EnipError::Closed),
            Err(_elapsed) => {
                // The actor is wedged or gone: it owed a verdict by `deadline` and produced none, so
                // the backstop fires and — like every other timeout — is counted (§10.2).
                self.inner.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(EnipError::Timeout { op })
            }
        }
    }

    /// UCMM (unconnected) send (§7.1) — direct, or wrapped in Unconnected_Send when routed.
    async fn send_unconnected(&self, mr: MessageRequest, op: &'static str) -> Result<crate::cip::message::MessageReply> {
        let outer = match &self.inner.route {
            Some(route) if !route.is_empty() => wrap_unconnected_send(&mr, route)?,
            _ => mr,
        };
        let mr_bytes = outer.encode()?;
        let cpf = Cpf::from_items(vec![CpfItem::null_address(), CpfItem::unconnected_data(mr_bytes)]);
        let data = encap_data_with_cpf(&cpf)?;
        let frame = self.transaction(Command::SendRRData, data, op).await?;
        parse_explicit_reply(&frame)
    }

    /// Read the device identity over the session (§5.3, §11.2) — a ListIdentity command.
    pub async fn identity(&self) -> Result<DeviceIdentity> {
        let frame = self.transaction(Command::ListIdentity, Bytes::new(), "identity").await?;
        if !frame.header.status.is_ok() {
            return Err(EnipError::Encap(frame.header.status));
        }
        DeviceIdentity::parse_reply(&frame.data).map_err(EnipError::Malformed)
    }

    /// Gracefully close the session (§11.1): ForwardClose any class-3 connection (best-effort), then
    /// UnRegisterSession and drop the socket.
    ///
    /// Every wait is bounded. The ForwardClose rides [`EipClient::transaction`] and is therefore
    /// capped by `request_timeout`; the actor hand-off and its done-ack are capped together by
    /// [`CLOSE_HANDOFF_DEADLINE`]. If the actor is wedged (parked mid-read on a silent peer) the
    /// deadline elapses and `close()` returns anyway — the courtesy UnRegisterSession is best-effort
    /// and shutdown must not hang on a peer's behaviour.
    pub async fn close(&self) {
        if let Some(conn) = &self.inner.connected {
            let _ = self.forward_close(conn).await;
        }
        let (done_tx, done_rx) = oneshot::channel();
        let _ = tokio::time::timeout(CLOSE_HANDOFF_DEADLINE, async {
            if self.tx.send(SessionCommand::Unregister { done_tx }).await.is_ok() {
                let _ = done_rx.await;
            }
        })
        .await;
    }
}

/// Wrap a Message Router request in Unconnected_Send (`0x52`) to the Connection Manager, appending
/// the route path (§7.1).
fn wrap_unconnected_send(inner: &MessageRequest, route: &RoutePath) -> Result<MessageRequest> {
    let emb = inner.encode()?;
    let emb_len = u16::try_from(emb.len()).map_err(|_| EnipError::TooLarge { limit: u16::MAX as usize })?;
    let route_bytes = route.to_epath().encode()?;
    let words = route_bytes.len().checked_div(2).unwrap_or(0);
    let route_words = u8::try_from(words).map_err(|_| EnipError::TooLarge { limit: 255 })?;

    let mut data = WireWriter::new();
    data.u8(0x03); // priority / time_tick
    data.u8(0xFA); // timeout ticks
    data.u16(emb_len);
    data.put_slice(&emb);
    if emb.len() & 1 == 1 {
        data.u8(0); // pad the embedded message to an even boundary
    }
    data.u8(route_words);
    data.u8(0); // reserved
    data.put_slice(&route_bytes);
    Ok(MessageRequest::new(
        crate::cm::service::UNCONNECTED_SEND,
        connection_manager_path(),
        data.into_bytes(),
    ))
}

/// Build the encapsulation data portion for `SendRRData`/`SendUnitData`: interface handle `u32 = 0`,
/// timeout `u16 = 0`, then the CPF (§5.2).
fn encap_data_with_cpf(cpf: &Cpf) -> Result<Bytes> {
    let cpf_bytes = cpf.encode().map_err(EnipError::Malformed)?;
    let mut w = WireWriter::with_capacity(cpf_bytes.len().saturating_add(6));
    w.u32(0); // interface handle
    w.u16(0); // timeout
    w.put_slice(&cpf_bytes);
    Ok(w.into_bytes())
}

/// Decode a UCMM reply frame into a Message Router reply (§5.2, invariant 6 of §4).
fn parse_explicit_reply(frame: &EncapFrame) -> Result<crate::cip::message::MessageReply> {
    if !frame.header.status.is_ok() {
        return Err(EnipError::Encap(frame.header.status));
    }
    let mut r = WireReader::with_context(&frame.data, "sendrrdata reply");
    let _interface_handle = r.u32()?;
    let _timeout = r.u16()?;
    let cpf = Cpf::decode(r.take_rest()).map_err(EnipError::Malformed)?;
    let mr_bytes = cpf.expect_explicit_data().map_err(EnipError::Malformed)?;
    crate::cip::message::MessageReply::decode(mr_bytes).map_err(EnipError::Malformed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn unconnected_send_wrapping_shape() {
        // Embedded Read Tag for "A" (1 element): 0x4C, path 1 word (symbol "A" padded), count 1.
        let tag = crate::cip::epath::TagAddress::parse("AA").unwrap();
        let mut cnt = WireWriter::new();
        cnt.u16(1);
        let inner = MessageRequest::new(0x4C, tag.into_path(), cnt.into_bytes());
        let route = RoutePath::backplane_slot(0);
        let wrapped = wrap_unconnected_send(&inner, &route).unwrap();
        let bytes = wrapped.encode().unwrap();
        // Outer service 0x52 to CM path [0x20 0x06 0x24 0x01].
        assert_eq!(bytes[0], 0x52);
        assert_eq!(&bytes[2..6], &[0x20, 0x06, 0x24, 0x01]);
        // Then priority 0x03, timeout 0xFA, embedded size.
        assert_eq!(bytes[6], 0x03);
        assert_eq!(bytes[7], 0xFA);
    }

    /// §10.2/§10.4 — the caller-side **reply backstop**, and that it is not silent. An actor that
    /// takes the hand-off and then never answers is modelled by a command receiver nobody polls: the
    /// channel has capacity, so the enqueue succeeds and the caller ends up on the backstop. The
    /// wait must end one `REPLY_BACKSTOP_GRACE` past the deadline (never at the deadline itself —
    /// that instant belongs to the actor's own verdict) with a counted `Timeout`.
    #[tokio::test(start_paused = true)]
    async fn reply_backstop_fires_past_the_deadline_and_is_counted() {
        let (tx, _rx) = tokio::sync::mpsc::channel(32); // held open, never polled
        let request_timeout = Duration::from_millis(200);
        let client = EipClient {
            tx,
            inner: Arc::new(Inner {
                route: None,
                request_timeout,
                max_value_bytes: 1 << 20,
                stats: Arc::new(SessionStats::default()),
                connected: None,
            }),
            peer_addr: None,
            #[cfg(feature = "tls")]
            tls_info: None,
        };

        let started = tokio::time::Instant::now();
        let r = client
            .transaction(Command::ListIdentity, Bytes::new(), "identity")
            .await;
        assert!(matches!(r, Err(EnipError::Timeout { op: "identity" })), "{r:?}");
        assert!(
            started.elapsed() >= request_timeout + REPLY_BACKSTOP_GRACE,
            "the backstop must fire strictly after the deadline, not on it"
        );
        assert_eq!(client.stats().timeouts, 1, "the backstop is never silent");
    }

    #[test]
    fn default_options() {
        let o = ClientOptions::default();
        assert_eq!(o.port, 44818);
        assert_eq!(o.max_value_bytes, 1 << 20);
        assert_eq!(o.max_consecutive_timeouts, 3);
        assert!(!o.connected_messaging);
        // §7.6 — the class-3 knobs default to the values the crate hard-coded before they became
        // options, so a caller that changes nothing gets a byte-identical ForwardOpen.
        assert_eq!(o.class3_rpi, Duration::from_secs(2));
        assert_eq!(o.class3_timeout_multiplier, crate::cm::TimeoutMultiplier::X16);
        assert_eq!(
            o.class3_rpi.as_micros(),
            2_000_000,
            "the requested packet interval is what lands on the wire, in µs"
        );
    }
}
