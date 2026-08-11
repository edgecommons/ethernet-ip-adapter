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

/// The correlation context stamped on the RegisterSession request, and required back on its reply
/// (§5.5, D-ENIP-21).
///
/// The handshake runs *before* the actor owns the stream, so the session-scoped monotonic context of
/// §10.3 does not exist yet — this fixed 8-byte tag stands in for it. Requiring the echo is what
/// makes the handshake correlated at all: without it, any RegisterSession-shaped frame already
/// sitting on the stream (a reply to somebody else's request on a proxied/multiplexed path, or a
/// peer that simply speaks first) could be adopted as *our* session.
pub(crate) const REGISTER_CONTEXT: [u8; 8] = *b"ECREGIST";

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
        let mut segs: Vec<_> = self
            .segments
            .iter()
            .cloned()
            .map(crate::cip::epath::Segment::Port)
            .collect();
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
    /// Deadline for opening a session **in total** (default 5 s): the TCP connect and everything
    /// [`EipClient::connect_over`] then does — the RegisterSession handshake (request write and
    /// reply read alike) plus, when `connected_messaging` is set, the class-3 ForwardOpen — share
    /// this one budget, stamped before the connect. [`EipClient::connect_tls`] applies it the same
    /// way across the TCP connect and the TLS handshake.
    ///
    /// Reached directly, [`EipClient::connect_over`] bounds its own work by the full value: it is a
    /// public entry point handed an already-open stream, so there is no earlier phase to charge.
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
    /// Replies discarded because the encapsulation `options` field was not 0 (§5.1, D-ENIP-21).
    pub discarded_options: u64,
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
    /// Connect to `addr` (host or `host:port`) and open a session (§5.5). **`connect_timeout` is
    /// one budget for the whole open**, not one per phase: the clock starts before the TCP connect
    /// and the RegisterSession handshake spends whatever the connect left of it.
    ///
    /// Stamping a fresh deadline for the handshake made the crate-level worst case ~2 ×
    /// `connect_timeout` — a caller that asked for a 5 s bound on opening a session could wait 10 s
    /// against a peer that is slow to complete the TCP handshake and then silent. This mirrors
    /// [`EipClient::connect_tls`], which has always run on one budget.
    pub async fn connect(addr: &str, opts: ClientOptions) -> Result<Self> {
        let target = if addr.contains(':') {
            addr.to_owned()
        } else {
            format!("{addr}:{}", opts.port)
        };
        let started = std::time::Instant::now();
        let connect = TcpStream::connect(target);
        let stream = match tokio::time::timeout(opts.connect_timeout, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(EnipError::Io(e)),
            Err(_elapsed) => return Err(EnipError::Timeout { op: "connect" }),
        };
        stream.set_nodelay(true).ok();
        let peer_addr = stream.peer_addr().ok();
        // The handshake spends the remainder of the same budget. Floored at 1 ms rather than 0 so a
        // connect that consumed the whole allowance still *attempts* the handshake and fails on its
        // own deadline, instead of returning a timeout for work never started.
        let remaining = opts
            .connect_timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(1));
        let mut client = tokio::time::timeout(remaining, Self::connect_over(stream, opts))
            .await
            .map_err(|_elapsed| EnipError::Timeout { op: "register" })??;
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
            EncapHeader::request(Command::RegisterSession, 0, 0, REGISTER_CONTEXT),
            reg_data.into_bytes(),
        );
        send_frame_by(&mut stream, &reg_frame, handshake_deadline).await?;

        let mut codec = EncapCodec::new();
        let mut buf = BytesMut::new();
        let reply = recv_frame(
            &mut stream,
            &mut buf,
            &mut codec,
            handshake_deadline,
            "register",
        )
        .await?;

        // §5.5 (D-ENIP-21) — the RegisterSession reply validation list, in order: context echo,
        // command echo, header options 0, status ok, non-zero handle, then the whole 4-byte
        // command-specific body (protocol version 1, session options 0, and nothing after it).
        //
        // The **context echo comes first**: a frame that is not even our reply must not be
        // diagnosed by its other fields, and every check below is only meaningful once the frame
        // claims to answer the request we just wrote.
        if reply.header.sender_context != REGISTER_CONTEXT {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply context mismatch",
            });
        }
        if !matches!(reply.header.command, Command::RegisterSession) {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply command mismatch",
            });
        }
        // Deliberately asymmetric with the session actor, which discards a non-zero-`options` frame
        // and keeps waiting (§5.1): pre-actor there is exactly one expected frame on the stream, so
        // looping over discards during a handshake buys nothing against a peer this broken — and
        // adopting a session from it would be worse.
        if reply.header.options != 0 {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply carries non-zero options",
            });
        }
        if !reply.header.status.is_ok() {
            return Err(EnipError::Encap(reply.header.status));
        }
        let session_handle = reply.header.session_handle;
        if session_handle == 0 {
            return Err(EnipError::ProtocolViolation {
                detail: "register assigned session handle 0",
            });
        }
        // The command-specific body is validated WHOLE, not just its first word (§5.5): the reply
        // carries back the same four bytes the request sent — `u16 protocol_version = 1`,
        // `u16 options = 0` — and nothing else. Reading only the version accepted a two-byte
        // `01 00` reply, in which the required options word is simply absent, and accepted any
        // amount of trailing data after a well-formed one; both are frames the encapsulation layer
        // is entitled to reject, and a peer that emits either is not the peer §5.5 describes.
        //
        // **The options word must be 0**, the same value the request carries. ODVA Vol 2 defines it
        // as the RegisterSession session-options field with all bits reserved and no defined
        // meaning, so a target has nothing it may legitimately say there; a non-zero word means the
        // peer is either negotiating an option we never offered or overlaying a different structure
        // on the same four bytes. Neither is a session we can reason about, and the header-level
        // `options` refusal directly above is the same rule one layer out.
        //
        // Variant split, deliberately: the **version** is `Unsupported` — the frame is exactly the
        // shape §5.5 defines and the peer is speaking a protocol generation this crate does not
        // implement, which is also how the equivalent encapsulation status `0x0069`
        // (`UnsupportedProtocolVersion`) surfaces, so both routes to "wrong generation" read the
        // same to a caller. Everything else here is `ProtocolViolation` — a body of the wrong
        // length, or a reserved field carrying bits, is not a protocol we could support at some
        // other version, it is a frame that does not conform. A reader can therefore tell
        // "understood, cannot speak it" from "malformed" by the variant alone; both are
        // non-transient, so neither is retried behind the adapter's back.
        let mut vr = WireReader::with_context(&reply.data, "register reply");
        let Ok(version) = vr.u16() else {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply body ends before the protocol version",
            });
        };
        if version != PROTOCOL_VERSION {
            return Err(EnipError::Unsupported {
                what: "encapsulation protocol version",
            });
        }
        let Ok(session_options) = vr.u16() else {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply body ends before the session options word",
            });
        };
        if session_options != 0 {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply body carries non-zero session options",
            });
        }
        if vr.expect_end().is_err() {
            return Err(EnipError::ProtocolViolation {
                detail: "register reply body has trailing bytes after the 4-byte payload",
            });
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
            connected_seq_mismatches: self
                .inner
                .stats
                .connected_seq_mismatches
                .load(Ordering::Relaxed),
            keepalives_sent: self.inner.stats.keepalives_sent.load(Ordering::Relaxed),
            discarded_options: self.inner.stats.discarded_options.load(Ordering::Relaxed),
        }
    }

    /// Whether this client sends over a connected class-3 path (§7.6).
    #[must_use]
    pub fn is_connected_messaging(&self) -> bool {
        self.inner.connected.is_some()
    }

    /// Send a CIP Message Router request and return the decoded reply (§7). Routes over the connected
    /// class-3 path when open, else over UCMM (wrapping in Unconnected_Send when a route is set).
    pub(crate) async fn send_cip(
        &self,
        mr: MessageRequest,
        op: &'static str,
    ) -> Result<crate::cip::message::MessageReply> {
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
    async fn transaction(
        &self,
        command: Command,
        data: Bytes,
        op: &'static str,
    ) -> Result<EncapFrame> {
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
    async fn send_unconnected(
        &self,
        mr: MessageRequest,
        op: &'static str,
    ) -> Result<crate::cip::message::MessageReply> {
        let outer = match &self.inner.route {
            Some(route) if !route.is_empty() => wrap_unconnected_send(&mr, route)?,
            _ => mr,
        };
        let mr_bytes = outer.encode()?;
        let cpf = Cpf::from_items(vec![
            CpfItem::null_address(),
            CpfItem::unconnected_data(mr_bytes),
        ]);
        let data = encap_data_with_cpf(&cpf)?;
        let frame = self.transaction(Command::SendRRData, data, op).await?;
        parse_explicit_reply(&frame)
    }

    /// Read the device identity over the session (§5.3, §11.2) — a ListIdentity command.
    pub async fn identity(&self) -> Result<DeviceIdentity> {
        let frame = self
            .transaction(Command::ListIdentity, Bytes::new(), "identity")
            .await?;
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
            if self
                .tx
                .send(SessionCommand::Unregister { done_tx })
                .await
                .is_ok()
            {
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
    let emb_len = u16::try_from(emb.len()).map_err(|_| EnipError::TooLarge {
        limit: u16::MAX as usize,
    })?;
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
    // §5.2 (D-ENIP-21) — the CIP interface handle is 0 by Vol 2. A non-zero value means the peer is
    // addressing some other interface, i.e. speaking something that is not the CIP encapsulation we
    // asked for; the reply's contents cannot be trusted to be a CIP Message Router reply at all.
    // `ProtocolViolation` is non-transient by design: a peer that mislabels its interface will keep
    // doing so, so surfacing beats hammering.
    let interface_handle = r.u32()?;
    if interface_handle != 0 {
        return Err(EnipError::ProtocolViolation {
            detail: "non-zero interface handle in SendRRData reply",
        });
    }
    let _timeout = r.u16()?;
    let cpf = Cpf::decode(r.take_rest()).map_err(EnipError::Malformed)?;
    let mr_bytes = cpf.expect_explicit_data().map_err(EnipError::Malformed)?;
    crate::cip::message::MessageReply::decode(mr_bytes).map_err(EnipError::Malformed)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
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
        assert!(
            matches!(r, Err(EnipError::Timeout { op: "identity" })),
            "{r:?}"
        );
        assert!(
            started.elapsed() >= request_timeout + REPLY_BACKSTOP_GRACE,
            "the backstop must fire strictly after the deadline, not on it"
        );
        assert_eq!(client.stats().timeouts, 1, "the backstop is never silent");
    }

    /// **D-ENIP-25 / §5.5.** `connect_timeout` is one budget for the whole open, so a TCP connect
    /// that is slow but *successful* leaves the RegisterSession handshake only the remainder —
    /// never a fresh full allowance on top.
    ///
    /// Making the connect phase slow deterministically is the whole difficulty: a loopback TCP
    /// handshake is instant, and nothing portable delays it. The lever used here is the resolver.
    /// A target that is **not** a literal socket address (`localhost:<port>`, not `127.0.0.1:<port>`)
    /// sends `TcpStream::connect` through `getaddrinfo` on tokio's blocking pool, so a runtime
    /// built with exactly one blocking thread — already occupied by a sleeper — queues the lookup
    /// behind it. The connect then genuinely takes `STALL` before succeeding against a listener
    /// that accepts and never speaks EtherNet/IP, and the handshake is left to run out whatever is
    /// left of `BUDGET`.
    ///
    /// Two budgets: `STALL + BUDGET` = 3000 ms. One budget: `BUDGET` = 2000 ms. `CEILING` sits
    /// between them with 500 ms of slack either way. The margins are deliberately wide, because the
    /// test shares a machine with the rest of the suite (the TLS tests mint certificates): `BUDGET`
    /// must leave the resolver-plus-connect far more time than it needs once the stall releases, or
    /// a loaded runner turns a scheduling delay into a *connect-phase* timeout that proves nothing —
    /// which is why the accept is asserted before the elapsed time is.
    #[test]
    fn plaintext_connect_spends_one_budget_across_the_tcp_connect_and_the_handshake() {
        const STALL: Duration = Duration::from_millis(1_000);
        const BUDGET: Duration = Duration::from_millis(2_000);
        const CEILING: Duration = Duration::from_millis(2_500);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            // Exactly one blocking thread, so the sleeper below owns the pool and the resolver
            // queues behind it.
            .max_blocking_threads(1)
            .build()
            .unwrap();

        rt.block_on(async {
            // A plain TCP listener — it accepts and then says nothing. Not an EtherNet/IP peer
            // (D-ENIP-14): the client is the only implementation on the socket.
            //
            // Bound by NAME, not by literal address, so it lands on whichever address `localhost`
            // resolves to *first* — the same one `TcpStream::connect` will try first. Binding
            // `127.0.0.1` on a host whose `localhost` leads with `::1` would leave the first
            // attempt to fail, and how long that failure takes is a per-OS variable this test must
            // not depend on.
            let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen = accepted.clone();
            let server = tokio::spawn(async move {
                // Hold the accepted stream for the rest of the test — dropping it would give the
                // client an EOF (a framing error) instead of the silence under test.
                if let Ok((stream, _)) = listener.accept().await {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    drop(stream);
                }
            });

            // Occupy the single blocking thread. The DNS lookup `TcpStream::connect` needs cannot
            // start until this returns.
            let sleeper = tokio::task::spawn_blocking(|| std::thread::sleep(STALL));

            let opts = ClientOptions {
                connect_timeout: BUDGET,
                ..ClientOptions::default()
            };
            let started = std::time::Instant::now();
            let result = EipClient::connect(&format!("localhost:{port}"), opts).await;
            let elapsed = started.elapsed();

            match result {
                Err(EnipError::Timeout { .. }) => {}
                Err(other) => {
                    panic!("a peer that accepts and never answers must time out, got {other:?} after {elapsed:?}")
                }
                Ok(_client) => panic!("a peer that never answers must not yield a session"),
            }
            assert!(
                accepted.load(std::sync::atomic::Ordering::SeqCst),
                "the TCP connect must have SUCCEEDED — otherwise the timeout came from the connect \
                 phase and says nothing about how the two phases share the budget \
                 (elapsed {elapsed:?})"
            );
            assert!(
                elapsed >= STALL,
                "the connect phase really was delayed (elapsed {elapsed:?}, stall {STALL:?})"
            );
            assert!(
                elapsed < CEILING,
                "opening a session must cost ONE connect_timeout, not one per phase: \
                 elapsed {elapsed:?} against a {BUDGET:?} budget after a {STALL:?} connect"
            );

            server.abort();
            sleeper.await.unwrap();
        });
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
        assert_eq!(
            o.class3_timeout_multiplier,
            crate::cm::TimeoutMultiplier::X16
        );
        assert_eq!(
            o.class3_rpi.as_micros(),
            2_000_000,
            "the requested packet interval is what lands on the wire, in µs"
        );
    }
}
