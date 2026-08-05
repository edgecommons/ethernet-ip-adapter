//! The session actor (PROTOCOL-DESIGN §11.1, §10.3–§10.4).
//!
//! One task per [`crate::client::EipClient`] owns the byte stream (any `AsyncRead + AsyncWrite`, so a
//! real `TcpStream` in production and an in-memory [`tokio::io::duplex`] pair in tests — there is no
//! embedded server). It enforces:
//!
//! * **One in-flight request** with `sender_context` correlation (§10.3): the context is a
//!   session-scoped monotonic `u64`. A reply whose context ≠ the outstanding request is a *stale
//!   reply* from a timed-out predecessor — discarded, counted (`stale_replies`), never delivered.
//! * **Header-complete reply matching** (§10.3, §5.2): a reply answers the outstanding request only
//!   when its `sender_context`, its encapsulation command, and — for the session-scoped commands
//!   `SendRRData`/`SendUnitData` — its session handle all agree with what we sent. The discovery
//!   commands (`ListIdentity`/`ListServices`/`ListInterfaces`) are sessionless-capable per §5.2, so
//!   their replies are matched on context + command only (live targets commonly answer them with
//!   handle 0). Everything that fails a check is counted and discarded, never delivered
//!   ([`match_reply`]).
//! * **Per-request deadlines** (§10.4): the deadline is **absolute** and computed at *enqueue* time in
//!   [`crate::client::EipClient::transaction`], so queue wait counts against the caller's budget and
//!   every phase — actor hand-off, frame write, reply read — is bounded by the same instant. On expiry
//!   the caller gets `Err(Timeout)` immediately and the timed-out context is simply abandoned. Because
//!   contexts never repeat and TCP preserves order, a late reply bearing that context is dropped by
//!   the correlation rule — it can never answer a newer request (the *stale-reply quarantine*).
//! * **Dequeue triage** ([`preflight`]): a transaction whose caller has already gone away is skipped
//!   entirely (no stream I/O, no context consumed); one whose deadline elapsed while it sat in the
//!   queue is completed `Err(Timeout)` without touching the stream, and — because queue backlog is
//!   *not* evidence of peer silence — without advancing the consecutive-timeout kill counter.
//! * **Liveness**: three consecutive read timeouts, a transport error, or EOF ⇒ `ConnectionLost`; the
//!   actor exits and every pending/subsequent request completes `Err`.
//!
//! Cancel-safety, and why the two directions differ: the reader keeps a persistent [`BytesMut`] and
//! decodes with [`EncapCodec`], so a deadline that cancels an in-flight `read_buf` leaves the
//! already-received bytes in the buffer and framing never desynchronises across a timeout. The
//! **write** side has no such recovery. Cancelling `write_all` at a deadline may leave a *partial*
//! encapsulation frame already flushed to the peer: the target will then read our 24-byte header's
//! declared length across whatever bytes follow, so the byte stream's framing is desynchronised and no
//! later request/reply boundary on that connection can be trusted. A write that hits its deadline is
//! therefore **not** a recoverable per-request timeout — it is reported as
//! `ConnectionLost { context: "send deadline elapsed mid-frame" }` (never `Timeout`) and the actor
//! dies, so the adapter reconnects onto a fresh stream. Sever, do not quarantine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Decoder;

use crate::encap::codec::EncapCodec;
use crate::encap::{Command, EncapFrame, EncapHeader};
use crate::error::{EnipError, Result};

/// Bounds the best-effort UnRegisterSession write during shutdown (§10.4). §5.2 defines no reply to
/// UnRegisterSession, so the write is fire-and-forget — but it must never wedge the actor's exit
/// against a peer that has stopped reading.
pub(crate) const UNREGISTER_WRITE_DEADLINE: Duration = Duration::from_millis(500);

/// Peer-driven counters exposed on the client handle (§10.2). Never silent: every discarded reply is
/// counted so the adapter can alarm on a noisy/hostile peer without the crate knowing what an alarm
/// is.
#[derive(Debug, Default)]
pub(crate) struct SessionStats {
    /// Replies discarded because their `sender_context` did not match the outstanding request
    /// (§10.3) — the stale-reply / quarantine counter.
    pub stale_replies: AtomicU64,
    /// Requests that hit their deadline (§10.4).
    pub timeouts: AtomicU64,
    /// Connected class-3 replies discarded because the connected-data sequence count did not match
    /// (D-ENIP-5).
    pub connected_seq_mismatches: AtomicU64,
    /// Class-3 inactivity keepalives that completed an exchange with the target (§7.6, D-ENIP-18) —
    /// the observable evidence that the session is feeding the target's connection watchdog. A
    /// keepalive whose reply carried a CIP error still counts: the exchange flowed.
    pub keepalives_sent: AtomicU64,
}

/// A single request/reply transaction for the actor to run.
pub(crate) struct Transaction {
    /// The encapsulation command (`SendRRData` / `SendUnitData` / …).
    pub command: Command,
    /// The encapsulation data portion (interface-handle/timeout prefix + CPF, already built).
    pub data: Bytes,
    /// The **absolute** per-request deadline (§10.4), computed at *enqueue* time in
    /// [`crate::client::EipClient::transaction`] — so the time this transaction spends waiting behind
    /// another in the actor's queue counts against the caller's budget, and the hand-off, the write,
    /// and the read are all bounded by the same instant.
    pub deadline: tokio::time::Instant,
    /// Where the reply frame (or error) is delivered.
    pub reply_tx: oneshot::Sender<Result<EncapFrame>>,
}

/// A command sent to the session actor.
pub(crate) enum SessionCommand {
    /// Run a request/reply transaction.
    Transact(Transaction),
    /// Send UnRegisterSession (no reply) and shut the actor down.
    Unregister {
        /// Signalled once the UnRegisterSession has been written and the socket dropped.
        done_tx: oneshot::Sender<()>,
    },
}

/// The outcome of one bounded read attempt.
enum ReadOutcome {
    /// A full frame decoded.
    Frame(EncapFrame),
    /// The stream reached EOF.
    Eof,
    /// The deadline elapsed before a full frame arrived.
    TimedOut,
    /// The stream or framing broke (I/O error or malformed length).
    Broken(EnipError),
}

/// Write one encapsulation frame and flush it.
///
/// **Unbounded by construction** — the `write_all` inside is the raw primitive. Every call site wraps
/// it in `tokio::time::timeout_at` (see [`send_frame_by`], [`SessionActor::transact`], and
/// [`SessionActor::send_unregister`]): a peer that stops reading must never wedge the actor. A write
/// cancelled by such a deadline desynchronises framing, so its callers sever the session rather than
/// retry (module docs).
pub(crate) async fn send_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &EncapFrame,
) -> Result<()> {
    let bytes = frame.encode().map_err(EnipError::Malformed)?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Write one encapsulation frame by an **absolute** deadline. On elapse the frame may be partially
/// flushed, so the stream is unusable: the failure is `ConnectionLost`, never `Timeout` (module docs).
pub(crate) async fn send_frame_by<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &EncapFrame,
    deadline: tokio::time::Instant,
) -> Result<()> {
    match tokio::time::timeout_at(deadline, send_frame(stream, frame)).await {
        Ok(res) => res,
        Err(_elapsed) => Err(EnipError::ConnectionLost {
            context: "send deadline elapsed mid-frame",
        }),
    }
}

/// What we sent, and therefore what a reply must echo back to be *ours* (§10.3, §5.2).
pub(crate) struct ReplyExpectation {
    /// The encapsulation command of the outstanding request.
    pub command: Command,
    /// Our registered session handle (§5.5).
    pub session_handle: u32,
    /// The outstanding request's correlation context.
    pub context: [u8; 8],
}

/// The verdict on one received reply header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyMatch {
    /// The reply answers the outstanding request — deliver it.
    Match,
    /// A different (or never-issued) `sender_context`: a stale reply from a timed-out predecessor or a
    /// noisy peer. Discard, count, keep waiting (§10.3 quarantine).
    StaleContext,
    /// Our context, but a header field a compliant target must echo does not agree. Discard, count,
    /// and log loudly — this is a peer defect, not ordinary staleness. The payload names the field.
    HeaderMismatch(&'static str),
}

/// Whether `command` may be answered without our session handle (§5.2). The discovery commands are
/// *sessionless-capable* — they are defined over an unregistered connection too, and live targets
/// commonly answer them with a zero handle even inside a registered session — so their replies are
/// matched on context + command only. Everything else must carry the handle we registered.
fn session_handle_exempt(command: Command) -> bool {
    matches!(
        command,
        Command::ListIdentity | Command::ListServices | Command::ListInterfaces
    )
}

/// Match a received reply header against the outstanding request (§10.3, §5.2).
///
/// The context is checked first: a foreign context is ordinary staleness and says nothing about the
/// rest of the header. Only once the reply claims to be *ours* do the echoed header fields become
/// evidence — the command echo is required of every reply, the session handle of every
/// non-[`session_handle_exempt`] one.
pub(crate) fn match_reply(expected: &ReplyExpectation, header: &EncapHeader) -> ReplyMatch {
    if header.sender_context != expected.context {
        return ReplyMatch::StaleContext;
    }
    if header.command != expected.command {
        return ReplyMatch::HeaderMismatch("command");
    }
    if !session_handle_exempt(expected.command) && header.session_handle != expected.session_handle {
        return ReplyMatch::HeaderMismatch("session handle");
    }
    ReplyMatch::Match
}

/// The dequeue-time triage verdict for a queued transaction (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Preflight {
    /// Still wanted and still in budget — run it.
    Run,
    /// The deadline elapsed while it waited in the queue: complete `Err(Timeout)` without touching the
    /// stream. Queue backlog is not evidence of peer silence, so it must not advance the
    /// consecutive-timeout kill counter.
    Expired,
    /// The caller dropped its receiver: skip entirely — no stream I/O, no correlation context burned.
    Abandoned,
}

/// Triage a transaction at dequeue time. `Abandoned` wins over `Expired`: if nobody is waiting for
/// the answer there is nothing to report, and skipping costs neither a context nor a wire round-trip.
pub(crate) fn preflight(
    deadline: tokio::time::Instant,
    reply_closed: bool,
    now: tokio::time::Instant,
) -> Preflight {
    if reply_closed {
        return Preflight::Abandoned;
    }
    if deadline <= now {
        return Preflight::Expired;
    }
    Preflight::Run
}

/// Read one frame by an **absolute** deadline, decoding from the persistent buffer first
/// (cancel-safe). The deadline is absolute so the whole call is bounded even across several stale
/// frames — a peer cannot extend a request by dribbling replies (§10.4).
async fn read_outcome<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    codec: &mut EncapCodec,
    deadline: tokio::time::Instant,
) -> ReadOutcome {
    loop {
        match codec.decode(buf) {
            Ok(Some(frame)) => return ReadOutcome::Frame(frame),
            Ok(None) => {}
            Err(e) => return ReadOutcome::Broken(e),
        }
        match tokio::time::timeout_at(deadline, stream.read_buf(buf)).await {
            Ok(Ok(0)) => {
                return match codec.decode_eof(buf) {
                    Ok(Some(frame)) => ReadOutcome::Frame(frame),
                    Ok(None) => ReadOutcome::Eof,
                    Err(e) => ReadOutcome::Broken(e),
                };
            }
            Ok(Ok(_n)) => continue,
            Ok(Err(e)) => return ReadOutcome::Broken(EnipError::Io(e)),
            Err(_elapsed) => return ReadOutcome::TimedOut,
        }
    }
}

/// Compute an absolute deadline `now + dur`.
///
/// An unrepresentable sum falls back **far into the future**, never to `now`. A caller that sets
/// `request_timeout`/`connect_timeout` to something enormous (`Duration::MAX`) means "effectively no
/// timeout"; saturating to `now` would invert that into "every call has already expired" — and since
/// the same deadline bounds the enqueue, the write, and the handshake, one overflowed value would
/// fail every one of them instantly. A year is beyond any real session's life, so it is
/// indistinguishable from "no timeout" while keeping the instant representable.
pub(crate) fn deadline_from(dur: Duration) -> tokio::time::Instant {
    /// The far-future fallback for a deadline that cannot be represented (one year).
    const FAR_FUTURE: Duration = Duration::from_secs(31_536_000);
    let now = tokio::time::Instant::now();
    now.checked_add(dur)
        .or_else(|| now.checked_add(FAR_FUTURE))
        .unwrap_or(now)
}

/// Read one frame by an **absolute** deadline, mapping non-frame outcomes to errors — the handshake
/// helper used by [`crate::client::EipClient::connect_over`] before the actor is spawned. Taking the
/// deadline (not a duration) lets the caller bound the write and the read of one handshake with a
/// single instant.
pub(crate) async fn recv_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    codec: &mut EncapCodec,
    deadline: tokio::time::Instant,
    op: &'static str,
) -> Result<EncapFrame> {
    match read_outcome(stream, buf, codec, deadline).await {
        ReadOutcome::Frame(frame) => Ok(frame),
        ReadOutcome::Eof => Err(EnipError::ConnectionLost { context: "eof during handshake" }),
        ReadOutcome::TimedOut => Err(EnipError::Timeout { op }),
        ReadOutcome::Broken(e) => Err(e),
    }
}

/// The session actor state.
struct SessionActor<S> {
    stream: S,
    buf: BytesMut,
    codec: EncapCodec,
    session_handle: u32,
    next_context: u64,
    consecutive_timeouts: u32,
    max_consecutive_timeouts: u32,
    stats: Arc<SessionStats>,
}

impl<S> SessionActor<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// The next correlation context — a session-scoped monotonic `u64` that never repeats (§10.3).
    fn next_context(&mut self) -> [u8; 8] {
        self.next_context = self.next_context.wrapping_add(1);
        self.next_context.to_le_bytes()
    }

    /// The actor loop: process one command at a time (one in-flight request, §10.3). Returns when a
    /// transaction reports the connection lost or an `Unregister` is handled or all senders drop.
    async fn run(mut self, mut rx: mpsc::Receiver<SessionCommand>) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                SessionCommand::Transact(t) => {
                    if self.transact(t).await.is_err() {
                        // ConnectionLost — the actor dies; the mpsc receiver drops, so every
                        // pending/subsequent request completes with a send failure the client maps
                        // to `ConnectionLost`/`Closed`.
                        return;
                    }
                }
                SessionCommand::Unregister { done_tx } => {
                    self.send_unregister().await;
                    let _ = done_tx.send(());
                    return;
                }
            }
        }
    }

    /// Run one transaction. `Ok(())` keeps the actor alive; `Err(())` means the session is gone.
    async fn transact(&mut self, t: Transaction) -> core::result::Result<(), ()> {
        // Dequeue triage (§10.4) — before any stream I/O and before a correlation context is burned.
        match preflight(
            t.deadline,
            t.reply_tx.is_closed(),
            tokio::time::Instant::now(),
        ) {
            Preflight::Run => {}
            Preflight::Abandoned => {
                tracing::debug!("skipping abandoned transaction: caller dropped the receiver");
                return Ok(());
            }
            Preflight::Expired => {
                // The budget was spent waiting in the queue, not on a silent peer — count the
                // timeout but leave `consecutive_timeouts` alone so backlog cannot fake a dead peer.
                self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                let _ = t.reply_tx.send(Err(EnipError::Timeout { op: "request" }));
                return Ok(());
            }
        }

        let deadline = t.deadline;
        let ctx = self.next_context();
        let header = EncapHeader::request(t.command, 0, self.session_handle, ctx);
        let frame = EncapFrame::new(header, t.data);
        match tokio::time::timeout_at(deadline, send_frame(&mut self.stream, &frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = t.reply_tx.send(Err(e));
                return Err(());
            }
            Err(_elapsed) => {
                // A cancelled write may have flushed a partial frame: framing is desynchronised and
                // no later request/reply boundary is trustworthy. Sever, do not quarantine (module
                // docs) — and report it as a lost connection, never a per-request timeout.
                self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                let _ = t.reply_tx.send(Err(EnipError::ConnectionLost {
                    context: "send deadline elapsed mid-frame",
                }));
                return Err(());
            }
        }

        let expected = ReplyExpectation {
            command: t.command,
            session_handle: self.session_handle,
            context: ctx,
        };
        loop {
            match read_outcome(&mut self.stream, &mut self.buf, &mut self.codec, deadline).await {
                ReadOutcome::Frame(reply) => match match_reply(&expected, &reply.header) {
                    ReplyMatch::Match => {
                        self.consecutive_timeouts = 0;
                        let _ = t.reply_tx.send(Ok(reply));
                        return Ok(());
                    }
                    // Stale reply from a timed-out predecessor (§10.3/§10.4): drop + count, keep
                    // waiting for the reply that actually matches this request's context.
                    ReplyMatch::StaleContext => {
                        self.stats.stale_replies.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("discarding stale reply: context mismatch");
                    }
                    // Our context, but a field a compliant target must echo disagrees — a peer
                    // defect. Never delivered; the deadline still bounds the wait.
                    ReplyMatch::HeaderMismatch(field) => {
                        self.stats.stale_replies.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(field, "reply header mismatch on a correlated context");
                    }
                },
                ReadOutcome::Eof => {
                    let _ = t.reply_tx.send(Err(EnipError::ConnectionLost { context: "session eof" }));
                    return Err(());
                }
                ReadOutcome::Broken(e) => {
                    let _ = t.reply_tx.send(Err(e));
                    return Err(());
                }
                ReadOutcome::TimedOut => {
                    self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
                    if self.consecutive_timeouts >= self.max_consecutive_timeouts {
                        let _ = t.reply_tx.send(Err(EnipError::ConnectionLost {
                            context: "consecutive request timeouts",
                        }));
                        return Err(());
                    }
                    // The context `ctx` is now abandoned; a late reply bearing it is dropped by the
                    // correlation rule above when the next transaction reads it (quarantine).
                    let _ = t.reply_tx.send(Err(EnipError::Timeout { op: "request" }));
                    return Ok(());
                }
            }
        }
    }

    /// Best-effort UnRegisterSession (§5.5): send, no reply expected, then drop the socket. The write
    /// is bounded by [`UNREGISTER_WRITE_DEADLINE`] and its outcome deliberately ignored — §5.2 defines
    /// no reply, and shutdown must not hang on a peer that has stopped reading. The socket is dropped
    /// straight after either way, which closes the session even if the courtesy frame never landed.
    async fn send_unregister(&mut self) {
        let header =
            EncapHeader::request(Command::UnRegisterSession, 0, self.session_handle, [0u8; 8]);
        let frame = EncapFrame::new(header, Bytes::new());
        let _ = tokio::time::timeout_at(
            deadline_from(UNREGISTER_WRITE_DEADLINE),
            send_frame(&mut self.stream, &frame),
        )
        .await;
    }
}

/// Spawn a session actor over `stream` (already registered) and return the command sender.
pub(crate) fn spawn_session<S>(
    stream: S,
    leftover: BytesMut,
    session_handle: u32,
    max_consecutive_timeouts: u32,
    stats: Arc<SessionStats>,
) -> mpsc::Sender<SessionCommand>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(32);
    let actor = SessionActor {
        stream,
        buf: leftover,
        codec: EncapCodec::new(),
        session_handle,
        next_context: 0,
        consecutive_timeouts: 0,
        max_consecutive_timeouts: max_consecutive_timeouts.max(1),
        stats,
    };
    tokio::spawn(actor.run(rx));
    tx
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::encap::EncapStatus;

    const OURS: [u8; 8] = *b"CTX00001";
    const THEIRS: [u8; 8] = *b"CTX99999";
    const HANDLE: u32 = 0x00AB_CDEF;

    /// Build a reply header with the given echoed fields.
    fn reply_header(command: Command, session_handle: u32, context: [u8; 8]) -> EncapHeader {
        EncapHeader {
            command,
            length: 0,
            session_handle,
            status: EncapStatus::Success,
            sender_context: context,
            options: 0,
        }
    }

    /// §10.3/§5.2 — the full reply-matching truth table, swept exhaustively over
    /// {context ok/bad} × {command ok/bad} × {handle ok/bad/zero} × every command we correlate.
    ///
    /// A bad context is *always* ordinary staleness (nothing else is even inspected). Once the reply
    /// claims our context, the command echo is mandatory for every command, and the session handle is
    /// mandatory for the session-scoped commands only — `ListIdentity`/`ListServices`/`ListInterfaces`
    /// are sessionless-capable, so both a zero and a garbage handle are accepted for them.
    #[test]
    fn match_reply_full_matrix() {
        let commands = [
            Command::SendRRData,
            Command::SendUnitData,
            Command::ListIdentity,
            Command::ListServices,
            Command::ListInterfaces,
        ];
        // (handle value, is it the one we registered)
        let handles = [(HANDLE, true), (HANDLE.wrapping_add(1), false), (0, false)];

        let mut seen_match = 0u32;
        let mut seen_stale = 0u32;
        let mut seen_command = 0u32;
        let mut seen_handle = 0u32;

        for command in commands {
            let expected = ReplyExpectation {
                command,
                session_handle: HANDLE,
                context: OURS,
            };
            // A wrong command echo: pick one that is definitely not `command`.
            let wrong_command = if matches!(command, Command::SendUnitData) {
                Command::SendRRData
            } else {
                Command::SendUnitData
            };
            for (context, context_ok) in [(OURS, true), (THEIRS, false)] {
                for (reply_command, command_ok) in [(command, true), (wrong_command, false)] {
                    for (handle, handle_ok) in handles {
                        let header = reply_header(reply_command, handle, context);
                        let got = match_reply(&expected, &header);
                        let want = if !context_ok {
                            ReplyMatch::StaleContext
                        } else if !command_ok {
                            ReplyMatch::HeaderMismatch("command")
                        } else if handle_ok || session_handle_exempt(command) {
                            ReplyMatch::Match
                        } else {
                            ReplyMatch::HeaderMismatch("session handle")
                        };
                        assert_eq!(
                            got, want,
                            "cmd={command:?} reply_cmd={reply_command:?} handle={handle:#X} ctx_ok={context_ok}"
                        );
                        match got {
                            ReplyMatch::Match => seen_match += 1,
                            ReplyMatch::StaleContext => seen_stale += 1,
                            ReplyMatch::HeaderMismatch("command") => seen_command += 1,
                            ReplyMatch::HeaderMismatch(_) => seen_handle += 1,
                        }
                    }
                }
            }
        }

        // The sweep really did cover every arm (5 commands × 2 contexts × 2 commands × 3 handles).
        assert_eq!(
            seen_match + seen_stale + seen_command + seen_handle,
            5 * 2 * 2 * 3
        );
        // 2 session-scoped commands contribute 1 matching handle each (2); the 3 exempt ones match on
        // all 3 handle values (9).
        assert_eq!(seen_match, 2 + 3 * 3);
        assert_eq!(seen_handle, 2 * 2); // only the session-scoped commands can fail the handle check
        assert_eq!(seen_command, 5 * 3); // one wrong-command row per handle, per command
        assert_eq!(seen_stale, 5 * 2 * 3); // every bad-context row, whatever else it carried

        // A zero handle is accepted for a discovery reply and rejected for a session-scoped one —
        // the §5.2 exemption, stated on its own.
        assert_eq!(
            match_reply(
                &ReplyExpectation {
                    command: Command::ListIdentity,
                    session_handle: HANDLE,
                    context: OURS
                },
                &reply_header(Command::ListIdentity, 0, OURS)
            ),
            ReplyMatch::Match
        );
        assert_eq!(
            match_reply(
                &ReplyExpectation {
                    command: Command::SendRRData,
                    session_handle: HANDLE,
                    context: OURS
                },
                &reply_header(Command::SendRRData, 0, OURS)
            ),
            ReplyMatch::HeaderMismatch("session handle")
        );
    }

    /// §10.4 — dequeue triage. An open receiver with budget left runs; an open receiver whose deadline
    /// has passed (or is exactly now) is `Expired`; a dropped receiver is `Abandoned` even when the
    /// budget is untouched (abandonment wins over expiry — there is nobody to report a timeout to).
    #[test]
    fn preflight_matrix() {
        // Derive all three instants by *adding* to one base so nothing depends on how far the
        // monotonic clock already is from its epoch.
        let past = tokio::time::Instant::now();
        let now = past + Duration::from_secs(10);
        let future = now + Duration::from_secs(1);

        assert_eq!(preflight(future, false, now), Preflight::Run);
        assert_eq!(preflight(past, false, now), Preflight::Expired);
        assert_eq!(preflight(now, false, now), Preflight::Expired);

        assert_eq!(preflight(future, true, now), Preflight::Abandoned);
        assert_eq!(preflight(past, true, now), Preflight::Abandoned);
        assert_eq!(preflight(now, true, now), Preflight::Abandoned);
    }

    /// §10.4 — a timeout so large it cannot be added to `now` means "effectively no timeout", so the
    /// deadline lands far in the future. Saturating to `now` would expire every enqueue, write, and
    /// handshake instantly — the exact inversion of what the caller asked for.
    #[test]
    fn deadline_from_huge_duration_is_far_future() {
        let d = deadline_from(Duration::MAX);
        assert!(d > tokio::time::Instant::now() + Duration::from_secs(86_400));
    }

    /// The ordinary path is unchanged: a representable duration is added exactly.
    #[test]
    fn deadline_from_normal_duration_is_exact() {
        let before = tokio::time::Instant::now();
        let d = deadline_from(Duration::from_secs(3));
        assert!(d >= before + Duration::from_secs(3));
        assert!(d < before + Duration::from_secs(4));
    }
}
