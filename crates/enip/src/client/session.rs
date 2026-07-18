//! The session actor (PROTOCOL-DESIGN §11.1, §10.3–§10.4).
//!
//! One task per [`crate::client::EipClient`] owns the byte stream (any `AsyncRead + AsyncWrite`, so a
//! real `TcpStream` in production and an in-memory [`tokio::io::duplex`] pair in tests — there is no
//! embedded server). It enforces:
//!
//! * **One in-flight request** with `sender_context` correlation (§10.3): the context is a
//!   session-scoped monotonic `u64`. A reply whose context ≠ the outstanding request is a *stale
//!   reply* from a timed-out predecessor — discarded, counted (`stale_replies`), never delivered.
//! * **Per-request deadlines** (§10.4): on expiry the caller gets `Err(Timeout)` immediately and the
//!   timed-out context is simply abandoned. Because contexts never repeat and TCP preserves order, a
//!   late reply bearing that context is dropped by the correlation rule — it can never answer a newer
//!   request (the *stale-reply quarantine*).
//! * **Liveness**: three consecutive timeouts, a transport error, or EOF ⇒ `ConnectionLost`; the
//!   actor exits and every pending/subsequent request completes `Err`.
//!
//! Cancel-safety: the reader keeps a persistent [`BytesMut`] and decodes with [`EncapCodec`]; a
//! deadline that cancels an in-flight `read_buf` leaves the already-received bytes in the buffer, so
//! framing never desynchronises across a timeout.

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
}

/// A single request/reply transaction for the actor to run.
pub(crate) struct Transaction {
    /// The encapsulation command (`SendRRData` / `SendUnitData` / …).
    pub command: Command,
    /// The encapsulation data portion (interface-handle/timeout prefix + CPF, already built).
    pub data: Bytes,
    /// The per-request deadline (§10.4).
    pub deadline: Duration,
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
pub(crate) async fn send_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &EncapFrame,
) -> Result<()> {
    let bytes = frame.encode().map_err(EnipError::Malformed)?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
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

/// Compute an absolute deadline `now + dur` (saturating — a `None` from overflow means "immediately",
/// which is fine for our small durations).
fn deadline_from(dur: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(dur).unwrap_or(now)
}

/// Read one frame with a deadline, mapping non-frame outcomes to errors — the handshake helper used
/// by [`crate::client::EipClient::connect`] before the actor is spawned.
pub(crate) async fn recv_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    codec: &mut EncapCodec,
    deadline: Duration,
    op: &'static str,
) -> Result<EncapFrame> {
    match read_outcome(stream, buf, codec, deadline_from(deadline)).await {
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
        let ctx = self.next_context();
        let header = EncapHeader::request(t.command, 0, self.session_handle, ctx);
        let frame = EncapFrame::new(header, t.data);
        if let Err(e) = send_frame(&mut self.stream, &frame).await {
            let _ = t.reply_tx.send(Err(e));
            return Err(());
        }

        let deadline = deadline_from(t.deadline);
        loop {
            match read_outcome(&mut self.stream, &mut self.buf, &mut self.codec, deadline).await {
                ReadOutcome::Frame(reply) => {
                    if reply.header.sender_context == ctx {
                        self.consecutive_timeouts = 0;
                        let _ = t.reply_tx.send(Ok(reply));
                        return Ok(());
                    }
                    // Stale reply from a timed-out predecessor (§10.3/§10.4): drop + count, keep
                    // waiting for the reply that actually matches this request's context.
                    self.stats.stale_replies.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("discarding stale reply: context mismatch");
                }
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

    /// Best-effort UnRegisterSession (§5.5): send, no reply expected, then drop the socket.
    async fn send_unregister(&mut self) {
        let header =
            EncapHeader::request(Command::UnRegisterSession, 0, self.session_handle, [0u8; 8]);
        let frame = EncapFrame::new(header, Bytes::new());
        let _ = send_frame(&mut self.stream, &frame).await;
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
