//! Class-1 implicit I/O runtime (PROTOCOL-DESIGN §8.5–§8.8, D-ENIP-7/8/9/10).
//!
//! The adapter is the **scanner/originator**: it ForwardOpens an I/O connection pair against a
//! target's assembly instances and then produces O→T frames at the negotiated O→T API while
//! consuming the T→O frames the target produces. Everything runs over bare CPF datagrams on UDP —
//! no encapsulation header (§8.1). O→T goes to the **target's** registered [`IO_UDP_PORT`] (2222);
//! T→O comes back to whatever port the originator bound and advertised in the ForwardOpen's
//! Sockaddr Info items, which for this adapter is an ephemeral one. This module owns:
//!
//! * [`IoFrame`] — the class-1 connected-data frame codec. **Frame order is sequence-then-header**
//!   (D-ENIP-10): `[u16 class-1 sequence][u32 run/idle header if present][data]`, on **both** encode
//!   and decode. EIPScanner decodes header-first — a reference bug we deliberately do not copy. A
//!   runt or oversized datagram is a typed drop through [`crate::wire::WireReader`], never a panic.
//! * [`IoConnection`] — the pure, socket-free state machine: the signed-window sequence rule
//!   `(new − last) as i16 > 0` (duplicates / stale / reorders dropped **and counted**, D-ENIP-7), the
//!   size-vs-negotiated check (dropped + counted), the produce scheduler (a frame — data or heartbeat
//!   — every O→T API, incrementing the class-1 and encapsulation sequences, D-ENIP-9), and the
//!   originator watchdog (`timeout_multiplier × T2O_API`, D-ENIP-8). It takes an explicit `now`, so
//!   the whole gauntlet, produce cadence, and watchdog are testable with crafted bytes and a paused
//!   clock — **no socket, no peer** (§12.2).
//! * [`IoManager`] — the thin UDP socket task: recv → route by connection id → **check the
//!   datagram's source IP against the connection's target** (D-ENIP-24: a mismatch is a counted
//!   `source_mismatch_datagrams` drop that never reaches the gauntlet and never feeds the watchdog)
//!   → drive
//!   [`IoConnection::consume`]; and a scheduler tick that drives [`IoConnection::poll_produce`] /
//!   [`IoConnection::poll_watchdog`]. It exposes [`IoConnectionHandle`] (`events`, `set_output`,
//!   `stage_output`, `stage_output_by`, `set_run`, `stats`, `close`). Commands that can fail inside
//!   the task — registering a connection (the multicast join), and the confirmed form of output
//!   staging — carry a `oneshot` acknowledgement, so `forward_open` returns only once the
//!   connection is **armed** and `stage_output` reports whether the buffer will actually ride a
//!   frame. A staging command also carries its caller's **absolute deadline**, and the task drops
//!   an expired one instead of mutating the producer buffer, so a staging call that reports a
//!   timeout cannot be applied afterwards (D-ENIP-20).
//!
//! **Socket errors are classified, never swallowed** (§8.6–§8.7, D-ENIP-7). Every `recv_from` /
//! `send_to` failure increments a counter (`recv_errors` manager-wide, `send_errors` per
//! connection). A *per-datagram* kind ([`is_per_datagram_error`] — notably Windows'
//! `ConnectionReset` from an ICMP port-unreachable for a previously sent datagram) is a survivable
//! drop that proves the socket still works. Three consecutive errors of any other kind declare the
//! socket dead: [`IoEvent::Lost`] with [`LostReason::Io`] fans out to **every** registered
//! connection and the manager task exits. `Lost` is a control event on the per-connection queue and
//! is never evicted by a backlog of samples; **the event stream ending is still the authoritative
//! terminal signal** — a consumer that sees `recv() == None` must treat the connection as gone
//! whether or not it saw the `Lost` event.
//!
//! The per-connection event stream is **latest-wins** (§8.6): the queue bounds `Data` events, and a
//! sample arriving at capacity evicts the OLDEST queued sample (counted as `overflowed_events`).
//! Telemetry prefers fresh data over backpressure — a consumer that falls behind reads the newest
//! frames, never a stale backlog.
//!
//! The ForwardOpen/ForwardClose wire codecs live in [`crate::cm`]; the network call rides the owning
//! TCP session through the [`ForwardOpenService`] seam (implemented by the explicit-messaging client,
//! keeping this module below `client` in the layering — §3.2).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

use crate::cip::epath::Segment;
use crate::cip::message::{MessageReply, MessageRequest};
use crate::cm::{
    connection_manager_path, io_connection_path, transport_class1_trigger,
    verify_forward_open_echo, ConnType, ForwardCloseRequest, ForwardOpenRequest,
    ForwardOpenSuccess, ForwardRequestFail, NetworkConnectionParams, Priority, ProductionTrigger,
    TimeoutMultiplier, VariableLength,
};
use crate::cpf::{Cpf, CpfItem, ItemType, SequencedAddress, SockAddrInfo};
use crate::error::{EnipError, Result};
use crate::wire::{WireReader, WireWriter};

/// The IANA-assigned EtherNet/IP implicit-I/O UDP port (§8.1).
pub const IO_UDP_PORT: u16 = 2222;

/// The on-wire size above which a standard ForwardOpen cannot express the connection and the driver
/// switches to LargeForwardOpen (§8.2).
const LARGE_FORWARD_OPEN_THRESHOLD: u16 = 505;

/// Per-connection event queue depth, in `Data` events. Bounded so a stalled consumer cannot grow
/// memory without bound; overflow is counted (`overflowed_events`) and the **oldest** queued `Data`
/// event is evicted — latest-wins, telemetry prefers fresh data over backpressure (§8.6).
/// [`IoEvent::Up`] and [`IoEvent::Lost`] are never evicted: a connection emits at most one of each,
/// and losing a terminal event would hide why a connection ended.
const EVENT_CHANNEL_DEPTH: usize = 256;

/// The scheduler-tick resolution. Per-connection produce cadence and watchdog deadlines are honoured
/// by [`IoConnection::poll_produce`] / [`IoConnection::poll_watchdog`]; the tick only needs to be
/// finer than the smallest RPI in play.
const SCHEDULER_TICK: Duration = Duration::from_millis(1);

/// Depth of the manager task's command queue. Bounded, so a caller that outruns the task waits
/// rather than growing it — which is why a staging caller under a deadline bounds its handoff too
/// (D-ENIP-20).
const MANAGER_COMMAND_DEPTH: usize = 64;

/// The smallest actual packet interval a ForwardOpen reply may name (§8.2). Below this the value is
/// not a timer input but a protocol violation: a 0 µs API used to livelock the produce scheduler.
pub(crate) const MIN_REPLY_API: Duration = Duration::from_micros(100);

/// The largest actual packet interval a ForwardOpen reply may name (§8.2). Ten minutes is already
/// far beyond any real class-1 cadence; anything larger is a corrupt or hostile field.
pub(crate) const MAX_REPLY_API: Duration = Duration::from_secs(600);

/// Consecutive non-survivable `recv_from` errors that declare the shared UDP socket dead (§8.6).
pub(crate) const MAX_CONSECUTIVE_FATAL_RECV_ERRORS: u32 = 3;

/// Consecutive non-survivable `send_to` errors that declare one connection dead (§8.7).
pub(crate) const MAX_CONSECUTIVE_SEND_ERRORS: u32 = 3;

/// Validate the **actual** packet intervals a ForwardOpen success reply names (§8.2), returning them
/// as `Duration`s. Both directions must lie within `[MIN_REPLY_API, MAX_REPLY_API]`; anything else —
/// most importantly 0 — is [`EnipError::ProtocolViolation`], never a timer input.
///
/// Class-3 does not call this. Its keepalive window IS derived from the reply's O→T API
/// ([`crate::client::keepalive::class3_inactivity_window`], §7.6), but under the opposite rule: an
/// API outside the band forfeits the refinement and falls back to the requested RPI instead of
/// failing the open. The asymmetry is deliberate — here the APIs drive the produce scheduler and the
/// connection watchdog, so an implausible one poisons the connection; there the only timer they feed
/// is our own keepalive, and explicit messaging has always worked against targets that answer with a
/// wonky API.
pub(crate) fn validate_reply_apis(success: &ForwardOpenSuccess) -> Result<(Duration, Duration)> {
    let o2t = Duration::from_micros(u64::from(success.o_t_api));
    let t2o = Duration::from_micros(u64::from(success.t_o_api));
    for api in [o2t, t2o] {
        if api < MIN_REPLY_API || api > MAX_REPLY_API {
            return Err(EnipError::ProtocolViolation {
                detail: "forward-open reply API out of range",
            });
        }
    }
    Ok((o2t, t2o))
}

/// Whether a socket error kind affects **one datagram** rather than the socket (§8.6–§8.7).
///
/// `ConnectionReset` is the Windows case that matters: an ICMP port-unreachable for a datagram we
/// already sent surfaces as `WSAECONNRESET` on the *next* UDP call even though the socket is
/// perfectly healthy. `ConnectionRefused` is the Linux spelling of the same condition,
/// `ConnectionAborted` its BSD cousin, and `Interrupted` / `WouldBlock` are ordinary transient
/// scheduling outcomes. None of them says anything about the socket's viability.
pub(crate) fn is_per_datagram_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

/// The receive-side socket-error policy (§8.6): a consecutive-failure streak over the *non*
/// per-datagram kinds, reset by any success or by a per-datagram error (which demonstrates the
/// socket still carries traffic).
#[derive(Debug, Default)]
pub(crate) struct RecvErrorPolicy {
    consecutive_fatal: u32,
}

/// What the manager should do after a `recv_from` error (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecvErrorAction {
    /// Survivable — count it, log it, keep receiving.
    Continue,
    /// The socket is dead: fan `Lost { Io }` out to every connection and exit the task.
    FatalSocket,
}

impl RecvErrorPolicy {
    /// Classify one `recv_from` error. Per-datagram kinds reset the streak and continue; any other
    /// kind extends it, declaring the socket dead at [`MAX_CONSECUTIVE_FATAL_RECV_ERRORS`].
    pub(crate) fn on_recv_error(&mut self, kind: std::io::ErrorKind) -> RecvErrorAction {
        if is_per_datagram_error(kind) {
            self.consecutive_fatal = 0;
            return RecvErrorAction::Continue;
        }
        self.consecutive_fatal = self.consecutive_fatal.saturating_add(1);
        if self.consecutive_fatal >= MAX_CONSECUTIVE_FATAL_RECV_ERRORS {
            RecvErrorAction::FatalSocket
        } else {
            RecvErrorAction::Continue
        }
    }

    /// A successful receive clears the streak.
    pub(crate) fn on_recv_ok(&mut self) {
        self.consecutive_fatal = 0;
    }
}

/// The outcome of accounting one O→T datagram send (§8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The datagram reached the socket; `frames_produced` advanced.
    Sent,
    /// The send failed but the connection survives (a per-datagram error, or a streak short of the
    /// limit). Counted as `send_errors`.
    Dropped,
    /// Consecutive non-survivable send failures reached [`MAX_CONSECUTIVE_SEND_ERRORS`]: this
    /// connection is dead and must be lost with [`LostReason::Io`].
    ConnectionDead,
}

// ---------------------------------------------------------------------------
// Real-time format & frame codec (§8.5, D-ENIP-10)
// ---------------------------------------------------------------------------

/// The real-time transfer format of one direction of a class-1 connection (§8.5). Conventional
/// scanners run O→T as [`Header32Bit`](Self::Header32Bit) (the scanner signals run/idle) and T→O as
/// [`Modeless`](Self::Modeless) (pure data), but both are configurable per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealTimeFormat {
    /// Class-1 sequence count followed by application data (no run/idle header).
    Modeless,
    /// Class-1 sequence count, a 32-bit run/idle header, then application data.
    Header32Bit,
    /// Class-1 sequence count only — the O→T heartbeat used when a direction carries no data.
    Heartbeat,
    /// A pure zero-length payload (no sequence, no data).
    ZeroLength,
}

impl RealTimeFormat {
    /// Whether the frame carries the leading 16-bit class-1 sequence count.
    #[must_use]
    pub fn has_sequence(self) -> bool {
        !matches!(self, Self::ZeroLength)
    }

    /// Whether the frame carries the 32-bit run/idle header (only [`Header32Bit`](Self::Header32Bit)).
    #[must_use]
    pub fn has_header(self) -> bool {
        matches!(self, Self::Header32Bit)
    }

    /// Whether the frame carries application data after the sequence/header.
    #[must_use]
    pub fn carries_data(self) -> bool {
        matches!(self, Self::Modeless | Self::Header32Bit)
    }

    /// The framing overhead in bytes (sequence + header) this format prepends to the data.
    fn overhead(self) -> usize {
        let seq: usize = if self.has_sequence() { 2 } else { 0 };
        let hdr: usize = if self.has_header() { 4 } else { 0 };
        seq.saturating_add(hdr)
    }
}

/// A decoded class-1 connected-data frame (§8.5). Field presence follows the direction's
/// [`RealTimeFormat`]: `sequence` is `None` only for [`RealTimeFormat::ZeroLength`], `run_mode` is
/// `Some` only when the format carries the 32-bit header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoFrame {
    /// The 16-bit class-1 sequence count.
    pub sequence: Option<u16>,
    /// Run (`true`) / Idle (`false`) from the 32-bit header (bit 0), when present.
    pub run_mode: Option<bool>,
    /// The application (assembly) bytes.
    pub data: Bytes,
}

impl IoFrame {
    /// Encode the frame in **sequence-then-header order** (D-ENIP-10): the 16-bit class-1 sequence
    /// (when the format has one), then the 32-bit run/idle header (when present), then the data.
    #[must_use]
    pub fn encode(&self, format: RealTimeFormat) -> Bytes {
        let mut w = WireWriter::with_capacity(self.data.len().saturating_add(6));
        if format.has_sequence() {
            w.u16(self.sequence.unwrap_or(0));
        }
        if format.has_header() {
            // bit 0: 1 = Run, 0 = Idle; bits 1–31 reserved 0.
            w.u32(u32::from(self.run_mode.unwrap_or(true)));
        }
        w.put_slice(&self.data);
        w.into_bytes()
    }

    /// Decode a class-1 connected-data frame per the direction's `format`, in the same
    /// sequence-then-header order (D-ENIP-10). Every read is bounds-checked: a runt buffer is
    /// [`crate::error::WireError`], never a panic (the EIPScanner overrun class).
    pub fn decode(
        format: RealTimeFormat,
        buf: &[u8],
    ) -> core::result::Result<Self, crate::error::WireError> {
        let mut r = WireReader::with_context(buf, "io frame");
        let sequence = if format.has_sequence() {
            Some(r.u16()?)
        } else {
            None
        };
        let run_mode = if format.has_header() {
            let header = r.u32()?;
            Some(header & 1 != 0)
        } else {
            None
        };
        let data = Bytes::copy_from_slice(r.take_rest());
        Ok(Self {
            sequence,
            run_mode,
            data,
        })
    }
}

// ---------------------------------------------------------------------------
// Events, counters, drop reasons
// ---------------------------------------------------------------------------

/// Why an I/O connection was declared lost (§8.8, §11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostReason {
    /// No valid T→O frame arrived within `timeout_multiplier × T2O_API` (the watchdog, D-ENIP-8).
    Timeout,
    /// The peer closed the connection.
    ClosedByPeer,
    /// A socket-level error on the transmit or receive path.
    Io,
}

/// One accepted T→O sample delivered to the consumer (§8.6).
#[derive(Debug, Clone)]
pub struct IoUpdate {
    /// The application (assembly) bytes, with the sequence/header stripped.
    pub data: Bytes,
    /// The 16-bit class-1 sequence count of the frame (0 for a formatless direction).
    pub sequence: u16,
    /// The encapsulation sequence from the sequenced-address item.
    pub encap_sequence: u32,
    /// The run/idle state carried by the frame's header (defaults to Run when the direction is
    /// modeless).
    pub run_mode: bool,
    /// When the frame was accepted (monotonic).
    pub received_at: Instant,
}

/// An event on a connection's stream (§11.2). `Up` is emitted once, on the first accepted frame;
/// `Data` carries each accepted sample; `Lost` is terminal.
#[derive(Debug, Clone)]
pub enum IoEvent {
    /// The first valid T→O frame arrived; the negotiated actual packet intervals are reported.
    Up {
        /// The actual O→T packet interval (from the ForwardOpen reply).
        o2t_api: Duration,
        /// The actual T→O packet interval (from the ForwardOpen reply).
        t2o_api: Duration,
    },
    /// An accepted T→O sample.
    Data(IoUpdate),
    /// The connection was lost and closed.
    Lost {
        /// Why the connection ended.
        reason: LostReason,
    },
}

/// Why a datagram or frame was dropped in the consume gauntlet (§8.6). Every drop increments the
/// matching counter; none is ever silent (D-ENIP-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// CPF-level: the datagram was not a well-formed `[sequenced-address, connected-data]` pair.
    Malformed,
    /// The sequenced-address connection id matched no live connection.
    UnknownConnection,
    /// The datagram's source IP was not the connection's target (D-ENIP-24). Dropped before the
    /// consume gauntlet, so it neither delivers a sample nor feeds the connection's watchdog.
    SourceMismatch,
    /// The stripped data length did not match the negotiated T→O size (or the frame was a runt).
    SizeMismatch,
    /// The class-1 sequence was a duplicate, stale, or reordered frame (signed-window rule).
    Stale,
}

/// Live, lock-free per-connection counters (§8.6, §10.2). Shared between the manager task (writer)
/// and the handle (reader).
#[derive(Debug, Default)]
pub(crate) struct ConnCounters {
    frames_accepted: AtomicU64,
    frames_produced: AtomicU64,
    size_mismatch: AtomicU64,
    stale_frames: AtomicU64,
    sequence_gaps: AtomicU64,
    overflowed_events: AtomicU64,
    produce_overruns: AtomicU64,
    send_errors: AtomicU64,
    refused_redirects: AtomicU64,
}

/// Manager-wide datagram counters (§8.6, §10.2). Shared across every connection on the socket.
#[derive(Debug, Default)]
struct ManagerCounters {
    malformed_frames: AtomicU64,
    unknown_connection: AtomicU64,
    recv_errors: AtomicU64,
    source_mismatch_datagrams: AtomicU64,
}

/// A snapshot of a connection's peer-driven counters (§10.2). The adapter alarms on these without
/// the crate knowing what an alarm is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoStats {
    /// T→O frames accepted and delivered.
    pub frames_accepted: u64,
    /// O→T frames actually sent onto the wire (data or heartbeat) by the produce scheduler (§8.7).
    pub frames_produced: u64,
    /// Frames dropped for a size mismatch (or a runt frame).
    pub size_mismatch: u64,
    /// Frames dropped as duplicate / stale / reordered by the signed-window rule.
    pub stale_frames: u64,
    /// Sum of forward sequence gaps observed (missed frames).
    pub sequence_gaps: u64,
    /// Accepted samples evicted because the event queue was at its `Data` capacity (latest-wins,
    /// §8.6): each one is an older sample the consumer never saw.
    pub overflowed_events: u64,
    /// Produce ticks skipped because a prior tick had not been serviced.
    pub produce_overruns: u64,
    /// O→T datagrams whose socket send failed (per connection).
    pub send_errors: u64,
    /// UDP recv errors on the shared socket (manager-wide).
    pub recv_errors: u64,
    /// Datagrams dropped as malformed CPF (manager-wide).
    pub malformed_frames: u64,
    /// Datagrams whose connection id matched no live connection (manager-wide).
    pub unknown_connection: u64,
    /// Datagrams addressed to a live connection but sourced from an IP that is not that
    /// connection's target (manager-wide, D-ENIP-24). They are dropped before the consume gauntlet,
    /// so they deliver nothing and do not feed the watchdog. Nonzero means either something else on
    /// the segment is producing into our connection id, or the target is genuinely sourcing its
    /// T→O stream from a second interface — the latter shows up as a link that never comes up.
    pub source_mismatch_datagrams: u64,
    /// O→T sockaddr redirects whose foreign address was refused at ForwardOpen (D-ENIP-17); 0 or 1
    /// per connection. Nonzero means the target asked for its outputs on an address we will not
    /// transmit to: only the sockaddr's **port** was honoured, and a device that genuinely requires
    /// the redirect never receives the O→T stream.
    pub refused_redirects: u64,
}

impl ConnCounters {
    fn snapshot(&self) -> IoStats {
        IoStats {
            frames_accepted: self.frames_accepted.load(Ordering::Relaxed),
            frames_produced: self.frames_produced.load(Ordering::Relaxed),
            size_mismatch: self.size_mismatch.load(Ordering::Relaxed),
            stale_frames: self.stale_frames.load(Ordering::Relaxed),
            sequence_gaps: self.sequence_gaps.load(Ordering::Relaxed),
            overflowed_events: self.overflowed_events.load(Ordering::Relaxed),
            produce_overruns: self.produce_overruns.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: 0,
            malformed_frames: 0,
            unknown_connection: 0,
            source_mismatch_datagrams: 0,
            refused_redirects: self.refused_redirects.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// The per-connection event queue: latest-wins overflow (§8.6)
// ---------------------------------------------------------------------------

/// Pure latest-wins queue state (§8.6). `capacity` bounds **`Data` events only**; control events
/// ([`IoEvent::Up`] / [`IoEvent::Lost`]) always enqueue — a connection emits at most one of each per
/// lifetime, so the queue is bounded by `capacity + 2`.
pub(crate) struct EventQueueState {
    deque: std::collections::VecDeque<IoEvent>,
    capacity: usize,
    data_len: usize,
    tx_closed: bool,
    rx_closed: bool,
}

impl EventQueueState {
    /// A queue holding at most `capacity` `Data` events. A zero capacity is clamped to one: the
    /// policy is "prefer the newest sample", never "deliver nothing".
    fn new(capacity: usize) -> Self {
        Self {
            deque: std::collections::VecDeque::new(),
            capacity: capacity.max(1),
            data_len: 0,
            tx_closed: false,
            rx_closed: false,
        }
    }

    /// Pop the front (oldest surviving) event, keeping the `Data` census in step.
    fn pop(&mut self) -> Option<IoEvent> {
        let ev = self.deque.pop_front()?;
        if matches!(ev, IoEvent::Data(_)) {
            self.data_len = self.data_len.saturating_sub(1);
        }
        Some(ev)
    }
}

/// What [`push_latest_wins`] did with one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushOutcome {
    /// Enqueued; nothing dropped.
    Queued,
    /// The queue was at `Data` capacity: the OLDEST queued `Data` event was evicted to admit this
    /// one (latest-wins, §8.6). The caller counts it as `overflowed_events`.
    EvictedOldest,
    /// The receiver is gone; the event was dropped (nothing to deliver to).
    ReceiverGone,
}

/// **PURE**: push one event under the latest-wins policy (§8.6).
///
/// * A closed receiver ⇒ [`PushOutcome::ReceiverGone`] — a dead consumer never grows the queue.
/// * `Data` at capacity ⇒ the frontmost `Data` event is removed to admit the new one
///   ([`PushOutcome::EvictedOldest`]). The scan is front→back over at most `capacity + 2` entries,
///   and in steady state the front **is** a `Data` event, so it is O(1) amortised.
/// * `Up` / `Lost` ⇒ enqueued unconditionally: control events are never evicted, so a terminal
///   reason cannot be lost behind a flood of samples.
///
/// The relative order of the surviving events is preserved.
pub(crate) fn push_latest_wins(state: &mut EventQueueState, ev: IoEvent) -> PushOutcome {
    if state.rx_closed {
        return PushOutcome::ReceiverGone;
    }
    if !matches!(ev, IoEvent::Data(_)) {
        state.deque.push_back(ev);
        return PushOutcome::Queued;
    }
    if state.data_len >= state.capacity {
        if let Some(idx) = state
            .deque
            .iter()
            .position(|e| matches!(e, IoEvent::Data(_)))
        {
            state.deque.remove(idx);
            state.data_len = state.data_len.saturating_sub(1);
            state.deque.push_back(ev);
            state.data_len = state.data_len.saturating_add(1);
            return PushOutcome::EvictedOldest;
        }
    }
    state.deque.push_back(ev);
    state.data_len = state.data_len.saturating_add(1);
    PushOutcome::Queued
}

/// The shared half of one connection's event queue: the state plus the receiver's wakeup.
struct EventQueueShared {
    state: std::sync::Mutex<EventQueueState>,
    notify: tokio::sync::Notify,
}

/// Lock the queue state. A poisoned lock is impossible here — no code path can panic inside a
/// critical section — but the crate denies `unwrap`/`expect`, so the total form is used.
fn lock_state(m: &std::sync::Mutex<EventQueueState>) -> std::sync::MutexGuard<'_, EventQueueState> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl EventQueueShared {
    /// Take the next event, or say why there is none. One lock acquisition serves both the
    /// non-blocking `try_recv` and each iteration of `recv`.
    fn take(&self) -> core::result::Result<IoEvent, TryRecvError> {
        let mut state = lock_state(&self.state);
        if let Some(ev) = state.pop() {
            return Ok(ev);
        }
        if state.tx_closed {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }
}

/// Why [`IoEventReceiver::try_recv`] returned no event (mirrors `mpsc`'s shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    /// Nothing queued right now; the connection is still live.
    Empty,
    /// The sender is gone and the queue is drained — the connection is over (§8.6).
    Disconnected,
}

impl core::fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("no event queued"),
            Self::Disconnected => f.write_str("the connection's event stream is closed"),
        }
    }
}

impl std::error::Error for TryRecvError {}

/// The manager-side producer half of a connection's event queue. Owns the connection's counters, so
/// a latest-wins eviction is counted at the source (§8.6).
pub(crate) struct IoEventSender {
    shared: Arc<EventQueueShared>,
    counters: Arc<ConnCounters>,
}

impl IoEventSender {
    /// Deliver one event. Non-blocking and infallible: `Data` follows the latest-wins policy (an
    /// eviction counts `overflowed_events`), `Up`/`Lost` always enqueue, and a gone receiver simply
    /// discards. The receiver is woken for anything that landed.
    pub(crate) fn send(&self, ev: IoEvent) {
        let outcome = {
            let mut state = lock_state(&self.shared.state);
            push_latest_wins(&mut state, ev)
        };
        match outcome {
            PushOutcome::EvictedOldest => {
                self.counters
                    .overflowed_events
                    .fetch_add(1, Ordering::Relaxed);
                self.shared.notify.notify_one();
            }
            PushOutcome::Queued => self.shared.notify.notify_one(),
            PushOutcome::ReceiverGone => {}
        }
    }
}

impl Drop for IoEventSender {
    /// Dropping the sender is the terminal signal (§8.6): the receiver drains what is queued and
    /// then reports end-of-stream.
    fn drop(&mut self) {
        lock_state(&self.shared.state).tx_closed = true;
        self.shared.notify.notify_waiters();
    }
}

/// The consumer half of a connection's event stream, exposed by [`IoConnectionHandle::events`]. The
/// API mirrors `tokio::sync::mpsc::Receiver`: [`recv`](Self::recv) awaits the next event and yields
/// `None` once the stream has ended, [`try_recv`](Self::try_recv) never blocks.
///
/// Overflow is **latest-wins** (§8.6): when a slow consumer lets the queue reach its `Data`
/// capacity, the oldest queued sample is evicted (and counted as `overflowed_events`) so what the
/// consumer eventually reads is the freshest telemetry. `Up` and `Lost` are never evicted.
pub struct IoEventReceiver {
    shared: Arc<EventQueueShared>,
}

impl IoEventReceiver {
    /// The next event, FIFO over the surviving events. `None` once the sender is gone **and** the
    /// queue is drained — the authoritative terminal signal (§8.6).
    ///
    /// Cancel-safe: dropping the returned future never loses a queued event, so it can be used
    /// directly as a `tokio::select!` branch.
    pub async fn recv(&mut self) -> Option<IoEvent> {
        loop {
            // Lost-wakeup discipline: register interest BEFORE inspecting the queue, so a `send`
            // that lands between the inspection and the await still wakes this future. `enable()`
            // registers the waiter exactly as a first poll would (and consumes any stored permit,
            // which the loop's re-check then makes harmless).
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.shared.take() {
                Ok(ev) => return Some(ev),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => notified.await,
            }
        }
    }

    /// The next event without waiting (the drain-to-latest idiom): [`TryRecvError::Empty`] while the
    /// connection is live, [`TryRecvError::Disconnected`] once it has ended and drained.
    ///
    /// # Errors
    ///
    /// [`TryRecvError`] when no event is available.
    pub fn try_recv(&mut self) -> core::result::Result<IoEvent, TryRecvError> {
        self.shared.take()
    }
}

impl Drop for IoEventReceiver {
    /// A gone consumer stops the queue growing: further pushes are [`PushOutcome::ReceiverGone`].
    fn drop(&mut self) {
        lock_state(&self.shared.state).rx_closed = true;
    }
}

/// Construct a connected sender/receiver pair whose queue holds at most `capacity` `Data` events.
/// `counters` is the connection's counter block, so evictions are counted where they happen.
pub(crate) fn io_event_channel(
    capacity: usize,
    counters: Arc<ConnCounters>,
) -> (IoEventSender, IoEventReceiver) {
    let shared = Arc::new(EventQueueShared {
        state: std::sync::Mutex::new(EventQueueState::new(capacity)),
        notify: tokio::sync::Notify::new(),
    });
    (
        IoEventSender {
            shared: Arc::clone(&shared),
            counters,
        },
        IoEventReceiver { shared },
    )
}

// ---------------------------------------------------------------------------
// Connection spec (the forward-open surface, §11.2)
// ---------------------------------------------------------------------------

/// One direction of a class-1 connection request (§11.2). The scanner requests the RPI and data
/// size; the target's ForwardOpen reply supplies the *actual* packet interval that drives timing.
#[derive(Debug, Clone)]
pub struct DirectionSpec {
    /// Requested packet interval.
    pub rpi: Duration,
    /// Application data size in bytes (0 ⇒ heartbeat for the O→T direction).
    pub data_size: usize,
    /// The real-time transfer format for this direction (§8.5).
    pub format: RealTimeFormat,
    /// Connection type — P2P, or multicast for a shared T→O group (§8.3).
    pub conn_type: ConnType,
    /// Connection priority (§8.3).
    pub priority: Priority,
    /// Fixed- vs variable-length framing (§8.3).
    pub variable: VariableLength,
}

/// The assembly-instance connection path for a class-1 open (§8.4).
#[derive(Debug, Clone)]
pub struct AssemblyPath {
    /// Config assembly instance, when the target requires one (OpENer and most adapters do).
    pub config: Option<u16>,
    /// Output (O→T) assembly instance / connection point.
    pub output: u16,
    /// Input (T→O) assembly instance / connection point.
    pub input: u16,
    /// Optional route port segments to a chassis slot (empty = direct).
    pub route: Vec<crate::cip::epath::PortSegment>,
}

/// The full class-1 ForwardOpen request the adapter hands [`IoManager::forward_open`] (§11.2).
#[derive(Debug, Clone)]
pub struct IoConnectionSpec {
    /// The assembly connection path.
    pub assembly: AssemblyPath,
    /// The T→O (input) direction.
    pub t2o: DirectionSpec,
    /// The O→T (output) direction.
    pub o2t: DirectionSpec,
    /// The inactivity-watchdog multiplier code (§8.2 field 8).
    pub timeout_multiplier: TimeoutMultiplier,
    /// The production trigger (cyclic by default).
    pub trigger: ProductionTrigger,
    /// The originator vendor id stamped into the ForwardOpen.
    pub vendor_id: u16,
}

impl IoConnectionSpec {
    /// The requested on-wire size of a direction (§8.3): `data + sequence + header` per its format.
    fn on_wire_size(dir: &DirectionSpec) -> Result<u16> {
        let data = if dir.format.carries_data() {
            dir.data_size
        } else {
            0
        };
        let total = dir
            .format
            .overhead()
            .checked_add(data)
            .ok_or(EnipError::TooLarge {
                limit: usize::from(u16::MAX),
            })?;
        u16::try_from(total).map_err(|_| EnipError::TooLarge {
            limit: usize::from(u16::MAX),
        })
    }
}

// ---------------------------------------------------------------------------
// The pure connection state machine (§8.6–§8.8)
// ---------------------------------------------------------------------------

/// The negotiated parameters that construct an [`IoConnection`] — everything the runtime needs after
/// a successful ForwardOpen, in one struct so the constructor stays narrow and the state machine is
/// buildable directly in tests.
#[derive(Debug, Clone)]
pub struct IoConnectionParams {
    /// O→T connection id (target-assigned) — stamped on the frames we send.
    pub o2t_connection_id: u32,
    /// T→O connection id (originator-chosen) — the routing key on receive.
    pub t2o_connection_id: u32,
    /// Actual O→T packet interval (from the reply).
    pub o2t_api: Duration,
    /// Actual T→O packet interval (from the reply).
    pub t2o_api: Duration,
    /// The watchdog multiplier value (`4 << code`).
    pub timeout_multiplier: u32,
    /// O→T real-time format.
    pub o2t_format: RealTimeFormat,
    /// T→O real-time format.
    pub t2o_format: RealTimeFormat,
    /// Negotiated O→T application data size.
    pub o2t_data_size: usize,
    /// Negotiated T→O application data size.
    pub t2o_data_size: usize,
    /// Whether the O→T frame is fixed-length.
    pub o2t_fixed: bool,
    /// Whether the T→O frame is fixed-length.
    pub t2o_fixed: bool,
    /// Where O→T datagrams are sent (target :2222, or the O→T sockaddr redirect).
    pub tx_endpoint: SocketAddr,
    /// The **only** source IP whose datagrams this connection accepts (D-ENIP-24) — the target's
    /// own address, the one the TCP session was opened to. A T→O datagram from anywhere else is
    /// dropped and counted before the consume gauntlet, whether the stream is unicast or multicast
    /// (a multicast T→O frame still carries the producing device's unicast source IP).
    ///
    /// The source **port** is deliberately not part of this: a target's producing port is
    /// legitimately ephemeral.
    pub expected_source_ip: IpAddr,
    /// The T→O multicast group to join, when the reply carried a multicast T→O sockaddr.
    pub multicast_group: Option<Ipv4Addr>,
}

/// The socket-free class-1 connection state machine (§8.6–§8.8). All timing is driven by an explicit
/// `now`, so consume/produce/watchdog are unit-testable with crafted bytes and a paused clock.
#[derive(Debug)]
pub struct IoConnection {
    params: IoConnectionParams,
    // produce state
    o2t_class1_seq: u16,
    encap_seq: u32,
    output: Bytes,
    run: bool,
    next_produce_at: Instant,
    consecutive_send_errors: u32,
    // consume state
    last_accepted_seq: Option<u16>,
    up: bool,
    watchdog_deadline: Instant,
    counters: Arc<ConnCounters>,
}

impl IoConnection {
    /// Build a connection from its negotiated parameters, arming the first produce tick one O→T API
    /// out and the watchdog `timeout_multiplier × T2O_API` out from `now`.
    #[must_use]
    pub fn new(params: IoConnectionParams, now: Instant) -> Self {
        let next_produce_at = now.checked_add(params.o2t_api).unwrap_or(now);
        let watchdog_deadline = now
            .checked_add(watchdog_timeout(params.t2o_api, params.timeout_multiplier))
            .unwrap_or(now);
        Self {
            params,
            o2t_class1_seq: 0,
            encap_seq: 0,
            output: Bytes::new(),
            run: true,
            next_produce_at,
            consecutive_send_errors: 0,
            last_accepted_seq: None,
            up: false,
            watchdog_deadline,
            counters: Arc::new(ConnCounters::default()),
        }
    }

    /// The T→O connection id — the key the manager routes inbound datagrams by.
    #[must_use]
    pub fn connection_id(&self) -> u32 {
        self.params.t2o_connection_id
    }

    /// The negotiated `(O→T API, T→O API)` (§8.2 reply values).
    #[must_use]
    pub fn apis(&self) -> (Duration, Duration) {
        (self.params.o2t_api, self.params.t2o_api)
    }

    /// The transmit endpoint O→T frames are sent to.
    #[must_use]
    pub fn tx_endpoint(&self) -> SocketAddr {
        self.params.tx_endpoint
    }

    /// The only source IP whose T→O datagrams this connection accepts (D-ENIP-24).
    #[must_use]
    pub fn expected_source_ip(&self) -> IpAddr {
        self.params.expected_source_ip
    }

    /// The T→O multicast group to join, if any.
    #[must_use]
    pub fn multicast_group(&self) -> Option<Ipv4Addr> {
        self.params.multicast_group
    }

    /// A snapshot of this connection's counters (manager-wide fields are 0 here; the handle merges
    /// them in).
    #[must_use]
    pub fn stats(&self) -> IoStats {
        self.counters.snapshot()
    }

    /// Set the O→T output buffer (validated by the handle before it reaches here).
    pub fn set_output(&mut self, bytes: Bytes) {
        self.output = bytes;
    }

    /// Set the O→T run/idle bit (§8.7 / D-ENIP-9).
    pub fn set_run(&mut self, run: bool) {
        self.run = run;
    }

    /// Consume one connected-data payload for this connection (§8.6): strip the sequence + optional
    /// header per the T→O format, size-check against the negotiated size, then apply the signed
    /// forward-window sequence rule `(new − last) as i16 > 0`. Every reject is a counted, typed drop;
    /// an accepted frame refreshes the watchdog and yields an [`IoUpdate`].
    pub fn consume(
        &mut self,
        connected_data: &[u8],
        encap_sequence: u32,
        now: Instant,
    ) -> ConsumeOutcome {
        // Strip sequence + optional header. A runt frame is a typed drop, counted as a size mismatch.
        let frame = match IoFrame::decode(self.params.t2o_format, connected_data) {
            Ok(frame) => frame,
            Err(_) => {
                self.counters.size_mismatch.fetch_add(1, Ordering::Relaxed);
                return ConsumeOutcome::Dropped {
                    reason: DropReason::SizeMismatch,
                };
            }
        };

        // Size check against the negotiated T→O data size (§8.6).
        let len = frame.data.len();
        let bad = if self.params.t2o_fixed {
            len != self.params.t2o_data_size
        } else {
            len > self.params.t2o_data_size
        };
        if bad {
            self.counters.size_mismatch.fetch_add(1, Ordering::Relaxed);
            return ConsumeOutcome::Dropped {
                reason: DropReason::SizeMismatch,
            };
        }

        // Sequence acceptance: signed forward window (§8.6, D-ENIP-7).
        if let Some(seq) = frame.sequence {
            if let Some(last) = self.last_accepted_seq {
                let delta = seq.wrapping_sub(last) as i16;
                if delta <= 0 {
                    self.counters.stale_frames.fetch_add(1, Ordering::Relaxed);
                    return ConsumeOutcome::Dropped {
                        reason: DropReason::Stale,
                    };
                }
                if delta > 1 {
                    // A forward jump > 1 counts the gap (missed frames) but still accepts.
                    let gap = u64::from((delta as u16).saturating_sub(1));
                    self.counters
                        .sequence_gaps
                        .fetch_add(gap, Ordering::Relaxed);
                }
            }
            self.last_accepted_seq = Some(seq);
        }

        // Accepted: refresh the watchdog, deliver.
        let first = !self.up;
        self.up = true;
        self.watchdog_deadline = now
            .checked_add(watchdog_timeout(
                self.params.t2o_api,
                self.params.timeout_multiplier,
            ))
            .unwrap_or(now);
        self.counters
            .frames_accepted
            .fetch_add(1, Ordering::Relaxed);
        ConsumeOutcome::Accepted {
            first,
            update: IoUpdate {
                data: frame.data,
                sequence: frame.sequence.unwrap_or(0),
                encap_sequence,
                run_mode: frame.run_mode.unwrap_or(true),
                received_at: now,
            },
        }
    }

    /// Produce the next O→T datagram if a produce tick is due at `now` (§8.7). Honours the O→T API
    /// cadence with `MissedTickBehavior::Skip` semantics — a lapsed schedule fires **once** and
    /// counts the skipped ticks as `produce_overruns`. Returns `None` when no tick is due.
    /// Production never stops while the connection is open (D-ENIP-9): a heartbeat direction still
    /// emits the seq-only frame.
    ///
    /// The catch-up is **arithmetic, not a per-tick loop**: it is O(1) for any `o2t_api` and any
    /// lapse, and produces exactly the values the loop did (`skipped` = `ticks − 1`, the schedule
    /// re-armed at the first tick strictly after `now`). A zero `o2t_api` — which a target must
    /// never name, and [`validate_reply_apis`] rejects before it can reach here — degrades to the
    /// effective 1 ns floor below, i.e. at most one frame per scheduler tick, instead of spinning
    /// forever.
    ///
    /// In that degraded state the overrun **accounting** is clamped to at most one per call. The 1 ns
    /// floor is a liveness device, not a schedule: counting one overrun per nanosecond of lapse would
    /// put ~10⁹ imaginary skipped ticks per second on an operator-visible counter. "The schedule
    /// lapsed once this tick" is the honest statement. A non-zero API — every reply that survives
    /// [`validate_reply_apis`] — is counted exactly, unclamped.
    pub fn poll_produce(&mut self, now: Instant) -> Option<Result<Bytes>> {
        if now < self.next_produce_at {
            return None;
        }
        // The effective period never reaches zero: a pathological 0 µs API becomes 1 ns, which keeps
        // both the division below and the re-arming strictly monotone.
        let period = self.params.o2t_api.max(Duration::from_nanos(1));
        let period_ns = period.as_nanos().max(1);
        let elapsed = now.saturating_duration_since(self.next_produce_at);
        // Ticks strictly before this one that came and went unserviced.
        let skipped = elapsed.as_nanos().checked_div(period_ns).unwrap_or(0);
        // The re-arm below still uses the full `skipped` (the schedule really is that far behind);
        // only the reported count is clamped in the floored, scheduleless zero-API state.
        let counted = if self.params.o2t_api.is_zero() {
            skipped.min(1)
        } else {
            skipped
        };
        if counted > 0 {
            self.counters.produce_overruns.fetch_add(
                u64::try_from(counted).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        // Re-arm at `next_produce_at + (skipped + 1) × period` — the first tick strictly after `now`.
        // Any clamp or overflow on the way re-phases the schedule from `now` instead.
        let rearmed = u32::try_from(skipped.saturating_add(1))
            .ok()
            .and_then(|steps| period.checked_mul(steps))
            .and_then(|delta| self.next_produce_at.checked_add(delta));
        self.next_produce_at = match rearmed {
            Some(t) => t,
            None => now.checked_add(period).unwrap_or(now),
        };
        Some(self.produce_frame())
    }

    /// Account for the result of sending one produced O→T datagram (§8.7). `Ok` is the only path
    /// that advances `frames_produced` — the counter names frames that reached the socket, not
    /// frames that were built. Every failure increments `send_errors`; a per-datagram kind
    /// ([`is_per_datagram_error`]) leaves the streak alone (target liveness is the T→O watchdog's
    /// job, not the send path's), while any other kind extends it and declares the connection dead
    /// at [`MAX_CONSECUTIVE_SEND_ERRORS`].
    pub fn record_send(
        &mut self,
        result: core::result::Result<(), std::io::ErrorKind>,
    ) -> SendOutcome {
        match result {
            Ok(()) => {
                self.counters
                    .frames_produced
                    .fetch_add(1, Ordering::Relaxed);
                self.consecutive_send_errors = 0;
                SendOutcome::Sent
            }
            Err(kind) => {
                self.counters.send_errors.fetch_add(1, Ordering::Relaxed);
                if is_per_datagram_error(kind) {
                    return SendOutcome::Dropped;
                }
                self.consecutive_send_errors = self.consecutive_send_errors.saturating_add(1);
                if self.consecutive_send_errors >= MAX_CONSECUTIVE_SEND_ERRORS {
                    SendOutcome::ConnectionDead
                } else {
                    SendOutcome::Dropped
                }
            }
        }
    }

    /// Build one O→T datagram, advancing the class-1 sequence (skip 0 on wrap) and the encapsulation
    /// sequence (§8.7). Public so the produce logic is testable without the scheduler or a socket.
    ///
    /// Building a frame does **not** count it: `frames_produced` advances in
    /// [`IoConnection::record_send`], once the datagram has actually reached the socket. The
    /// sequences still advance here, so a failed send leaves a wire-visible sequence gap — which is
    /// exactly what the target's signed-window consumer is built to tolerate (it counts the gap and
    /// accepts the next frame), and is preferable to reusing a sequence the peer may already have.
    pub fn produce_frame(&mut self) -> Result<Bytes> {
        self.encap_seq = self.encap_seq.wrapping_add(1);
        self.o2t_class1_seq = self.o2t_class1_seq.wrapping_add(1);
        if self.o2t_class1_seq == 0 {
            self.o2t_class1_seq = 1; // class-1 sequence skips 0 on wrap (§8.7)
        }

        let format = self.params.o2t_format;
        let data = if format.carries_data() {
            self.output.clone()
        } else {
            Bytes::new()
        };
        let frame = IoFrame {
            sequence: if format.has_sequence() {
                Some(self.o2t_class1_seq)
            } else {
                None
            },
            run_mode: if format.has_header() {
                Some(self.run)
            } else {
                None
            },
            data,
        };
        let payload = frame.encode(format);
        let seq_addr = SequencedAddress {
            connection_id: self.params.o2t_connection_id,
            encap_sequence: self.encap_seq,
        };
        let cpf = Cpf::from_items(vec![
            CpfItem::new(ItemType::SequencedAddress, seq_addr.encode()),
            CpfItem::connected_data(payload),
        ]);
        cpf.encode().map_err(EnipError::Malformed)
    }

    /// Whether the watchdog has expired at `now` — no valid T→O frame within
    /// `timeout_multiplier × T2O_API` (§8.8, D-ENIP-8).
    #[must_use]
    pub fn poll_watchdog(&self, now: Instant) -> bool {
        now >= self.watchdog_deadline
    }

    /// The class-1 sequence value most recently produced (test/inspection).
    #[must_use]
    pub fn last_produced_sequence(&self) -> u16 {
        self.o2t_class1_seq
    }

    /// The encapsulation sequence most recently produced (test/inspection).
    #[must_use]
    pub fn last_encap_sequence(&self) -> u32 {
        self.encap_seq
    }
}

/// `timeout_multiplier × T2O_API`, saturating so a pathological product cannot panic (§8.8).
fn watchdog_timeout(t2o_api: Duration, multiplier: u32) -> Duration {
    t2o_api.checked_mul(multiplier).unwrap_or(Duration::MAX)
}

/// The outcome of [`IoConnection::consume`] (§8.6).
#[derive(Debug, Clone)]
pub enum ConsumeOutcome {
    /// The frame was accepted; `first` marks the first accepted frame (the `Up` trigger).
    Accepted {
        /// Whether this is the first accepted frame on the connection.
        first: bool,
        /// The delivered sample.
        update: IoUpdate,
    },
    /// The frame was dropped and counted.
    Dropped {
        /// Why it was dropped.
        reason: DropReason,
    },
}

// ---------------------------------------------------------------------------
// Datagram routing registry (§8.6)
// ---------------------------------------------------------------------------

/// The routing table the manager task drives: CPF-decode a datagram, look the connection up by its
/// sequenced-address connection id, check the datagram's source against that connection's target,
/// and hand the connected-data payload to that connection's [`IoConnection::consume`]. Datagram-level
/// drops (malformed shape, unknown id, source mismatch) are counted here; the per-connection drops
/// are counted inside `consume`.
struct Registry {
    conns: HashMap<u32, IoConnection>,
    stats: Arc<ManagerCounters>,
}

/// The result of routing one datagram (§8.6).
enum Routed {
    Accepted {
        connection_id: u32,
        first: bool,
        update: IoUpdate,
    },
    Dropped {
        connection_id: Option<u32>,
        reason: DropReason,
    },
}

impl Registry {
    fn new(stats: Arc<ManagerCounters>) -> Self {
        Self {
            conns: HashMap::new(),
            stats,
        }
    }

    /// Decode `buf` as a class-1 datagram, received from `src_ip`, and route it to its connection
    /// (§8.6). Every failure is a counted, typed drop — never a panic, whatever bytes arrive.
    fn consume_datagram(&mut self, buf: &[u8], src_ip: IpAddr, now: Instant) -> Routed {
        let cpf = match Cpf::decode(buf) {
            Ok(cpf) => cpf,
            Err(_) => {
                self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
                return Routed::Dropped {
                    connection_id: None,
                    reason: DropReason::Malformed,
                };
            }
        };
        let (Some(addr_item), Some(data_item)) = (
            cpf.find(ItemType::SequencedAddress),
            cpf.find(ItemType::ConnectedData),
        ) else {
            self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
            return Routed::Dropped {
                connection_id: None,
                reason: DropReason::Malformed,
            };
        };
        let addr = match SequencedAddress::decode(&addr_item.data) {
            Ok(addr) => addr,
            Err(_) => {
                self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
                return Routed::Dropped {
                    connection_id: None,
                    reason: DropReason::Malformed,
                };
            }
        };
        let Some(conn) = self.conns.get_mut(&addr.connection_id) else {
            self.stats
                .unknown_connection
                .fetch_add(1, Ordering::Relaxed);
            return Routed::Dropped {
                connection_id: Some(addr.connection_id),
                reason: DropReason::UnknownConnection,
            };
        };
        // Source filter (D-ENIP-24), between the routing lookup and the consume gauntlet. The
        // connection id is a routing key, not an authenticator: it travels in cleartext in every
        // frame, so anything on the segment can address a live connection with it — and an accepted
        // frame both delivers a sample and refreshes the watchdog, which is what makes a spoofed
        // stream able to hold a dead link "up". The target's IP is the one fact we already know
        // independently of the datagram (it is where the TCP session was opened), so it gates the
        // frame *before* it can touch any connection state. The port is not checked: a target's
        // producing port is legitimately ephemeral.
        //
        // Honestly scoped: this is OpENer-style hygiene ("coming from the originator") and defence
        // in depth, not an integrity control. Plaintext class-1 has no integrity by design, so an
        // on-segment attacker that can also spoof the target's source address still gets through —
        // CIP Security/DTLS is the real control. What it does buy is that a stray or misdirected
        // producer, and any off-path sender, can no longer inject samples or keep the watchdog fed.
        if src_ip != conn.expected_source_ip() {
            self.stats
                .source_mismatch_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return Routed::Dropped {
                connection_id: Some(addr.connection_id),
                reason: DropReason::SourceMismatch,
            };
        }
        match conn.consume(&data_item.data, addr.encap_sequence, now) {
            ConsumeOutcome::Accepted { first, update } => Routed::Accepted {
                connection_id: addr.connection_id,
                first,
                update,
            },
            ConsumeOutcome::Dropped { reason } => Routed::Dropped {
                connection_id: Some(addr.connection_id),
                reason,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The forward-open session seam (§3.2 dependency inversion)
// ---------------------------------------------------------------------------

/// The session capability [`IoManager`] needs to open and close I/O connections: issue a
/// Connection-Manager request (ForwardOpen / ForwardClose) over the owning TCP session's UCMM path
/// and return the full reply CPF (so the caller can read both the Message Router reply and any
/// Sockaddr Info items, §8.2). Defined here — below `client` in the layering — and implemented by
/// [`crate::client::EipClient`], so `io` never imports upward (§3.2).
pub trait ForwardOpenService {
    /// Send a Connection-Manager `MessageRequest` over UCMM and return the reply CPF item list.
    /// `extra_items` are appended to the request CPF after the null-address + unconnected-data pair —
    /// the class-1 ForwardOpen uses this to carry the O→T / T→O **Sockaddr Info items** (§8.2) that
    /// tell the target which UDP endpoint the originator receives T→O on (ForwardClose passes none).
    fn cm_ucmm(
        &self,
        request: MessageRequest,
        extra_items: Vec<CpfItem>,
    ) -> impl core::future::Future<Output = Result<Cpf>> + Send;

    /// The target device's IP, used as the default O→T transmit address when the reply carries no
    /// O→T sockaddr redirect. `None` for a non-socket session (in-memory test fixtures).
    fn target_ip(&self) -> Option<IpAddr>;
}

// ---------------------------------------------------------------------------
// The manager task & handle (§8.6, §11.1)
// ---------------------------------------------------------------------------

/// A command from a handle (or `forward_open`) to the manager task.
///
/// `Add` and the confirmed form of `SetOutput` carry a `oneshot` acknowledgement (D-ENIP-20): the
/// manager's verdict travels back to the caller instead of being inferred from the fact that a
/// message was queued. Arming a connection can fail *inside* the task (the multicast join), and
/// staging an output can be aimed at a connection the task has already removed — neither is
/// knowable from the send side.
enum ManagerCommand {
    Add {
        conn: Box<IoConnection>,
        events_tx: IoEventSender,
        /// Armed-or-not verdict: `Ok(())` once the connection is registered (and any multicast
        /// group joined); `Err` carries the join failure. Never silent.
        ack: oneshot::Sender<Result<()>>,
    },
    SetOutput {
        connection_id: u32,
        bytes: Bytes,
        /// The caller's absolute deadline, carried to the **only** place that mutates the producer
        /// buffer (D-ENIP-20). A command whose deadline has passed is dropped there rather than
        /// staged: its caller has already been told the write failed. `None` is a caller with no
        /// deadline ([`IoConnectionHandle::set_output`] / [`IoConnectionHandle::stage_output`]).
        deadline: Option<Instant>,
        /// `None` preserves the fire-and-forget [`IoConnectionHandle::set_output`]; `Some` is the
        /// confirmed path ([`IoConnectionHandle::stage_output`]).
        ack: Option<oneshot::Sender<Result<()>>>,
    },
    SetRun {
        connection_id: u32,
        run: bool,
    },
    Remove {
        connection_id: u32,
    },
    Shutdown,
}

/// The class-1 I/O manager (§8.6, §11.1): one bound UDP socket, one task that receives datagrams and
/// routes them to their connection, and a scheduler tick that drives produce + watchdog. Cheap to
/// clone the command sender; `forward_open` returns an [`IoConnectionHandle`] per connection.
#[derive(Clone)]
pub struct IoManager {
    tx: mpsc::Sender<ManagerCommand>,
    local_addr: SocketAddr,
    stats: Arc<ManagerCounters>,
}

impl IoManager {
    /// Bind the implicit-I/O UDP socket at `addr` and spawn the socket task (§8.6). The task owns
    /// the socket; this handle owns only the command channel.
    ///
    /// An **originator** binds an ephemeral port (`"0.0.0.0:0"`) and lets [`Self::forward_open`]
    /// advertise it to the target in the Sockaddr Info items, so it never contends for the
    /// registered port with a target on the same host; only a **target**-role consumer binds
    /// [`IO_UDP_PORT`] (`"0.0.0.0:2222"`) to be reachable there.
    pub async fn bind(addr: impl tokio::net::ToSocketAddrs) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let stats = Arc::new(ManagerCounters::default());
        let (tx, rx) = mpsc::channel(MANAGER_COMMAND_DEPTH);
        tokio::spawn(manager_task(socket, rx, stats.clone()));
        Ok(Self {
            tx,
            local_addr,
            stats,
        })
    }

    /// The bound local socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Open a class-1 I/O connection against a target's assembly instances (§8.2) via a ForwardOpen
    /// over `session`, then register it with the socket task and return its handle. The connection
    /// ids and **actual** packet intervals come from the ForwardOpen reply (§8.2), not the request.
    /// A refusal is [`EnipError::ForwardOpenRejected`].
    ///
    /// **Post-condition: when this returns `Ok`, the connection is armed** (D-ENIP-20) — the socket
    /// task has registered it and has joined any multicast T→O group, so a datagram arriving
    /// immediately after cannot be dropped as `unknown_connection`. The wait for that verdict is
    /// causal, not timed: the manager task either services its queue or has exited, and both
    /// complete the await.
    ///
    /// **Invariant: any failure after a successful ForwardOpen issues a best-effort ForwardClose**
    /// ([`best_effort_forward_close`]) before the typed error propagates. Past the target's success
    /// reply the target believes a connection is open and will produce into it until its own
    /// watchdog expires; every way this function can still fail — a reply that fails echo
    /// verification or API validation, an unresolvable O→T transmit endpoint, a multicast T→O
    /// sockaddr on a connection that did not request multicast T→O, a multicast group the socket
    /// could not join, a manager task that has already exited — leaves that same stranded
    /// connection, so all of them tear it down.
    pub async fn forward_open<S: ForwardOpenService>(
        &self,
        session: &S,
        spec: IoConnectionSpec,
    ) -> Result<IoConnectionHandle> {
        let t2o_connection_id = rand::random::<u32>() | 1;
        let connection_serial = rand::random::<u16>() | 1;
        let originator_serial = rand::random::<u32>();

        let open = build_class1_open(
            &spec,
            t2o_connection_id,
            connection_serial,
            originator_serial,
        )?;
        let mr = MessageRequest::new(open.service(), connection_manager_path(), open.encode()?);
        // Advertise the UDP endpoint the originator receives T→O on, and sends O→T from, via the
        // O→T (0x8000) + T→O (0x8001) Sockaddr Info items (§8.2). Targets take the T→O item's port as
        // the destination for the frames they produce; without it a target defaults to the standard
        // implicit-I/O port 2222, which collides with our own socket when scanner and target share a
        // host. `sin_addr` = 0 (INADDR_ANY): a point-to-point target sends to the TCP-peer IP and
        // ignores this field, so the connection's IP is used.
        let recv_port = self.local_addr.port();
        let sock_o2t = SockAddrInfo::ipv4(0, recv_port).encode();
        let sock_t2o = SockAddrInfo::ipv4(0, recv_port).encode();
        let extra_items = vec![
            CpfItem::new(ItemType::SockAddrOtoT, sock_o2t),
            CpfItem::new(ItemType::SockAddrTtoO, sock_t2o),
        ];
        let reply_cpf = session.cm_ucmm(mr, extra_items).await?;

        let data_item =
            reply_cpf
                .find(ItemType::UnconnectedData)
                .ok_or(EnipError::ProtocolViolation {
                    detail: "forward-open reply missing data item",
                })?;
        let reply = MessageReply::decode(&data_item.data).map_err(EnipError::Malformed)?;
        reply.expect_service(open.service())?;
        if !reply.status.is_ok() {
            let fail = ForwardRequestFail::decode(&reply.data).ok();
            return Err(EnipError::ForwardOpenRejected {
                status: reply.status,
                remaining_path_size: fail.and_then(|f| f.remaining_path_size),
            });
        }
        let success = ForwardOpenSuccess::decode(&reply.data).map_err(EnipError::Malformed)?;

        // The reply is verified BEFORE anything is armed (§8.2, D-ENIP-16): the originator echo quad
        // must match the request, and both actual packet intervals must be usable timer values. A
        // reply that fails either check still left the target believing a connection is open, so a
        // best-effort ForwardClose goes out before the typed error propagates.
        if let Err(e) = verify_forward_open_echo(&open, &success) {
            best_effort_forward_close(session, &open).await;
            return Err(e);
        }
        let (o2t_api, t2o_api) = match validate_reply_apis(&success) {
            Ok(apis) => apis,
            Err(e) => {
                best_effort_forward_close(session, &open).await;
                return Err(e);
            }
        };

        // Sockaddr items (§8.2, D-ENIP-17): an O→T sockaddr may retarget our transmit **port**, never
        // its address; a T→O multicast sockaddr is the group to join, and only on a connection whose
        // T→O direction was requested multicast.
        let o2t_sock = reply_cpf
            .find(ItemType::SockAddrOtoT)
            .and_then(|i| SockAddrInfo::decode(&i.data).ok());
        let t2o_sock = reply_cpf
            .find(ItemType::SockAddrTtoO)
            .and_then(|i| SockAddrInfo::decode(&i.data).ok());
        // Same invariant as the two verification failures above: the target already answered with a
        // success, so an endpoint we cannot address still leaves a connection open on its side.
        let (tx_endpoint, disposition) = match resolve_tx_endpoint(o2t_sock, session.target_ip()) {
            Ok(resolved) => resolved,
            Err(e) => {
                best_effort_forward_close(session, &open).await;
                return Err(e);
            }
        };
        // A refused redirect is not fatal (the port is still honoured), but it IS the one silent
        // failure mode left in D-ENIP-17: a device that requires the redirect to receive outputs and
        // never enforces its own O→T inactivity watchdog keeps producing T→O, so the adapter reports
        // the link healthy while its outputs go nowhere. Counted per connection so the adapter can
        // surface it (`refusedRedirects`, `io-redirect-refused`).
        let redirect_refused = matches!(disposition, TxEndpointDisposition::RefusedForeign(_));
        if let TxEndpointDisposition::RefusedForeign(refused) = disposition {
            tracing::warn!(
                %refused,
                endpoint = %tx_endpoint,
                "forward-open reply pointed the O→T stream at a foreign address; \
                 address refused, sockaddr port honoured"
            );
        }
        // A multicast T→O sockaddr on a connection that did not request multicast T→O is a protocol
        // violation, not a group to join — same teardown invariant as every other post-success
        // failure.
        let multicast_group = match resolve_multicast_group(t2o_sock, spec.t2o.conn_type) {
            Ok(group) => group,
            Err(e) => {
                best_effort_forward_close(session, &open).await;
                return Err(e);
            }
        };

        let params = IoConnectionParams {
            o2t_connection_id: success.o_t_connection_id,
            t2o_connection_id,
            o2t_api,
            t2o_api,
            timeout_multiplier: spec.timeout_multiplier.multiplier(),
            o2t_format: spec.o2t.format,
            t2o_format: spec.t2o.format,
            o2t_data_size: spec.o2t.data_size,
            t2o_data_size: spec.t2o.data_size,
            o2t_fixed: matches!(spec.o2t.variable, VariableLength::Fixed),
            t2o_fixed: matches!(spec.t2o.variable, VariableLength::Fixed),
            tx_endpoint,
            // The transmit endpoint's ADDRESS is the target's by construction — `resolve_tx_endpoint`
            // fails when the session has no known target address and refuses any redirect that names
            // a different one (D-ENIP-17), so its address half is exactly `session.target_ip()`. That
            // makes it the receive-side filter (D-ENIP-24) without a second, separately-derivable
            // notion of "the target" that could drift from the one we transmit to.
            expected_source_ip: tx_endpoint.ip(),
            multicast_group,
        };
        let conn = IoConnection::new(params, Instant::now());
        let counters = conn.counters.clone();
        if redirect_refused {
            counters.refused_redirects.store(1, Ordering::Relaxed);
        }
        let (events_tx, events_rx) = io_event_channel(EVENT_CHANNEL_DEPTH, counters.clone());

        // Arming is acknowledged (D-ENIP-20). A send failure means the manager task has exited, so
        // nothing will ever service this connection; an `Err` verdict means the task refused to arm
        // it (the multicast join failed); a dropped ack sender means the task died mid-command. In
        // all three the target is already producing into a connection nobody owns, so the same
        // best-effort teardown runs before the typed error propagates.
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .tx
            .send(ManagerCommand::Add {
                conn: Box::new(conn),
                events_tx,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            best_effort_forward_close(session, &open).await;
            return Err(EnipError::Closed);
        }
        match ack_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                best_effort_forward_close(session, &open).await;
                return Err(e);
            }
            Err(_manager_gone) => {
                best_effort_forward_close(session, &open).await;
                return Err(EnipError::Closed);
            }
        }

        Ok(IoConnectionHandle {
            connection_id: t2o_connection_id,
            events: events_rx,
            cmd: self.tx.clone(),
            counters,
            manager_stats: self.stats.clone(),
            o2t_data_size: spec.o2t.data_size,
            o2t_fixed: matches!(spec.o2t.variable, VariableLength::Fixed),
            o2t_carries_data: spec.o2t.format.carries_data(),
            o2t_api,
            t2o_api,
            open_request: open,
        })
    }

    /// Shut the socket task down (drops the socket and every connection).
    pub async fn shutdown(&self) {
        let _ = self.tx.send(ManagerCommand::Shutdown).await;
    }
}

/// A handle to one open class-1 connection (§11.2). Exposes the event stream, output/run setters, a
/// counter snapshot, and a graceful close (ForwardClose + registry removal).
pub struct IoConnectionHandle {
    connection_id: u32,
    events: IoEventReceiver,
    cmd: mpsc::Sender<ManagerCommand>,
    counters: Arc<ConnCounters>,
    manager_stats: Arc<ManagerCounters>,
    o2t_data_size: usize,
    o2t_fixed: bool,
    o2t_carries_data: bool,
    o2t_api: Duration,
    t2o_api: Duration,
    open_request: ForwardOpenRequest,
}

/// The operation name [`EnipError::Timeout`] carries when an output-staging deadline runs out —
/// on the handoff, on the verdict, or at the producer buffer itself (D-ENIP-20).
const OUTPUT_STAGING: &str = "output staging";

/// Await `f`, bounded by `deadline` when the caller set one. `None` = the deadline passed first.
///
/// `tokio::time::timeout_at` polls `f` before the timer, so a future that is already complete wins
/// even at an expired deadline — the answer is never thrown away in favour of the clock.
async fn by<F: core::future::Future>(deadline: Option<Instant>, f: F) -> Option<F::Output> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, f).await.ok(),
        None => Some(f.await),
    }
}

impl IoConnectionHandle {
    /// The T→O connection id (the routing key).
    #[must_use]
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// The negotiated `(O→T API, T→O API)`.
    #[must_use]
    pub fn apis(&self) -> (Duration, Duration) {
        (self.o2t_api, self.t2o_api)
    }

    /// The event stream (`Up`, `Data`, `Lost`) — a bounded, latest-wins receiver (§11.2, §8.6). A
    /// consumer that falls behind loses the OLDEST samples (counted as `overflowed_events`), never
    /// the freshest ones and never `Up`/`Lost`.
    pub fn events(&mut self) -> &mut IoEventReceiver {
        &mut self.events
    }

    /// Validate a candidate O→T buffer against the negotiated O→T size (§8.7). A fixed-size
    /// connection requires an exact match; a variable-size one caps at the negotiated size. Shared
    /// by [`set_output`](Self::set_output) and [`stage_output`](Self::stage_output) so the two
    /// paths can never drift apart on what a legal buffer is.
    fn validate_output(&self, bytes: &Bytes) -> Result<()> {
        if self.o2t_carries_data {
            if self.o2t_fixed && bytes.len() != self.o2t_data_size {
                return Err(EnipError::ProtocolViolation {
                    detail: "output size does not match the negotiated fixed O→T size",
                });
            }
            if bytes.len() > self.o2t_data_size {
                return Err(EnipError::TooLarge {
                    limit: self.o2t_data_size,
                });
            }
        }
        Ok(())
    }

    /// Set the O→T output buffer, validated against the negotiated O→T size (§8.7). A fixed-size
    /// connection requires an exact match; a variable-size one caps at the negotiated size.
    ///
    /// **Unconfirmed** (§11.2): `Ok` says the command was queued for the manager task, not that the
    /// buffer was accepted — a connection the task has already removed swallows it. Callers that
    /// must know the buffer will ride a frame use [`stage_output`](Self::stage_output).
    pub fn set_output(&self, bytes: impl Into<Bytes>) -> Result<()> {
        let bytes = bytes.into();
        self.validate_output(&bytes)?;
        self.cmd
            .try_send(ManagerCommand::SetOutput {
                connection_id: self.connection_id,
                bytes,
                deadline: None,
                ack: None,
            })
            .map_err(|_| EnipError::Closed)
    }

    /// Stage the O→T output buffer and confirm the manager accepted it for a live connection
    /// (D-ENIP-20). Same validation as [`set_output`](Self::set_output); the difference is the
    /// verdict — this awaits the manager task's answer instead of assuming one.
    ///
    /// Unbounded: it waits as long as the manager takes. A caller that must not wait past a
    /// deadline uses [`stage_output_by`](Self::stage_output_by), which also guarantees the buffer
    /// is not staged after that deadline.
    ///
    /// # Errors
    ///
    /// [`EnipError::ProtocolViolation`] / [`EnipError::TooLarge`] when the buffer does not fit the
    /// negotiated O→T size, and [`EnipError::Closed`] when the manager task has shut down or no
    /// longer holds this connection (lost or closed) — in that case the buffer will never ride a
    /// frame. The wait is causal: the manager either answers or is gone.
    pub async fn stage_output(&self, bytes: impl Into<Bytes>) -> Result<()> {
        self.stage(bytes.into(), None).await
    }

    /// Stage the O→T output buffer under an **absolute deadline** (D-ENIP-20): the handoff to the
    /// manager, the wait for its verdict, and the staging decision itself all live inside
    /// `deadline`.
    ///
    /// The deadline travels *with* the command, so the manager drops an expired one instead of
    /// mutating the producer buffer with it. That is what makes the refusal safe to act on: a
    /// caller told `Err(Timeout)` knows the value cannot appear in a later O→T frame, which a
    /// caller-side timer alone can never promise — the command it abandoned is still queued.
    ///
    /// # Errors
    ///
    /// As [`stage_output`](Self::stage_output), plus [`EnipError::Timeout`] when the deadline
    /// passes before the manager accepts the buffer.
    pub async fn stage_output_by(&self, bytes: impl Into<Bytes>, deadline: Instant) -> Result<()> {
        self.stage(bytes.into(), Some(deadline)).await
    }

    /// The shared body of the two confirmed staging paths: validate, hand the command to the
    /// manager, and return its verdict — each await bounded by `deadline` when there is one.
    async fn stage(&self, bytes: Bytes, deadline: Option<Instant>) -> Result<()> {
        self.validate_output(&bytes)?;
        let (ack_tx, ack_rx) = oneshot::channel();
        let queued = self.cmd.send(ManagerCommand::SetOutput {
            connection_id: self.connection_id,
            bytes,
            deadline,
            ack: Some(ack_tx),
        });
        by(deadline, queued)
            .await
            .ok_or(EnipError::Timeout { op: OUTPUT_STAGING })?
            .map_err(|_| EnipError::Closed)?;
        by(deadline, ack_rx)
            .await
            .ok_or(EnipError::Timeout { op: OUTPUT_STAGING })?
            .map_err(|_manager_gone| EnipError::Closed)?
    }

    /// Set the O→T run/idle bit (§8.7 / D-ENIP-9).
    pub fn set_run(&self, run: bool) -> Result<()> {
        self.cmd
            .try_send(ManagerCommand::SetRun {
                connection_id: self.connection_id,
                run,
            })
            .map_err(|_| EnipError::Closed)
    }

    /// A snapshot of this connection's counters merged with the manager-wide datagram counters
    /// (§10.2).
    #[must_use]
    pub fn stats(&self) -> IoStats {
        let mut s = self.counters.snapshot();
        s.malformed_frames = self.manager_stats.malformed_frames.load(Ordering::Relaxed);
        s.unknown_connection = self
            .manager_stats
            .unknown_connection
            .load(Ordering::Relaxed);
        s.recv_errors = self.manager_stats.recv_errors.load(Ordering::Relaxed);
        s.source_mismatch_datagrams = self
            .manager_stats
            .source_mismatch_datagrams
            .load(Ordering::Relaxed);
        s
    }

    /// Gracefully close the connection (§8.8): a best-effort ForwardClose over `session`, then
    /// removal from the socket task (which aborts the produce timer and leaves any multicast group).
    pub async fn close<S: ForwardOpenService>(&self, session: &S) -> Result<()> {
        let close = ForwardCloseRequest::for_open(&self.open_request);
        let mr = MessageRequest::new(
            crate::cm::service::FORWARD_CLOSE,
            connection_manager_path(),
            close.encode()?,
        );
        // Best-effort: the target may already consider the connection dead.
        let _ = session.cm_ucmm(mr, Vec::new()).await;
        let _ = self
            .cmd
            .send(ManagerCommand::Remove {
                connection_id: self.connection_id,
            })
            .await;
        Ok(())
    }
}

/// Tear down a connection the target believes it opened but we did not arm (§8.2, §8.8). Every
/// step is best-effort: the encode, the round trip, and the reply status are all discarded — the
/// caller is on its way out with a typed error and must not have that error replaced by this one.
async fn best_effort_forward_close<S: ForwardOpenService>(session: &S, open: &ForwardOpenRequest) {
    let close = ForwardCloseRequest::for_open(open);
    if let Ok(data) = close.encode() {
        let mr = MessageRequest::new(
            crate::cm::service::FORWARD_CLOSE,
            connection_manager_path(),
            data,
        );
        let _ = session.cm_ucmm(mr, Vec::new()).await;
    }
}

/// Build the class-1 ForwardOpen from the spec, sizing each direction and route-prefixing the path.
fn build_class1_open(
    spec: &IoConnectionSpec,
    t2o_connection_id: u32,
    connection_serial: u16,
    originator_serial: u32,
) -> Result<ForwardOpenRequest> {
    let o2t_size = IoConnectionSpec::on_wire_size(&spec.o2t)?;
    let t2o_size = IoConnectionSpec::on_wire_size(&spec.t2o)?;
    let large = o2t_size > LARGE_FORWARD_OPEN_THRESHOLD || t2o_size > LARGE_FORWARD_OPEN_THRESHOLD;

    let o2t_params = NetworkConnectionParams::io(
        o2t_size,
        spec.o2t.variable,
        spec.o2t.priority,
        spec.o2t.conn_type,
    );
    let t2o_params = NetworkConnectionParams::io(
        t2o_size,
        spec.t2o.variable,
        spec.t2o.priority,
        spec.t2o.conn_type,
    );

    let o2t_rpi = duration_to_micros(spec.o2t.rpi)?;
    let t2o_rpi = duration_to_micros(spec.t2o.rpi)?;

    let mut path = io_connection_path(
        spec.assembly.config,
        spec.assembly.output,
        spec.assembly.input,
    );
    // Prefix route port segments so the ForwardOpen reaches a chassis-backed target (§8.4).
    for seg in spec.assembly.route.iter().rev() {
        path.prepend(Segment::Port(seg.clone()));
    }

    Ok(ForwardOpenRequest::class1(
        t2o_connection_id,
        connection_serial,
        spec.vendor_id,
        originator_serial,
        spec.timeout_multiplier,
        o2t_rpi,
        o2t_params,
        t2o_rpi,
        t2o_params,
        transport_class1_trigger(spec.trigger),
        path,
        large,
    ))
}

/// A `Duration` as microseconds in a `u32` RPI field (§8.2), or [`EnipError::TooLarge`].
fn duration_to_micros(d: Duration) -> Result<u32> {
    u32::try_from(d.as_micros()).map_err(|_| EnipError::TooLarge {
        limit: u32::MAX as usize,
    })
}

/// How the O→T Sockaddr Info item of a ForwardOpen reply was treated (§8.2, D-ENIP-17). The
/// endpoint that comes with it is always addressed at the target; this says what the reply asked
/// for, so the caller can log a refusal without the classifier doing I/O of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxEndpointDisposition {
    /// No O→T sockaddr in the reply — the target IP on :2222.
    Direct,
    /// The sockaddr named `0.0.0.0` (INADDR_ANY): its port applies, the target supplies the address.
    PortOnly,
    /// The sockaddr named the target's own address: honoured as written.
    Honored,
    /// The sockaddr named a **different** address. It is refused (the enclosed address is never
    /// transmitted to); only the port is taken.
    RefusedForeign(IpAddr),
}

/// Resolve the O→T transmit endpoint (§8.2, D-ENIP-17). **The address is always the target's**: a
/// ForwardOpen reply may retarget the port, never the destination host. A sockaddr naming any other
/// address — foreign unicast, broadcast, multicast, loopback — has its address refused and its port
/// kept, because honouring it would let a target aim our cyclic O→T stream at a third party. With no
/// known target address there is nothing to address and nothing to compare against, so a redirect
/// can never be honoured on that path: it is [`EnipError::ProtocolViolation`].
fn resolve_tx_endpoint(
    o2t_sock: Option<SockAddrInfo>,
    target_ip: Option<IpAddr>,
) -> Result<(SocketAddr, TxEndpointDisposition)> {
    let target = target_ip.ok_or(EnipError::ProtocolViolation {
        detail: "no O→T transmit address available",
    })?;
    let Some(s) = o2t_sock else {
        return Ok((
            SocketAddr::new(target, IO_UDP_PORT),
            TxEndpointDisposition::Direct,
        ));
    };
    let sock_ip = Ipv4Addr::from(s.sin_addr);
    let port = if s.sin_port != 0 {
        s.sin_port
    } else {
        IO_UDP_PORT
    };
    let disposition = if sock_ip.is_unspecified() {
        TxEndpointDisposition::PortOnly
    } else if IpAddr::V4(sock_ip) == target {
        TxEndpointDisposition::Honored
    } else {
        TxEndpointDisposition::RefusedForeign(IpAddr::V4(sock_ip))
    };
    Ok((SocketAddr::new(target, port), disposition))
}

/// Resolve the T→O multicast group from the reply's T→O sockaddr (§8.2–§8.3, D-ENIP-17).
///
/// A group is joined **only** when the ForwardOpen requested `ConnType::Multicast` for T→O. A
/// multicast sockaddr answering any other request is a protocol violation: the originator asked for
/// a private stream, and joining an arbitrary group on the target's say-so subscribes the scanner to
/// traffic it never requested. The violation names the type that *was* requested, so a null
/// (reconfigure) request is not misreported as a point-to-point one. A requested-multicast
/// connection whose reply carries a unicast or absent T→O sockaddr simply consumes unicast — no
/// group, no error.
fn resolve_multicast_group(
    t2o_sock: Option<SockAddrInfo>,
    requested_t2o: ConnType,
) -> Result<Option<Ipv4Addr>> {
    let Some(s) = t2o_sock else { return Ok(None) };
    let ip = Ipv4Addr::from(s.sin_addr);
    if !ip.is_multicast() {
        return Ok(None);
    }
    let detail = match requested_t2o {
        ConnType::Multicast => return Ok(Some(ip)),
        ConnType::P2P => "multicast T→O sockaddr on a point-to-point request",
        ConnType::Null => "multicast T→O sockaddr on a null (reconfigure) request",
    };
    Err(EnipError::ProtocolViolation { detail })
}

/// Has a carried staging deadline already passed (D-ENIP-20)? A command with no deadline never
/// expires.
fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

/// The socket task (§8.6, §11.1): receive datagrams and route them; drive produce + watchdog on a
/// scheduler tick. Thin — all tested logic lives in [`IoConnection`] / [`Registry`].
async fn manager_task(
    socket: UdpSocket,
    mut rx: mpsc::Receiver<ManagerCommand>,
    stats: Arc<ManagerCounters>,
) {
    let mut registry = Registry::new(stats);
    let mut events: HashMap<u32, IoEventSender> = HashMap::new();
    let mut buf = vec![0u8; 65_535];
    let mut recv_policy = RecvErrorPolicy::default();
    let mut tick = tokio::time::interval(SCHEDULER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    None | Some(ManagerCommand::Shutdown) => break,
                    Some(ManagerCommand::Add { conn, events_tx, ack }) => {
                        let id = conn.connection_id();
                        if let Some(group) = conn.multicast_group() {
                            if let Err(e) = socket.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED) {
                                // The join is load-bearing (D-ENIP-20): without membership the T→O
                                // stream never arrives and the operator would see only a delayed
                                // watchdog timeout instead of the interface error. Refuse to arm.
                                tracing::warn!(
                                    %group,
                                    error = %e,
                                    "class-1 multicast join failed; refusing to arm the connection"
                                );
                                let _ = ack.send(Err(EnipError::Io(e)));
                                continue;
                            }
                        }
                        registry.conns.insert(id, *conn);
                        events.insert(id, events_tx);
                        if ack.send(Ok(())).is_err() {
                            // The opener vanished between send and ack (its future was cancelled):
                            // nothing owns this connection, so unregister it — leaving any group —
                            // rather than produce O→T into it forever.
                            remove_connection(&socket, &mut registry, &mut events, id);
                        }
                    }
                    Some(ManagerCommand::SetOutput { connection_id, bytes, deadline, ack }) => {
                        let verdict = match registry.conns.get_mut(&connection_id) {
                            // This is the ONLY place a producer buffer is mutated, so it is where
                            // an expired command has to die (D-ENIP-20). A caller whose deadline
                            // ran out has already been told its write failed; staging the buffer
                            // now would put a refused value on the next O→T frame. The command is
                            // still in the queue precisely because something was slow, so the
                            // check belongs here rather than only at the send side.
                            Some(_) if expired(deadline) => {
                                Err(EnipError::Timeout { op: OUTPUT_STAGING })
                            }
                            Some(conn) => { conn.set_output(bytes); Ok(()) }
                            // The connection was removed (lost or closed): the buffer will never
                            // ride a frame, and a confirmed caller must be told so.
                            None => Err(EnipError::Closed),
                        };
                        if let Some(ack) = ack {
                            let _ = ack.send(verdict);
                        }
                    }
                    Some(ManagerCommand::SetRun { connection_id, run }) => {
                        if let Some(conn) = registry.conns.get_mut(&connection_id) {
                            conn.set_run(run);
                        }
                    }
                    Some(ManagerCommand::Remove { connection_id }) => {
                        remove_connection(&socket, &mut registry, &mut events, connection_id);
                    }
                }
            }
            recv = socket.recv_from(&mut buf) => {
                match recv {
                    Ok((n, src)) => {
                        recv_policy.on_recv_ok();
                        let now = Instant::now();
                        if let Some(slice) = buf.get(..n) {
                            match registry.consume_datagram(slice, src.ip(), now) {
                                Routed::Accepted { connection_id, first, update } => {
                                    deliver(&registry, &events, connection_id, first, update);
                                }
                                Routed::Dropped { connection_id, reason } => {
                                    // The registry already counted the drop; trace names it for the
                                    // operator without spending a metric on every hostile packet.
                                    tracing::trace!(?connection_id, ?reason, "dropped class-1 datagram");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Never silent (§8.6): every socket error is counted, then classified.
                        registry.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
                        match recv_policy.on_recv_error(e.kind()) {
                            RecvErrorAction::Continue => {
                                tracing::debug!(error = %e, "class-1 recv error (survivable)");
                            }
                            RecvErrorAction::FatalSocket => {
                                tracing::warn!(
                                    error = %e,
                                    "class-1 udp socket declared dead; losing every connection"
                                );
                                fan_out_lost(&mut registry, &mut events, &socket, LostReason::Io);
                                break;
                            }
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                // One collection for both terminal causes: the watchdog (Timeout) and a dead
                // transmit path (Io), so a single emit/remove loop handles either.
                let mut expired: Vec<(u32, LostReason)> = Vec::new();
                for (id, conn) in registry.conns.iter_mut() {
                    let send_result = match conn.poll_produce(now) {
                        Some(Ok(datagram)) => Some(
                            socket
                                .send_to(&datagram, conn.tx_endpoint())
                                .await
                                .map(|_sent| ())
                                .map_err(|e| e.kind()),
                        ),
                        // An encode failure is accounted like a send failure so a connection that
                        // can never build a frame is not silently mute forever.
                        Some(Err(_encode)) => Some(Err(std::io::ErrorKind::InvalidData)),
                        None => None,
                    };
                    if let Some(result) = send_result {
                        if conn.record_send(result) == SendOutcome::ConnectionDead {
                            expired.push((*id, LostReason::Io));
                            continue;
                        }
                    }
                    if conn.poll_watchdog(now) {
                        expired.push((*id, LostReason::Timeout));
                    }
                }
                for (id, reason) in expired {
                    if let Some(tx) = events.get(&id) {
                        // `Lost` is a control event: it is never evicted by a full queue, so the
                        // typed reason survives even a flooded consumer (§8.6).
                        tx.send(IoEvent::Lost { reason });
                    }
                    remove_connection(&socket, &mut registry, &mut events, id);
                }
            }
        }
    }
}

/// Deliver an accepted sample to its connection's stream: an `Up` on the first frame, then the
/// `Data`. A queue at its `Data` capacity evicts its OLDEST sample to admit this one — latest-wins,
/// counted as `overflowed_events` by the sender (§8.6).
fn deliver(
    registry: &Registry,
    events: &HashMap<u32, IoEventSender>,
    connection_id: u32,
    first: bool,
    update: IoUpdate,
) {
    let Some(tx) = events.get(&connection_id) else {
        return;
    };
    if first {
        if let Some(conn) = registry.conns.get(&connection_id) {
            let (o2t_api, t2o_api) = conn.apis();
            tx.send(IoEvent::Up { o2t_api, t2o_api });
        }
    }
    tx.send(IoEvent::Data(update));
}

/// Lose **every** registered connection with one reason (§8.6): the shared socket is dead, so no
/// connection on it can survive. Each consumer gets the `Lost` — a control event, never evicted by a
/// full queue — and then has its stream closed by the removal; the stream ending is the
/// authoritative terminal signal, so even a consumer that never drains learns the connection is
/// gone.
fn fan_out_lost(
    registry: &mut Registry,
    events: &mut HashMap<u32, IoEventSender>,
    socket: &UdpSocket,
    reason: LostReason,
) {
    let ids: Vec<u32> = registry.conns.keys().copied().collect();
    for id in ids {
        if let Some(tx) = events.get(&id) {
            tx.send(IoEvent::Lost { reason });
        }
        remove_connection(socket, registry, events, id);
    }
}

/// Remove a connection: leave its multicast group and drop its state + event sender.
fn remove_connection(
    socket: &UdpSocket,
    registry: &mut Registry,
    events: &mut HashMap<u32, IoEventSender>,
    connection_id: u32,
) {
    if let Some(conn) = registry.conns.remove(&connection_id) {
        if let Some(group) = conn.multicast_group() {
            let _ = socket.leave_multicast_v4(group, Ipv4Addr::UNSPECIFIED);
        }
    }
    events.remove(&connection_id);
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

    // -- test builders ------------------------------------------------------

    fn params(o2t_format: RealTimeFormat, t2o_format: RealTimeFormat) -> IoConnectionParams {
        IoConnectionParams {
            o2t_connection_id: 0xAABB_CCDD,
            t2o_connection_id: 0x1122_3344,
            o2t_api: Duration::from_millis(20),
            t2o_api: Duration::from_millis(20),
            timeout_multiplier: 16,
            o2t_format,
            t2o_format,
            o2t_data_size: 4,
            t2o_data_size: 8,
            o2t_fixed: true,
            t2o_fixed: true,
            tx_endpoint: SocketAddr::new(TARGET_IP, IO_UDP_PORT),
            expected_source_ip: TARGET_IP,
            multicast_group: None,
        }
    }

    /// The target address every in-module fixture connection is opened against — its transmit
    /// destination and, by D-ENIP-24, the only source its T→O datagrams may carry.
    const TARGET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

    /// A source IP that is **not** the fixture target: the spoofer / stray producer.
    const FOREIGN_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));

    /// A T→O connected-data payload with the given class-1 sequence and `data`, modeless (no header).
    fn modeless_payload(seq: u16, data: &[u8]) -> Vec<u8> {
        let mut v = seq.to_le_bytes().to_vec();
        v.extend_from_slice(data);
        v
    }

    /// A full class-1 datagram (CPF) for connection id `cid`, encap seq `eseq`, carrying `payload`.
    fn datagram(cid: u32, eseq: u32, payload: &[u8]) -> Vec<u8> {
        let cpf = Cpf::from_items(vec![
            CpfItem::new(
                ItemType::SequencedAddress,
                SequencedAddress {
                    connection_id: cid,
                    encap_sequence: eseq,
                }
                .encode(),
            ),
            CpfItem::connected_data(Bytes::copy_from_slice(payload)),
        ]);
        cpf.encode().unwrap().to_vec()
    }

    // -- frame codec / D-ENIP-10 order -------------------------------------

    #[test]
    fn frame_order_is_sequence_then_header_then_data() {
        // Header32Bit: [u16 seq][u32 run/idle][data] — sequence FIRST (D-ENIP-10).
        let frame = IoFrame {
            sequence: Some(0x0005),
            run_mode: Some(true),
            data: Bytes::from_static(&[0xAA, 0xBB]),
        };
        let bytes = frame.encode(RealTimeFormat::Header32Bit);
        assert_eq!(
            bytes.as_ref(),
            &[0x05, 0x00, /* seq */ 0x01, 0x00, 0x00, 0x00, /* run header */ 0xAA, 0xBB]
        );
        // Round-trips.
        assert_eq!(
            IoFrame::decode(RealTimeFormat::Header32Bit, &bytes).unwrap(),
            frame
        );

        // Idle header has bit 0 clear.
        let idle = IoFrame {
            sequence: Some(1),
            run_mode: Some(false),
            data: Bytes::new(),
        };
        let ib = idle.encode(RealTimeFormat::Header32Bit);
        assert_eq!(ib.as_ref(), &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            IoFrame::decode(RealTimeFormat::Header32Bit, &ib)
                .unwrap()
                .run_mode,
            Some(false)
        );

        // Modeless: seq then data, no header.
        let m = IoFrame {
            sequence: Some(7),
            run_mode: None,
            data: Bytes::from_static(&[1, 2, 3]),
        };
        let mb = m.encode(RealTimeFormat::Modeless);
        assert_eq!(mb.as_ref(), &[0x07, 0x00, 1, 2, 3]);
        assert_eq!(IoFrame::decode(RealTimeFormat::Modeless, &mb).unwrap(), m);
    }

    #[test]
    fn runt_frame_is_typed_drop_never_panic() {
        // A 1-byte buffer cannot hold the 2-byte sequence — Truncated, not a panic.
        assert!(IoFrame::decode(RealTimeFormat::Modeless, &[0x00]).is_err());
        // Header32Bit needs 6 bytes minimum; 3 is a runt.
        assert!(IoFrame::decode(RealTimeFormat::Header32Bit, &[0, 0, 0]).is_err());
    }

    // -- consume gauntlet: every §8.6 drop counter -------------------------

    #[tokio::test]
    async fn accepts_first_then_forward_frames_and_counts_gap() {
        let now = Instant::now();
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );

        // First frame (seq 1) → accepted, first == true.
        let out = conn.consume(&modeless_payload(1, &[0u8; 8]), 100, now);
        assert!(matches!(out, ConsumeOutcome::Accepted { first: true, .. }));
        assert_eq!(conn.stats().frames_accepted, 1);

        // Forward by 1 (seq 2) → accepted, no gap.
        assert!(matches!(
            conn.consume(&modeless_payload(2, &[0u8; 8]), 101, now),
            ConsumeOutcome::Accepted { first: false, .. }
        ));
        assert_eq!(conn.stats().sequence_gaps, 0);

        // Forward jump seq 2 → 5 (gap of 2) → accepted, sequence_gaps += 2.
        assert!(matches!(
            conn.consume(&modeless_payload(5, &[0u8; 8]), 102, now),
            ConsumeOutcome::Accepted { .. }
        ));
        assert_eq!(conn.stats().sequence_gaps, 2);
        assert_eq!(conn.stats().frames_accepted, 3);
    }

    #[tokio::test]
    async fn duplicate_and_stale_and_reordered_are_dropped_and_counted() {
        let now = Instant::now();
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        conn.consume(&modeless_payload(10, &[0u8; 8]), 1, now); // accept seq 10

        // Duplicate (seq 10): (10-10) as i16 == 0, not > 0 → stale.
        assert!(matches!(
            conn.consume(&modeless_payload(10, &[0u8; 8]), 2, now),
            ConsumeOutcome::Dropped {
                reason: DropReason::Stale
            }
        ));
        // Stale (seq 9): negative delta → stale.
        assert!(matches!(
            conn.consume(&modeless_payload(9, &[0u8; 8]), 3, now),
            ConsumeOutcome::Dropped {
                reason: DropReason::Stale
            }
        ));
        // Reordered old (seq 5): negative delta → stale.
        assert!(matches!(
            conn.consume(&modeless_payload(5, &[0u8; 8]), 4, now),
            ConsumeOutcome::Dropped {
                reason: DropReason::Stale
            }
        ));
        assert_eq!(conn.stats().stale_frames, 3);

        // A valid forward frame after the drops is still accepted.
        assert!(matches!(
            conn.consume(&modeless_payload(11, &[0u8; 8]), 5, now),
            ConsumeOutcome::Accepted { .. }
        ));
        assert_eq!(conn.stats().frames_accepted, 2);
    }

    #[tokio::test]
    async fn wrong_size_frame_is_dropped_and_counted() {
        let now = Instant::now();
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        // Negotiated T→O data size is 8; deliver 4 bytes → size mismatch.
        assert!(matches!(
            conn.consume(&modeless_payload(1, &[0u8; 4]), 1, now),
            ConsumeOutcome::Dropped {
                reason: DropReason::SizeMismatch
            }
        ));
        // A runt (no room for the sequence) → also a size-mismatch drop, never a panic.
        assert!(matches!(
            conn.consume(&[0x00], 2, now),
            ConsumeOutcome::Dropped {
                reason: DropReason::SizeMismatch
            }
        ));
        assert_eq!(conn.stats().size_mismatch, 2);
        // A correctly-sized frame is then accepted.
        assert!(matches!(
            conn.consume(&modeless_payload(1, &[0u8; 8]), 3, now),
            ConsumeOutcome::Accepted { .. }
        ));
    }

    #[tokio::test]
    async fn unknown_connection_and_malformed_datagrams_are_counted_by_registry() {
        let now = Instant::now();
        let stats = Arc::new(ManagerCounters::default());
        let mut registry = Registry::new(stats.clone());
        let conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        let cid = conn.connection_id();
        registry.conns.insert(cid, conn);

        // Unknown connection id 0xDEADBEEF.
        let unknown = datagram(0xDEAD_BEEF, 1, &modeless_payload(1, &[0u8; 8]));
        assert!(matches!(
            registry.consume_datagram(&unknown, TARGET_IP, now),
            Routed::Dropped {
                reason: DropReason::UnknownConnection,
                ..
            }
        ));
        assert_eq!(stats.unknown_connection.load(Ordering::Relaxed), 1);

        // Malformed CPF (garbage bytes that are not a valid item list).
        assert!(matches!(
            registry.consume_datagram(&[0xFF, 0xFF, 0xFF], TARGET_IP, now),
            Routed::Dropped {
                reason: DropReason::Malformed,
                ..
            }
        ));
        assert!(stats.malformed_frames.load(Ordering::Relaxed) >= 1);

        // The known connection still accepts a valid datagram after the drops.
        let good = datagram(cid, 1, &modeless_payload(1, &[0u8; 8]));
        assert!(matches!(
            registry.consume_datagram(&good, TARGET_IP, now),
            Routed::Accepted { first: true, .. }
        ));
    }

    /// **D-ENIP-24, at the routing layer.** A datagram that is perfect in every other respect —
    /// well-formed CPF, the live connection's id, the next sequence — is dropped and counted when
    /// its source IP is not the connection's target, and it reaches the consume gauntlet not at
    /// all: no sample, no sequence acceptance, and (the load-bearing half) **no watchdog refresh**,
    /// so a spoofed stream cannot hold a dead link up.
    #[tokio::test]
    async fn a_datagram_from_a_foreign_source_is_dropped_counted_and_never_consumed() {
        let now = Instant::now();
        let stats = Arc::new(ManagerCounters::default());
        let mut registry = Registry::new(stats.clone());
        let conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        let cid = conn.connection_id();
        let armed_deadline = conn.watchdog_deadline;
        registry.conns.insert(cid, conn);

        let frame = datagram(cid, 1, &modeless_payload(1, &[0u8; 8]));
        // Later than `now`, so a refresh would be observable as a moved deadline.
        let later = now
            .checked_add(Duration::from_millis(50))
            .expect("instant in range");
        assert!(matches!(
            registry.consume_datagram(&frame, FOREIGN_IP, later),
            Routed::Dropped {
                reason: DropReason::SourceMismatch,
                connection_id: Some(id),
            } if id == cid
        ));
        assert_eq!(stats.source_mismatch_datagrams.load(Ordering::Relaxed), 1);
        // Not counted as anything else, and nothing reached `consume`.
        assert_eq!(stats.malformed_frames.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unknown_connection.load(Ordering::Relaxed), 0);
        let conn = registry.conns.get(&cid).expect("connection still live");
        assert_eq!(conn.stats().frames_accepted, 0);
        assert_eq!(conn.stats().stale_frames, 0);
        assert_eq!(conn.stats().size_mismatch, 0);
        assert_eq!(
            conn.watchdog_deadline, armed_deadline,
            "a refused datagram must not feed the watchdog"
        );

        // The very same bytes from the target are accepted — the filter is on the source alone.
        assert!(matches!(
            registry.consume_datagram(&frame, TARGET_IP, later),
            Routed::Accepted { first: true, .. }
        ));
        assert_eq!(stats.source_mismatch_datagrams.load(Ordering::Relaxed), 1);
        let conn = registry.conns.get(&cid).expect("connection still live");
        assert!(
            conn.watchdog_deadline > armed_deadline,
            "an accepted datagram does feed the watchdog"
        );
    }

    /// **D-ENIP-24, port independence.** A target's producing port is legitimately ephemeral, so
    /// only the IP is compared: the same source address on a different port is still accepted.
    #[tokio::test]
    async fn the_source_filter_compares_the_ip_and_not_the_port() {
        let now = Instant::now();
        let stats = Arc::new(ManagerCounters::default());
        let mut registry = Registry::new(stats.clone());
        let conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        let cid = conn.connection_id();
        // The connection transmits to the target on IO_UDP_PORT; the datagram below arrives from
        // the same address on an ephemeral one.
        assert_eq!(conn.tx_endpoint().port(), IO_UDP_PORT);
        assert_eq!(conn.expected_source_ip(), TARGET_IP);
        registry.conns.insert(cid, conn);

        let ephemeral = SocketAddr::new(TARGET_IP, 51_234);
        let frame = datagram(cid, 1, &modeless_payload(1, &[0u8; 8]));
        assert!(matches!(
            registry.consume_datagram(&frame, ephemeral.ip(), now),
            Routed::Accepted { first: true, .. }
        ));
        assert_eq!(stats.source_mismatch_datagrams.load(Ordering::Relaxed), 0);
    }

    // -- watchdog (D-ENIP-8), paused clock ---------------------------------

    #[tokio::test(start_paused = true)]
    async fn watchdog_fires_once_after_multiplier_times_t2o_api() {
        let now = Instant::now();
        // T2O API 20 ms × multiplier 16 = 320 ms deadline.
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        assert!(!conn.poll_watchdog(now));

        // Just before the deadline → not expired.
        tokio::time::advance(Duration::from_millis(319)).await;
        assert!(!conn.poll_watchdog(Instant::now()));

        // At/after the deadline → expired.
        tokio::time::advance(Duration::from_millis(2)).await;
        assert!(conn.poll_watchdog(Instant::now()));

        // An accepted frame refreshes the deadline (watchdog survives while data flows).
        let refreshed = Instant::now();
        conn.consume(&modeless_payload(1, &[0u8; 8]), 1, refreshed);
        assert!(!conn.poll_watchdog(refreshed));
        tokio::time::advance(Duration::from_millis(319)).await;
        assert!(!conn.poll_watchdog(Instant::now()));
        tokio::time::advance(Duration::from_millis(2)).await;
        assert!(conn.poll_watchdog(Instant::now()));
    }

    // -- produce cadence + heartbeat (D-ENIP-9), paused clock --------------

    #[tokio::test(start_paused = true)]
    async fn produce_fires_at_o2t_api_incrementing_sequences() {
        let now = Instant::now();
        // O→T Header32Bit with data; first tick one API out.
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Header32Bit, RealTimeFormat::Modeless),
            now,
        );
        conn.set_output(Bytes::from_static(&[1, 2, 3, 4]));

        // Nothing due yet.
        assert!(conn.poll_produce(now).is_none());

        // Advance one O→T API (20 ms) → one frame, seq 1 / encap 1.
        tokio::time::advance(Duration::from_millis(20)).await;
        let d1 = conn.poll_produce(Instant::now()).unwrap().unwrap();
        // Only a frame that reaches the socket counts (§8.7) — the manager reports that back here.
        assert_eq!(conn.record_send(Ok(())), SendOutcome::Sent);
        assert_eq!(conn.last_produced_sequence(), 1);
        assert_eq!(conn.last_encap_sequence(), 1);
        // Decode the produced datagram: sequenced address + connected data (seq then header then data).
        let cpf = Cpf::decode(&d1).unwrap();
        let addr =
            SequencedAddress::decode(&cpf.find(ItemType::SequencedAddress).unwrap().data).unwrap();
        assert_eq!(addr.connection_id, 0xAABB_CCDD);
        assert_eq!(addr.encap_sequence, 1);
        let frame = IoFrame::decode(
            RealTimeFormat::Header32Bit,
            &cpf.find(ItemType::ConnectedData).unwrap().data,
        )
        .unwrap();
        assert_eq!(frame.sequence, Some(1));
        assert_eq!(frame.run_mode, Some(true));
        assert_eq!(frame.data.as_ref(), &[1, 2, 3, 4]);

        // Advance another API → seq 2 / encap 2.
        tokio::time::advance(Duration::from_millis(20)).await;
        conn.poll_produce(Instant::now()).unwrap().unwrap();
        assert_eq!(conn.record_send(Ok(())), SendOutcome::Sent);
        assert_eq!(conn.last_produced_sequence(), 2);
        assert_eq!(conn.last_encap_sequence(), 2);
        // Each produced datagram (data or heartbeat) counts toward frames_produced (§8.7).
        assert_eq!(conn.stats().frames_produced, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_size_o2t_still_heartbeats() {
        let now = Instant::now();
        let mut p = params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless);
        p.o2t_data_size = 0;
        let mut conn = IoConnection::new(p, now);

        tokio::time::advance(Duration::from_millis(20)).await;
        let d = conn.poll_produce(Instant::now()).unwrap().unwrap();
        let cpf = Cpf::decode(&d).unwrap();
        let frame = IoFrame::decode(
            RealTimeFormat::Heartbeat,
            &cpf.find(ItemType::ConnectedData).unwrap().data,
        )
        .unwrap();
        // Heartbeat: sequence present, no data.
        assert_eq!(frame.sequence, Some(1));
        assert!(frame.data.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn missed_produce_ticks_count_overruns() {
        let now = Instant::now();
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        // Jump three API periods at once: one fire, two skipped.
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(conn.poll_produce(Instant::now()).is_some());
        assert_eq!(conn.record_send(Ok(())), SendOutcome::Sent);
        assert_eq!(conn.stats().produce_overruns, 2);
        // Only one frame was produced despite three periods elapsing.
        assert_eq!(conn.last_encap_sequence(), 1);
        assert_eq!(
            conn.stats().frames_produced,
            1,
            "one fire despite two skipped ticks"
        );
    }

    // -- forward-open sizing / trigger -------------------------------------

    #[test]
    fn on_wire_size_accounts_for_sequence_and_header() {
        // Modeless T→O of 8 bytes data → 2 (seq) + 8 = 10.
        let t2o = DirectionSpec {
            rpi: Duration::from_millis(20),
            data_size: 8,
            format: RealTimeFormat::Modeless,
            conn_type: ConnType::P2P,
            priority: Priority::Scheduled,
            variable: VariableLength::Fixed,
        };
        assert_eq!(IoConnectionSpec::on_wire_size(&t2o).unwrap(), 10);
        // Header32Bit O→T of 4 bytes → 2 (seq) + 4 (header) + 4 = 10.
        let o2t = DirectionSpec {
            format: RealTimeFormat::Header32Bit,
            data_size: 4,
            ..t2o.clone()
        };
        assert_eq!(IoConnectionSpec::on_wire_size(&o2t).unwrap(), 10);
        // Heartbeat O→T size 0 → 2 (seq only).
        let hb = DirectionSpec {
            format: RealTimeFormat::Heartbeat,
            data_size: 0,
            ..t2o
        };
        assert_eq!(IoConnectionSpec::on_wire_size(&hb).unwrap(), 2);
    }

    #[test]
    fn build_open_produces_class1_trigger_and_sized_ncp() {
        let spec = IoConnectionSpec {
            assembly: AssemblyPath {
                config: Some(151),
                output: 150,
                input: 100,
                route: vec![],
            },
            t2o: DirectionSpec {
                rpi: Duration::from_millis(20),
                data_size: 32,
                format: RealTimeFormat::Modeless,
                conn_type: ConnType::P2P,
                priority: Priority::Scheduled,
                variable: VariableLength::Fixed,
            },
            o2t: DirectionSpec {
                rpi: Duration::from_millis(20),
                data_size: 4,
                format: RealTimeFormat::Header32Bit,
                conn_type: ConnType::P2P,
                priority: Priority::Scheduled,
                variable: VariableLength::Fixed,
            },
            timeout_multiplier: TimeoutMultiplier::X16,
            trigger: ProductionTrigger::Cyclic,
            vendor_id: 0x1337,
        };
        let open = build_class1_open(&spec, 0x1122_3344, 7, 0xDEAD_BEEF).unwrap();
        assert_eq!(open.transport_class_trigger, 0x01);
        assert!(!open.large);
        // O→T on-wire = 2+4+4 = 10; T→O on-wire = 2+32 = 34.
        assert_eq!(open.o_t_params.size, 10);
        assert_eq!(open.t_o_params.size, 34);
        // The class-1 open leaves O→T id 0 for the target to assign.
        assert_eq!(open.o_t_connection_id, 0);
        assert_eq!(open.t_o_connection_id, 0x1122_3344);
    }

    /// **Redirect hardening (D-ENIP-17).** A reply's O→T sockaddr may move the transmit *port*,
    /// never the transmit *address*: honouring a foreign address would let a target aim our cyclic
    /// O→T stream at an arbitrary victim (a reflection/amplification primitive). The previous
    /// behaviour — "a concrete address in the reply wins" — is exactly that hole.
    #[tokio::test]
    async fn tx_endpoint_refuses_a_foreign_o2t_redirect_port_only() {
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        // A foreign unicast address: refused, its port kept.
        let sa = SockAddrInfo::ipv4(0xC0A8_0164, 0x08AE); // 192.168.1.100:2222
        let (ep, how) = resolve_tx_endpoint(Some(sa), Some(target)).unwrap();
        assert_eq!(
            ep,
            SocketAddr::new(target, 2222),
            "we transmit to the target, on the named port"
        );
        assert_eq!(
            how,
            TxEndpointDisposition::RefusedForeign(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
        // The port really does follow the sockaddr — the refusal is address-only.
        let (ep_port, _) =
            resolve_tx_endpoint(Some(SockAddrInfo::ipv4(0xC0A8_0164, 4444)), Some(target)).unwrap();
        assert_eq!(ep_port, SocketAddr::new(target, 4444));
        // Broadcast, multicast, and loopback redirects are refused by the same rule.
        for addr in [0xFFFF_FFFF, 0xEFC0_0001, 0x7F00_0001] {
            let (ep, how) =
                resolve_tx_endpoint(Some(SockAddrInfo::ipv4(addr, 0x08AE)), Some(target)).unwrap();
            assert_eq!(
                ep.ip(),
                target,
                "{addr:#010x} must not become a transmit target"
            );
            assert!(
                matches!(how, TxEndpointDisposition::RefusedForeign(_)),
                "{addr:#010x}"
            );
        }
        // A foreign redirect with no known target address is unresolvable, never honoured.
        assert!(resolve_tx_endpoint(Some(sa), None).is_err());

        // End to end: the refusal is not fatal — the connection still opens (no ForwardClose), it
        // just keeps transmitting to the target.
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000).with_o2t_sock(sa);
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        assert_eq!(
            handle.apis(),
            (Duration::from_millis(20), Duration::from_millis(20))
        );
        assert_eq!(
            fixture.requests().len(),
            1,
            "a refused redirect does not tear the connection down"
        );
        mgr.shutdown().await;
    }

    /// The guard against over-tightening: the three legitimate sockaddr shapes keep working, and an
    /// endpoint that cannot be addressed is still a typed error rather than a panic.
    #[test]
    fn tx_endpoint_keeps_zero_addr_and_same_addr_behavior() {
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // 0.0.0.0 (INADDR_ANY): the target supplies the address, the sockaddr the port.
        let (ep0, how0) =
            resolve_tx_endpoint(Some(SockAddrInfo::ipv4(0, 0x08AE)), Some(target)).unwrap();
        assert_eq!(ep0, SocketAddr::new(target, 2222));
        assert_eq!(how0, TxEndpointDisposition::PortOnly);
        // A zero port still falls back to the standard implicit-I/O port.
        let (ep_zero_port, _) =
            resolve_tx_endpoint(Some(SockAddrInfo::ipv4(0, 0)), Some(target)).unwrap();
        assert_eq!(ep_zero_port, SocketAddr::new(target, IO_UDP_PORT));
        // The target's own address: honoured as written.
        let (ep_same, how_same) =
            resolve_tx_endpoint(Some(SockAddrInfo::ipv4(0x0A00_0001, 4444)), Some(target)).unwrap();
        assert_eq!(ep_same, SocketAddr::new(target, 4444));
        assert_eq!(how_same, TxEndpointDisposition::Honored);
        // No sockaddr → the target IP on :2222.
        let (ep1, how1) = resolve_tx_endpoint(None, Some(target)).unwrap();
        assert_eq!(ep1, SocketAddr::new(target, IO_UDP_PORT));
        assert_eq!(how1, TxEndpointDisposition::Direct);
        // No sockaddr and no target IP → a typed error, never a panic.
        assert!(resolve_tx_endpoint(None, None).is_err());
    }

    /// **Multicast-join hardening (D-ENIP-17).** A multicast T→O sockaddr answering a request that
    /// did not ask for multicast T→O is a protocol violation: we asked for a private stream, so a
    /// target must not be able to subscribe our socket to an arbitrary group. The connection the
    /// target believes it opened is torn down on the way out, and the violation names the type that
    /// was actually requested rather than assuming point-to-point.
    #[tokio::test]
    async fn p2p_request_refuses_a_multicast_t2o_sockaddr() {
        // The pure decision.
        let group = SockAddrInfo::ipv4(0xEFC0_0001, 0x08AE); // 239.192.0.1:2222
        match resolve_multicast_group(Some(group), ConnType::P2P) {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(detail, "multicast T→O sockaddr on a point-to-point request");
            }
            other => panic!("expected a protocol violation, got {other:?}"),
        }
        // A null (reconfigure) request is refused by the same rule, and reported as what it is.
        match resolve_multicast_group(Some(group), ConnType::Null) {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(
                    detail,
                    "multicast T→O sockaddr on a null (reconfigure) request"
                );
            }
            other => panic!("expected a protocol violation, got {other:?}"),
        }

        // End to end: `sample_spec()` requests P2P, so the forged reply fails the open.
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000).with_t2o_sock(group);
        match mgr.forward_open(&fixture, sample_spec()).await {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(detail, "multicast T→O sockaddr on a point-to-point request");
            }
            other => panic!(
                "expected a protocol violation, got {:?}",
                other.map(|h| h.apis())
            ),
        }
        assert_forward_closed(&fixture.requests());
        mgr.shutdown().await;
    }

    /// The other side of the same rule: a connection that *asked* for multicast T→O joins the group
    /// the reply names, and a unicast or absent T→O sockaddr simply means unicast consumption — no
    /// group, no error.
    #[tokio::test]
    async fn multicast_request_joins_only_a_valid_multicast_group() {
        let group = SockAddrInfo::ipv4(0xEFC0_0001, 0x08AE); // 239.192.0.1:2222
        let unicast = SockAddrInfo::ipv4(0xC0A8_0164, 0x08AE); // 192.168.1.100:2222
        assert_eq!(
            resolve_multicast_group(Some(group), ConnType::Multicast).unwrap(),
            Some(Ipv4Addr::new(239, 192, 0, 1)),
            "the requested-multicast connection records the group"
        );
        assert_eq!(
            resolve_multicast_group(Some(unicast), ConnType::Multicast).unwrap(),
            None
        );
        assert_eq!(
            resolve_multicast_group(None, ConnType::Multicast).unwrap(),
            None
        );
        assert_eq!(
            resolve_multicast_group(Some(unicast), ConnType::P2P).unwrap(),
            None
        );
        assert_eq!(resolve_multicast_group(None, ConnType::P2P).unwrap(), None);

        // End to end: a multicast-requested spec opens against either reply.
        let spec = || IoConnectionSpec {
            t2o: DirectionSpec {
                conn_type: ConnType::Multicast,
                ..sample_spec().t2o
            },
            ..sample_spec()
        };
        for sock in [group, unicast] {
            let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
            let fixture = FoFixture::new(None, 20_000, 20_000).with_t2o_sock(sock);
            let handle = mgr.forward_open(&fixture, spec()).await.unwrap();
            assert_eq!(
                handle.apis(),
                (Duration::from_millis(20), Duration::from_millis(20))
            );
            assert_eq!(
                fixture.requests().len(),
                1,
                "no ForwardClose on the happy path"
            );
            mgr.shutdown().await;
        }
    }

    // -- produce catch-up is arithmetic, not a loop (F1 regression) ---------

    /// **Livelock regression.** A ForwardOpen reply naming a 0 µs O→T API used to spin the catch-up
    /// loop forever (it advanced `next` by zero every iteration), wedging the manager task and every
    /// connection on the socket. The test *completing* is the assertion.
    #[tokio::test(start_paused = true)]
    async fn poll_produce_zero_api_terminates_and_degrades_to_tick_cadence() {
        let now = Instant::now();
        let mut p = params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless);
        p.o2t_api = Duration::ZERO;
        let mut conn = IoConnection::new(p, now);
        let armed = conn.next_produce_at;

        tokio::time::advance(Duration::from_millis(10)).await;
        let at = Instant::now();
        assert!(conn.poll_produce(at).is_some(), "a tick is due");
        assert!(
            conn.stats().produce_overruns > 0,
            "the lapsed ticks are counted"
        );
        assert!(
            conn.next_produce_at > armed,
            "the schedule advanced despite the zero period"
        );
        // Degraded to at most one frame per scheduler tick, not an unbounded burst.
        assert!(conn.poll_produce(at).is_none());

        // **Counter-inflation regression.** The 1 ns floor is a liveness device, not a schedule:
        // the 10 ms lapse above must read as one lapse, not 10 million skipped ticks. The clamp is
        // per call, so the counter can never outrun the number of firing polls.
        assert_eq!(conn.stats().produce_overruns, 1, "one lapse, counted once");
        let mut fires = 1u64;
        for _ in 0..5 {
            tokio::time::advance(SCHEDULER_TICK).await;
            if conn.poll_produce(Instant::now()).is_some() {
                fires = fires.saturating_add(1);
            }
            assert!(
                conn.stats().produce_overruns <= fires,
                "at most one overrun per firing poll, got {} over {fires} fires",
                conn.stats().produce_overruns
            );
        }
        assert!(
            fires > 1,
            "the degraded connection keeps producing on the tick cadence"
        );
    }

    /// A huge lapse against a tiny period is O(1): the old loop would have run ~864 million
    /// iterations here. The overrun count must equal what that loop would have produced.
    #[tokio::test(start_paused = true)]
    async fn poll_produce_catchup_is_constant_time_after_huge_lapse() {
        let now = Instant::now();
        let period = MIN_REPLY_API; // 100 µs — the smallest API a reply may legally name
        let mut p = params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless);
        p.o2t_api = period;
        let mut conn = IoConnection::new(p, now);

        // The first tick is armed one period out, so the lapse past it is `lapse - period`.
        let lapse = Duration::from_secs(24 * 3600);
        tokio::time::advance(lapse).await;
        let expected_skipped =
            u64::try_from((lapse.as_nanos() - period.as_nanos()) / period.as_nanos()).unwrap();

        assert!(conn.poll_produce(Instant::now()).is_some());
        assert_eq!(conn.stats().produce_overruns, expected_skipped);
        assert_eq!(
            conn.stats().frames_produced,
            0,
            "nothing was sent, only built"
        );
    }

    /// The arithmetic form must be indistinguishable from the loop for ordinary periods: fire at
    /// exactly one API, no overruns; a three-period jump fires once, counts two, re-arms at 3p.
    #[tokio::test(start_paused = true)]
    async fn poll_produce_semantics_unchanged_for_normal_periods() {
        let start = Instant::now();
        let period = Duration::from_millis(20);
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            start,
        );

        assert!(conn.poll_produce(start).is_none());
        tokio::time::advance(Duration::from_millis(19)).await;
        assert!(
            conn.poll_produce(Instant::now()).is_none(),
            "not due one ms early"
        );

        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(
            conn.poll_produce(Instant::now()).is_some(),
            "due at exactly one API"
        );
        assert_eq!(conn.stats().produce_overruns, 0);
        assert_eq!(conn.next_produce_at, start + period * 2);

        // Three periods pass unserviced: one fire, two counted skips, re-armed at the next period.
        tokio::time::advance(period * 3).await;
        assert!(conn.poll_produce(Instant::now()).is_some());
        assert_eq!(conn.stats().produce_overruns, 2);
        assert_eq!(conn.next_produce_at, start + period * 5);
        assert!(
            conn.poll_produce(Instant::now()).is_none(),
            "the schedule is re-armed ahead"
        );
    }

    // -- reply-API validation (F1) -----------------------------------------

    #[test]
    fn validate_reply_apis_bounds() {
        fn reply(o_t_api: u32, t_o_api: u32) -> ForwardOpenSuccess {
            ForwardOpenSuccess {
                o_t_connection_id: 1,
                t_o_connection_id: 2,
                connection_serial: 3,
                vendor_id: 4,
                originator_serial: 5,
                o_t_api,
                t_o_api,
                app_data: Bytes::new(),
            }
        }
        const IN_RANGE: u32 = 20_000; // 20 ms
        const MAX_US: u32 = 600_000_000; // 600 s

        // Each direction is bounded independently: a good partner never rescues a bad value.
        for &bad in &[0u32, 99, MAX_US + 1] {
            assert!(
                validate_reply_apis(&reply(bad, IN_RANGE)).is_err(),
                "o→t {bad} µs"
            );
            assert!(
                validate_reply_apis(&reply(IN_RANGE, bad)).is_err(),
                "t→o {bad} µs"
            );
        }
        for &good in &[100u32, IN_RANGE, MAX_US] {
            assert!(validate_reply_apis(&reply(good, good)).is_ok(), "{good} µs");
        }
        assert_eq!(
            validate_reply_apis(&reply(100, MAX_US)).unwrap(),
            (MIN_REPLY_API, MAX_REPLY_API)
        );
        match validate_reply_apis(&reply(0, IN_RANGE)) {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(detail, "forward-open reply API out of range");
            }
            other => panic!("expected a protocol violation, got {other:?}"),
        }
    }

    // -- send accounting (F6, the io.rs frames_produced regression) --------

    #[test]
    fn record_send_counts_only_successful_sends() {
        use std::io::ErrorKind;
        let now = Instant::now();
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );

        // Building a frame does not count it; only the send does.
        let _ = conn.produce_frame().unwrap();
        assert_eq!(conn.stats().frames_produced, 0);
        assert_eq!(conn.record_send(Ok(())), SendOutcome::Sent);
        assert_eq!(conn.stats().frames_produced, 1);

        // A per-datagram failure is counted but never advances frames_produced, and never
        // contributes to the death streak (target liveness is the T→O watchdog's job).
        for _ in 0..10 {
            assert_eq!(
                conn.record_send(Err(ErrorKind::ConnectionReset)),
                SendOutcome::Dropped
            );
        }
        assert_eq!(
            conn.stats().frames_produced,
            1,
            "a failed send is not a produced frame"
        );
        assert_eq!(conn.stats().send_errors, 10);

        // Three consecutive non-survivable failures declare the connection dead.
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::ConnectionDead
        );
        assert_eq!(conn.stats().send_errors, 13);

        // An interleaved success resets the streak.
        let mut conn = IoConnection::new(
            params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless),
            now,
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(conn.record_send(Ok(())), SendOutcome::Sent);
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::Dropped
        );
        assert_eq!(
            conn.record_send(Err(ErrorKind::AddrNotAvailable)),
            SendOutcome::ConnectionDead
        );
        assert_eq!(conn.stats().frames_produced, 1);
        assert_eq!(conn.stats().send_errors, 5);
    }

    // -- recv-error classification (F6, the io.rs silent-`if let Ok` regression) --

    #[test]
    fn recv_error_policy_matrix() {
        use std::io::ErrorKind;
        // Exactly the survivable set: a datagram died, the socket did not.
        const PER_DATAGRAM: [ErrorKind; 5] = [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionAborted,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ];
        // A spread of kinds that say the socket itself is unusable.
        const NON_SURVIVABLE: [ErrorKind; 3] = [
            ErrorKind::AddrNotAvailable,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
        ];

        // Per-datagram kinds never escalate, however many arrive.
        let mut policy = RecvErrorPolicy::default();
        for _ in 0..4 {
            for kind in PER_DATAGRAM {
                assert!(is_per_datagram_error(kind), "{kind:?} is per-datagram");
                assert_eq!(
                    policy.on_recv_error(kind),
                    RecvErrorAction::Continue,
                    "{kind:?}"
                );
            }
        }

        // Every other kind escalates on exactly the third consecutive error.
        for kind in NON_SURVIVABLE {
            assert!(!is_per_datagram_error(kind), "{kind:?} is not per-datagram");
            let mut policy = RecvErrorPolicy::default();
            assert_eq!(policy.on_recv_error(kind), RecvErrorAction::Continue);
            assert_eq!(policy.on_recv_error(kind), RecvErrorAction::Continue);
            assert_eq!(policy.on_recv_error(kind), RecvErrorAction::FatalSocket);
        }

        // A successful receive clears the streak.
        let mut policy = RecvErrorPolicy::default();
        let _ = policy.on_recv_error(ErrorKind::AddrNotAvailable);
        let _ = policy.on_recv_error(ErrorKind::AddrNotAvailable);
        policy.on_recv_ok();
        assert_eq!(
            policy.on_recv_error(ErrorKind::AddrNotAvailable),
            RecvErrorAction::Continue
        );

        // …and so does a per-datagram error mid-streak: it proves the socket still carries traffic.
        let mut policy = RecvErrorPolicy::default();
        let _ = policy.on_recv_error(ErrorKind::AddrNotAvailable);
        let _ = policy.on_recv_error(ErrorKind::AddrNotAvailable);
        assert_eq!(
            policy.on_recv_error(ErrorKind::ConnectionReset),
            RecvErrorAction::Continue
        );
        assert_eq!(
            policy.on_recv_error(ErrorKind::AddrNotAvailable),
            RecvErrorAction::Continue
        );
        assert_eq!(
            policy.on_recv_error(ErrorKind::AddrNotAvailable),
            RecvErrorAction::Continue
        );
        assert_eq!(
            policy.on_recv_error(ErrorKind::AddrNotAvailable),
            RecvErrorAction::FatalSocket
        );
    }

    #[tokio::test]
    async fn fan_out_lost_delivers_io_to_every_connection_and_drains_registry() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut registry = Registry::new(Arc::new(ManagerCounters::default()));
        let mut events: HashMap<u32, IoEventSender> = HashMap::new();
        let mut receivers = Vec::new();
        let now = Instant::now();

        for id in [0x1000_0001u32, 0x2000_0002, 0x3000_0003] {
            let mut p = params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless);
            p.t2o_connection_id = id;
            let conn = IoConnection::new(p, now);
            let (tx, rx) = io_event_channel(EVENT_CHANNEL_DEPTH, conn.counters.clone());
            registry.conns.insert(id, conn);
            events.insert(id, tx);
            receivers.push(rx);
        }

        fan_out_lost(&mut registry, &mut events, &socket, LostReason::Io);

        for mut rx in receivers {
            match rx.recv().await {
                Some(IoEvent::Lost { reason }) => assert_eq!(reason, LostReason::Io),
                other => panic!("expected Lost{{Io}}, got {other:?}"),
            }
            // The channel closing is the authoritative terminal signal (§8.6).
            assert!(rx.recv().await.is_none(), "the stream ends after Lost");
        }
        assert!(registry.conns.is_empty(), "the registry is drained");
        assert!(events.is_empty(), "every event sender is dropped");
    }

    // -- latest-wins event queue (F8, §8.6) --------------------------------

    /// One accepted sample carrying `seq`, for queue tests (the payload is irrelevant here).
    fn sample(seq: u16) -> IoUpdate {
        IoUpdate {
            data: Bytes::new(),
            sequence: seq,
            encap_sequence: u32::from(seq),
            run_mode: true,
            received_at: Instant::now(),
        }
    }

    /// The class-1 sequences of the `Data` events currently queued, oldest first.
    fn queued_sequences(state: &EventQueueState) -> Vec<u16> {
        state
            .deque
            .iter()
            .filter_map(|e| match e {
                IoEvent::Data(u) => Some(u.sequence),
                _ => None,
            })
            .collect()
    }

    /// Drain a receiver without waiting, returning everything queued right now.
    fn drain(rx: &mut IoEventReceiver) -> Vec<IoEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    /// **F8, the policy.** At capacity the queue evicts the OLDEST sample, not the newest: telemetry
    /// prefers fresh data over backpressure (§8.6). The surviving order is preserved.
    #[test]
    fn push_latest_wins_evicts_the_oldest_data_and_preserves_order() {
        let mut state = EventQueueState::new(3);
        let outcomes: Vec<PushOutcome> = (1..=5)
            .map(|seq| push_latest_wins(&mut state, IoEvent::Data(sample(seq))))
            .collect();
        assert_eq!(
            outcomes,
            vec![
                PushOutcome::Queued,
                PushOutcome::Queued,
                PushOutcome::Queued,
                PushOutcome::EvictedOldest,
                PushOutcome::EvictedOldest,
            ]
        );
        assert_eq!(
            queued_sequences(&state),
            vec![3, 4, 5],
            "the three newest survive, in order"
        );
        assert_eq!(
            state.data_len, 3,
            "the Data census never exceeds the capacity"
        );
    }

    /// **Control events are immune.** `Up` and `Lost` enqueue even while `Data` is at capacity, and
    /// an eviction never consumes them — a terminal reason cannot be lost behind a flood.
    #[test]
    fn push_latest_wins_never_evicts_control() {
        let mut state = EventQueueState::new(2);
        assert_eq!(
            push_latest_wins(
                &mut state,
                IoEvent::Up {
                    o2t_api: Duration::from_millis(10),
                    t2o_api: Duration::from_millis(10)
                }
            ),
            PushOutcome::Queued
        );
        assert_eq!(
            push_latest_wins(&mut state, IoEvent::Data(sample(1))),
            PushOutcome::Queued
        );
        assert_eq!(
            push_latest_wins(&mut state, IoEvent::Data(sample(2))),
            PushOutcome::Queued
        );
        assert_eq!(
            push_latest_wins(&mut state, IoEvent::Data(sample(3))),
            PushOutcome::EvictedOldest
        );
        assert_eq!(
            push_latest_wins(
                &mut state,
                IoEvent::Lost {
                    reason: LostReason::Timeout
                }
            ),
            PushOutcome::Queued,
            "Lost enqueues even at Data capacity"
        );

        // [Up, Data(2), Data(3), Lost] — the evicted entry was the oldest Data, never the Up.
        let kinds: Vec<&'static str> = state
            .deque
            .iter()
            .map(|e| match e {
                IoEvent::Up { .. } => "up",
                IoEvent::Data(_) => "data",
                IoEvent::Lost { .. } => "lost",
            })
            .collect();
        assert_eq!(kinds, vec!["up", "data", "data", "lost"]);
        assert_eq!(queued_sequences(&state), vec![2, 3]);
    }

    /// A dead consumer never grows the queue: every push after the receiver is gone is dropped.
    #[test]
    fn push_latest_wins_after_receiver_drop_is_receiver_gone() {
        let mut state = EventQueueState::new(4);
        state.rx_closed = true;
        assert_eq!(
            push_latest_wins(&mut state, IoEvent::Data(sample(1))),
            PushOutcome::ReceiverGone
        );
        assert_eq!(
            push_latest_wins(
                &mut state,
                IoEvent::Lost {
                    reason: LostReason::Io
                }
            ),
            PushOutcome::ReceiverGone
        );
        assert!(
            state.deque.is_empty(),
            "nothing is retained for a gone receiver"
        );
    }

    /// **The F8 headline, end to end on the real queue.** A stalled consumer that finally drains
    /// reads the NEWEST samples; the ones it missed are counted as `overflowed_events`. Against the
    /// pre-F8 mpsc channel this drained 1,2,3,4 — the oldest, and progressively staler under load.
    #[tokio::test]
    async fn overflow_prefers_the_newest_data_and_counts() {
        let counters = Arc::new(ConnCounters::default());
        let (tx, mut rx) = io_event_channel(4, counters.clone());
        for seq in 1..=10u16 {
            tx.send(IoEvent::Data(sample(seq)));
        }
        let seqs: Vec<u16> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| match e {
                IoEvent::Data(u) => Some(u.sequence),
                _ => None,
            })
            .collect();
        assert_eq!(seqs, vec![7, 8, 9, 10], "the four freshest samples survive");
        assert_eq!(
            counters.snapshot().overflowed_events,
            6,
            "every evicted sample is counted"
        );
    }

    /// **The second F8 defect.** `Lost` used to be a droppable `try_send` on a full channel, so a
    /// flooded consumer could lose the typed reason entirely. It now rides through a full queue and
    /// arrives after the freshest sample.
    #[tokio::test]
    async fn lost_is_delivered_even_when_the_queue_is_full() {
        let counters = Arc::new(ConnCounters::default());
        let (tx, mut rx) = io_event_channel(2, counters.clone());
        for seq in 1..=8u16 {
            tx.send(IoEvent::Data(sample(seq)));
        }
        tx.send(IoEvent::Lost {
            reason: LostReason::Timeout,
        });

        let events = drain(&mut rx);
        assert_eq!(
            events.len(),
            3,
            "two surviving samples plus the terminal event"
        );
        match events.last() {
            Some(IoEvent::Lost { reason }) => assert_eq!(*reason, LostReason::Timeout),
            other => panic!("expected Lost{{Timeout}} last, got {other:?}"),
        }
        match events.first() {
            Some(IoEvent::Data(u)) => {
                assert_eq!(u.sequence, 7, "the older samples were the ones evicted")
            }
            other => panic!("expected the freshest Data first, got {other:?}"),
        }
    }

    /// The terminal contract is unchanged: queued events drain first, then the stream ends.
    #[tokio::test]
    async fn sender_drop_is_terminal_after_drain() {
        let (tx, mut rx) = io_event_channel(4, Arc::new(ConnCounters::default()));
        tx.send(IoEvent::Data(sample(1)));
        drop(tx);
        match rx.recv().await {
            Some(IoEvent::Data(u)) => assert_eq!(u.sequence, 1),
            other => panic!("expected the queued Data first, got {other:?}"),
        }
        assert!(
            rx.recv().await.is_none(),
            "the stream ends once the sender is gone and drained"
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
        assert_eq!(
            TryRecvError::Disconnected.to_string(),
            "the connection's event stream is closed"
        );
        assert_eq!(TryRecvError::Empty.to_string(), "no event queued");
    }

    /// A consumer that goes away stops the queue: further events are dropped, and dropping them is
    /// not an overflow (nothing was evicted — there is simply nobody to deliver to).
    #[tokio::test]
    async fn send_after_the_receiver_is_gone_is_dropped_not_counted() {
        let counters = Arc::new(ConnCounters::default());
        let (tx, rx) = io_event_channel(2, counters.clone());
        drop(rx);
        for seq in 1..=8u16 {
            tx.send(IoEvent::Data(sample(seq)));
        }
        tx.send(IoEvent::Lost {
            reason: LostReason::Io,
        });
        assert_eq!(
            counters.snapshot().overflowed_events,
            0,
            "a gone consumer is not an overflow"
        );
    }

    /// `Up` carries the negotiated APIs and must reach the consumer whatever the sample rate — the
    /// eviction scan skips it, so a flood cannot consume it.
    #[tokio::test]
    async fn up_survives_a_data_flood() {
        let (tx, mut rx) = io_event_channel(4, Arc::new(ConnCounters::default()));
        tx.send(IoEvent::Up {
            o2t_api: Duration::from_millis(10),
            t2o_api: Duration::from_millis(20),
        });
        for seq in 1..=8u16 {
            tx.send(IoEvent::Data(sample(seq)));
        }
        match rx.recv().await {
            Some(IoEvent::Up { o2t_api, t2o_api }) => {
                assert_eq!(o2t_api, Duration::from_millis(10));
                assert_eq!(t2o_api, Duration::from_millis(20));
            }
            other => panic!("expected Up first, got {other:?}"),
        }
    }

    /// `recv()` wakes on a send that lands while it is waiting (the lost-wakeup discipline), and is
    /// cancel-safe: a cancelled `recv` — the shape `tokio::select!` gives every consumer — never
    /// swallows the event it was waiting for.
    #[tokio::test]
    async fn recv_wakes_on_a_late_send_and_is_cancel_safe() {
        let (tx, mut rx) = io_event_channel(4, Arc::new(ConnCounters::default()));

        // Cancel a pending recv (nothing queued), then send: the event is still there.
        assert!(tokio::time::timeout(Duration::from_millis(20), rx.recv())
            .await
            .is_err());
        tx.send(IoEvent::Data(sample(9)));
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(IoEvent::Data(u))) => assert_eq!(u.sequence, 9),
            other => panic!("expected the sample to survive the cancelled recv, got {other:?}"),
        }

        // A send from another task while recv is parked wakes it.
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(IoEvent::Lost {
                reason: LostReason::ClosedByPeer,
            });
        });
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(IoEvent::Lost { reason })) => assert_eq!(reason, LostReason::ClosedByPeer),
            other => panic!("expected a woken Lost, got {other:?}"),
        }
        handle.await.unwrap();
    }

    // -- forward-open reply verification (F1 + F10) ------------------------

    /// Which echoed identity field the fixture corrupts in its ForwardOpen success reply.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EchoField {
        TargetToOriginatorId,
        ConnectionSerial,
        VendorId,
        OriginatorSerial,
    }

    /// An in-test [`ForwardOpenService`]: records every request it is handed and answers a
    /// ForwardOpen with a crafted success reply (optionally corrupting one echoed field or naming
    /// out-of-range APIs), so `forward_open`'s verification and its best-effort ForwardClose are
    /// both observable without a socket or a peer.
    struct FoFixture {
        seen: std::sync::Mutex<Vec<(u8, Bytes)>>,
        corrupt: Option<EchoField>,
        o_t_api: u32,
        t_o_api: u32,
        /// What [`ForwardOpenService::target_ip`] answers. `None` models a session with no known
        /// peer address (an injected byte stream), which leaves the O→T transmit endpoint
        /// unresolvable when the reply carries no O→T sockaddr either.
        target_ip: Option<IpAddr>,
        /// An O→T Sockaddr Info item to attach to the ForwardOpen success reply — the transmit
        /// redirect a hostile or misconfigured target would use (D-ENIP-17).
        o2t_sock: Option<SockAddrInfo>,
        /// A T→O Sockaddr Info item to attach to the ForwardOpen success reply — the multicast
        /// group offer (D-ENIP-17).
        t2o_sock: Option<SockAddrInfo>,
    }

    impl FoFixture {
        fn new(corrupt: Option<EchoField>, o_t_api: u32, t_o_api: u32) -> Self {
            Self {
                seen: std::sync::Mutex::new(Vec::new()),
                corrupt,
                o_t_api,
                t_o_api,
                target_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                o2t_sock: None,
                t2o_sock: None,
            }
        }

        /// The same fixture with no resolvable target address.
        fn without_target_ip(mut self) -> Self {
            self.target_ip = None;
            self
        }

        /// The same fixture, reporting `ip` as the target address — which is both the O→T transmit
        /// destination and, by D-ENIP-24, the only source its T→O datagrams may carry.
        fn with_target_ip(mut self, ip: IpAddr) -> Self {
            self.target_ip = Some(ip);
            self
        }

        /// The same fixture, answering with the given O→T sockaddr redirect.
        fn with_o2t_sock(mut self, sock: SockAddrInfo) -> Self {
            self.o2t_sock = Some(sock);
            self
        }

        /// The same fixture, answering with the given T→O sockaddr.
        fn with_t2o_sock(mut self, sock: SockAddrInfo) -> Self {
            self.t2o_sock = Some(sock);
            self
        }

        /// The sockaddr items this fixture attaches to a ForwardOpen success reply.
        fn sock_items(&self) -> Vec<CpfItem> {
            let mut items = Vec::new();
            if let Some(s) = self.o2t_sock {
                items.push(CpfItem::new(ItemType::SockAddrOtoT, s.encode()));
            }
            if let Some(s) = self.t2o_sock {
                items.push(CpfItem::new(ItemType::SockAddrTtoO, s.encode()));
            }
            items
        }

        /// Every `(service, service-data)` pair the fixture was asked to send, in order.
        fn requests(&self) -> Vec<(u8, Bytes)> {
            self.seen.lock().unwrap().clone()
        }

        /// Wrap Message Router reply bytes in the UCMM reply CPF `forward_open` expects, plus any
        /// sockaddr items the reply carries.
        fn reply_cpf(service: u8, data: Bytes, extra: Vec<CpfItem>) -> Cpf {
            let mut mr = WireWriter::new();
            mr.u8(service | 0x80);
            mr.u8(0); // reserved
            mr.u8(0); // general status: success
            mr.u8(0); // extended-status words
            mr.put_slice(&data);
            let mut items = vec![
                CpfItem::null_address(),
                CpfItem::unconnected_data(mr.into_bytes()),
            ];
            items.extend(extra);
            Cpf::from_items(items)
        }
    }

    impl ForwardOpenService for FoFixture {
        async fn cm_ucmm(
            &self,
            request: MessageRequest,
            _extra_items: Vec<CpfItem>,
        ) -> Result<Cpf> {
            let service = request.service;
            let data = request.data.clone();
            self.seen.lock().unwrap().push((service, data.clone()));

            if service == crate::cm::service::FORWARD_CLOSE {
                // §8.8 success reply: serial, vendor, originator serial (echoed straight back).
                let mut r = WireReader::new(&data);
                let _priority = r.u8()?;
                let _ticks = r.u8()?;
                let mut w = WireWriter::new();
                w.u16(r.u16()?);
                w.u16(r.u16()?);
                w.u32(r.u32()?);
                return Ok(Self::reply_cpf(service, w.into_bytes(), Vec::new()));
            }

            // Read the originator identity straight out of the ForwardOpen request (§8.2 fields 3–7).
            let mut r = WireReader::new(&data);
            let _priority = r.u8()?;
            let _ticks = r.u8()?;
            let _o_t_id = r.u32()?;
            let mut t_o_id = r.u32()?;
            let mut serial = r.u16()?;
            let mut vendor = r.u16()?;
            let mut orig_serial = r.u32()?;
            match self.corrupt {
                Some(EchoField::TargetToOriginatorId) => t_o_id ^= 1,
                Some(EchoField::ConnectionSerial) => serial ^= 1,
                Some(EchoField::VendorId) => vendor ^= 1,
                Some(EchoField::OriginatorSerial) => orig_serial ^= 1,
                None => {}
            }

            let mut w = WireWriter::new();
            w.u32(0xAABB_CCDD); // O→T id: target-assigned, never echo-checked
            w.u32(t_o_id);
            w.u16(serial);
            w.u16(vendor);
            w.u32(orig_serial);
            w.u32(self.o_t_api);
            w.u32(self.t_o_api);
            w.u8(0); // application reply words
            w.u8(0); // reserved
            Ok(Self::reply_cpf(service, w.into_bytes(), self.sock_items()))
        }

        fn target_ip(&self) -> Option<IpAddr> {
            self.target_ip
        }
    }

    fn sample_spec() -> IoConnectionSpec {
        let dir = DirectionSpec {
            rpi: Duration::from_millis(20),
            data_size: 8,
            format: RealTimeFormat::Modeless,
            conn_type: ConnType::P2P,
            priority: Priority::Scheduled,
            variable: VariableLength::Fixed,
        };
        IoConnectionSpec {
            assembly: AssemblyPath {
                config: Some(151),
                output: 150,
                input: 100,
                route: vec![],
            },
            t2o: dir.clone(),
            o2t: DirectionSpec {
                data_size: 4,
                format: RealTimeFormat::Header32Bit,
                ..dir
            },
            timeout_multiplier: TimeoutMultiplier::X16,
            trigger: ProductionTrigger::Cyclic,
            vendor_id: 0x1337,
        }
    }

    /// Assert the fixture saw the open, then a ForwardClose (`0x4E`) carrying the open's connection
    /// serial. ForwardOpen: `priority·ticks·o_t_id(4)·t_o_id(4)·serial(2)`; ForwardClose:
    /// `priority·ticks·serial(2)`.
    fn assert_forward_closed(requests: &[(u8, Bytes)]) {
        assert_eq!(requests.len(), 2, "an open then a best-effort close");
        let (open_service, open_data) = &requests[0];
        assert!(
            *open_service == crate::cm::service::FORWARD_OPEN
                || *open_service == crate::cm::service::LARGE_FORWARD_OPEN,
            "first request is the open"
        );
        let (close_service, close_data) = &requests[1];
        assert_eq!(
            *close_service,
            crate::cm::service::FORWARD_CLOSE,
            "0x4E follows the refusal"
        );
        assert_eq!(
            &close_data[2..4],
            &open_data[10..12],
            "the close carries the open's serial"
        );
    }

    /// **F1 regression.** A reply naming a 0 µs O→T API is refused *before* anything is armed, and
    /// the connection the target believes it opened is torn down.
    #[tokio::test]
    async fn forward_open_rejects_out_of_range_api_and_forward_closes() {
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 0, 20_000);
        match mgr.forward_open(&fixture, sample_spec()).await {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(detail, "forward-open reply API out of range");
            }
            other => panic!(
                "expected a protocol violation, got {:?}",
                other.map(|h| h.apis())
            ),
        }
        assert_forward_closed(&fixture.requests());
        mgr.shutdown().await;
    }

    /// **F10 regression.** Each echoed identity field, corrupted singly, is refused with a typed
    /// error and a best-effort ForwardClose — an unverified reply could otherwise bind our runtime
    /// to another originator's connection.
    #[tokio::test]
    async fn forward_open_rejects_echo_mismatch_and_forward_closes() {
        for field in [
            EchoField::TargetToOriginatorId,
            EchoField::ConnectionSerial,
            EchoField::VendorId,
            EchoField::OriginatorSerial,
        ] {
            let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
            let fixture = FoFixture::new(Some(field), 20_000, 20_000);
            match mgr.forward_open(&fixture, sample_spec()).await {
                Err(EnipError::ProtocolViolation { detail }) => {
                    assert!(
                        detail.starts_with("forward-open reply"),
                        "{field:?}: {detail}"
                    );
                }
                other => panic!(
                    "{field:?}: expected a violation, got {:?}",
                    other.map(|h| h.apis())
                ),
            }
            assert_forward_closed(&fixture.requests());
            mgr.shutdown().await;
        }
    }

    /// **The invariant, on its third trigger.** A reply that passes both verifications can still
    /// fail to arm — here the O→T transmit endpoint is unresolvable (no O→T sockaddr in the reply
    /// and no target address on the session). The target nonetheless believes the connection is
    /// open, so the same best-effort ForwardClose goes out before the typed error propagates.
    #[tokio::test]
    async fn forward_open_unresolvable_tx_endpoint_forward_closes() {
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000).without_target_ip();
        match mgr.forward_open(&fixture, sample_spec()).await {
            Err(EnipError::ProtocolViolation { detail }) => {
                assert_eq!(detail, "no O→T transmit address available");
            }
            other => panic!(
                "expected a protocol violation, got {:?}",
                other.map(|h| h.apis())
            ),
        }
        assert_forward_closed(&fixture.requests());
        mgr.shutdown().await;
    }

    /// The guard against over-tightening: a faithful reply still opens, and the handle reports the
    /// validated APIs.
    #[tokio::test]
    async fn forward_open_accepts_faithful_reply() {
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000);
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        assert_eq!(
            handle.apis(),
            (Duration::from_millis(20), Duration::from_millis(20))
        );
        assert_eq!(
            fixture.requests().len(),
            1,
            "no ForwardClose on the happy path"
        );
        mgr.shutdown().await;
    }

    /// **D-ENIP-17 observability.** A refused foreign O→T redirect is no longer only a log line: the
    /// connection counts it, so the adapter can surface `refusedRedirects` and warn that a device
    /// requiring the redirect will never receive its outputs. Both polarities are pinned — an
    /// honoured (target's own) address and a reply with no sockaddr at all count zero.
    #[tokio::test]
    async fn refused_foreign_redirect_sets_the_stats_counter() {
        // The fixture's target is 127.0.0.1; 192.168.1.100 is foreign.
        let foreign = SockAddrInfo::ipv4(0xC0A8_0164, 9999);
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000).with_o2t_sock(foreign);
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        assert_eq!(
            handle.stats().refused_redirects,
            1,
            "the refusal is counted once"
        );
        assert_eq!(
            fixture.requests().len(),
            1,
            "and is not fatal — the connection still opens"
        );
        mgr.shutdown().await;

        // The target's own address, honoured as written: nothing was refused.
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let own = SockAddrInfo::ipv4(0x7F00_0001, 4444);
        let fixture = FoFixture::new(None, 20_000, 20_000).with_o2t_sock(own);
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        assert_eq!(handle.stats().refused_redirects, 0);
        mgr.shutdown().await;

        // No O→T sockaddr at all: the plain path, nothing refused.
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let fixture = FoFixture::new(None, 20_000, 20_000);
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        assert_eq!(handle.stats().refused_redirects, 0);
        mgr.shutdown().await;
    }

    // -- manager select-loop glue, end to end over real loopback UDP -------

    /// **The wiring test.** [`RecvErrorPolicy`], [`fan_out_lost`], the consume gauntlet, and the
    /// produce scheduler are each unit-proven; this drives the `select!` that composes them over a
    /// real socket: recv → route → deliver, tick → produce → `send_to`, watchdog → `Lost` → remove.
    /// It also exercises the D-ENIP-17 port-honouring path on a live endpoint (the reply's O→T
    /// sockaddr is `0.0.0.0:<peer port>`, so O→T frames must arrive at the peer's port on the
    /// target's address) and the latest-wins queue in its real position.
    ///
    /// Deliberately NOT covered here: injecting a socket-fatal `recv_from` error through the loop.
    /// There is no cross-platform way to make a bound UDP socket fail that way on demand without a
    /// socket trait seam whose only consumer would be this test — the seam would then be the
    /// untested wiring. The policy and the fan-out stay unit-proven above.
    #[tokio::test]
    async fn manager_select_loop_end_to_end_consume_produce_watchdog() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();

        // 10 ms APIs in the reply; X16 ⇒ a 160 ms T→O watchdog.
        let fixture =
            FoFixture::new(None, 10_000, 10_000).with_o2t_sock(SockAddrInfo::ipv4(0, peer_port));
        let dir = DirectionSpec {
            rpi: Duration::from_millis(10),
            ..sample_spec().t2o
        };
        let spec = IoConnectionSpec {
            t2o: dir.clone(),
            o2t: DirectionSpec {
                data_size: 4,
                format: RealTimeFormat::Header32Bit,
                ..dir
            },
            ..sample_spec()
        };
        let mut handle = mgr.forward_open(&fixture, spec).await.unwrap();

        // The T→O connection id the target was told to produce into, read off the recorded
        // ForwardOpen request (`priority·ticks·o_t_id(4)·t_o_id(4)`).
        let requests = fixture.requests();
        let open_data = &requests[0].1;
        let t2o_cid = u32::from_le_bytes([open_data[6], open_data[7], open_data[8], open_data[9]]);
        assert_eq!(
            t2o_cid,
            handle.connection_id(),
            "the handle routes by the on-wire T→O id"
        );

        // (1) The peer produces T→O frames until the loop routes one and delivers Up.
        //
        // A retry, not a single datagram: the contract this test proves is recv → route → deliver,
        // so it does not rest on any one datagram surviving the loopback. (The registration race
        // this loop used to absorb is gone — `forward_open` returns only once the connection is
        // armed, D-ENIP-20, which `forward_open_returns_only_after_the_connection_is_armed` pins.)
        // Each attempt carries the next sequence, so a retry is never rejected as a stale duplicate.
        let mut sent: u16 = 0;
        loop {
            sent += 1;
            assert!(
                sent <= 40,
                "the manager never reported Up after {sent} T→O frames — the recv → route → deliver \
                 path is not running, or the connection was never registered"
            );
            peer.send_to(
                &datagram(t2o_cid, u32::from(sent), &modeless_payload(sent, &[0u8; 8])),
                mgr.local_addr(),
            )
            .await
            .unwrap();
            match tokio::time::timeout(Duration::from_millis(25), handle.events().recv()).await {
                Ok(Some(IoEvent::Up { o2t_api, t2o_api })) => {
                    assert_eq!(o2t_api, Duration::from_millis(10));
                    assert_eq!(t2o_api, Duration::from_millis(10));
                    break;
                }
                // Nothing yet — the connection may not be registered. Send another.
                Err(_) => {}
                other => panic!("expected Up as the first event, got {other:?}"),
            }
        }
        match tokio::time::timeout(Duration::from_secs(2), handle.events().recv()).await {
            Ok(Some(IoEvent::Data(u))) => assert!(
                (1..=sent).contains(&u.sequence),
                "the delivered sample is one of the frames the peer sent (got {}, sent 1..={sent})",
                u.sequence
            ),
            other => panic!("expected the accepted sample, got {other:?}"),
        }

        // (2) The scheduler produces O→T frames at the peer's port on the target's address.
        let mut buf = vec![0u8; 2048];
        let Ok(received) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await
        else {
            panic!("expected a produced O→T datagram at the peer within 2 s");
        };
        let (n, _src) = received.unwrap();
        let cpf = Cpf::decode(&buf[..n]).unwrap();
        let addr =
            SequencedAddress::decode(&cpf.find(ItemType::SequencedAddress).unwrap().data).unwrap();
        assert_eq!(
            addr.connection_id, 0xAABB_CCDD,
            "produced under the target-assigned O→T id"
        );
        assert!(
            cpf.find(ItemType::ConnectedData).is_some(),
            "the frame carries connected data"
        );

        // (3) The peer goes silent ⇒ the watchdog declares the connection lost and removes it.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut lost = None;
        while lost.is_none() && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(2), handle.events().recv()).await {
                Ok(Some(IoEvent::Lost { reason })) => lost = Some(reason),
                Ok(Some(IoEvent::Data(_) | IoEvent::Up { .. })) => {}
                other => panic!("expected Lost from the watchdog, got {other:?}"),
            }
        }
        assert_eq!(lost, Some(LostReason::Timeout), "the T→O watchdog fired");
        assert!(
            handle.events().recv().await.is_none(),
            "the stream ends when the connection is removed"
        );

        // (4) Both directions really moved through the loop.
        let stats = handle.stats();
        assert!(stats.frames_accepted >= 1, "consume path: {stats:?}");
        assert!(stats.frames_produced >= 1, "produce path: {stats:?}");
        mgr.shutdown().await;
    }

    /// **D-ENIP-24, through the real select loop over loopback UDP.** The manager routes by
    /// connection id, and an accepted frame both delivers a sample and refreshes the watchdog — so
    /// a sender that merely knows the id could keep a link that has actually stopped producing
    /// looking healthy forever. With the source filter, a datagram whose source IP is not the
    /// connection's target is dropped at the routing layer: nothing is delivered, the drop is
    /// counted on `source_mismatch_datagrams`, and the watchdog runs out **while the spoofed stream
    /// is still arriving**.
    ///
    /// The mismatch is arranged by giving the fixture a target address the loopback peer cannot
    /// have (TEST-NET-1, RFC 5737) rather than by sourcing from a second loopback alias, which is
    /// not portable. The reply's O→T API is 5 s so the produce scheduler never ticks inside the
    /// test and never tries to reach that unroutable address; the T→O API is 30 ms, so the ×16
    /// watchdog is 480 ms.
    #[tokio::test]
    async fn a_spoofed_source_is_dropped_counted_and_never_feeds_the_watchdog() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let elsewhere = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let fixture = FoFixture::new(None, 5_000_000, 30_000).with_target_ip(elsewhere);
        let mut handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        let cid = handle.connection_id();

        // Keep a well-formed, correctly-addressed, sequence-advancing stream arriving from the
        // WRONG source for longer than the watchdog window. If any of it were accepted the
        // watchdog would be refreshed on every frame and `Lost` could never fire.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut seq: u16 = 0;
        let mut lost = None;
        while lost.is_none() && Instant::now() < deadline {
            seq = seq.wrapping_add(1);
            peer.send_to(
                &datagram(cid, u32::from(seq), &modeless_payload(seq, &[0u8; 8])),
                mgr.local_addr(),
            )
            .await
            .unwrap();
            match tokio::time::timeout(Duration::from_millis(20), handle.events().recv()).await {
                Ok(Some(IoEvent::Lost { reason })) => lost = Some(reason),
                Ok(other) => panic!(
                    "a datagram from {} must never be delivered on a connection whose target is \
                     {elsewhere}; got {other:?}",
                    peer.local_addr().unwrap()
                ),
                // Nothing delivered in this slice — the expected steady state. Send another.
                Err(_elapsed) => {}
            }
        }

        assert_eq!(
            lost,
            Some(LostReason::Timeout),
            "the watchdog must expire even though frames kept arriving ({seq} sent)"
        );
        let stats = handle.stats();
        assert!(
            // All but (at most) the last: the datagram sent in the same slice as the `Lost` may
            // still be in flight when the counters are read.
            stats.source_mismatch_datagrams >= u64::from(seq).saturating_sub(1),
            "every refused datagram is counted: {stats:?} after {seq} sent"
        );
        assert!(stats.source_mismatch_datagrams > 0, "{stats:?}");
        assert_eq!(stats.frames_accepted, 0, "nothing was consumed: {stats:?}");
        assert_eq!(stats.stale_frames, 0, "nothing reached the sequence window");
        assert_eq!(stats.size_mismatch, 0, "nothing reached the size check");
        assert_eq!(
            stats.unknown_connection, 0,
            "the id DID match a live connection — the source is what refused it"
        );
        mgr.shutdown().await;
    }

    // -- arming acknowledgements (D-ENIP-20) -------------------------------

    /// `sample_spec()` with a **multicast** T→O direction — the only shape whose reply may name a
    /// group to join (D-ENIP-17).
    fn multicast_spec() -> IoConnectionSpec {
        let base = sample_spec();
        IoConnectionSpec {
            t2o: DirectionSpec {
                conn_type: ConnType::Multicast,
                ..base.t2o
            },
            ..base
        }
    }

    /// A T→O sockaddr naming `group` on the standard implicit-I/O port.
    fn multicast_sock(group: Ipv4Addr) -> SockAddrInfo {
        SockAddrInfo::ipv4(u32::from(group), IO_UDP_PORT)
    }

    /// A live class-1 connection over loopback whose O→T frames land on `peer`: a faithful reply
    /// with a 20 ms O→T API (so the produce scheduler ticks promptly) and a 1 s T→O API (so the
    /// ×16 watchdog cannot fire inside a test).
    async fn open_against_peer(mgr: &IoManager, peer_port: u16) -> (FoFixture, IoConnectionHandle) {
        let fixture =
            FoFixture::new(None, 20_000, 1_000_000).with_o2t_sock(SockAddrInfo::ipv4(0, peer_port));
        let handle = mgr.forward_open(&fixture, sample_spec()).await.unwrap();
        (fixture, handle)
    }

    /// The next O→T datagram at `peer`, decoded as a 32-bit-header frame — bounded by `deadline`.
    async fn next_o2t_frame(peer: &UdpSocket, deadline: Instant) -> IoFrame {
        let mut buf = vec![0u8; 2048];
        let Ok(received) = tokio::time::timeout_at(deadline, peer.recv_from(&mut buf)).await else {
            panic!("no O→T datagram reached the peer before the deadline");
        };
        let (n, _src) = received.unwrap();
        let cpf = Cpf::decode(&buf[..n]).unwrap();
        let data = &cpf.find(ItemType::ConnectedData).unwrap().data;
        IoFrame::decode(RealTimeFormat::Header32Bit, data).unwrap()
    }

    /// **P2-7 regression (D-ENIP-20).** The T→O multicast join is load-bearing: a connection whose
    /// group could not be joined is NOT armed, `forward_open` fails with the socket error, and the
    /// connection the target believes it opened is torn down. Before the fix the join result was
    /// discarded (`let _ = socket.join_multicast_v4(..)`), so the open reported success and the
    /// operator's first symptom was a `Lost { Timeout }` a watchdog period later — the interface
    /// error that actually caused it thrown away at the one point it was known.
    ///
    /// The join is forced to fail by joining the same group twice on one manager socket — the
    /// deliberate fail-fast of the no-refcounting decision (D-ENIP-20): the adapter runs one
    /// `IoManager` per push session, so a shared group never occurs in product use.
    #[tokio::test]
    async fn forward_open_fails_typed_when_the_multicast_join_fails() {
        let group = Ipv4Addr::new(239, 192, 1, 1);
        let mgr = IoManager::bind("0.0.0.0:0").await.unwrap();

        // (a) The first open joins the group and arms normally.
        let first = FoFixture::new(None, 20_000, 1_000_000).with_t2o_sock(multicast_sock(group));
        let handle = mgr
            .forward_open(&first, multicast_spec())
            .await
            .expect("the first multicast open joins the group and arms");
        assert_eq!(
            first.requests().len(),
            1,
            "no ForwardClose on the armed path"
        );

        // (b) The second open on the SAME manager socket re-joins the same group: the OS refuses
        // the duplicate membership, so the connection must not be armed.
        let second = FoFixture::new(None, 20_000, 1_000_000).with_t2o_sock(multicast_sock(group));
        match mgr.forward_open(&second, multicast_spec()).await {
            Err(EnipError::Io(_)) => {}
            other => panic!(
                "expected the join failure as a typed Io error, got {:?}",
                other.map(|h| h.apis())
            ),
        }
        assert_forward_closed(&second.requests());

        // The refusal is the second connection's alone — the first is still armed and producing.
        assert_eq!(handle.stats().refused_redirects, 0);
        mgr.shutdown().await;
    }

    /// **D-ENIP-20 post-condition.** `forward_open` returns only once the socket task has
    /// registered the connection, so a T→O datagram sent the instant it returns is routed, not
    /// dropped as an unknown connection.
    ///
    /// This is the **guarantee's** pin, not the fix's discriminator. Before the ack, `Add` was
    /// fire-and-forget and nothing in the contract stopped an early datagram from being counted as
    /// `unknown_connection`; in practice the manager's `select!` could not lose that race in-process
    /// (a freshly created `recv_from` future is `Pending` until the reactor reports readability,
    /// while a queued command is ready synchronously), so the hole was a latent contract gap rather
    /// than an observable flake. What proves the ack itself is
    /// `forward_open_fails_typed_when_the_multicast_join_fails` — the manager's verdict cannot be
    /// reported without awaiting it. This test locks the ordering down so no later scheduling or
    /// `select!` change can quietly reopen it.
    ///
    /// Six independent opens rather than one, and a **std** sender, so the datagram genuinely
    /// precedes any hand-off to the manager task.
    #[tokio::test]
    async fn forward_open_returns_only_after_the_connection_is_armed() {
        // A **std** socket, deliberately: its `send_to` is a plain syscall, so the datagram reaches
        // the manager's socket without ever handing the runtime to the manager task. An awaited
        // `tokio::net::UdpSocket::send_to` would yield and let the task drain the `Add` first — the
        // very ordering under test — and `try_send_to` would depend on tokio write-readiness that
        // has not been established yet.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();

        let mut opened = Vec::new();
        for attempt in 1..=6u32 {
            let (fixture, mut handle) = open_against_peer(&mgr, peer_port).await;
            peer.send_to(
                &datagram(handle.connection_id(), 1, &modeless_payload(1, &[0u8; 8])),
                mgr.local_addr(),
            )
            .unwrap();

            match tokio::time::timeout(Duration::from_secs(5), handle.events().recv()).await {
                Ok(Some(IoEvent::Up { .. })) => {}
                other => panic!(
                    "attempt {attempt}: expected Up from the very first datagram, got {other:?} \
                     (unknown_connection = {})",
                    handle.stats().unknown_connection
                ),
            }
            match tokio::time::timeout(Duration::from_secs(5), handle.events().recv()).await {
                Ok(Some(IoEvent::Data(u))) => assert_eq!(u.sequence, 1),
                other => panic!("attempt {attempt}: expected the accepted sample, got {other:?}"),
            }
            opened.push((fixture, handle));
        }

        assert_eq!(
            mgr.stats.unknown_connection.load(Ordering::Relaxed),
            0,
            "no datagram was ever seen against an unregistered connection"
        );
        mgr.shutdown().await;
    }

    /// **D-ENIP-20, the cancelled-opener path.** If the caller's `forward_open` future is dropped
    /// between the `Add` and its ack, nobody owns the connection — so the manager unregisters it
    /// (leaving any group) instead of producing O→T into it for the rest of the process's life.
    #[tokio::test]
    async fn an_abandoned_forward_open_does_not_leave_a_producing_connection() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();

        let mut p = params(RealTimeFormat::Header32Bit, RealTimeFormat::Modeless);
        p.tx_endpoint = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer.local_addr().unwrap().port(),
        );
        let cid = p.t2o_connection_id;
        let conn = IoConnection::new(p, Instant::now());
        let (events_tx, mut events_rx) =
            io_event_channel(EVENT_CHANNEL_DEPTH, conn.counters.clone());

        // The opener vanishes: its ack receiver is gone before the manager services the command.
        let (ack_tx, ack_rx) = oneshot::channel();
        drop(ack_rx);
        mgr.tx
            .send(ManagerCommand::Add {
                conn: Box::new(conn),
                events_tx,
                ack: ack_tx,
            })
            .await
            .unwrap();

        // Causal wait: the event stream ends exactly when the manager drops the sender, which only
        // happens because it unregistered the connection it had just inserted.
        match tokio::time::timeout(Duration::from_secs(5), events_rx.recv()).await {
            Ok(None) => {}
            other => panic!("expected the abandoned connection's stream to end, got {other:?}"),
        }

        // And a datagram for it now counts as unknown rather than feeding a live connection.
        peer.send_to(
            &datagram(cid, 1, &modeless_payload(1, &[0u8; 8])),
            mgr.local_addr(),
        )
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while mgr.stats.unknown_connection.load(Ordering::Relaxed) == 0 {
            assert!(
                Instant::now() < deadline,
                "the datagram was never counted as unknown — the connection is still registered"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            events_rx.try_recv().is_err(),
            "no sample was ever delivered to the abandoned stream"
        );
        mgr.shutdown().await;
    }

    /// **D-ENIP-20, the confirmed staging path.** `stage_output` returns `Ok` only after the
    /// manager has taken the buffer for a live connection — and the very next produced frame
    /// carries it.
    #[tokio::test]
    async fn stage_output_confirms_against_a_live_connection() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let (_fixture, handle) = open_against_peer(&mgr, peer_port).await;

        handle
            .stage_output(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]))
            .await
            .expect("the manager accepts the buffer for a live connection");

        // Every frame produced after the ack carries the staged bytes; frames already in flight
        // when it landed carry the initial empty buffer, so drain past those.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let frame = next_o2t_frame(&peer, deadline).await;
            if frame.data.as_ref() == [0xDE, 0xAD, 0xBE, 0xEF] {
                break;
            }
            assert!(
                frame.data.is_empty(),
                "an O→T frame carried neither the initial nor the staged buffer: {frame:?}"
            );
        }
        mgr.shutdown().await;
    }

    /// **D-ENIP-20, the honest refusal.** Once the connection is gone, staging cannot succeed —
    /// and says so. The unconfirmed `set_output` reports `Ok` here (the command is merely queued),
    /// which is exactly the silent success this API exists to replace.
    #[tokio::test]
    async fn stage_output_errors_once_the_connection_is_removed() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let (fixture, handle) = open_against_peer(&mgr, peer_port).await;

        handle.close(&fixture).await.unwrap();
        // The contrast, pinned: the unconfirmed setter still answers `Ok` — its command is merely
        // queued, and the manager drops it on the floor. That is the silent success `stage_output`
        // replaces, not a bug in `set_output`'s own (documented) contract.
        assert!(handle.set_output(Bytes::from_static(&[1, 2, 3, 4])).is_ok());
        // The channel is FIFO, so the manager has processed `Remove` before it reads this command.
        match handle.stage_output(Bytes::from_static(&[1, 2, 3, 4])).await {
            Err(EnipError::Closed) => {}
            other => panic!("expected Closed for a removed connection, got {other:?}"),
        }
        // Validation still runs first: a mis-sized buffer is refused on its own terms.
        match handle.stage_output(Bytes::from_static(&[1, 2])).await {
            Err(EnipError::ProtocolViolation { detail }) => assert_eq!(
                detail,
                "output size does not match the negotiated fixed O→T size"
            ),
            other => panic!("expected the size violation, got {other:?}"),
        }
        mgr.shutdown().await;
    }

    /// **D-ENIP-20, the expired command.** A staging call whose deadline passes is refused — and,
    /// decisively, the buffer it carried never reaches the producer.
    ///
    /// A caller-side timer alone can never promise that: the command it abandons is still in the
    /// manager's queue, and staging it afterwards puts a value the caller was told had failed on
    /// the very next O→T frame, and on every frame after it. The deadline therefore travels with
    /// the command to the one place that mutates the producer buffer.
    ///
    /// Deterministic, not timed: the command channel releases its permit when the manager task
    /// **dequeues** the command, and that task handles it to completion in the same loop iteration
    /// — before its produce tick can run again. So the restored capacity is a causal signal that
    /// the decision is made, and every frame after it reflects the decision.
    #[tokio::test]
    async fn an_expired_stage_output_is_refused_and_never_reaches_the_producer_buffer() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let (_fixture, handle) = open_against_peer(&mgr, peer_port).await;
        let refused: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

        let verdict = handle
            .stage_output_by(Bytes::from_static(refused), Instant::now())
            .await;

        let gate = Instant::now() + Duration::from_secs(10);
        while mgr.tx.capacity() < MANAGER_COMMAND_DEPTH {
            assert!(
                Instant::now() < gate,
                "the manager never took the expired command off its queue"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // Nothing already on the wire can mask the failure: drain what the producer emitted before
        // the decision, then judge only frames produced after it.
        let mut discard = vec![0u8; 2048];
        while peer.try_recv_from(&mut discard).is_ok() {}
        let deadline = Instant::now() + Duration::from_secs(5);
        for _ in 0..5 {
            let frame = next_o2t_frame(&peer, deadline).await;
            assert!(
                frame.data.is_empty(),
                "a buffer whose deadline had passed was staged anyway and is on the wire: {frame:?}"
            );
        }
        match verdict {
            Err(EnipError::Timeout { op }) => assert_eq!(op, OUTPUT_STAGING),
            other => panic!("expected an expired staging request to be refused, got {other:?}"),
        }

        // The same observation, positive: a staging request inside its deadline IS applied — so the
        // assertion above is about the refusal, not about a test that cannot see a staged value.
        let accepted: &[u8] = &[1, 2, 3, 4];
        handle
            .stage_output_by(
                Bytes::from_static(accepted),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect("a staging request inside its deadline is accepted");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let frame = next_o2t_frame(&peer, deadline).await;
            if frame.data.as_ref() == accepted {
                break;
            }
            assert!(
                frame.data.is_empty(),
                "the refused buffer resurfaced behind the accepted one: {frame:?}"
            );
        }
        mgr.shutdown().await;
    }

    /// **D-ENIP-20, the dead-manager verdict.** A staging call after the socket task has gone
    /// reports `Closed` — whether the command channel is already closed or the command is dropped
    /// unserviced with its ack sender.
    #[tokio::test]
    async fn stage_output_errors_after_manager_shutdown() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        let (_fixture, handle) = open_against_peer(&mgr, peer_port).await;

        mgr.shutdown().await;
        match handle.stage_output(Bytes::from_static(&[1, 2, 3, 4])).await {
            Err(EnipError::Closed) => {}
            other => panic!("expected Closed after the manager shut down, got {other:?}"),
        }
    }

    // -- manager smoke (bind, no live peer) --------------------------------

    #[tokio::test]
    async fn manager_binds_and_shuts_down() {
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(mgr.local_addr().port(), 0);
        mgr.shutdown().await;
    }
}
