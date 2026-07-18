//! Class-1 implicit I/O runtime (PROTOCOL-DESIGN §8.5–§8.8, D-ENIP-7/8/9/10).
//!
//! The adapter is the **scanner/originator**: it ForwardOpens an I/O connection pair against a
//! target's assembly instances and then produces O→T frames at the negotiated O→T API while
//! consuming the T→O frames the target produces. Everything runs over bare CPF datagrams on UDP
//! :2222 — no encapsulation header (§8.1). This module owns:
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
//! * [`IoManager`] — the thin UDP socket task: recv → route by connection id → drive
//!   [`IoConnection::consume`]; and a scheduler tick that drives [`IoConnection::poll_produce`] /
//!   [`IoConnection::poll_watchdog`]. It exposes [`IoConnectionHandle`] (`events`, `set_output`,
//!   `set_run`, `stats`, `close`).
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
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

use crate::cip::epath::Segment;
use crate::cip::message::{MessageReply, MessageRequest};
use crate::cm::{
    connection_manager_path, io_connection_path, transport_class1_trigger, ConnType,
    ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess, ForwardRequestFail,
    NetworkConnectionParams, Priority, ProductionTrigger, TimeoutMultiplier, VariableLength,
};
use crate::cpf::{Cpf, CpfItem, ItemType, SequencedAddress, SockAddrInfo};
use crate::error::{EnipError, Result};
use crate::wire::{WireReader, WireWriter};

/// The IANA-assigned EtherNet/IP implicit-I/O UDP port (§8.1).
pub const IO_UDP_PORT: u16 = 2222;

/// The on-wire size above which a standard ForwardOpen cannot express the connection and the driver
/// switches to LargeForwardOpen (§8.2).
const LARGE_FORWARD_OPEN_THRESHOLD: u16 = 505;

/// Per-connection event channel depth. Bounded so a stalled consumer cannot grow memory without
/// bound; overflow is counted (`overflowed_events`) and the newest frame is dropped — telemetry
/// consumers drain fresh samples and alarm on the counter (§8.6).
const EVENT_CHANNEL_DEPTH: usize = 256;

/// The scheduler-tick resolution. Per-connection produce cadence and watchdog deadlines are honoured
/// by [`IoConnection::poll_produce`] / [`IoConnection::poll_watchdog`]; the tick only needs to be
/// finer than the smallest RPI in play.
const SCHEDULER_TICK: Duration = Duration::from_millis(1);

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
    pub fn decode(format: RealTimeFormat, buf: &[u8]) -> core::result::Result<Self, crate::error::WireError> {
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
        Ok(Self { sequence, run_mode, data })
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
    /// The stripped data length did not match the negotiated T→O size (or the frame was a runt).
    SizeMismatch,
    /// The class-1 sequence was a duplicate, stale, or reordered frame (signed-window rule).
    Stale,
}

/// Live, lock-free per-connection counters (§8.6, §10.2). Shared between the manager task (writer)
/// and the handle (reader).
#[derive(Debug, Default)]
struct ConnCounters {
    frames_accepted: AtomicU64,
    size_mismatch: AtomicU64,
    stale_frames: AtomicU64,
    sequence_gaps: AtomicU64,
    overflowed_events: AtomicU64,
    produce_overruns: AtomicU64,
}

/// Manager-wide datagram counters (§8.6, §10.2). Shared across every connection on the socket.
#[derive(Debug, Default)]
struct ManagerCounters {
    malformed_frames: AtomicU64,
    unknown_connection: AtomicU64,
}

/// A snapshot of a connection's peer-driven counters (§10.2). The adapter alarms on these without
/// the crate knowing what an alarm is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoStats {
    /// T→O frames accepted and delivered.
    pub frames_accepted: u64,
    /// Frames dropped for a size mismatch (or a runt frame).
    pub size_mismatch: u64,
    /// Frames dropped as duplicate / stale / reordered by the signed-window rule.
    pub stale_frames: u64,
    /// Sum of forward sequence gaps observed (missed frames).
    pub sequence_gaps: u64,
    /// Accepted samples dropped because the event channel was full.
    pub overflowed_events: u64,
    /// Produce ticks skipped because a prior tick had not been serviced.
    pub produce_overruns: u64,
    /// Datagrams dropped as malformed CPF (manager-wide).
    pub malformed_frames: u64,
    /// Datagrams whose connection id matched no live connection (manager-wide).
    pub unknown_connection: u64,
}

impl ConnCounters {
    fn snapshot(&self) -> IoStats {
        IoStats {
            frames_accepted: self.frames_accepted.load(Ordering::Relaxed),
            size_mismatch: self.size_mismatch.load(Ordering::Relaxed),
            stale_frames: self.stale_frames.load(Ordering::Relaxed),
            sequence_gaps: self.sequence_gaps.load(Ordering::Relaxed),
            overflowed_events: self.overflowed_events.load(Ordering::Relaxed),
            produce_overruns: self.produce_overruns.load(Ordering::Relaxed),
            malformed_frames: 0,
            unknown_connection: 0,
        }
    }
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
        let data = if dir.format.carries_data() { dir.data_size } else { 0 };
        let total = dir
            .format
            .overhead()
            .checked_add(data)
            .ok_or(EnipError::TooLarge { limit: usize::from(u16::MAX) })?;
        u16::try_from(total).map_err(|_| EnipError::TooLarge { limit: usize::from(u16::MAX) })
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
    pub fn consume(&mut self, connected_data: &[u8], encap_sequence: u32, now: Instant) -> ConsumeOutcome {
        // Strip sequence + optional header. A runt frame is a typed drop, counted as a size mismatch.
        let frame = match IoFrame::decode(self.params.t2o_format, connected_data) {
            Ok(frame) => frame,
            Err(_) => {
                self.counters.size_mismatch.fetch_add(1, Ordering::Relaxed);
                return ConsumeOutcome::Dropped { reason: DropReason::SizeMismatch };
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
            return ConsumeOutcome::Dropped { reason: DropReason::SizeMismatch };
        }

        // Sequence acceptance: signed forward window (§8.6, D-ENIP-7).
        if let Some(seq) = frame.sequence {
            if let Some(last) = self.last_accepted_seq {
                let delta = seq.wrapping_sub(last) as i16;
                if delta <= 0 {
                    self.counters.stale_frames.fetch_add(1, Ordering::Relaxed);
                    return ConsumeOutcome::Dropped { reason: DropReason::Stale };
                }
                if delta > 1 {
                    // A forward jump > 1 counts the gap (missed frames) but still accepts.
                    let gap = u64::from((delta as u16).saturating_sub(1));
                    self.counters.sequence_gaps.fetch_add(gap, Ordering::Relaxed);
                }
            }
            self.last_accepted_seq = Some(seq);
        }

        // Accepted: refresh the watchdog, deliver.
        let first = !self.up;
        self.up = true;
        self.watchdog_deadline = now
            .checked_add(watchdog_timeout(self.params.t2o_api, self.params.timeout_multiplier))
            .unwrap_or(now);
        self.counters.frames_accepted.fetch_add(1, Ordering::Relaxed);
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
    /// cadence with `MissedTickBehavior::Skip` semantics — a lapsed schedule fires once and counts
    /// the skipped ticks as `produce_overruns`. Returns `None` when no tick is due. Production never
    /// stops while the connection is open (D-ENIP-9): a heartbeat direction still emits the seq-only
    /// frame.
    pub fn poll_produce(&mut self, now: Instant) -> Option<Result<Bytes>> {
        if now < self.next_produce_at {
            return None;
        }
        // Count the scheduled ticks at or before `now`; fire once, skip the rest.
        let mut ticks: u64 = 0;
        let mut next = self.next_produce_at;
        loop {
            if next <= now {
                ticks = ticks.saturating_add(1);
                match next.checked_add(self.params.o2t_api) {
                    Some(t) => next = t,
                    None => break,
                }
            } else {
                break;
            }
        }
        self.next_produce_at = next;
        if ticks > 1 {
            self.counters.produce_overruns.fetch_add(ticks.saturating_sub(1), Ordering::Relaxed);
        }
        Some(self.produce_frame())
    }

    /// Build one O→T datagram, advancing the class-1 sequence (skip 0 on wrap) and the encapsulation
    /// sequence (§8.7). Public so the produce logic is testable without the scheduler or a socket.
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
            sequence: if format.has_sequence() { Some(self.o2t_class1_seq) } else { None },
            run_mode: if format.has_header() { Some(self.run) } else { None },
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
/// sequenced-address connection id, and hand the connected-data payload to that connection's
/// [`IoConnection::consume`]. CPF-level drops (malformed shape, unknown id) are counted here; the
/// per-connection drops are counted inside `consume`.
struct Registry {
    conns: HashMap<u32, IoConnection>,
    stats: Arc<ManagerCounters>,
}

/// The result of routing one datagram (§8.6).
enum Routed {
    Accepted { connection_id: u32, first: bool, update: IoUpdate },
    Dropped { connection_id: Option<u32>, reason: DropReason },
}

impl Registry {
    fn new(stats: Arc<ManagerCounters>) -> Self {
        Self { conns: HashMap::new(), stats }
    }

    /// Decode `buf` as a class-1 datagram and route it to its connection (§8.6). Every failure is a
    /// counted, typed drop — never a panic, whatever bytes arrive.
    fn consume_datagram(&mut self, buf: &[u8], now: Instant) -> Routed {
        let cpf = match Cpf::decode(buf) {
            Ok(cpf) => cpf,
            Err(_) => {
                self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
                return Routed::Dropped { connection_id: None, reason: DropReason::Malformed };
            }
        };
        let (Some(addr_item), Some(data_item)) = (
            cpf.find(ItemType::SequencedAddress),
            cpf.find(ItemType::ConnectedData),
        ) else {
            self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
            return Routed::Dropped { connection_id: None, reason: DropReason::Malformed };
        };
        let addr = match SequencedAddress::decode(&addr_item.data) {
            Ok(addr) => addr,
            Err(_) => {
                self.stats.malformed_frames.fetch_add(1, Ordering::Relaxed);
                return Routed::Dropped { connection_id: None, reason: DropReason::Malformed };
            }
        };
        let Some(conn) = self.conns.get_mut(&addr.connection_id) else {
            self.stats.unknown_connection.fetch_add(1, Ordering::Relaxed);
            return Routed::Dropped {
                connection_id: Some(addr.connection_id),
                reason: DropReason::UnknownConnection,
            };
        };
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
    fn cm_ucmm(&self, request: MessageRequest) -> impl core::future::Future<Output = Result<Cpf>> + Send;

    /// The target device's IP, used as the default O→T transmit address when the reply carries no
    /// O→T sockaddr redirect. `None` for a non-socket session (in-memory test fixtures).
    fn target_ip(&self) -> Option<IpAddr>;
}

// ---------------------------------------------------------------------------
// The manager task & handle (§8.6, §11.1)
// ---------------------------------------------------------------------------

/// A command from a handle (or `forward_open`) to the manager task.
enum ManagerCommand {
    Add {
        conn: Box<IoConnection>,
        events_tx: mpsc::Sender<IoEvent>,
    },
    SetOutput {
        connection_id: u32,
        bytes: Bytes,
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
    /// Bind the implicit-I/O UDP socket at `addr` (e.g. `"0.0.0.0:2222"`) and spawn the socket task
    /// (§8.6). The task owns the socket; this handle owns only the command channel.
    pub async fn bind(addr: impl tokio::net::ToSocketAddrs) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let stats = Arc::new(ManagerCounters::default());
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(manager_task(socket, rx, stats.clone()));
        Ok(Self { tx, local_addr, stats })
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
    pub async fn forward_open<S: ForwardOpenService>(
        &self,
        session: &S,
        spec: IoConnectionSpec,
    ) -> Result<IoConnectionHandle> {
        let t2o_connection_id = rand::random::<u32>() | 1;
        let connection_serial = rand::random::<u16>() | 1;
        let originator_serial = rand::random::<u32>();

        let open = build_class1_open(&spec, t2o_connection_id, connection_serial, originator_serial)?;
        let mr = MessageRequest::new(open.service(), connection_manager_path(), open.encode()?);
        let reply_cpf = session.cm_ucmm(mr).await?;

        let data_item = reply_cpf
            .find(ItemType::UnconnectedData)
            .ok_or(EnipError::ProtocolViolation { detail: "forward-open reply missing data item" })?;
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

        // Sockaddr items (§8.2): an O→T sockaddr redirects our transmit endpoint; a multicast T→O
        // sockaddr is the group to join.
        let o2t_sock = reply_cpf
            .find(ItemType::SockAddrOtoT)
            .and_then(|i| SockAddrInfo::decode(&i.data).ok());
        let t2o_sock = reply_cpf
            .find(ItemType::SockAddrTtoO)
            .and_then(|i| SockAddrInfo::decode(&i.data).ok());
        let tx_endpoint = resolve_tx_endpoint(o2t_sock, session.target_ip())?;
        let multicast_group = t2o_sock.and_then(|s| {
            let ip = Ipv4Addr::from(s.sin_addr);
            ip.is_multicast().then_some(ip)
        });

        let params = IoConnectionParams {
            o2t_connection_id: success.o_t_connection_id,
            t2o_connection_id,
            o2t_api: Duration::from_micros(u64::from(success.o_t_api)),
            t2o_api: Duration::from_micros(u64::from(success.t_o_api)),
            timeout_multiplier: spec.timeout_multiplier.multiplier(),
            o2t_format: spec.o2t.format,
            t2o_format: spec.t2o.format,
            o2t_data_size: spec.o2t.data_size,
            t2o_data_size: spec.t2o.data_size,
            o2t_fixed: matches!(spec.o2t.variable, VariableLength::Fixed),
            t2o_fixed: matches!(spec.t2o.variable, VariableLength::Fixed),
            tx_endpoint,
            multicast_group,
        };
        let conn = IoConnection::new(params, Instant::now());
        let counters = conn.counters.clone();
        let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_DEPTH);

        self.tx
            .send(ManagerCommand::Add { conn: Box::new(conn), events_tx })
            .await
            .map_err(|_| EnipError::Closed)?;

        Ok(IoConnectionHandle {
            connection_id: t2o_connection_id,
            events: events_rx,
            cmd: self.tx.clone(),
            counters,
            manager_stats: self.stats.clone(),
            o2t_data_size: spec.o2t.data_size,
            o2t_fixed: matches!(spec.o2t.variable, VariableLength::Fixed),
            o2t_carries_data: spec.o2t.format.carries_data(),
            o2t_api: Duration::from_micros(u64::from(success.o_t_api)),
            t2o_api: Duration::from_micros(u64::from(success.t_o_api)),
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
    events: mpsc::Receiver<IoEvent>,
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

    /// The event stream (`Up`, `Data`, `Lost`) — a bounded receiver (§11.2).
    pub fn events(&mut self) -> &mut mpsc::Receiver<IoEvent> {
        &mut self.events
    }

    /// Set the O→T output buffer, validated against the negotiated O→T size (§8.7). A fixed-size
    /// connection requires an exact match; a variable-size one caps at the negotiated size.
    pub fn set_output(&self, bytes: impl Into<Bytes>) -> Result<()> {
        let bytes = bytes.into();
        if self.o2t_carries_data {
            if self.o2t_fixed && bytes.len() != self.o2t_data_size {
                return Err(EnipError::ProtocolViolation {
                    detail: "output size does not match the negotiated fixed O→T size",
                });
            }
            if bytes.len() > self.o2t_data_size {
                return Err(EnipError::TooLarge { limit: self.o2t_data_size });
            }
        }
        self.cmd
            .try_send(ManagerCommand::SetOutput { connection_id: self.connection_id, bytes })
            .map_err(|_| EnipError::Closed)
    }

    /// Set the O→T run/idle bit (§8.7 / D-ENIP-9).
    pub fn set_run(&self, run: bool) -> Result<()> {
        self.cmd
            .try_send(ManagerCommand::SetRun { connection_id: self.connection_id, run })
            .map_err(|_| EnipError::Closed)
    }

    /// A snapshot of this connection's counters merged with the manager-wide datagram counters
    /// (§10.2).
    #[must_use]
    pub fn stats(&self) -> IoStats {
        let mut s = self.counters.snapshot();
        s.malformed_frames = self.manager_stats.malformed_frames.load(Ordering::Relaxed);
        s.unknown_connection = self.manager_stats.unknown_connection.load(Ordering::Relaxed);
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
        let _ = session.cm_ucmm(mr).await;
        let _ = self
            .cmd
            .send(ManagerCommand::Remove { connection_id: self.connection_id })
            .await;
        Ok(())
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

    let o2t_params = NetworkConnectionParams::io(o2t_size, spec.o2t.variable, spec.o2t.priority, spec.o2t.conn_type);
    let t2o_params = NetworkConnectionParams::io(t2o_size, spec.t2o.variable, spec.t2o.priority, spec.t2o.conn_type);

    let o2t_rpi = duration_to_micros(spec.o2t.rpi)?;
    let t2o_rpi = duration_to_micros(spec.t2o.rpi)?;

    let mut path = io_connection_path(spec.assembly.config, spec.assembly.output, spec.assembly.input);
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
    u32::try_from(d.as_micros()).map_err(|_| EnipError::TooLarge { limit: u32::MAX as usize })
}

/// Resolve the O→T transmit endpoint (§8.2): the O→T sockaddr redirect if present (its address
/// unless `0.0.0.0`, its port unless 0), else the target IP on :2222.
fn resolve_tx_endpoint(o2t_sock: Option<SockAddrInfo>, target_ip: Option<IpAddr>) -> Result<SocketAddr> {
    if let Some(s) = o2t_sock {
        let sock_ip = Ipv4Addr::from(s.sin_addr);
        let port = if s.sin_port != 0 { s.sin_port } else { IO_UDP_PORT };
        let ip = if sock_ip.is_unspecified() {
            target_ip.ok_or(EnipError::ProtocolViolation { detail: "no O→T transmit address available" })?
        } else {
            IpAddr::V4(sock_ip)
        };
        return Ok(SocketAddr::new(ip, port));
    }
    let ip = target_ip.ok_or(EnipError::ProtocolViolation { detail: "no O→T transmit address available" })?;
    Ok(SocketAddr::new(ip, IO_UDP_PORT))
}

/// The socket task (§8.6, §11.1): receive datagrams and route them; drive produce + watchdog on a
/// scheduler tick. Thin — all tested logic lives in [`IoConnection`] / [`Registry`].
async fn manager_task(
    socket: UdpSocket,
    mut rx: mpsc::Receiver<ManagerCommand>,
    stats: Arc<ManagerCounters>,
) {
    let mut registry = Registry::new(stats);
    let mut events: HashMap<u32, mpsc::Sender<IoEvent>> = HashMap::new();
    let mut buf = vec![0u8; 65_535];
    let mut tick = tokio::time::interval(SCHEDULER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    None | Some(ManagerCommand::Shutdown) => break,
                    Some(ManagerCommand::Add { conn, events_tx }) => {
                        let id = conn.connection_id();
                        if let Some(group) = conn.multicast_group() {
                            let _ = socket.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED);
                        }
                        registry.conns.insert(id, *conn);
                        events.insert(id, events_tx);
                    }
                    Some(ManagerCommand::SetOutput { connection_id, bytes }) => {
                        if let Some(conn) = registry.conns.get_mut(&connection_id) {
                            conn.set_output(bytes);
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
                if let Ok((n, _src)) = recv {
                    let now = Instant::now();
                    if let Some(slice) = buf.get(..n) {
                        match registry.consume_datagram(slice, now) {
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
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let mut expired: Vec<u32> = Vec::new();
                for (id, conn) in registry.conns.iter_mut() {
                    if let Some(Ok(datagram)) = conn.poll_produce(now) {
                        let _ = socket.send_to(&datagram, conn.tx_endpoint()).await;
                    }
                    if conn.poll_watchdog(now) {
                        expired.push(*id);
                    }
                }
                for id in expired {
                    if let Some(tx) = events.get(&id) {
                        let _ = tx.try_send(IoEvent::Lost { reason: LostReason::Timeout });
                    }
                    remove_connection(&socket, &mut registry, &mut events, id);
                }
            }
        }
    }
}

/// Deliver an accepted sample to its connection's stream: an `Up` on the first frame, then the
/// `Data`; a full channel counts `overflowed_events` and drops the newest (§8.6).
fn deliver(
    registry: &Registry,
    events: &HashMap<u32, mpsc::Sender<IoEvent>>,
    connection_id: u32,
    first: bool,
    update: IoUpdate,
) {
    let Some(tx) = events.get(&connection_id) else { return };
    if first {
        if let Some(conn) = registry.conns.get(&connection_id) {
            let (o2t_api, t2o_api) = conn.apis();
            let _ = tx.try_send(IoEvent::Up { o2t_api, t2o_api });
        }
    }
    if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(IoEvent::Data(update)) {
        if let Some(conn) = registry.conns.get(&connection_id) {
            conn.counters.overflowed_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Remove a connection: leave its multicast group and drop its state + event sender.
fn remove_connection(
    socket: &UdpSocket,
    registry: &mut Registry,
    events: &mut HashMap<u32, mpsc::Sender<IoEvent>>,
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
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
            tx_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), IO_UDP_PORT),
            multicast_group: None,
        }
    }

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
                SequencedAddress { connection_id: cid, encap_sequence: eseq }.encode(),
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
        assert_eq!(IoFrame::decode(RealTimeFormat::Header32Bit, &bytes).unwrap(), frame);

        // Idle header has bit 0 clear.
        let idle = IoFrame { sequence: Some(1), run_mode: Some(false), data: Bytes::new() };
        let ib = idle.encode(RealTimeFormat::Header32Bit);
        assert_eq!(ib.as_ref(), &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(IoFrame::decode(RealTimeFormat::Header32Bit, &ib).unwrap().run_mode, Some(false));

        // Modeless: seq then data, no header.
        let m = IoFrame { sequence: Some(7), run_mode: None, data: Bytes::from_static(&[1, 2, 3]) };
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
        let mut conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);

        // First frame (seq 1) → accepted, first == true.
        let out = conn.consume(&modeless_payload(1, &[0u8; 8]), 100, now);
        assert!(matches!(out, ConsumeOutcome::Accepted { first: true, .. }));
        assert_eq!(conn.stats().frames_accepted, 1);

        // Forward by 1 (seq 2) → accepted, no gap.
        assert!(matches!(conn.consume(&modeless_payload(2, &[0u8; 8]), 101, now), ConsumeOutcome::Accepted { first: false, .. }));
        assert_eq!(conn.stats().sequence_gaps, 0);

        // Forward jump seq 2 → 5 (gap of 2) → accepted, sequence_gaps += 2.
        assert!(matches!(conn.consume(&modeless_payload(5, &[0u8; 8]), 102, now), ConsumeOutcome::Accepted { .. }));
        assert_eq!(conn.stats().sequence_gaps, 2);
        assert_eq!(conn.stats().frames_accepted, 3);
    }

    #[tokio::test]
    async fn duplicate_and_stale_and_reordered_are_dropped_and_counted() {
        let now = Instant::now();
        let mut conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);
        conn.consume(&modeless_payload(10, &[0u8; 8]), 1, now); // accept seq 10

        // Duplicate (seq 10): (10-10) as i16 == 0, not > 0 → stale.
        assert!(matches!(conn.consume(&modeless_payload(10, &[0u8; 8]), 2, now), ConsumeOutcome::Dropped { reason: DropReason::Stale }));
        // Stale (seq 9): negative delta → stale.
        assert!(matches!(conn.consume(&modeless_payload(9, &[0u8; 8]), 3, now), ConsumeOutcome::Dropped { reason: DropReason::Stale }));
        // Reordered old (seq 5): negative delta → stale.
        assert!(matches!(conn.consume(&modeless_payload(5, &[0u8; 8]), 4, now), ConsumeOutcome::Dropped { reason: DropReason::Stale }));
        assert_eq!(conn.stats().stale_frames, 3);

        // A valid forward frame after the drops is still accepted.
        assert!(matches!(conn.consume(&modeless_payload(11, &[0u8; 8]), 5, now), ConsumeOutcome::Accepted { .. }));
        assert_eq!(conn.stats().frames_accepted, 2);
    }

    #[tokio::test]
    async fn wrong_size_frame_is_dropped_and_counted() {
        let now = Instant::now();
        let mut conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);
        // Negotiated T→O data size is 8; deliver 4 bytes → size mismatch.
        assert!(matches!(conn.consume(&modeless_payload(1, &[0u8; 4]), 1, now), ConsumeOutcome::Dropped { reason: DropReason::SizeMismatch }));
        // A runt (no room for the sequence) → also a size-mismatch drop, never a panic.
        assert!(matches!(conn.consume(&[0x00], 2, now), ConsumeOutcome::Dropped { reason: DropReason::SizeMismatch }));
        assert_eq!(conn.stats().size_mismatch, 2);
        // A correctly-sized frame is then accepted.
        assert!(matches!(conn.consume(&modeless_payload(1, &[0u8; 8]), 3, now), ConsumeOutcome::Accepted { .. }));
    }

    #[tokio::test]
    async fn unknown_connection_and_malformed_datagrams_are_counted_by_registry() {
        let now = Instant::now();
        let stats = Arc::new(ManagerCounters::default());
        let mut registry = Registry::new(stats.clone());
        let conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);
        let cid = conn.connection_id();
        registry.conns.insert(cid, conn);

        // Unknown connection id 0xDEADBEEF.
        let unknown = datagram(0xDEAD_BEEF, 1, &modeless_payload(1, &[0u8; 8]));
        assert!(matches!(registry.consume_datagram(&unknown, now), Routed::Dropped { reason: DropReason::UnknownConnection, .. }));
        assert_eq!(stats.unknown_connection.load(Ordering::Relaxed), 1);

        // Malformed CPF (garbage bytes that are not a valid item list).
        assert!(matches!(registry.consume_datagram(&[0xFF, 0xFF, 0xFF], now), Routed::Dropped { reason: DropReason::Malformed, .. }));
        assert!(stats.malformed_frames.load(Ordering::Relaxed) >= 1);

        // The known connection still accepts a valid datagram after the drops.
        let good = datagram(cid, 1, &modeless_payload(1, &[0u8; 8]));
        assert!(matches!(registry.consume_datagram(&good, now), Routed::Accepted { first: true, .. }));
    }

    // -- watchdog (D-ENIP-8), paused clock ---------------------------------

    #[tokio::test(start_paused = true)]
    async fn watchdog_fires_once_after_multiplier_times_t2o_api() {
        let now = Instant::now();
        // T2O API 20 ms × multiplier 16 = 320 ms deadline.
        let mut conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);
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
        let mut conn = IoConnection::new(params(RealTimeFormat::Header32Bit, RealTimeFormat::Modeless), now);
        conn.set_output(Bytes::from_static(&[1, 2, 3, 4]));

        // Nothing due yet.
        assert!(conn.poll_produce(now).is_none());

        // Advance one O→T API (20 ms) → one frame, seq 1 / encap 1.
        tokio::time::advance(Duration::from_millis(20)).await;
        let d1 = conn.poll_produce(Instant::now()).unwrap().unwrap();
        assert_eq!(conn.last_produced_sequence(), 1);
        assert_eq!(conn.last_encap_sequence(), 1);
        // Decode the produced datagram: sequenced address + connected data (seq then header then data).
        let cpf = Cpf::decode(&d1).unwrap();
        let addr = SequencedAddress::decode(&cpf.find(ItemType::SequencedAddress).unwrap().data).unwrap();
        assert_eq!(addr.connection_id, 0xAABB_CCDD);
        assert_eq!(addr.encap_sequence, 1);
        let frame = IoFrame::decode(RealTimeFormat::Header32Bit, &cpf.find(ItemType::ConnectedData).unwrap().data).unwrap();
        assert_eq!(frame.sequence, Some(1));
        assert_eq!(frame.run_mode, Some(true));
        assert_eq!(frame.data.as_ref(), &[1, 2, 3, 4]);

        // Advance another API → seq 2 / encap 2.
        tokio::time::advance(Duration::from_millis(20)).await;
        conn.poll_produce(Instant::now()).unwrap().unwrap();
        assert_eq!(conn.last_produced_sequence(), 2);
        assert_eq!(conn.last_encap_sequence(), 2);
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
        let frame = IoFrame::decode(RealTimeFormat::Heartbeat, &cpf.find(ItemType::ConnectedData).unwrap().data).unwrap();
        // Heartbeat: sequence present, no data.
        assert_eq!(frame.sequence, Some(1));
        assert!(frame.data.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn missed_produce_ticks_count_overruns() {
        let now = Instant::now();
        let mut conn = IoConnection::new(params(RealTimeFormat::Heartbeat, RealTimeFormat::Modeless), now);
        // Jump three API periods at once: one fire, two skipped.
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(conn.poll_produce(Instant::now()).is_some());
        assert_eq!(conn.stats().produce_overruns, 2);
        // Only one frame was produced despite three periods elapsing.
        assert_eq!(conn.last_encap_sequence(), 1);
    }

    // -- forward-open sizing / trigger -------------------------------------

    #[test]
    fn on_wire_size_accounts_for_sequence_and_header() {
        // Modeless T→O of 8 bytes data → 2 (seq) + 8 = 10.
        let t2o = DirectionSpec {
            rpi: Duration::from_millis(20), data_size: 8, format: RealTimeFormat::Modeless,
            conn_type: ConnType::P2P, priority: Priority::Scheduled, variable: VariableLength::Fixed,
        };
        assert_eq!(IoConnectionSpec::on_wire_size(&t2o).unwrap(), 10);
        // Header32Bit O→T of 4 bytes → 2 (seq) + 4 (header) + 4 = 10.
        let o2t = DirectionSpec { format: RealTimeFormat::Header32Bit, data_size: 4, ..t2o.clone() };
        assert_eq!(IoConnectionSpec::on_wire_size(&o2t).unwrap(), 10);
        // Heartbeat O→T size 0 → 2 (seq only).
        let hb = DirectionSpec { format: RealTimeFormat::Heartbeat, data_size: 0, ..t2o };
        assert_eq!(IoConnectionSpec::on_wire_size(&hb).unwrap(), 2);
    }

    #[test]
    fn build_open_produces_class1_trigger_and_sized_ncp() {
        let spec = IoConnectionSpec {
            assembly: AssemblyPath { config: Some(151), output: 150, input: 100, route: vec![] },
            t2o: DirectionSpec { rpi: Duration::from_millis(20), data_size: 32, format: RealTimeFormat::Modeless, conn_type: ConnType::P2P, priority: Priority::Scheduled, variable: VariableLength::Fixed },
            o2t: DirectionSpec { rpi: Duration::from_millis(20), data_size: 4, format: RealTimeFormat::Header32Bit, conn_type: ConnType::P2P, priority: Priority::Scheduled, variable: VariableLength::Fixed },
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

    #[test]
    fn tx_endpoint_prefers_o2t_sockaddr_then_target_ip() {
        // O→T sockaddr with a concrete address + port wins.
        let sa = SockAddrInfo::ipv4(0xC0A8_0164, 0x08AE); // 192.168.1.100:2222
        let ep = resolve_tx_endpoint(Some(sa), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).unwrap();
        assert_eq!(ep, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 2222));
        // 0.0.0.0 sockaddr falls back to the target IP, keeping the sockaddr port.
        let sa0 = SockAddrInfo::ipv4(0, 0x08AE);
        let ep0 = resolve_tx_endpoint(Some(sa0), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).unwrap();
        assert_eq!(ep0, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 2222));
        // No sockaddr → target IP on :2222.
        let ep1 = resolve_tx_endpoint(None, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).unwrap();
        assert_eq!(ep1, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 2222));
        // No sockaddr and no target IP → a typed error, never a panic.
        assert!(resolve_tx_endpoint(None, None).is_err());
    }

    // -- manager smoke (bind, no live peer) --------------------------------

    #[tokio::test]
    async fn manager_binds_and_shuts_down() {
        let mgr = IoManager::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(mgr.local_addr().port(), 0);
        mgr.shutdown().await;
    }
}
