//! # `enip` — an owned, pure-Rust EtherNet/IP + CIP protocol stack
//!
//! This crate is the wire engine `ethernet-ip-adapter` is built on: CIP **explicit messaging**
//! (unconnected UCMM and connected class-3 reads/writes) and **class-1 implicit I/O** (cyclic
//! produced/consumed assemblies over UDP), plus Allen-Bradley Logix tag services and device
//! discovery — faithful to the ODVA *CIP Networks Library* (Vol 1 CIP, Vol 2 EtherNet/IP).
//!
//! ## The isolation contract (D-ENIP-1, D-EIP-17)
//!
//! It is **pure protocol**. It deliberately knows nothing about EdgeCommons — no `edgecommons`
//! dependency, no UNS, no message envelopes, no `SouthboundSignalUpdate`, no metrics, no command
//! verbs, no adapter config schema. Its vocabulary is sessions, services, EPATHs, CIP values,
//! connections, and frames. The adapter consumes it only through its `device.rs` seam. This
//! isolation is what makes the stack independently testable, fuzzable, and reusable.
//!
//! ## Memory-safe by construction (D-ENIP-2/3, §4)
//!
//! Every inbound byte is device/attacker-controlled. The crate forbids `unsafe` and routes every
//! decode through a single bounds-checked cursor: a malformed, truncated, or hostile packet yields
//! a typed [`enum@error::WireError`], never a panic or UB.
//!
//! ## Module map (PROTOCOL-DESIGN §3.2)
//!
//! Layering (enforced by review + visibility): `wire` ← `encap`/`cpf`/`cip` ←
//! `cm`/`logix`/`io`/`assembly` ← `client`/`discovery`. Nothing imports upward.
//!
//! **Slices P1, P2, and P3 are implemented.** P1: the encapsulation layer, CPF, the CIP explicit
//! request/reply layer (EPATH, message router, status, types), device discovery, and the framed
//! codec. P2: the async session actor with `sender_context` correlation, per-request deadlines, and
//! stale-reply quarantine (§10.3–§10.4); the [`EipClient`] handle + [`ClientOptions`]; UCMM and
//! routed Unconnected_Send; connected class-3 messaging with a hard sequence match; the Connection
//! Manager (ForwardOpen/Close, NCP bit-packing); Logix Read/Write Tag with auto-fragmentation, tag
//! enumeration, and [`SymbolType`]; and the generic CIP attribute services. P3: class-1 implicit I/O
//! ([`io`]) — the [`IoManager`] socket task, the [`IoFrame`] codec in sequence-then-header order
//! (D-ENIP-10), the signed-window consume gauntlet with counted drops (D-ENIP-7), the produce
//! scheduler + run/idle (D-ENIP-9), and the inactivity watchdog (D-ENIP-8) — plus the class-1
//! ForwardOpen extensions in [`cm`] and the bounds-checked [`AssemblyLayout`] ([`assembly`]).
//!
//! There is deliberately **no embedded test server**: device simulators are external containers
//! (cpppo/OpENer) validated in later integration slices. The P2 state-machine tests drive the
//! session actor over in-memory [`tokio::io::duplex`] byte-stream fixtures (the actor is generic over
//! any `AsyncRead + AsyncWrite + Unpin`).
#![forbid(unsafe_code)]

pub mod error;

pub mod wire;

pub mod encap;

pub mod cpf;

pub mod cip;

// Connection Manager: ForwardOpen/Close codecs + NCP bit-packing (P2 implements the class-3 path;
// the class-1 use is P3).
pub mod cm;

// Logix tag services: Read/Write Tag (+ auto-fragmentation), tag enumeration, the symbol-type word.
pub mod logix;

// Class-1 implicit I/O runtime: IoManager (UDP socket task), IoConnection state machine, the
// sequence-then-header frame codec, the counted consume gauntlet, the produce scheduler, and the
// inactivity watchdog (§8.5–§8.8).
pub mod io;

// Assembly layout mapping: bounds-checked field extraction/insertion (§9, D-ENIP-11).
pub mod assembly;

// The async client handle + session actor (correlation, deadlines, quarantine) + connected class-3.
pub mod client;

pub mod discovery;

// The shared fuzz/decode-exercise harness (§12.3): one panic-free entry per hostile decode surface,
// the single source of truth driven by both the `crates/enip/fuzz` libFuzzer targets and the
// cross-platform `tests/fuzz_corpus.rs` regression sweep. `#[doc(hidden)]` — internal test scaffolding,
// not part of the consumed API surface.
#[doc(hidden)]
pub mod harness;

// ---- P1 public re-exports (the surface `DESIGN.md` §3.3 consumes from this slice) ----

pub use error::{EnipError, Result, WireError};

pub use wire::{WireReader, WireWriter};

pub use encap::codec::EncapCodec;
pub use encap::{
    Command, EncapFrame, EncapHeader, EncapStatus, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT, HEADER_LEN,
    MAX_DATA_LEN, PROTOCOL_VERSION,
};

pub use cpf::{Cpf, CpfItem, ItemType, SequencedAddress, SockAddrInfo};

pub use cip::epath::{EPath, PathError, PortSegment, Segment, TagAddress};
pub use cip::message::{MessageReply, MessageRequest};
pub use cip::status::{CipStatus, GeneralStatus};
pub use cip::types::{CipType, CipValue};

pub use discovery::{
    parse_list_interfaces, parse_list_services, DeviceIdentity, DeviceType, InterfaceItem,
    ServiceItem, VendorId,
};

// ---- P2 public re-exports (the async client surface `DESIGN.md` §3.3 consumes) ----

pub use client::{ClientOptions, ClientStats, EipClient, RoutePath};

pub use cm::{
    connection_manager_path, io_connection_path, transport_class1_trigger, ConnType,
    ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess, ForwardRequestFail,
    NetworkConnectionParams, Priority, ProductionTrigger, TimeoutMultiplier, VariableLength,
    TRANSPORT_CLASS1_TRIGGER,
};

pub use logix::{parse_tag_list, Scope, SymbolInfo, SymbolType, TagReadResult};

// ---- P3 public re-exports: class-1 implicit I/O + assembly mapping (§8–§9, §11.2) ----

pub use io::{
    AssemblyPath, ConsumeOutcome, DirectionSpec, DropReason, ForwardOpenService, IoConnection,
    IoConnectionHandle, IoConnectionParams, IoConnectionSpec, IoEvent, IoFrame, IoManager, IoStats,
    IoUpdate, LostReason, RealTimeFormat, IO_UDP_PORT,
};

pub use assembly::{AssemblyError, AssemblyLayout, FieldSpec};
