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
//! **Slices P1 and P2 are implemented.** P1: the encapsulation layer, CPF, the CIP explicit
//! request/reply layer (EPATH, message router, status, types), device discovery, and the framed
//! codec. P2: the async session actor with `sender_context` correlation, per-request deadlines, and
//! stale-reply quarantine (§10.3–§10.4); the [`EipClient`] handle + [`ClientOptions`]; UCMM and
//! routed Unconnected_Send; connected class-3 messaging with a hard sequence match; the Connection
//! Manager (ForwardOpen/Close, NCP bit-packing); Logix Read/Write Tag with auto-fragmentation, tag
//! enumeration, and [`SymbolType`]; and the generic CIP attribute services. Class-1 implicit I/O
//! (`io`) and assembly mapping (`assembly`) are P3.
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

// P3: class-1 implicit I/O runtime (IoManager, produce/consume, watchdog) — stub until the I/O slice.
pub mod io;

// P3: assembly layout mapping — stub until the class-1 I/O slice.
pub mod assembly;

// The async client handle + session actor (correlation, deadlines, quarantine) + connected class-3.
pub mod client;

pub mod discovery;

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
    ConnType, ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess, ForwardRequestFail,
    NetworkConnectionParams, Priority, TimeoutMultiplier, VariableLength,
};

pub use logix::{Scope, SymbolInfo, SymbolType, TagReadResult};
