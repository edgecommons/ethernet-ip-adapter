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
//! **Slice P1 is implemented**: the encapsulation layer, CPF, the CIP explicit request/reply layer
//! (EPATH, message router, status, types), device discovery, and the framed codec — all with the
//! no-panic decode invariant of §4 proven by truncation sweeps and golden vectors (§12). The
//! session actor, connection manager, Logix tag services, class-1 I/O, assembly mapping, and the
//! client handle are P2/P3 — their modules are still stubs, re-exported only where P1 needs a name.
#![forbid(unsafe_code)]

pub mod error;

pub mod wire;

pub mod encap;

pub mod cpf;

pub mod cip;

// P2: Connection Manager (ForwardOpen/Close, NCP bit-packing) — stub until the class-1 I/O slice.
pub mod cm;

// P2: Logix tag services (Read/Write Tag, enumeration, symbol-type word) — stub until the tag slice.
pub mod logix;

// P3: class-1 implicit I/O runtime (IoManager, produce/consume, watchdog) — stub until the I/O slice.
pub mod io;

// P2: assembly layout mapping — stub until the class-1 I/O slice.
pub mod assembly;

// P2/P3: the async client handle + session actor — stub until the session slice.
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

// The in-crate mock target (explicit-messaging responder + class-1 producer/consumer) used by the
// state-machine tests and the adapter's push validation fallback (D-ENIP-14, §12.5). Feature-gated
// so it never ships in the adapter's release binary.
#[cfg(feature = "testserver")]
pub mod testserver;
