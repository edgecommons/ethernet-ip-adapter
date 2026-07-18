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
//! **This is the slice-S1 skeleton: the module tree exists but is empty. P1 fills each module with
//! its codecs and the public API re-exported here.**
#![forbid(unsafe_code)]
// P1: the modules are intentionally empty in S1 (structure only). `dead_code` is allowed at the
// crate root so the skeleton builds clean under `-D warnings`; P1 removes this as the modules gain
// their public surface and internal callers.
#![allow(dead_code)]

pub mod error;

pub mod wire;

pub mod encap;

pub mod cpf;

pub mod cip;

pub mod cm;

pub mod logix;

pub mod io;

pub mod assembly;

pub mod client;

pub mod discovery;

// The in-crate mock target (explicit-messaging responder + class-1 producer/consumer) used by the
// state-machine tests and the adapter's push validation fallback (D-ENIP-14, §12.5). Feature-gated
// so it never ships in the adapter's release binary.
#[cfg(feature = "testserver")]
pub mod testserver;
