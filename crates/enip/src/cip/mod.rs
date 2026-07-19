//! CIP layer (PROTOCOL-DESIGN §6).
//!
//! Message Router request/reply, EPATH encoding, elementary CIP data types and values, the typed
//! `GeneralStatus`, and the generic attribute services. Split into the submodules below.
//!
//! P1 fills these modules.

pub mod epath;
pub mod message;
pub mod status;
pub mod types;
pub mod services;
// CIP Security object model (0x5D/0x5E/0x5F) — typed posture reads over the generic attribute
// services (§7.7 / DESIGN-cip-security.md §4.1). Pure decoding, no new deps, no feature gate.
pub mod security;
