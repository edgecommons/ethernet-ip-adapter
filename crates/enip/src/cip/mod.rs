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
