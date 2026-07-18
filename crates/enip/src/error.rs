//! Error & failure model (PROTOCOL-DESIGN §10).
//!
//! `EnipError` (session/connection/CIP-status-carrying) and `WireError`
//! (`Truncated`/`Malformed`, naming the layer that failed). Decoders are total functions
//! `&[u8] -> Result<T, WireError>` — no panic, no UB, no wrapping arithmetic on wire numbers.
//!
//! P1 fills this module.
