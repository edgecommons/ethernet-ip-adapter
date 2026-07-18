//! `WireReader` / `WireWriter` — the ONLY way wire bytes are read or written (PROTOCOL-DESIGN §4).
//!
//! A checked little-endian cursor: every read validates `remaining()` first and returns
//! `Err(WireError::Truncated)` rather than indexing or wrapping. This is where the no-panic
//! invariant is made mechanical (`clippy::indexing_slicing`/`arithmetic_side_effects` denied).
//!
//! P1 fills this module.
