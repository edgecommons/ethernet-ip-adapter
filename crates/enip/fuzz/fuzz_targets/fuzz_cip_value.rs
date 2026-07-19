#![no_main]
//! libFuzzer target for the `cip_value` decode surface (PROTOCOL-DESIGN §12.3). Invariant: decode is
//! total — no panic, no OOM — on any input.
//!
//! Two paths are driven every run:
//! * the **raw** [`enip::harness::cip_value`] body (shared verbatim with `tests/fuzz_corpus.rs`),
//!   which drives `decode_tagged` and `decode` under every representative type code; and
//! * a **structured** `(type_code, bytes)` round-trip via `arbitrary`, so the fuzzer can steer the
//!   wire type independently of the value bytes (`decode` → `encode_value` → `decode`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u16, &[u8])| {
    let (type_code, data) = input;
    enip::harness::cip_value(data);
    enip::harness::cip_value_typed(type_code, data);
});
