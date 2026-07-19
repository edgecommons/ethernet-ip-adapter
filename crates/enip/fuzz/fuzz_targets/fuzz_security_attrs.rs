#![no_main]
//! libFuzzer target for the `security_attrs` decode surface (PROTOCOL-DESIGN §12.3,
//! DESIGN-cip-security.md §4.1): the CIP Security object model (0x5D/0x5E/0x5F) attribute decoders.
//! Invariant: decode is total — no panic, no OOM — on any input. Body shared with
//! `tests/fuzz_corpus.rs` via [`enip::harness`], so the fuzzer and the cross-platform regression
//! exercise identical code.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    enip::harness::security_attrs(data);
});
