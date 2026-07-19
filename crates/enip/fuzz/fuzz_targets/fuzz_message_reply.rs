#![no_main]
//! libFuzzer target for the `message_reply` decode surface (PROTOCOL-DESIGN §12.3). Invariant: decode is
//! total — no panic, no OOM — on any input. Body shared with `tests/fuzz_corpus.rs` via
//! [`enip::harness`], so the fuzzer and the cross-platform regression exercise identical code.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    enip::harness::message_reply(data);
});
