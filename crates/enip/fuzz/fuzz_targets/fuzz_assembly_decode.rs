#![no_main]
//! libFuzzer target for the `assembly_decode` surface (PROTOCOL-DESIGN §12.3). Invariant: the
//! [`enip::AssemblyLayout`] builder and extractor are total against hostile field descriptors — no
//! panic, no out-of-bounds, no unchecked arithmetic — on any input.
//!
//! The body is [`enip::harness::assembly_decode`], shared verbatim with `tests/fuzz_corpus.rs`: it
//! derives an arbitrary but validated layout from the leading bytes (`arbitrary` is not needed to
//! structure it — the derivation is deterministic over the raw slice) and runs
//! `AssemblyLayout::decode` over the tail.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    enip::harness::assembly_decode(data);
});
