//! Cross-platform fuzz-corpus regression (PROTOCOL-DESIGN §12.3, §4).
//!
//! libFuzzer/cargo-fuzz needs a nightly toolchain on Linux, so CI on Windows (and every ordinary
//! `cargo test`) cannot run it. This test makes the fuzz invariant — **every decoder is total: no
//! panic on any input** — regression-tested *everywhere* by running each fuzz target's exact decode
//! body ([`enip::harness`], the same functions the libFuzzer targets call) over:
//!
//! 1. the checked-in **seed corpus** (`fuzz/corpus/<target>/*`) — the golden vectors + crafted
//!    malformed inputs the deeper Linux/WSL fuzzing starts from;
//! 2. every **truncation prefix** of each seed (the §12.2 sweep, applied to the fuzz surface); and
//! 3. a deterministic **random/adversarial sweep** — pseudo-random buffers plus structured "length
//!    lie" payloads across a spread of lengths.
//!
//! A panic in any decoder surfaces as a failed test on any platform; cargo-fuzz remains the deeper
//! exploration layer (`--max_total_time`, coverage-guided mutation) run on Linux/WSL/CI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::path::{Path, PathBuf};

use enip::harness::{self, SURFACES};

/// The checked-in corpus directory for a target, if it exists.
fn corpus_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz").join("corpus").join(name)
}

/// A tiny deterministic SplitMix64 — no external crate, reproducible across platforms.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A pseudo-random byte buffer of length `len`.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

#[test]
fn every_fuzz_surface_survives_its_seed_corpus() {
    let mut total_seeds = 0usize;
    for (name, exercise) in SURFACES {
        let dir = corpus_dir(name);
        assert!(dir.is_dir(), "missing seed corpus dir for {name}: {}", dir.display());
        let mut seeds = 0usize;
        for entry in fs::read_dir(&dir).expect("read corpus dir") {
            let path = entry.expect("dir entry").path();
            if !path.is_file() {
                continue;
            }
            let data = fs::read(&path).expect("read seed");
            // The seed itself, and every truncation prefix of it — none may panic.
            exercise(&data);
            for n in 0..=data.len() {
                exercise(&data[..n]);
            }
            seeds += 1;
        }
        assert!(seeds > 0, "seed corpus for {name} is empty");
        total_seeds += seeds;
    }
    assert!(total_seeds >= SURFACES.len(), "each surface must have at least one seed");
}

#[test]
fn every_fuzz_surface_survives_a_random_sweep() {
    // Deterministic seed so a failure reproduces exactly.
    let mut rng = SplitMix64(0x0DDB_1A5E_5EED_CAFE);
    // Lengths chosen to straddle each decoder's fixed-header boundaries (0..=40) plus a few larger
    // buffers that exercise count/length fields and allocation caps.
    let lengths = [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 25, 32, 40, 64, 128, 255, 512];
    for (_name, exercise) in SURFACES {
        for &len in &lengths {
            for _ in 0..64 {
                let buf = rng.bytes(len);
                exercise(&buf);
            }
        }
        // Structured "length lie" payloads: a plausible header followed by a wildly wrong declared
        // length/count, which is the classic over-read/over-allocate trap.
        for &declared in &[0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
            let payloads: [Vec<u8>; 3] = [
                vec![0xCC, 0x00, 0xFF, declared],            // MR reply ext-status size lie
                vec![declared, 0x00, 0x0C, 0x00, declared],  // CPF item-count / length lie
                vec![0x01, 0x00, declared, declared, 0xC4],  // assorted count/type bytes
            ];
            for p in payloads {
                exercise(&p);
                for n in 0..=p.len() {
                    exercise(&p[..n]);
                }
            }
        }
    }
}

#[test]
fn typed_cip_value_roundtrip_survives_random_sweep() {
    // The structured `(type_code, bytes)` path the `fuzz_cip_value` libFuzzer target drives via
    // `arbitrary` — exercised here over a deterministic spread so the round-trip is regression-tested
    // on every platform.
    let mut rng = SplitMix64(0xC1_C2_C3_C4_D0_D1_D2_D3);
    let codes = [0xC1u16, 0xC2, 0xC3, 0xC4, 0xC5, 0xC8, 0xCA, 0xCB, 0xD0, 0xD4, 0x02A0, 0x1234];
    for &code in &codes {
        for len in 0..=17usize {
            for _ in 0..16 {
                let buf = rng.bytes(len);
                harness::cip_value_typed(code, &buf);
            }
        }
    }
}
