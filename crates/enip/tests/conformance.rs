//! Truncation sweeps for the protocol decoders (PROTOCOL-DESIGN §12.1/§12.2).
//!
//! The executable form of the §4 no-panic claim, one sweep per decoder P1 ships: the shared
//! [`sweep_truncated`] / [`sweep_no_panic`] helpers run every prefix `frame[..n]` of a valid buffer
//! through a decoder and assert it never panics (and, for the fixed-layout decoders, that every
//! strict prefix decodes to `Err`, never `Ok`). The byte-exact golden vectors these prefixes are cut
//! from live in the consolidated §12.4 manifest, `tests/vectors.rs`; the deeper hostile-input
//! exploration is the fuzz suite (`enip::harness` + `crates/enip/fuzz`) and its cross-platform
//! regression, `tests/fuzz_corpus.rs`.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use enip::cip::message::MessageReply;
use enip::cip::types::CipValue;
use enip::cpf::{Cpf, SequencedAddress, SockAddrInfo};
use enip::discovery::DeviceIdentity;
use enip::encap::{EncapFrame, EncapHeader};
use enip::{CipType, ItemType, TagAddress};

/// Parse a compact hex string into bytes (test-local, no external crate).
fn hx(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "odd hex length");
    cleaned
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
            (hi << 4) | lo
        })
        .collect()
}

/// §12.2 sweep for a **fixed-layout** decoder (one that consumes its whole buffer): every strict
/// prefix must decode to `Err` — never a panic — and the full buffer must decode `Ok`.
fn sweep_truncated<T, E>(full: &[u8], decode: impl Fn(&[u8]) -> Result<T, E>) {
    for n in 0..full.len() {
        let prefix = &full[..n];
        match catch_unwind(AssertUnwindSafe(|| decode(prefix))) {
            Ok(Ok(_)) => panic!("prefix len {n} of {} decoded Ok, expected Err", full.len()),
            Ok(Err(_)) => {}
            Err(_) => panic!("PANIC decoding prefix len {n} of {}", full.len()),
        }
    }
    assert!(
        decode(full).is_ok(),
        "the full {}-byte buffer should decode Ok",
        full.len()
    );
}

/// §12.2 sweep for a **variable-tail** decoder (one that legitimately accepts short buffers, e.g. an
/// MR reply that keeps whatever service data remains): every prefix — including the empty one —
/// must return without panicking. `Ok` or `Err` are both acceptable; a panic is not.
fn sweep_no_panic<T, E>(full: &[u8], decode: impl Fn(&[u8]) -> Result<T, E>) {
    for n in 0..=full.len() {
        let prefix = &full[..n];
        if catch_unwind(AssertUnwindSafe(|| decode(prefix))).is_err() {
            panic!("PANIC decoding prefix len {n} of {}", full.len());
        }
    }
}

// Real bytes captured from a live cpppo simulator (mirrored in the §12.4 manifest, `tests/vectors`).
const REGISTER_SESSION_REQUEST: &str =
    "65000400000000000000000052454749535445520000000001000000";
const REGISTER_SESSION_REPLY: &str =
    "65000400dfab99c60000000052454749535445520000000001000000";
const READ_TAG_REPLY_FRAME: &str =
    "6f001a00dfab99c600000000524541445441475f00000000000000000000020000000000b2000a00cc000000c40000000000";
const READ_TAG_REPLY_MISSING_FRAME: &str =
    "6f001600dfab99c600000000524541445441475f00000000000000000000020000000000b2000600cc0005010000";
const LIST_IDENTITY_REPLY_FRAME: &str =
    "63003c0000000000000000004c4953544944454e0000000001000c00360001000002af1200000000000000000000000001000e003600140b60311a066c0014313735362d4c36312f42204c4f47495835353631ff";

/// Extract the CIP Message-Router reply bytes from a captured SendRRData frame.
fn mr_reply_from_frame(frame_hex: &str) -> Vec<u8> {
    let frame = hx(frame_hex);
    let decoded = EncapFrame::decode(&frame).expect("frame decodes");
    let cpf_bytes = &decoded.data[6..];
    let cpf = Cpf::decode(cpf_bytes).expect("cpf decodes");
    cpf.expect_explicit_data().expect("explicit data").to_vec()
}

#[test]
fn sweep_encap_frame() {
    for v in [
        REGISTER_SESSION_REQUEST,
        REGISTER_SESSION_REPLY,
        READ_TAG_REPLY_FRAME,
        READ_TAG_REPLY_MISSING_FRAME,
        LIST_IDENTITY_REPLY_FRAME,
    ] {
        sweep_truncated(&hx(v), EncapFrame::decode);
    }
}

#[test]
fn sweep_encap_header() {
    let full = &hx(REGISTER_SESSION_REPLY)[..24];
    sweep_truncated(full, EncapHeader::decode);
}

#[test]
fn sweep_cpf() {
    let frame = EncapFrame::decode(&hx(LIST_IDENTITY_REPLY_FRAME)).unwrap();
    sweep_truncated(frame.data.as_ref(), Cpf::decode);
}

#[test]
fn sweep_sockaddr_and_sequenced_address() {
    sweep_truncated(&hx("0002 08ae c0a80132 0000000000000000"), SockAddrInfo::decode);
    sweep_truncated(&hx("11223344 00000007"), SequencedAddress::decode);
}

#[test]
fn sweep_identity() {
    let frame = EncapFrame::decode(&hx(LIST_IDENTITY_REPLY_FRAME)).unwrap();
    sweep_truncated(frame.data.as_ref(), DeviceIdentity::parse_reply);
    let cpf = Cpf::decode(&frame.data).unwrap();
    let item = cpf.find(ItemType::Identity).unwrap();
    sweep_truncated(item.data.as_ref(), DeviceIdentity::parse_item);
}

#[test]
fn sweep_message_reply_and_values() {
    sweep_no_panic(&mr_reply_from_frame(READ_TAG_REPLY_FRAME), MessageReply::decode);
    sweep_no_panic(&mr_reply_from_frame(READ_TAG_REPLY_MISSING_FRAME), MessageReply::decode);
    sweep_no_panic(&hx("c40000000000"), CipValue::decode_tagged);
    sweep_no_panic(&hx("01000000020000000300000004000000"), |b| {
        CipValue::decode(CipType::Dint, b)
    });
}

#[test]
fn sweep_tag_path_parser_never_panics() {
    for tag in ["Program:Main.FillTimer.ACC", "ZONE_TEMPS[3]", "PROFILE[0,1,257]"] {
        let bytes = tag.as_bytes();
        for n in 0..=bytes.len() {
            let prefix = std::str::from_utf8(&bytes[..n]).unwrap();
            let _ = catch_unwind(AssertUnwindSafe(|| TagAddress::parse(prefix)));
        }
    }
}
