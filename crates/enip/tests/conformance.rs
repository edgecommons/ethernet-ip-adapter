//! Conformance suite for the P1 protocol layer (PROTOCOL-DESIGN §12).
//!
//! Two proofs live here:
//!
//! * **Truncation sweeps (§12.2)** — the shared [`sweep_truncated`] / [`sweep_no_panic`] helpers
//!   run every prefix `frame[..n]` of a valid buffer through a decoder and assert it never panics
//!   (and, for the fixed-layout decoders, that every strict prefix is `Err`). This is the
//!   executable form of the §4 no-panic claim, applied to every decoder P1 ships.
//! * **Golden conformance vectors (§12.4)** — byte-exact encode/decode assertions against real
//!   bytes captured from a live `cpppo` EtherNet/IP simulator (`cpppo/cpppo`, the tags
//!   `PRODUCT_COUNT=DINT`, `ZONE_TEMPS=REAL[8]`, …) plus hand-assembled shapes for layouts cpppo
//!   does not emit on this path. Each vector notes its source.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use enip::cip::message::MessageReply;
use enip::cip::types::CipValue;
use enip::cpf::{Cpf, SequencedAddress, SockAddrInfo};
use enip::discovery::DeviceIdentity;
use enip::encap::{Command, EncapFrame, EncapHeader, EncapStatus};
use enip::{CipType, GeneralStatus, MessageRequest, TagAddress};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// golden vectors — real bytes captured from a live cpppo simulator on :44818
// ---------------------------------------------------------------------------

// cpppo-captured. RegisterSession request we sent (accepted by cpppo) — protocol version 1,
// options 0, sender context "REGISTER".
const REGISTER_SESSION_REQUEST: &str =
    "65000400000000000000000052454749535445520000000001000000";

// cpppo-captured. RegisterSession reply — session handle 0xC699ABDF assigned in the header, same
// 4-byte data (version 1, options 0), status 0.
const REGISTER_SESSION_REPLY: &str =
    "65000400dfab99c60000000052454749535445520000000001000000";

// cpppo-captured. Read Tag (0x4C) reply for PRODUCT_COUNT (a DINT = 0), whole SendRRData frame.
const READ_TAG_REPLY_FRAME: &str =
    "6f001a00dfab99c600000000524541445441475f00000000000000000000020000000000b2000a00cc000000c40000000000";

// cpppo-captured. Read Tag reply for a non-existent tag — general status 0x05 (path destination
// unknown), one extended-status word 0x0000, whole SendRRData frame.
const READ_TAG_REPLY_MISSING_FRAME: &str =
    "6f001600dfab99c600000000524541445441475f00000000000000000000020000000000b2000600cc0005010000";

// cpppo-captured. ListIdentity reply — a single Identity (0x000C) item, whole frame.
const LIST_IDENTITY_REPLY_FRAME: &str =
    "63003c0000000000000000004c4953544944454e0000000001000c00360001000002af1200000000000000000000000001000e003600140b60311a066c0014313735362d4c36312f42204c4f47495835353631ff";

/// Extract the CIP Message-Router reply bytes from a captured SendRRData frame: strip the encap
/// header, the interface-handle/timeout prefix, and the CPF wrapper down to the `0x00B2` data item.
fn mr_reply_from_frame(frame_hex: &str) -> Vec<u8> {
    let frame = hx(frame_hex);
    let decoded = EncapFrame::decode(&frame).expect("frame decodes");
    // Data portion: u32 interface handle + u16 timeout, then the CPF.
    let cpf_bytes = &decoded.data[6..];
    let cpf = Cpf::decode(cpf_bytes).expect("cpf decodes");
    cpf.expect_explicit_data().expect("explicit data").to_vec()
}

// ---------------------------------------------------------------------------
// golden vector assertions (§12.4) — byte-exact both ways
// ---------------------------------------------------------------------------

#[test]
fn golden_register_session_request() {
    let expected = hx(REGISTER_SESSION_REQUEST);
    // Decode produces exactly the struct...
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::RegisterSession);
    assert_eq!(frame.header.session_handle, 0);
    assert_eq!(frame.header.status, EncapStatus::Success);
    assert_eq!(&frame.header.sender_context, b"REGISTER");
    assert_eq!(frame.data.as_ref(), &[0x01, 0x00, 0x00, 0x00]);

    // ...and re-encoding it (and building it fresh) produces exactly the bytes.
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
    let built = EncapFrame::new(
        EncapHeader::request(Command::RegisterSession, 4, 0, *b"REGISTER"),
        bytes::Bytes::from_static(&[0x01, 0x00, 0x00, 0x00]),
    );
    assert_eq!(built.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_register_session_reply() {
    let expected = hx(REGISTER_SESSION_REPLY);
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::RegisterSession);
    assert_eq!(frame.header.session_handle, 0xC699_ABDF);
    assert_eq!(frame.header.status, EncapStatus::Success);
    assert_eq!(frame.data.as_ref(), &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_read_tag_success_reply() {
    let mr_bytes = mr_reply_from_frame(READ_TAG_REPLY_FRAME);
    // The MR reply payload for a DINT read: reply 0xCC, status 0, then type 0xC4 + value.
    assert_eq!(mr_bytes, hx("cc000000c40000000000"));
    let reply = MessageReply::decode(&mr_bytes).unwrap();
    assert_eq!(reply.reply_service, 0xCC);
    reply.expect_service(0x4C).unwrap();
    assert!(reply.status.is_ok());
    // The service data decodes as a DINT of 0.
    let (ty, value) = CipValue::decode_tagged(&reply.data).unwrap();
    assert_eq!(ty, CipType::Dint);
    assert_eq!(value, CipValue::Dint(0));
}

#[test]
fn golden_read_tag_error_reply() {
    let mr_bytes = mr_reply_from_frame(READ_TAG_REPLY_MISSING_FRAME);
    assert_eq!(mr_bytes, hx("cc000501 0000"));
    let reply = MessageReply::decode(&mr_bytes).unwrap();
    assert_eq!(reply.status.general, GeneralStatus::PathDestinationUnknown);
    assert_eq!(reply.status.primary_extended(), Some(0x0000));
    assert!(reply.status.is_tag_not_found());
    assert!(reply.data.is_empty());
}

#[test]
fn golden_list_identity_reply() {
    let expected = hx(LIST_IDENTITY_REPLY_FRAME);
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::ListIdentity);

    let id = DeviceIdentity::parse_reply(&frame.data).unwrap();
    assert_eq!(id.protocol_version, 1);
    assert_eq!(id.vendor.0, 0x0001);
    assert_eq!(id.device_type.0, 0x000E);
    assert_eq!(id.product_code, 0x0036);
    assert_eq!(id.revision_major, 20);
    assert_eq!(id.revision_minor, 11);
    assert_eq!(id.serial_number, 0x006C_061A);
    assert_eq!(id.product_name, "1756-L61/B LOGIX5561");
    assert_eq!(id.state, 0xFF);
    assert_eq!(id.socket_addr.sin_port, 44818); // 0xAF12, big-endian on the wire

    // Byte-exact CPF roundtrip: decode then re-encode reproduces the frame's data portion.
    let cpf = Cpf::decode(&frame.data).unwrap();
    assert_eq!(cpf.encode().unwrap().as_ref(), frame.data.as_ref());
    // And the whole frame re-encodes byte-exact.
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_read_tag_request_matches_cpppo_accepted_bytes() {
    // cpppo-captured request MR portion: service 0x4C, path 8 words (symbol PRODUCT_COUNT, padded),
    // then u16 element count = 1. Our MessageRequest encoder must reproduce it byte-exact.
    let expected_mr = hx("4c08910d50524f445543545f434f554e5400 0100");
    let tag = TagAddress::parse("PRODUCT_COUNT").unwrap();
    let req = MessageRequest::new(0x4C, tag.into_path(), bytes::Bytes::from_static(&[0x01, 0x00]));
    assert_eq!(req.encode().unwrap().as_ref(), expected_mr.as_slice());
}

#[test]
fn golden_sockaddr_big_endian_handassembled() {
    // Hand-assembled (§12.4 source 3): the ODVA sockaddr layout — AF_INET, port 2222, 192.168.1.50.
    let sa = SockAddrInfo::ipv4(0xC0A8_0132, 2222);
    let expected = hx("0002 08ae c0a80132 0000000000000000");
    assert_eq!(sa.encode().as_ref(), expected.as_slice());
    assert_eq!(SockAddrInfo::decode(&expected).unwrap(), sa);
}

// ---------------------------------------------------------------------------
// truncation sweeps (§12.2) — one per decoder P1 ships
// ---------------------------------------------------------------------------

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
    // The 24-byte header decoder: a strict prefix is always Truncated.
    let full = &hx(REGISTER_SESSION_REPLY)[..24];
    sweep_truncated(full, EncapHeader::decode);
}

#[test]
fn sweep_cpf() {
    // The CPF data portion of the ListIdentity reply (a real item list).
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
    // And the raw Identity item payload directly.
    let cpf = Cpf::decode(&frame.data).unwrap();
    let item = &cpf.items[0];
    sweep_truncated(item.data.as_ref(), DeviceIdentity::parse_item);
}

#[test]
fn sweep_message_reply_and_values() {
    // Variable-tail decoders: no prefix may panic.
    sweep_no_panic(&mr_reply_from_frame(READ_TAG_REPLY_FRAME), MessageReply::decode);
    sweep_no_panic(&mr_reply_from_frame(READ_TAG_REPLY_MISSING_FRAME), MessageReply::decode);
    sweep_no_panic(&hx("c40000000000"), CipValue::decode_tagged);
    // A four-element DINT array value.
    sweep_no_panic(&hx("01000000020000000300000004000000"), |b| {
        CipValue::decode(CipType::Dint, b)
    });
}

#[test]
fn sweep_tag_path_parser_never_panics() {
    // The tag-path parser is a caller-supplied-string surface (fuzz target `fuzz_tag_path`).
    for tag in ["Program:Main.FillTimer.ACC", "ZONE_TEMPS[3]", "PROFILE[0,1,257]"] {
        let bytes = tag.as_bytes();
        for n in 0..=bytes.len() {
            let prefix = std::str::from_utf8(&bytes[..n]).unwrap();
            let _ = catch_unwind(AssertUnwindSafe(|| TagAddress::parse(prefix)));
        }
    }
}
