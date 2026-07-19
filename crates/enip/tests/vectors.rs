//! Conformance-vector manifest (PROTOCOL-DESIGN §12.4) — the byte-exact regression net that lets us
//! refactor codecs fearlessly.
//!
//! Every vector is an annotated golden byte sequence asserted **both directions** where an
//! encoder/decoder pair exists (`encode` produces exactly the bytes; `decode` produces exactly the
//! struct; decode→re-encode reproduces the bytes), and one direction where only one side exists (a
//! reply the scanner only ever decodes; a request it only ever encodes). Each vector is labelled by
//! [`Source`]:
//!
//! * [`Source::CpppoCaptured`] — real bytes captured from a live `cpppo` EtherNet/IP simulator
//!   (`cpppo/cpppo`, tags `PRODUCT_COUNT=DINT`, `ZONE_TEMPS=REAL[8]`): RegisterSession, Read Tag
//!   request/reply, an error-status reply, and ListIdentity.
//! * [`Source::HandAssembledPerSpec`] — assembled from the ODVA CIP/EtherNet/IP layouts in §5–§8 for
//!   shapes with no live producer on this bench: the ForwardOpen request/reply and ForwardClose, the
//!   class-1 real-time frames in both directions, the big-endian sockaddr item, and an encapsulation
//!   error-status frame.
//!
//! The [`MANIFEST`] table below is the machine-readable index (name · layer · direction · source ·
//! hex); the `golden_*` tests are the executable byte-exact proofs. A vector may only change with a
//! spec citation in the commit.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use enip::cip::message::MessageReply;
use enip::cip::types::CipValue;
use enip::cm::{
    connection_manager_path, ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess,
    ForwardRequestFail,
};
use enip::cpf::{Cpf, SockAddrInfo};
use enip::discovery::DeviceIdentity;
use enip::encap::{Command, EncapFrame, EncapHeader, EncapStatus};
use enip::io::{IoFrame, RealTimeFormat};
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

// ---------------------------------------------------------------------------
// the labelled manifest (§12.4)
// ---------------------------------------------------------------------------

/// The authority of a vector's bytes (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Captured from a live cpppo simulator.
    CpppoCaptured,
    /// Assembled by hand from the ODVA layouts (§5–§8).
    HandAssembledPerSpec,
}

/// Which direction(s) the vector is asserted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `encode` produces exactly these bytes, and `decode` reproduces the struct — both ways.
    Both,
    /// A reply the scanner only ever decodes (no encoder in the crate): bytes → struct.
    DecodeOnly,
    /// A request the scanner only ever encodes: struct → bytes.
    EncodeOnly,
}

/// One manifest entry: a labelled, spec-cited golden byte sequence.
struct Vector {
    name: &'static str,
    layer: &'static str,
    direction: Direction,
    source: Source,
    hex: &'static str,
}

/// The machine-readable conformance-vector index (§12.4). The `golden_*` tests below carry the typed
/// byte-exact assertions; this table labels each vector's provenance and asserts the raw bytes are
/// well-formed hex, so the manifest can be enumerated (e.g. exported for cross-implementation checks).
const MANIFEST: &[Vector] = &[
    Vector { name: "register_session_request", layer: "encap", direction: Direction::Both, source: Source::CpppoCaptured,
        hex: "65000400000000000000000052454749535445520000000001000000" },
    Vector { name: "register_session_reply", layer: "encap", direction: Direction::Both, source: Source::CpppoCaptured,
        hex: "65000400dfab99c60000000052454749535445520000000001000000" },
    Vector { name: "read_tag_reply_frame", layer: "encap/cpf/cip", direction: Direction::Both, source: Source::CpppoCaptured,
        hex: "6f001a00dfab99c600000000524541445441475f00000000000000000000020000000000b2000a00cc000000c40000000000" },
    Vector { name: "read_tag_missing_reply_frame", layer: "encap/cpf/cip", direction: Direction::Both, source: Source::CpppoCaptured,
        hex: "6f001600dfab99c600000000524541445441475f00000000000000000000020000000000b2000600cc0005010000" },
    Vector { name: "read_tag_request_mr", layer: "cip", direction: Direction::EncodeOnly, source: Source::CpppoCaptured,
        hex: "4c08910d50524f445543545f434f554e5400 0100" },
    Vector { name: "list_identity_reply_frame", layer: "encap/cpf/discovery", direction: Direction::Both, source: Source::CpppoCaptured,
        hex: "63003c0000000000000000004c4953544944454e0000000001000c00360001000002af1200000000000000000000000001000e003600140b60311a066c0014313735362d4c36312f42204c4f47495835353631ff" },
    Vector { name: "sockaddr_info_be", layer: "cpf", direction: Direction::Both, source: Source::HandAssembledPerSpec,
        hex: "000208aec0a801320000000000000000" },
    Vector { name: "encap_error_status_frame", layer: "encap", direction: Direction::Both, source: Source::HandAssembledPerSpec,
        hex: "650000000000000069000000000000000000000000000000" },
    Vector { name: "forward_open_request", layer: "cm", direction: Direction::EncodeOnly, source: Source::HandAssembledPerSpec,
        hex: "0a0e000000004433221105004d00efbeadde0200000080841e00f44380841e00f443a30220062401" },
    Vector { name: "forward_open_success_reply", layer: "cm", direction: Direction::DecodeOnly, source: Source::HandAssembledPerSpec,
        hex: "ddccbbaa4433221105004d00efbeadde80841e0080841e000000" },
    Vector { name: "forward_open_fail_reply", layer: "cm", direction: Direction::DecodeOnly, source: Source::HandAssembledPerSpec,
        hex: "05004d00efbeadde" },
    Vector { name: "forward_close_request", layer: "cm", direction: Direction::EncodeOnly, source: Source::HandAssembledPerSpec,
        hex: "0a0e05004d00efbeadde020020062401" },
    Vector { name: "class1_o2t_header32", layer: "io", direction: Direction::Both, source: Source::HandAssembledPerSpec,
        hex: "07000100000001020304" },
    Vector { name: "class1_t2o_modeless", layer: "io", direction: Direction::Both, source: Source::HandAssembledPerSpec,
        hex: "2a00aabb" },
    Vector { name: "class1_o2t_heartbeat", layer: "io", direction: Direction::Both, source: Source::HandAssembledPerSpec,
        hex: "0100" },
];

#[test]
fn manifest_is_labelled_and_hex_is_valid() {
    assert!(MANIFEST.len() >= 15, "the manifest must cover every §12.4 vector");
    for v in MANIFEST {
        // Every entry carries a source label and a layer, and its hex parses (empty allowed only for
        // the deliberately-empty class-1 zero-length frame, which is not in the table).
        assert!(!v.name.is_empty() && !v.layer.is_empty());
        let bytes = hx(v.hex);
        assert!(!bytes.is_empty(), "vector {} has empty bytes", v.name);
        // The direction/source labels are exhaustive enums; touch them so the fields are live.
        let _ = (v.direction, v.source);
    }
    // Both provenances are represented (§12.4 sources 1 and 3).
    assert!(MANIFEST.iter().any(|v| v.source == Source::CpppoCaptured));
    assert!(MANIFEST.iter().any(|v| v.source == Source::HandAssembledPerSpec));
}

/// Look up a manifest vector's bytes by name (keeps the typed tests and the table in lock-step —
/// a rename in one place fails the other).
fn vector(name: &str) -> Vec<u8> {
    let v = MANIFEST.iter().find(|v| v.name == name).expect("vector in manifest");
    hx(v.hex)
}

/// Extract the CIP Message-Router reply bytes from a captured SendRRData frame: strip the encap
/// header, the interface-handle/timeout prefix, and the CPF wrapper down to the `0x00B2` data item.
fn mr_reply_from_frame(frame_hex: &str) -> Vec<u8> {
    let frame = hx(frame_hex);
    let decoded = EncapFrame::decode(&frame).expect("frame decodes");
    let cpf_bytes = &decoded.data[6..];
    let cpf = Cpf::decode(cpf_bytes).expect("cpf decodes");
    cpf.expect_explicit_data().expect("explicit data").to_vec()
}

// ---------------------------------------------------------------------------
// cpppo-captured vectors (§12.4 source 1) — byte-exact both ways
// ---------------------------------------------------------------------------

#[test]
fn golden_register_session_request() {
    let expected = vector("register_session_request");
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::RegisterSession);
    assert_eq!(frame.header.session_handle, 0);
    assert_eq!(frame.header.status, EncapStatus::Success);
    assert_eq!(&frame.header.sender_context, b"REGISTER");
    assert_eq!(frame.data.as_ref(), &[0x01, 0x00, 0x00, 0x00]);

    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
    let built = EncapFrame::new(
        EncapHeader::request(Command::RegisterSession, 4, 0, *b"REGISTER"),
        bytes::Bytes::from_static(&[0x01, 0x00, 0x00, 0x00]),
    );
    assert_eq!(built.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_register_session_reply() {
    let expected = vector("register_session_reply");
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::RegisterSession);
    assert_eq!(frame.header.session_handle, 0xC699_ABDF);
    assert_eq!(frame.header.status, EncapStatus::Success);
    assert_eq!(frame.data.as_ref(), &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_read_tag_success_reply() {
    let frame_hex = "6f001a00dfab99c600000000524541445441475f00000000000000000000020000000000b2000a00cc000000c40000000000";
    let mr_bytes = mr_reply_from_frame(frame_hex);
    assert_eq!(mr_bytes, hx("cc000000c40000000000"));
    let reply = MessageReply::decode(&mr_bytes).unwrap();
    assert_eq!(reply.reply_service, 0xCC);
    reply.expect_service(0x4C).unwrap();
    assert!(reply.status.is_ok());
    let (ty, value) = CipValue::decode_tagged(&reply.data).unwrap();
    assert_eq!(ty, CipType::Dint);
    assert_eq!(value, CipValue::Dint(0));

    // The whole captured frame re-encodes byte-exact.
    let frame = EncapFrame::decode(&vector("read_tag_reply_frame")).unwrap();
    assert_eq!(frame.encode().unwrap().as_ref(), vector("read_tag_reply_frame").as_slice());
}

#[test]
fn golden_read_tag_error_reply() {
    let frame_hex = "6f001600dfab99c600000000524541445441475f00000000000000000000020000000000b2000600cc0005010000";
    let mr_bytes = mr_reply_from_frame(frame_hex);
    assert_eq!(mr_bytes, hx("cc000501 0000"));
    let reply = MessageReply::decode(&mr_bytes).unwrap();
    assert_eq!(reply.status.general, GeneralStatus::PathDestinationUnknown);
    assert_eq!(reply.status.primary_extended(), Some(0x0000));
    assert!(reply.status.is_tag_not_found());
    assert!(reply.data.is_empty());

    let frame = EncapFrame::decode(&vector("read_tag_missing_reply_frame")).unwrap();
    assert_eq!(frame.encode().unwrap().as_ref(), vector("read_tag_missing_reply_frame").as_slice());
}

#[test]
fn golden_read_tag_request_matches_cpppo_accepted_bytes() {
    let expected_mr = vector("read_tag_request_mr");
    let tag = TagAddress::parse("PRODUCT_COUNT").unwrap();
    let req = MessageRequest::new(0x4C, tag.into_path(), bytes::Bytes::from_static(&[0x01, 0x00]));
    assert_eq!(req.encode().unwrap().as_ref(), expected_mr.as_slice());
}

#[test]
fn golden_list_identity_reply() {
    let expected = vector("list_identity_reply_frame");
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

    let cpf = Cpf::decode(&frame.data).unwrap();
    assert_eq!(cpf.encode().unwrap().as_ref(), frame.data.as_ref());
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
}

// ---------------------------------------------------------------------------
// hand-assembled vectors (§12.4 source 3) — cross-checked against the ODVA layouts
// ---------------------------------------------------------------------------

#[test]
fn golden_sockaddr_big_endian() {
    // §5.4: the ODVA sockaddr layout — AF_INET, port 2222, 192.168.1.50 — big-endian family/port/addr.
    let sa = SockAddrInfo::ipv4(0xC0A8_0132, 2222);
    let expected = vector("sockaddr_info_be");
    assert_eq!(sa.encode().as_ref(), expected.as_slice());
    assert_eq!(SockAddrInfo::decode(&expected).unwrap(), sa);
}

#[test]
fn golden_encap_error_status_frame() {
    // §5.6: a RegisterSession reply carrying encap status 0x0069 (unsupported protocol version).
    let expected = vector("encap_error_status_frame");
    let frame = EncapFrame::decode(&expected).unwrap();
    assert_eq!(frame.header.command, Command::RegisterSession);
    assert_eq!(frame.header.status, EncapStatus::UnsupportedProtocolVersion);
    assert!(!frame.header.status.is_ok());
    assert!(frame.data.is_empty());
    assert_eq!(frame.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_forward_open_request() {
    // §8.2 layout: 0A 0E | o_t=0 | t_o=0x11223344 | serial=5 | vendor=0x4D | orig=0xDEADBEEF |
    // tmo code 2 (×16) | 3× reserved | o_t rpi 2_000_000 | o_t ncp 0x43F4 (P2P/variable/500) |
    // t_o rpi 2_000_000 | t_o ncp 0x43F4 | class/trigger 0xA3 | path 2 words | [20 06 24 01].
    let expected = vector("forward_open_request");
    let req = ForwardOpenRequest::class3(0, 0x1122_3344, 0x0005, 0x004D, 0xDEAD_BEEF, connection_manager_path());
    assert_eq!(req.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_forward_open_success_reply() {
    // §8.2: o_t id, t_o id, serial, vendor, orig serial, o_t API, t_o API, app-words, reserved.
    let expected = vector("forward_open_success_reply");
    let reply = ForwardOpenSuccess::decode(&expected).unwrap();
    assert_eq!(reply.o_t_connection_id, 0xAABB_CCDD);
    assert_eq!(reply.t_o_connection_id, 0x1122_3344);
    assert_eq!(reply.connection_serial, 0x0005);
    assert_eq!(reply.vendor_id, 0x004D);
    assert_eq!(reply.originator_serial, 0xDEAD_BEEF);
    assert_eq!(reply.o_t_api, 2_000_000);
    assert_eq!(reply.t_o_api, 2_000_000);
    assert!(reply.app_data.is_empty());
}

#[test]
fn golden_forward_open_fail_reply() {
    // §8.2: the short failure form — serial, vendor, orig serial; no remaining-path-size tail.
    let expected = vector("forward_open_fail_reply");
    let reply = ForwardRequestFail::decode(&expected).unwrap();
    assert_eq!(reply.connection_serial, 0x0005);
    assert_eq!(reply.vendor_id, 0x004D);
    assert_eq!(reply.originator_serial, 0xDEAD_BEEF);
    assert_eq!(reply.remaining_path_size, None);
}

#[test]
fn golden_forward_close_request() {
    // §8.8: ForwardClose that tears down the golden ForwardOpen — note the reserved byte after the
    // path-size word (absent in ForwardOpen).
    let expected = vector("forward_close_request");
    let open = ForwardOpenRequest::class3(0, 0x1122_3344, 0x0005, 0x004D, 0xDEAD_BEEF, connection_manager_path());
    let close = ForwardCloseRequest::for_open(&open);
    assert_eq!(close.encode().unwrap().as_ref(), expected.as_slice());
}

#[test]
fn golden_class1_o2t_header32_frame() {
    // §8.5, D-ENIP-10: sequence-then-header order — seq 7, run header, 4 data bytes.
    let expected = vector("class1_o2t_header32");
    let frame = IoFrame {
        sequence: Some(7),
        run_mode: Some(true),
        data: bytes::Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
    };
    assert_eq!(frame.encode(RealTimeFormat::Header32Bit).as_ref(), expected.as_slice());
    let decoded = IoFrame::decode(RealTimeFormat::Header32Bit, &expected).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn golden_class1_t2o_modeless_frame() {
    // §8.5: T→O modeless — sequence 0x2A then pure data, no run/idle header.
    let expected = vector("class1_t2o_modeless");
    let frame = IoFrame {
        sequence: Some(0x2A),
        run_mode: None,
        data: bytes::Bytes::from_static(&[0xAA, 0xBB]),
    };
    assert_eq!(frame.encode(RealTimeFormat::Modeless).as_ref(), expected.as_slice());
    assert_eq!(IoFrame::decode(RealTimeFormat::Modeless, &expected).unwrap(), frame);
}

#[test]
fn golden_class1_o2t_heartbeat_frame() {
    // §8.5: a heartbeat direction — sequence only, zero data.
    let expected = vector("class1_o2t_heartbeat");
    let frame = IoFrame { sequence: Some(1), run_mode: None, data: bytes::Bytes::new() };
    assert_eq!(frame.encode(RealTimeFormat::Heartbeat).as_ref(), expected.as_slice());
    assert_eq!(IoFrame::decode(RealTimeFormat::Heartbeat, &expected).unwrap(), frame);
}

#[test]
fn golden_class1_zero_length_frame() {
    // §8.5: the pure zero-length frame (ZeroLength format) — no sequence, no data. Not in the hex
    // manifest because its bytes are empty; asserted here for both-direction completeness.
    let frame = IoFrame { sequence: None, run_mode: None, data: bytes::Bytes::new() };
    assert!(frame.encode(RealTimeFormat::ZeroLength).is_empty());
    assert_eq!(IoFrame::decode(RealTimeFormat::ZeroLength, &[]).unwrap(), frame);
}
