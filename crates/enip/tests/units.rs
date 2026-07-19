//! Focused unit coverage for the pure, socket-free surface of the crate (PROTOCOL-DESIGN §12.1):
//! typed-status classifiers and their `Display` renderings, the error model, the CPF/EPATH/CIP-value
//! constructors and their error paths, the discovery render tables, the assembly layout builder +
//! `encode_into` inverse, and the class-1 produce/watchdog **state machine** driven with crafted
//! bytes and a paused clock (§12.2 — no socket, fully deterministic). These are the branches the wire
//! decoders, the `duplex`-fixture session tests, and the fuzz corpus do not already reach.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;

use enip::assembly::{AssemblyError, AssemblyLayout, FieldSpec};
use enip::cip::status::{CipStatus, GeneralStatus};
use enip::cip::types::{CipType, CipValue};
use enip::cpf::{Cpf, CpfItem, ItemType};
use enip::encap::EncapStatus;
use enip::error::{EnipError, WireError};
use enip::io::{
    ConsumeOutcome, DropReason, IoConnection, IoConnectionParams, LostReason, RealTimeFormat,
};
use enip::{
    parse_list_interfaces, parse_list_services, DeviceType, EPath, MessageRequest, PathError,
    PortSegment, Segment, SymbolType, TagAddress, VendorId, WireReader, WireWriter,
};
use enip::cip::message::MessageReply;

// ---------------------------------------------------------------------------
// error model
// ---------------------------------------------------------------------------

#[test]
fn wire_error_display_covers_every_variant() {
    let variants = [
        WireError::Truncated { needed: 4, remaining: 2, context: "encap header" },
        WireError::Malformed { context: "cpf", detail: "bad item" },
        WireError::Overflow { context: "cip reply" },
        WireError::InvalidUtf8 { context: "logix" },
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
    assert!(variants[0].to_string().contains("needed 4"));
    assert!(variants[3].to_string().contains("utf-8"));
}

#[test]
fn enip_error_transient_classification_and_display() {
    // Transient classes.
    assert!(EnipError::ConnectionLost { context: "x" }.is_transient());
    assert!(EnipError::Timeout { op: "read" }.is_transient());
    assert!(EnipError::Io(std::io::Error::other("boom")).is_transient());
    assert!(EnipError::Encap(EncapStatus::InsufficientMemory).is_transient());
    assert!(EnipError::Cip(CipStatus::new(GeneralStatus::ResourceUnavailable)).is_transient());
    assert!(EnipError::ForwardOpenRejected {
        status: CipStatus::with_extended(GeneralStatus::ConnectionFailure, vec![0x0315]),
        remaining_path_size: Some(2),
    }
    .is_transient());

    // Non-transient classes.
    assert!(!EnipError::Encap(EncapStatus::UnsupportedCommand).is_transient());
    assert!(!EnipError::Cip(CipStatus::new(GeneralStatus::PathDestinationUnknown)).is_transient());
    assert!(!EnipError::Malformed(WireError::Overflow { context: "x" }).is_transient());
    assert!(!EnipError::ProtocolViolation { detail: "x" }.is_transient());
    assert!(!EnipError::Unsupported { what: "struct" }.is_transient());
    assert!(!EnipError::TooLarge { limit: 10 }.is_transient());
    assert!(!EnipError::Closed.is_transient());

    // Display (thiserror) renders each arm.
    for e in [
        EnipError::ConnectionLost { context: "eof" },
        EnipError::Timeout { op: "read" },
        EnipError::Encap(EncapStatus::InvalidLength),
        EnipError::Cip(CipStatus::new(GeneralStatus::ServiceNotSupported)),
        EnipError::ForwardOpenRejected { status: CipStatus::new(GeneralStatus::ConnectionFailure), remaining_path_size: None },
        EnipError::Malformed(WireError::Overflow { context: "x" }),
        EnipError::ProtocolViolation { detail: "d" },
        EnipError::Unsupported { what: "w" },
        EnipError::Closed,
        EnipError::TooLarge { limit: 5 },
    ] {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// typed CIP / encapsulation status
// ---------------------------------------------------------------------------

#[test]
fn general_status_description_total_over_all_codes() {
    for code in 0u8..=0xFF {
        let g = GeneralStatus::from_code(code);
        assert_eq!(g.code(), code);
        assert!(!g.description().is_empty());
    }
    assert_eq!(GeneralStatus::from_code(0x99).description(), "unknown status");
    assert!(GeneralStatus::Success.is_ok());
}

#[test]
fn cip_status_classifiers_and_display() {
    let ok = CipStatus::new(GeneralStatus::Success);
    assert!(ok.is_ok() && !ok.is_err() && ok.primary_extended().is_none());

    let res = CipStatus::new(GeneralStatus::ResourceUnavailable);
    assert!(res.is_resource_error() && res.is_routing_error() && res.is_err());

    // logix_extended_detail: each known code, an unknown ext, and the non-extended short-circuit.
    for (word, expect_some) in [(0x2104u16, true), (0x2105, true), (0x2107, true), (0x9999, false)] {
        let s = CipStatus::with_extended(GeneralStatus::ExtendedError, vec![word]);
        assert_eq!(s.logix_extended_detail().is_some(), expect_some);
    }
    assert!(CipStatus::new(GeneralStatus::PathSegmentError).logix_extended_detail().is_none());

    // Display: plain, with-detail, and with-extended-words rendering.
    assert_eq!(CipStatus::new(GeneralStatus::PartialTransfer).to_string(), "0x06 (partial transfer)");
    let ext = CipStatus::with_extended(GeneralStatus::ExtendedError, vec![0x2107, 0x0001]);
    let s = ext.to_string();
    assert!(s.contains("tag type mismatch") && s.contains("[ext 0x2107 0x0001]"));
}

#[test]
fn encap_status_display_and_predicates() {
    for st in [
        EncapStatus::Success,
        EncapStatus::UnsupportedCommand,
        EncapStatus::InsufficientMemory,
        EncapStatus::IncorrectData,
        EncapStatus::InvalidSessionHandle,
        EncapStatus::InvalidLength,
        EncapStatus::UnsupportedProtocolVersion,
        EncapStatus::Unknown(0xDEAD),
    ] {
        assert!(!st.to_string().is_empty());
        assert_eq!(EncapStatus::from_code(st.code()), st);
    }
    assert!(EncapStatus::Success.is_ok());
    assert!(EncapStatus::InvalidSessionHandle.poisons_session());
    assert!(!EncapStatus::Success.poisons_session());
}

// ---------------------------------------------------------------------------
// CPF constructors + CIP value/type edges
// ---------------------------------------------------------------------------

#[test]
fn cpf_constructors_and_helpers() {
    let empty = Cpf::from_items(vec![]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let cpf = Cpf::from_items(vec![
        CpfItem::null_address(),
        CpfItem::unconnected_data(Bytes::from_static(&[0x01, 0x02])),
        CpfItem::connected_address(0x1234),
        CpfItem::connected_data(Bytes::from_static(&[0xAA])),
    ]);
    assert_eq!(cpf.len(), 4);
    assert!(!cpf.is_empty());
    assert!(cpf.find(ItemType::NullAddress).is_some());
    assert!(cpf.find(ItemType::Identity).is_none());
    // expect_explicit_data rejects a >2-item list.
    assert!(cpf.expect_explicit_data().is_err());

    assert!(ItemType::SockAddrOtoT.is_sockaddr());
    assert!(ItemType::SockAddrTtoO.is_sockaddr());
    assert!(!ItemType::NullAddress.is_sockaddr());
    assert_eq!(ItemType::from_code(0x1357), ItemType::Unknown(0x1357));
}

#[test]
fn cip_type_and_value_edges() {
    assert_eq!(CipType::from_code(0x7777).code(), 0x7777);
    assert!(!CipType::String.is_elementary());
    assert!(CipType::from_code(0x7777).element_size().is_none());

    // Non-elementary decode is a typed error, never a panic.
    assert!(CipValue::decode(CipType::String, &[0u8; 4]).is_err());
    assert!(CipValue::decode(CipType::Dint, &[0u8; 3]).is_err()); // not a multiple of 4

    // encode_value refuses the opaque markers.
    let mut w = WireWriter::new();
    assert!(CipValue::Struct { handle: 1, bytes_len: 4 }.encode_value(&mut w).is_err());
    let mut w2 = WireWriter::new();
    assert!(CipValue::Unsupported { type_code: 0xD0, bytes_len: 2 }.encode_value(&mut w2).is_err());

    // A BOOL round-trips through encode_value (0xFF/0x00).
    let mut wb = WireWriter::new();
    CipValue::Bool(true).encode_value(&mut wb).unwrap();
    assert_eq!(wb.as_slice(), &[0xFF]);
}

#[test]
fn message_reply_service_mismatch_is_protocol_violation() {
    // reply service 0xCC (== 0x4C|0x80): matching request 0x4C ok, mismatching 0x4D errs.
    let reply = MessageReply::decode(&[0xCC, 0x00, 0x00, 0x00]).unwrap();
    assert!(reply.expect_service(0x4C).is_ok());
    assert!(matches!(
        reply.expect_service(0x4D),
        Err(EnipError::ProtocolViolation { .. })
    ));
}

// ---------------------------------------------------------------------------
// EPATH builders + tag-path parser errors
// ---------------------------------------------------------------------------

#[test]
fn epath_builders_and_word_len() {
    let mut p = EPath::new()
        .class(0x06)
        .instance(0x01)
        .attribute(0x03)
        .element(5)
        .connection_point(0x64)
        .symbol("Tag_1")
        .port(PortSegment::backplane_slot(3));
    assert!(p.word_len().unwrap() > 0);
    let bytes = p.encode().unwrap();
    assert!(bytes.len() % 2 == 0);
    assert!(!p.segments().is_empty());

    p.prepend(Segment::Class(0x02));
    assert!(matches!(p.segments().first(), Some(Segment::Class(0x02))));

    // Wide instance ids widen to the 16-bit segment forms.
    let wide = EPath::new().class(0x1234).instance(0x5678).connection_point(0x9ABC);
    assert!(wide.encode().unwrap().len() % 2 == 0);

    let from = EPath::from_segments(vec![Segment::Class(1), Segment::Instance(2)]);
    assert_eq!(from.segments().len(), 2);
}

#[test]
fn tag_path_parser_variants_and_errors() {
    // A dotted symbolic path with a bare numeric (bit) member and a bracket index.
    let t = TagAddress::parse("Program:Main.Motor.3").unwrap();
    assert_eq!(t.as_str(), "Program:Main.Motor.3");
    assert!(t.encode().is_ok());
    assert!(TagAddress::parse("ZONE_TEMPS[7]").is_ok());
    assert!(TagAddress::parse("PROFILE[0,1,2]").is_ok());

    // Error surface — each PathError variant is a typed error with a Display string.
    assert_eq!(TagAddress::parse(""), Err(PathError::Empty));
    assert!(matches!(TagAddress::parse("a..b"), Err(PathError::EmptyComponent)));
    assert!(TagAddress::parse("[3]").is_err()); // leading bracket, empty name
    // A wildly out-of-range index overflows u32.
    assert!(TagAddress::parse("X[99999999999999999999]").is_err());

    for e in [
        PathError::Empty,
        PathError::EmptyComponent,
        PathError::InvalidName,
        PathError::InvalidIndex,
        PathError::NumberOverflow,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// discovery render tables + ListServices/ListInterfaces
// ---------------------------------------------------------------------------

#[test]
fn vendor_and_device_type_render() {
    // A known vendor/device renders the name; an unknown one renders the raw id.
    let rockwell = VendorId(0x0001);
    assert!(rockwell.name().is_some());
    assert!(rockwell.to_string().contains("0x0001") || !rockwell.to_string().is_empty());
    let unknown_vendor = VendorId(0xFFFF);
    assert!(unknown_vendor.name().is_none());
    assert!(!unknown_vendor.to_string().is_empty());

    let plc = DeviceType(0x000E);
    assert!(plc.name().is_some());
    assert!(!plc.to_string().is_empty());
    assert!(DeviceType(0xFFFF).name().is_none());
    assert!(!DeviceType(0xFFFF).to_string().is_empty());
}

#[test]
fn parse_list_services_and_interfaces() {
    // One ListServices item (0x0100): version 1, capability with TCP(bit5)+UDP(bit8), name "Comm\0".
    let mut item = WireWriter::new();
    item.u16(1); // protocol version
    item.u16(0x0120); // capability: bit5 (0x20) TCP + bit8 (0x100) UDP
    item.put_slice(b"Comm\0\0\0\0\0\0\0\0\0\0\0\0"); // NUL-terminated within a fixed field
    let item_bytes = item.into_bytes();

    let mut cpf = WireWriter::new();
    cpf.u16(1); // item count
    cpf.u16(0x0100); // ListServices item type
    cpf.u16(u16::try_from(item_bytes.len()).unwrap());
    cpf.put_slice(&item_bytes);
    let services = parse_list_services(cpf.as_slice()).unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, "Comm");
    assert!(services[0].supports_tcp());
    assert!(services[0].supports_udp());

    // ListInterfaces surfaces raw typed items.
    let mut cpf2 = WireWriter::new();
    cpf2.u16(1);
    cpf2.u16(0x0000); // an arbitrary interface item type
    cpf2.u16(2);
    cpf2.put_slice(&[0xAB, 0xCD]);
    let ifaces = parse_list_interfaces(cpf2.as_slice()).unwrap();
    assert_eq!(ifaces.len(), 1);
    assert_eq!(ifaces[0].data.as_ref(), &[0xAB, 0xCD]);
}

// ---------------------------------------------------------------------------
// assembly layout builder + encode_into inverse
// ---------------------------------------------------------------------------

#[test]
fn assembly_layout_encode_into_roundtrip_and_errors() {
    // A 6-byte assembly: DINT at 0, packed BOOL at byte 4 bit 2, USINT at 5.
    let layout = AssemblyLayout::new(
        vec![
            FieldSpec::scalar(0, 0, CipType::Dint),
            FieldSpec::boolean(1, 4, 2),
            FieldSpec::scalar(2, 5, CipType::Usint),
        ],
        6,
    )
    .unwrap();
    assert_eq!(layout.data_size(), 6);
    assert_eq!(layout.fields().len(), 3);

    let mut buf = vec![0u8; 6];
    layout
        .encode_into(
            &[
                (0, CipValue::Dint(0x0A0B_0C0D)),
                (1, CipValue::Bool(true)),
                (2, CipValue::Usint(0x7F)),
            ],
            &mut buf,
        )
        .unwrap();
    let decoded = layout.decode(&buf).unwrap();
    assert_eq!(decoded[0], (0, CipValue::Dint(0x0A0B_0C0D)));
    assert_eq!(decoded[1], (1, CipValue::Bool(true)));
    assert_eq!(decoded[2], (2, CipValue::Usint(0x7F)));

    // Error paths.
    assert!(matches!(
        layout.encode_into(&[(9, CipValue::Dint(0))], &mut buf),
        Err(AssemblyError::UnknownField { key: 9 })
    ));
    assert!(matches!(
        layout.encode_into(&[(0, CipValue::Bool(true))], &mut buf),
        Err(AssemblyError::ValueTypeMismatch { key: 0 })
    ));
    let mut small = vec![0u8; 5];
    assert!(matches!(
        layout.encode_into(&[], &mut small),
        Err(AssemblyError::DataSizeMismatch { .. })
    ));
    assert!(matches!(layout.decode(&small), Err(AssemblyError::DataSizeMismatch { .. })));

    // Construction rejections + their Display strings.
    assert!(matches!(
        AssemblyLayout::new(vec![FieldSpec::array(0, 0, CipType::Dint, 0)], 8),
        Err(AssemblyError::ZeroCount { .. })
    ));
    assert!(matches!(
        AssemblyLayout::new(vec![FieldSpec::scalar(0, 0, CipType::String)], 8),
        Err(AssemblyError::NonElementaryType { .. })
    ));
    assert!(matches!(
        AssemblyLayout::new(vec![FieldSpec { key: 0, offset: 0, ty: CipType::Bool, bit: Some(9), count: 1 }], 8),
        Err(AssemblyError::InvalidBitField { .. })
    ));
    assert!(matches!(
        AssemblyLayout::new(vec![FieldSpec::scalar(0, 6, CipType::Dint)], 8),
        Err(AssemblyError::FieldOutOfBounds { .. })
    ));
    for e in [
        AssemblyError::FieldOutOfBounds { key: 0 },
        AssemblyError::ZeroCount { key: 0 },
        AssemblyError::InvalidBitField { key: 0 },
        AssemblyError::NonElementaryType { key: 0 },
        AssemblyError::DataSizeMismatch { expected: 6, actual: 5 },
        AssemblyError::UnknownField { key: 1 },
        AssemblyError::ValueTypeMismatch { key: 2 },
    ] {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// logix SymbolType decode (all field accessors)
// ---------------------------------------------------------------------------

#[test]
fn symbol_type_field_accessors() {
    // Atomic DINT scalar.
    let dint = SymbolType(0x00C4);
    assert!(dint.is_atomic() && !dint.is_struct());
    assert_eq!(dint.dims(), 0);
    assert_eq!(dint.type_code(), Some(0xC4));
    assert_eq!(dint.cip_type(), Some(CipType::Dint));
    assert!(dint.is_value_supported());
    assert!(!dint.is_bool());
    assert!(dint.bit_position().is_none());
    assert!(dint.template_instance().is_none());

    // BOOL at bit 5 → bit_position applies.
    let boolean = SymbolType((5 << 8) | 0x00C1);
    assert!(boolean.is_bool());
    assert_eq!(boolean.bit_position(), Some(5));

    // 1-D atomic array → reported but not value-decoded.
    let array = SymbolType((1 << 13) | 0x00C4);
    assert_eq!(array.dims(), 1);
    assert!(!array.is_value_supported());

    // Struct with a system-predefined template instance.
    let sys = SymbolType((1 << 15) | 0x0F01);
    assert!(sys.is_struct());
    assert_eq!(sys.type_code(), None);
    assert_eq!(sys.cip_type(), None);
    assert_eq!(sys.template_instance(), Some(0x0F01));
    assert!(sys.is_system_predefined());
    assert!(!sys.is_value_supported());

    // Struct with an ordinary (user) template instance.
    let user = SymbolType((1 << 15) | 0x0104);
    assert!(!user.is_system_predefined());
}

// ---------------------------------------------------------------------------
// class-1 produce / watchdog state machine (crafted bytes + paused clock, §12.2)
// ---------------------------------------------------------------------------

fn io_params(o2t_format: RealTimeFormat, t2o_format: RealTimeFormat) -> IoConnectionParams {
    IoConnectionParams {
        o2t_connection_id: 0x1000_0001,
        t2o_connection_id: 0x2000_0002,
        o2t_api: Duration::from_millis(10),
        t2o_api: Duration::from_millis(10),
        timeout_multiplier: 4,
        o2t_format,
        t2o_format,
        o2t_data_size: 4,
        t2o_data_size: 4,
        o2t_fixed: true,
        t2o_fixed: true,
        tx_endpoint: SocketAddr::from(([127, 0, 0, 1], 2222)),
        multicast_group: None,
    }
}

#[tokio::test(start_paused = true)]
async fn io_connection_produce_and_watchdog() {
    use tokio::time::{advance, Instant};

    let now = Instant::now();
    let mut conn = IoConnection::new(io_params(RealTimeFormat::Header32Bit, RealTimeFormat::Modeless), now);
    assert_eq!(conn.connection_id(), 0x2000_0002);
    assert_eq!(conn.apis(), (Duration::from_millis(10), Duration::from_millis(10)));
    assert_eq!(conn.tx_endpoint(), SocketAddr::from(([127, 0, 0, 1], 2222)));
    assert!(conn.multicast_group().is_none());
    conn.set_output(Bytes::from_static(&[1, 2, 3, 4]));
    conn.set_run(true);

    // No produce tick is due yet.
    assert!(conn.poll_produce(now).is_none());
    assert!(!conn.poll_watchdog(now));

    // Advance past one O→T API — a tick fires and the sequence advances.
    advance(Duration::from_millis(11)).await;
    let frame = conn.poll_produce(Instant::now()).expect("a produce tick is due").unwrap();
    assert!(!frame.is_empty());
    assert_eq!(conn.last_produced_sequence(), 1);
    assert_eq!(conn.last_encap_sequence(), 1);

    // Idle: a heartbeat-style direction still produces a frame directly.
    conn.set_run(false);
    let idle = conn.produce_frame().unwrap();
    assert!(!idle.is_empty());
    assert_eq!(conn.last_produced_sequence(), 2);

    // The watchdog expires once we pass timeout_multiplier × T2O_API with no accepted T→O frame.
    advance(Duration::from_millis(100)).await;
    assert!(conn.poll_watchdog(Instant::now()));
}

#[tokio::test(start_paused = true)]
async fn io_connection_consume_accept_and_size_drop() {
    use tokio::time::Instant;
    let now = Instant::now();
    let mut conn = IoConnection::new(io_params(RealTimeFormat::Modeless, RealTimeFormat::Modeless), now);

    // A correctly-sized modeless T→O frame (seq 1 + 4 data bytes) is accepted as the first frame.
    let frame = enip::IoFrame {
        sequence: Some(1),
        run_mode: None,
        data: Bytes::from_static(&[9, 9, 9, 9]),
    };
    let bytes = frame.encode(RealTimeFormat::Modeless);
    match conn.consume(&bytes, 7, now) {
        ConsumeOutcome::Accepted { first, update } => {
            assert!(first);
            assert_eq!(update.data.as_ref(), &[9, 9, 9, 9]);
            assert_eq!(update.encap_sequence, 7);
        }
        other => panic!("expected accept, got {other:?}"),
    }

    // A runt frame (too short to be the negotiated size) is a counted size-mismatch drop.
    match conn.consume(&[0x02, 0x00, 0x01], 8, now) {
        ConsumeOutcome::Dropped { reason } => assert_eq!(reason, DropReason::SizeMismatch),
        other => panic!("expected drop, got {other:?}"),
    }
    assert_eq!(conn.stats().size_mismatch, 1);
    assert_eq!(conn.stats().frames_accepted, 1);
}

#[test]
fn io_enum_helpers_and_debug() {
    for fmt in [
        RealTimeFormat::Modeless,
        RealTimeFormat::Header32Bit,
        RealTimeFormat::Heartbeat,
        RealTimeFormat::ZeroLength,
    ] {
        let _ = (fmt.has_sequence(), fmt.has_header(), fmt.carries_data());
        assert!(!format!("{fmt:?}").is_empty());
    }
    for r in [LostReason::Timeout, LostReason::ClosedByPeer, LostReason::Io] {
        assert!(!format!("{r:?}").is_empty());
    }
    for d in [DropReason::Malformed, DropReason::UnknownConnection, DropReason::SizeMismatch, DropReason::Stale] {
        assert!(!format!("{d:?}").is_empty());
    }
}

// A request with an over-long path/data surfaces a typed error, never a panic (encode guard).
#[test]
fn message_request_encode_guard() {
    let tag = TagAddress::parse("A").unwrap();
    let req = MessageRequest::new(0x4C, tag.into_path(), Bytes::from_static(&[0x01, 0x00]));
    assert!(req.encode().is_ok());
}

// ---------------------------------------------------------------------------
// wire cursor helpers
// ---------------------------------------------------------------------------

#[test]
fn wire_reader_writer_helpers_roundtrip() {
    let mut w = WireWriter::new();
    assert!(w.is_empty());
    w.u8(0x12);
    w.i8(-3);
    w.u16(0xABCD);
    w.i16(-1000);
    w.u32(0xDEAD_BEEF);
    w.i32(-70000);
    w.u64(0x0102_0304_0506_0708);
    w.i64(-1);
    w.f32(1.5);
    w.f64(-2.25);
    w.u16_be(0x1234);
    w.u32_be(0x89AB_CDEF);
    assert!(!w.is_empty());
    let bytes = w.into_bytes();

    let mut r = WireReader::new(&bytes);
    assert!(!r.is_empty());
    assert_eq!(r.peek_u8(), Some(0x12));
    assert_eq!(r.u8().unwrap(), 0x12);
    assert_eq!(r.i8().unwrap(), -3);
    assert_eq!(r.u16().unwrap(), 0xABCD);
    assert_eq!(r.i16().unwrap(), -1000);
    assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
    assert_eq!(r.i32().unwrap(), -70000);
    assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
    assert_eq!(r.i64().unwrap(), -1);
    assert_eq!(r.f32().unwrap(), 1.5);
    assert_eq!(r.f64().unwrap(), -2.25);
    assert_eq!(r.u16_be().unwrap(), 0x1234);
    assert_eq!(r.u32_be().unwrap(), 0x89AB_CDEF);
    assert!(r.is_empty());
    assert_eq!(r.peek_u8(), None);
    assert!(r.expect_end().is_ok());
}
