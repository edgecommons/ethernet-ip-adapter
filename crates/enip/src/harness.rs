//! Shared decode-exercise harness for fuzzing and corpus regression (PROTOCOL-DESIGN §12.3).
//!
//! Every function here takes an **arbitrary byte slice** and drives one hostile decode surface of the
//! crate, discarding the result. The single normative invariant, shared by all of them, is the §4
//! no-panic claim made executable: **decode is total — no panic, no unchecked arithmetic, no OOM —
//! on any input.** libFuzzer catches a violation as a crash; the `tests/fuzz_corpus.rs` regression
//! test catches it as a failed `#[test]` on every platform.
//!
//! This module is the **single source of truth** for both harnesses so a decoder can never be fuzzed
//! by one and skipped by the other:
//!
//! * `crates/enip/fuzz/fuzz_targets/*` — each libFuzzer target is a three-line shim
//!   `fuzz_target!(|data: &[u8]| enip::harness::<surface>(data))`.
//! * `crates/enip/tests/fuzz_corpus.rs` — runs the same functions over the checked-in seed corpus,
//!   truncation prefixes, and a deterministic random sweep, asserting none panics.
//!
//! The functions are ordinary crate code, so they inherit the crate's `forbid(unsafe_code)` and the
//! `deny`-level `indexing_slicing` / `arithmetic_side_effects` / `unwrap_used` / `expect_used` lints:
//! the harness itself is proven memory-safe, not just the code it exercises.

use core::time::Duration;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::time::Instant;

use crate::assembly::{AssemblyLayout, FieldSpec};
use crate::cip::message::MessageReply;
use crate::cip::types::{CipType, CipValue};
use crate::cip::epath::TagAddress;
use crate::cm::{ForwardOpenSuccess, ForwardRequestFail};
use crate::cpf::{Cpf, SequencedAddress, SockAddrInfo};
use crate::discovery::{parse_list_interfaces, parse_list_services, DeviceIdentity};
use crate::encap::codec::EncapCodec;
use crate::encap::{EncapFrame, EncapHeader};
use crate::io::{IoConnection, IoConnectionParams, IoFrame, RealTimeFormat};
use crate::logix::parse_tag_list;
use tokio_util::codec::Decoder;

/// Every real-time frame format, so [`io_frame`] exercises the seq/header/data permutations.
const IO_FORMATS: [RealTimeFormat; 4] = [
    RealTimeFormat::Modeless,
    RealTimeFormat::Header32Bit,
    RealTimeFormat::Heartbeat,
    RealTimeFormat::ZeroLength,
];

/// A spread of CIP type codes — every elementary code, the STRING/struct markers, and a couple of
/// unknown codes — so [`cip_value`] drives the scalar, array, `Unsupported`, and `Unknown` paths.
const CIP_TYPE_CODES: [u16; 20] = [
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xD1, 0xD2, 0xD3, 0xD4, 0xD0,
    0x02A0, 0x0000, 0x00CE, 0xFFFF,
];

/// Exercise the encapsulation decoders (`fuzz_encap_frame`): the whole-frame decoder, the 24-byte
/// header decoder, and the streaming [`EncapCodec`] (header + length games, NOP skipping, EOF).
pub fn encap_frame(data: &[u8]) {
    let _ = EncapHeader::decode(data);
    let _ = EncapFrame::decode(data);

    // The framed codec: feed the bytes and pull frames until it stalls, asks for more, or errs.
    let mut codec = EncapCodec::new();
    let mut buf = BytesMut::from(data);
    // Bounded loop — every `Ok(Some(_))` consumes `>= HEADER_LEN` bytes, so this terminates.
    while let Ok(Some(_frame)) = codec.decode(&mut buf) {}

    let mut eof = BytesMut::from(data);
    let _ = codec.decode_eof(&mut eof);
}

/// Exercise the Common Packet Format decoders (`fuzz_cpf`): the item-list decoder plus the
/// sockaddr-info (big-endian exception) and sequenced-address sub-decoders that ride CPF items.
pub fn cpf(data: &[u8]) {
    let _ = Cpf::decode(data);
    let _ = SockAddrInfo::decode(data);
    let _ = SequencedAddress::decode(data);
}

/// Exercise the CIP Message Router reply decoder (`fuzz_message_reply`), including the
/// extended-status size-lie path.
pub fn message_reply(data: &[u8]) {
    let _ = MessageReply::decode(data);
}

/// Exercise the CIP value decoders (`fuzz_cip_value`): the tagged form (`decode_tagged`) plus a raw
/// [`CipValue::decode`] under every representative type code, so scalar, array, `Struct`,
/// `Unsupported`, and `Unknown` decode paths are all reached.
pub fn cip_value(data: &[u8]) {
    let _ = CipValue::decode_tagged(data);
    for &code in &CIP_TYPE_CODES {
        let _ = CipValue::decode(CipType::from_code(code), data);
    }
}

/// Exercise a *typed* CIP value decode plus round-trip (`fuzz_cip_value`, structured path): decode
/// `data` under the wire type `code`, and if it decoded, re-encode and re-decode it, asserting
/// nothing panics. The structured libFuzzer target feeds `(code, data)` via `arbitrary`.
pub fn cip_value_typed(code: u16, data: &[u8]) {
    let ty = CipType::from_code(code);
    if let Ok(value) = CipValue::decode(ty, data) {
        let mut w = crate::wire::WireWriter::new();
        if value.encode_value(&mut w).is_ok() {
            let _ = CipValue::decode(ty, w.as_slice());
        }
    }
}

/// Exercise the ForwardOpen reply decoders (`fuzz_forward_open_reply`): the success reply (with the
/// application-word size field) and the failure reply (with the optional remaining-path-size tail).
pub fn forward_open_reply(data: &[u8]) {
    let _ = ForwardOpenSuccess::decode(data);
    let _ = ForwardRequestFail::decode(data);
}

/// Exercise the Get-Instance-Attribute-List record-stream decoder (`fuzz_tag_list`): name-length
/// lies and bad UTF-8 in the `0x55` reply body.
pub fn tag_list(data: &[u8]) {
    let _ = parse_tag_list(data);
}

/// Exercise the class-1 I/O receive path (`fuzz_io_frame`): the [`IoFrame`] codec under every
/// real-time format (runt frames — the EIPScanner overrun class) and the full consume gauntlet of a
/// live [`IoConnection`] (strip, size-check, signed-window sequence rule) against the raw bytes.
pub fn io_frame(data: &[u8]) {
    for &format in &IO_FORMATS {
        let _ = IoFrame::decode(format, data);
    }
    let now = Instant::now();
    let mut conn = IoConnection::new(sample_io_params(), now);
    let _ = conn.consume(data, 0, now);
}

/// The negotiated parameters of a representative T→O-modeless connection, so [`io_frame`] can drive
/// [`IoConnection::consume`] without a socket. Variable-length T→O with a 32-byte cap exercises both
/// the accept and the size-mismatch-drop branches across arbitrary input.
fn sample_io_params() -> IoConnectionParams {
    let endpoint: SocketAddr = SocketAddr::from(([127, 0, 0, 1], crate::io::IO_UDP_PORT));
    IoConnectionParams {
        o2t_connection_id: 0x1000_0001,
        t2o_connection_id: 0x2000_0002,
        o2t_api: Duration::from_millis(10),
        t2o_api: Duration::from_millis(10),
        timeout_multiplier: 16,
        o2t_format: RealTimeFormat::Header32Bit,
        t2o_format: RealTimeFormat::Modeless,
        o2t_data_size: 32,
        t2o_data_size: 32,
        o2t_fixed: false,
        t2o_fixed: false,
        tx_endpoint: endpoint,
        multicast_group: None,
    }
}

/// Exercise the assembly extractor (`fuzz_assembly_decode`): derive an arbitrary but valid
/// [`AssemblyLayout`] from the leading bytes, then run [`AssemblyLayout::decode`] over the tail. The
/// layout builder and the extractor must both be total against hostile field descriptors.
pub fn assembly_decode(data: &[u8]) {
    // Byte 0 selects the assembly data size (0..=63); the rest describe fields, 4 bytes each.
    let data_size = usize::from(data.first().copied().unwrap_or(0) & 0x3F);
    let mut fields = Vec::new();
    let mut chunks = data.get(1..).unwrap_or(&[]).chunks_exact(4);
    for (idx, chunk) in chunks.by_ref().enumerate() {
        if fields.len() >= 16 {
            break;
        }
        // Each 4-byte descriptor: offset, type index, count, bit selector — all masked into range so
        // the builder sees a spread of valid and invalid descriptors.
        let offset = usize::from(chunk.first().copied().unwrap_or(0) & 0x3F);
        // Mask the type selector to 0..=31 and index by `.get()`; out-of-range falls back to DINT.
        let ty_sel = usize::from(chunk.get(1).copied().unwrap_or(0) & 0x1F);
        let ty = CipType::from_code(CIP_TYPE_CODES.get(ty_sel).copied().unwrap_or(0xC4));
        let raw_count = chunk.get(2).copied().unwrap_or(1);
        let count = usize::from(raw_count & 0x07);
        let bit_sel = chunk.get(3).copied().unwrap_or(0);
        let field = if bit_sel & 0x80 != 0 {
            FieldSpec::boolean(idx, offset, bit_sel & 0x07)
        } else {
            FieldSpec::array(idx, offset, ty, count)
        };
        fields.push(field);
    }

    if let Ok(layout) = AssemblyLayout::new(fields, data_size) {
        // Decode against a correctly-sized buffer sliced/padded from the input, and against the raw
        // tail (which usually mismatches the size — the counted-error path).
        let mut sized = vec![0u8; data_size];
        let tail = data.get(1..).unwrap_or(&[]);
        let take = core::cmp::min(sized.len(), tail.len());
        if let (Some(dst), Some(src)) = (sized.get_mut(..take), tail.get(..take)) {
            dst.copy_from_slice(src);
        }
        let _ = layout.decode(&sized);
        let _ = layout.decode(tail);
    }
}

/// Exercise the Logix tag-path parser (`fuzz_tag_path`): the caller-supplied-string surface. Both the
/// strict-UTF-8 and lossy interpretations of the bytes are parsed.
pub fn tag_path(data: &[u8]) {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = TagAddress::parse(s);
    }
    let lossy = String::from_utf8_lossy(data);
    let _ = TagAddress::parse(&lossy);
}

/// Exercise the discovery decoders (`fuzz_discovery`): the ListIdentity reply and item parsers plus
/// the ListServices / ListInterfaces CPF walkers.
pub fn discovery(data: &[u8]) {
    let _ = DeviceIdentity::parse_reply(data);
    let _ = DeviceIdentity::parse_item(data);
    let _ = parse_list_services(data);
    let _ = parse_list_interfaces(data);
}

/// Exercise the CIP Security posture decoders (`fuzz_security_attrs`, DESIGN-cip-security.md §4.1):
/// every 0x5D/0x5E/0x5F attribute decoder over arbitrary bytes (cipher-suite count lies, short
/// strings, width-tolerant flags). The single source of truth is the decoder module's own entry.
pub fn security_attrs(data: &[u8]) {
    crate::cip::security::fuzz_security_attrs(data);
}

/// One named decode surface: its fuzz-target / corpus-directory name and its exercise function.
pub type Surface = (&'static str, fn(&[u8]));

/// Every harness entry, keyed by the fuzz-target / corpus-directory name. The corpus regression test
/// iterates this so adding a target here wires it into the regression sweep automatically.
pub const SURFACES: &[Surface] = &[
    ("fuzz_encap_frame", encap_frame),
    ("fuzz_cpf", cpf),
    ("fuzz_message_reply", message_reply),
    ("fuzz_cip_value", cip_value),
    ("fuzz_forward_open_reply", forward_open_reply),
    ("fuzz_tag_list", tag_list),
    ("fuzz_io_frame", io_frame),
    ("fuzz_assembly_decode", assembly_decode),
    ("fuzz_tag_path", tag_path),
    ("fuzz_discovery", discovery),
    ("fuzz_security_attrs", security_attrs),
];
