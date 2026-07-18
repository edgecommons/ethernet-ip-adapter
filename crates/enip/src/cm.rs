//! Connection Manager (PROTOCOL-DESIGN §8.2–§8.4, §8.8).
//!
//! ForwardOpen / LargeForwardOpen / ForwardClose codecs, [`NetworkConnectionParams`] bit packing,
//! the timeout-multiplier code, and the transport class/trigger byte. P2 implements exactly what the
//! **connected class-3** explicit path (§7.6) needs — the ForwardOpen request/reply encode+decode and
//! the ForwardClose — plus the fully round-tripped NCP packing that the class-1 implicit-I/O slice
//! (P3) will reuse unchanged. The class-1-specific driving (produce/consume, watchdog) stays in
//! [`crate::io`]; nothing here owns a socket.
//!
//! Bit-packing is a classic silent-corruption site, so [`NetworkConnectionParams`] and
//! [`TimeoutMultiplier`] carry exhaustive round-trip tests.

use bytes::Bytes;

use crate::cip::epath::EPath;
use crate::error::{EnipError, WireError};
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "connection manager";

/// The Connection Manager object service codes (§8.2, §8.8). These are **Connection-Manager-scoped**
/// and deliberately kept out of [`crate::logix`] (where `0x52`/`0x4E` mean Read-Fragmented /
/// Read-Modify-Write against the Symbol object, §7.2).
pub mod service {
    /// `Forward_Open` (§8.2).
    pub const FORWARD_OPEN: u8 = 0x54;
    /// `Large_Forward_Open` (§8.2) — NCP fields widen to `u32`.
    pub const LARGE_FORWARD_OPEN: u8 = 0x5B;
    /// `Forward_Close` (§8.8).
    pub const FORWARD_CLOSE: u8 = 0x4E;
    /// `Unconnected_Send` (§7.1) — routed UCMM wrapping.
    pub const UNCONNECTED_SEND: u8 = 0x52;
}

/// The transport class/trigger byte for connected **class-3** explicit messaging (§7.6):
/// `direction(server=1) << 7 | trigger(application=2) << 4 | class(3)` = `0xA3`.
pub const TRANSPORT_CLASS3_TRIGGER: u8 = (1 << 7) | (2 << 4) | 3;

/// The transport class/trigger byte for **class-1** implicit I/O (§8.2), cyclic production:
/// `direction(originator=0) << 7 | trigger(cyclic=0) << 4 | class(1)` = `0x01`. The scanner is the
/// originator, so the direction bit is 0 (client). Use [`transport_class1_trigger`] for the
/// change-of-state / application production triggers.
pub const TRANSPORT_CLASS1_TRIGGER: u8 = 0x01;

/// The production trigger for a class-1 I/O connection (§8.2 field 14, bits 4–6). Class-1 telemetry
/// is almost always cyclic; change-of-state and application triggers are supported for adapters that
/// negotiate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionTrigger {
    /// `0` — cyclic (produce at the RPI).
    Cyclic,
    /// `1` — change-of-state.
    ChangeOfState,
    /// `2` — application-triggered.
    Application,
}

/// The class-1 transport class/trigger byte for the given production trigger (§8.2): originator
/// direction (bit 7 = 0), the trigger in bits 4–6, transport class 1 in bits 0–3.
#[must_use]
pub fn transport_class1_trigger(trigger: ProductionTrigger) -> u8 {
    match trigger {
        ProductionTrigger::Cyclic => 0x01,
        ProductionTrigger::ChangeOfState => 0x11,
        ProductionTrigger::Application => 0x21,
    }
}

/// The Message Router connection path used by class-3 (§7.6): Message Router = class `0x02`
/// instance `0x01`. Callers prefix a [`crate::cip::epath::PortSegment`] when routed.
#[must_use]
pub fn message_router_path() -> EPath {
    EPath::new().class(0x02).instance(0x01)
}

/// The Connection Manager object path `[0x20 0x06 0x24 0x01]` (§8.2) — the target of every
/// ForwardOpen / ForwardClose.
#[must_use]
pub fn connection_manager_path() -> EPath {
    EPath::new().class(0x06).instance(0x01)
}

/// The class-1 I/O connection path (§8.4): Assembly object (class `0x04`), the optional config
/// **instance** segment (`0x24`), then the output (O→T) and input (T→O) **connection points**
/// (`0x2C`). Callers prefix route [`crate::cip::epath::PortSegment`]s via
/// [`EPath::prepend`]-equivalent construction when the target is behind a chassis. Instances above
/// 255 automatically widen to the 16-bit segment forms.
#[must_use]
pub fn io_connection_path(config: Option<u16>, output: u16, input: u16) -> EPath {
    let mut p = EPath::new().class(0x04);
    if let Some(config) = config {
        p = p.instance(config);
    }
    p.connection_point(output).connection_point(input)
}

/// Connection type (§8.3, bits 13–14 / 29–30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnType {
    /// `0` — null (reconfigure) connection.
    Null,
    /// `1` — multicast.
    Multicast,
    /// `2` — point-to-point.
    P2P,
}

impl ConnType {
    #[must_use]
    fn bits(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Multicast => 1,
            Self::P2P => 2,
        }
    }

    #[must_use]
    fn from_bits(bits: u32) -> Self {
        match bits & 0b11 {
            1 => Self::Multicast,
            2 => Self::P2P,
            _ => Self::Null,
        }
    }
}

/// Connection priority (§8.3, bits 10–11 / 26–27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// `0` — low.
    Low,
    /// `1` — high.
    High,
    /// `2` — scheduled.
    Scheduled,
    /// `3` — urgent.
    Urgent,
}

impl Priority {
    #[must_use]
    fn bits(self) -> u32 {
        match self {
            Self::Low => 0,
            Self::High => 1,
            Self::Scheduled => 2,
            Self::Urgent => 3,
        }
    }

    #[must_use]
    fn from_bits(bits: u32) -> Self {
        match bits & 0b11 {
            1 => Self::High,
            2 => Self::Scheduled,
            3 => Self::Urgent,
            _ => Self::Low,
        }
    }
}

/// Fixed- vs variable-length message frame (§8.3, bit 9 / 25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableLength {
    /// `0` — fixed length.
    Fixed,
    /// `1` — variable length.
    Variable,
}

impl VariableLength {
    #[must_use]
    fn is_variable(self) -> bool {
        matches!(self, Self::Variable)
    }

    #[must_use]
    fn from_bit(bit: bool) -> Self {
        if bit {
            Self::Variable
        } else {
            Self::Fixed
        }
    }
}

/// Network connection parameters (§8.3). Encodes to a `u16` (standard ForwardOpen) or a `u32`
/// (LargeForwardOpen). `size` is the on-wire connection size in bytes **including** the class-1
/// sequence count and the 32-bit run/idle header when present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConnectionParams {
    /// Connection size in bytes.
    pub size: u16,
    /// Fixed or variable length.
    pub variable: VariableLength,
    /// Connection priority.
    pub priority: Priority,
    /// Connection type.
    pub conn_type: ConnType,
    /// Redundant-owner flag (bit 15 / 31).
    pub redundant_owner: bool,
}

impl NetworkConnectionParams {
    /// A point-to-point, fixed-length, low-priority parameter set of the given size — the class-3
    /// explicit-messaging default (§7.6).
    #[must_use]
    pub fn p2p(size: u16) -> Self {
        Self {
            size,
            variable: VariableLength::Variable,
            priority: Priority::Low,
            conn_type: ConnType::P2P,
            redundant_owner: false,
        }
    }

    /// A fully-specified I/O parameter set (§8.3) — the class-1 implicit path picks connection type
    /// (P2P for O→T and directed T→O, multicast for a shared T→O group), priority, and fixed/variable
    /// framing per direction. `size` is the on-wire connection size **including** the class-1 sequence
    /// count and the 32-bit run/idle header when the direction carries one.
    #[must_use]
    pub fn io(
        size: u16,
        variable: VariableLength,
        priority: Priority,
        conn_type: ConnType,
    ) -> Self {
        Self {
            size,
            variable,
            priority,
            conn_type,
            redundant_owner: false,
        }
    }

    /// Pack the standard 16-bit form (§8.3): `bits 0–8` size, `bit 9` variable, `bits 10–11`
    /// priority, `bits 13–14` type, `bit 15` redundant. A size above `0x1FF` (511) does not fit the
    /// 9-bit field and is [`EnipError::TooLarge`] — use [`NetworkConnectionParams::encode_u32`].
    pub fn encode_u16(&self) -> Result<u16, EnipError> {
        if self.size > 0x01FF {
            return Err(EnipError::TooLarge { limit: 0x01FF });
        }
        let mut v: u16 = self.size & 0x01FF;
        v |= u16::from(self.variable.is_variable()) << 9;
        v |= (self.priority.bits() as u16) << 10;
        v |= (self.conn_type.bits() as u16) << 13;
        v |= u16::from(self.redundant_owner) << 15;
        Ok(v)
    }

    /// Pack the large 32-bit form (§8.3): size `bits 0–15`, variable `bit 25`, priority
    /// `bits 26–27`, type `bits 29–30`, redundant `bit 31`.
    #[must_use]
    pub fn encode_u32(&self) -> u32 {
        let mut v: u32 = u32::from(self.size);
        v |= u32::from(self.variable.is_variable()) << 25;
        v |= self.priority.bits() << 26;
        v |= self.conn_type.bits() << 29;
        v |= u32::from(self.redundant_owner) << 31;
        v
    }

    /// Decode the standard 16-bit form.
    #[must_use]
    pub fn decode_u16(v: u16) -> Self {
        Self {
            size: v & 0x01FF,
            variable: VariableLength::from_bit(v & (1 << 9) != 0),
            priority: Priority::from_bits(u32::from(v >> 10)),
            conn_type: ConnType::from_bits(u32::from(v >> 13)),
            redundant_owner: v & (1 << 15) != 0,
        }
    }

    /// Decode the large 32-bit form.
    #[must_use]
    pub fn decode_u32(v: u32) -> Self {
        // Size is the low 16 bits; truncation is intended (the field is exactly 16 bits wide).
        Self {
            size: (v & 0xFFFF) as u16,
            variable: VariableLength::from_bit(v & (1 << 25) != 0),
            priority: Priority::from_bits(v >> 26),
            conn_type: ConnType::from_bits(v >> 29),
            redundant_owner: v & (1 << 31) != 0,
        }
    }
}

/// The connection timeout multiplier **code** (§8.2 field 8): `multiplier = 4 << code`, so code 0 is
/// ×4 … code 7 is ×512.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutMultiplier {
    /// ×4.
    X4,
    /// ×8.
    X8,
    /// ×16.
    X16,
    /// ×32.
    X32,
    /// ×64.
    X64,
    /// ×128.
    X128,
    /// ×256.
    X256,
    /// ×512.
    X512,
}

impl TimeoutMultiplier {
    /// The wire code (0–7).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::X4 => 0,
            Self::X8 => 1,
            Self::X16 => 2,
            Self::X32 => 3,
            Self::X64 => 4,
            Self::X128 => 5,
            Self::X256 => 6,
            Self::X512 => 7,
        }
    }

    /// The numeric multiplier (`4 << code`).
    #[must_use]
    pub fn multiplier(self) -> u32 {
        4u32 << self.code()
    }

    /// Decode a wire code (values `> 7` clamp to ×512, the maximum defined).
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::X4,
            1 => Self::X8,
            2 => Self::X16,
            3 => Self::X32,
            4 => Self::X64,
            5 => Self::X128,
            6 => Self::X256,
            _ => Self::X512,
        }
    }
}

/// A ForwardOpen request (§8.2). Encodes the service-specific data that rides a
/// [`crate::cip::message::MessageRequest`] addressed to the Connection Manager. `large` selects the
/// LargeForwardOpen (`0x5B`) NCP widening; the client picks the service code accordingly.
#[derive(Debug, Clone)]
pub struct ForwardOpenRequest {
    /// Priority / time-tick byte.
    pub priority_time_tick: u8,
    /// Timeout ticks.
    pub timeout_ticks: u8,
    /// O→T connection id (0 for a P2P O→T the target assigns).
    pub o_t_connection_id: u32,
    /// T→O connection id (originator-chosen).
    pub t_o_connection_id: u32,
    /// Connection serial number (originator-unique).
    pub connection_serial: u16,
    /// Originator vendor id.
    pub vendor_id: u16,
    /// Originator serial number.
    pub originator_serial: u32,
    /// Timeout-multiplier code (§8.2 field 8).
    pub timeout_multiplier: TimeoutMultiplier,
    /// O→T requested packet interval (µs).
    pub o_t_rpi: u32,
    /// O→T network connection parameters.
    pub o_t_params: NetworkConnectionParams,
    /// T→O requested packet interval (µs).
    pub t_o_rpi: u32,
    /// T→O network connection parameters.
    pub t_o_params: NetworkConnectionParams,
    /// Transport class/trigger byte (§7.6 uses [`TRANSPORT_CLASS3_TRIGGER`]).
    pub transport_class_trigger: u8,
    /// The connection path (§8.4 / §7.6).
    pub connection_path: EPath,
    /// LargeForwardOpen selection (`0x5B`).
    pub large: bool,
}

impl ForwardOpenRequest {
    /// A class-3 explicit-messaging ForwardOpen (§7.6) against the Message Router, with the given
    /// originator ids and a fixed-size (500) connection.
    #[must_use]
    pub fn class3(
        o_t_connection_id: u32,
        t_o_connection_id: u32,
        connection_serial: u16,
        vendor_id: u16,
        originator_serial: u32,
        connection_path: EPath,
    ) -> Self {
        Self {
            priority_time_tick: 0x0A,
            timeout_ticks: 0x0E,
            o_t_connection_id,
            t_o_connection_id,
            connection_serial,
            vendor_id,
            originator_serial,
            timeout_multiplier: TimeoutMultiplier::X16,
            o_t_rpi: 2_000_000,
            o_t_params: NetworkConnectionParams::p2p(500),
            t_o_rpi: 2_000_000,
            t_o_params: NetworkConnectionParams::p2p(500),
            transport_class_trigger: TRANSPORT_CLASS3_TRIGGER,
            connection_path,
            large: false,
        }
    }

    /// A class-1 implicit-I/O ForwardOpen (§8.2). The O→T connection id is left 0 (the target assigns
    /// it for a P2P O→T); `t_o_connection_id` is the originator-chosen id the target will stamp on the
    /// frames it produces. `large` selects LargeForwardOpen (`0x5B`); the class-1 driver sets it when
    /// either direction's on-wire size exceeds 505 bytes. `connection_path` is built by
    /// [`io_connection_path`] (optionally route-prefixed).
    #[expect(
        clippy::too_many_arguments,
        reason = "a ForwardOpen is an inherently wide wire record; the I/O caller builds it once"
    )]
    #[must_use]
    pub fn class1(
        t_o_connection_id: u32,
        connection_serial: u16,
        vendor_id: u16,
        originator_serial: u32,
        timeout_multiplier: TimeoutMultiplier,
        o_t_rpi: u32,
        o_t_params: NetworkConnectionParams,
        t_o_rpi: u32,
        t_o_params: NetworkConnectionParams,
        transport_class_trigger: u8,
        connection_path: EPath,
        large: bool,
    ) -> Self {
        Self {
            priority_time_tick: 0x0A,
            timeout_ticks: 0x0E,
            o_t_connection_id: 0,
            t_o_connection_id,
            connection_serial,
            vendor_id,
            originator_serial,
            timeout_multiplier,
            o_t_rpi,
            o_t_params,
            t_o_rpi,
            t_o_params,
            transport_class_trigger,
            connection_path,
            large,
        }
    }

    /// The service code to use (`0x54` or `0x5B`).
    #[must_use]
    pub fn service(&self) -> u8 {
        if self.large {
            service::LARGE_FORWARD_OPEN
        } else {
            service::FORWARD_OPEN
        }
    }

    /// Encode the ForwardOpen service data (§8.2): the fixed header, the two RPI/NCP pairs, the
    /// transport class/trigger, the connection-path word count, then the padded connection path.
    pub fn encode(&self) -> Result<Bytes, EnipError> {
        let path_bytes = self.connection_path.encode()?;
        let words = path_bytes.len().checked_div(2).unwrap_or(0);
        let path_words = u8::try_from(words).map_err(|_| EnipError::TooLarge { limit: 255 })?;

        let mut w = WireWriter::new();
        w.u8(self.priority_time_tick);
        w.u8(self.timeout_ticks);
        w.u32(self.o_t_connection_id);
        w.u32(self.t_o_connection_id);
        w.u16(self.connection_serial);
        w.u16(self.vendor_id);
        w.u32(self.originator_serial);
        w.u8(self.timeout_multiplier.code());
        w.put_slice(&[0, 0, 0]); // reserved
        w.u32(self.o_t_rpi);
        self.write_params(&mut w, self.o_t_params)?;
        w.u32(self.t_o_rpi);
        self.write_params(&mut w, self.t_o_params)?;
        w.u8(self.transport_class_trigger);
        w.u8(path_words);
        w.put_slice(&path_bytes);
        Ok(w.into_bytes())
    }

    fn write_params(&self, w: &mut WireWriter, p: NetworkConnectionParams) -> Result<(), EnipError> {
        if self.large {
            w.u32(p.encode_u32());
        } else {
            w.u16(p.encode_u16()?);
        }
        Ok(())
    }
}

/// A successful ForwardOpen reply (§8.2). The APIs are the **actual** packet intervals the target
/// chose — the values that drive class-1 timing, not the requested RPIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardOpenSuccess {
    /// O→T connection id (target-assigned).
    pub o_t_connection_id: u32,
    /// T→O connection id (our value, echoed).
    pub t_o_connection_id: u32,
    /// Connection serial number.
    pub connection_serial: u16,
    /// Originator vendor id.
    pub vendor_id: u16,
    /// Originator serial number.
    pub originator_serial: u32,
    /// O→T actual packet interval (µs).
    pub o_t_api: u32,
    /// T→O actual packet interval (µs).
    pub t_o_api: u32,
    /// Application reply bytes (opaque).
    pub app_data: Bytes,
}

impl ForwardOpenSuccess {
    /// Decode a ForwardOpen success reply's service data (§8.2), every field through the cursor.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(data, CONTEXT);
        let o_t_connection_id = r.u32()?;
        let t_o_connection_id = r.u32()?;
        let connection_serial = r.u16()?;
        let vendor_id = r.u16()?;
        let originator_serial = r.u32()?;
        let o_t_api = r.u32()?;
        let t_o_api = r.u32()?;
        let app_words = r.u8()? as usize;
        let _reserved = r.u8()?;
        let app_bytes = app_words.checked_mul(2).ok_or(WireError::Overflow { context: CONTEXT })?;
        let app_data = Bytes::copy_from_slice(r.take(app_bytes)?);
        Ok(Self {
            o_t_connection_id,
            t_o_connection_id,
            connection_serial,
            vendor_id,
            originator_serial,
            o_t_api,
            t_o_api,
            app_data,
        })
    }
}

/// A rejected ForwardOpen / ForwardClose reply (§8.2). `remaining_path_size` is present on routing
/// errors (the reserved byte follows it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRequestFail {
    /// Connection serial number.
    pub connection_serial: u16,
    /// Originator vendor id.
    pub vendor_id: u16,
    /// Originator serial number.
    pub originator_serial: u32,
    /// The remaining route-path size on a routing error, if the reply carried it.
    pub remaining_path_size: Option<u8>,
}

impl ForwardRequestFail {
    /// Decode a ForwardOpen/Close failure reply's service data (§8.2). The `remaining_path_size` +
    /// reserved byte are read when present; a shorter reply leaves it `None` rather than erroring.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(data, CONTEXT);
        let connection_serial = r.u16()?;
        let vendor_id = r.u16()?;
        let originator_serial = r.u32()?;
        let remaining_path_size = if r.remaining() >= 1 {
            let rps = r.u8()?;
            let _reserved = r.u8(); // reserved byte, best-effort
            Some(rps)
        } else {
            None
        };
        Ok(Self {
            connection_serial,
            vendor_id,
            originator_serial,
            remaining_path_size,
        })
    }
}

/// A ForwardClose request (§8.8). Note the reserved byte after the path size, absent in ForwardOpen.
#[derive(Debug, Clone)]
pub struct ForwardCloseRequest {
    /// Priority / time-tick byte.
    pub priority_time_tick: u8,
    /// Timeout ticks.
    pub timeout_ticks: u8,
    /// Connection serial number (must match the open).
    pub connection_serial: u16,
    /// Originator vendor id.
    pub vendor_id: u16,
    /// Originator serial number.
    pub originator_serial: u32,
    /// The connection path (same as the open).
    pub connection_path: EPath,
}

impl ForwardCloseRequest {
    /// Build a ForwardClose that tears down the connection opened by `open`.
    #[must_use]
    pub fn for_open(open: &ForwardOpenRequest) -> Self {
        Self {
            priority_time_tick: open.priority_time_tick,
            timeout_ticks: open.timeout_ticks,
            connection_serial: open.connection_serial,
            vendor_id: open.vendor_id,
            originator_serial: open.originator_serial,
            connection_path: open.connection_path.clone(),
        }
    }

    /// Encode the ForwardClose service data (§8.8).
    pub fn encode(&self) -> Result<Bytes, EnipError> {
        let path_bytes = self.connection_path.encode()?;
        let words = path_bytes.len().checked_div(2).unwrap_or(0);
        let path_words = u8::try_from(words).map_err(|_| EnipError::TooLarge { limit: 255 })?;

        let mut w = WireWriter::new();
        w.u8(self.priority_time_tick);
        w.u8(self.timeout_ticks);
        w.u16(self.connection_serial);
        w.u16(self.vendor_id);
        w.u32(self.originator_serial);
        w.u8(path_words);
        w.u8(0); // reserved (present in ForwardClose, absent in ForwardOpen)
        w.put_slice(&path_bytes);
        Ok(w.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn ncp_u16_roundtrip_exhaustive_fields() {
        for &size in &[0u16, 1, 500, 504, 0x01FF] {
            for variable in [VariableLength::Fixed, VariableLength::Variable] {
                for priority in [Priority::Low, Priority::High, Priority::Scheduled, Priority::Urgent] {
                    for conn_type in [ConnType::Null, ConnType::Multicast, ConnType::P2P] {
                        for redundant_owner in [false, true] {
                            let p = NetworkConnectionParams {
                                size,
                                variable,
                                priority,
                                conn_type,
                                redundant_owner,
                            };
                            let packed = p.encode_u16().unwrap();
                            assert_eq!(NetworkConnectionParams::decode_u16(packed), p);
                            // The large form must survive the wider fields too.
                            assert_eq!(
                                NetworkConnectionParams::decode_u32(p.encode_u32()),
                                p
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn ncp_u16_rejects_oversize() {
        let p = NetworkConnectionParams::p2p(0x0200);
        assert!(matches!(p.encode_u16(), Err(EnipError::TooLarge { .. })));
        // But it fits the large form.
        assert_eq!(NetworkConnectionParams::decode_u32(p.encode_u32()).size, 0x0200);
    }

    #[test]
    fn timeout_multiplier_roundtrip() {
        for code in 0u8..=7 {
            let m = TimeoutMultiplier::from_code(code);
            assert_eq!(m.code(), code);
            assert_eq!(m.multiplier(), 4u32 << code);
        }
        assert_eq!(TimeoutMultiplier::X512.multiplier(), 512);
    }

    #[test]
    fn class3_trigger_byte() {
        assert_eq!(TRANSPORT_CLASS3_TRIGGER, 0xA3);
    }

    #[test]
    fn forward_open_encode_shape() {
        let req = ForwardOpenRequest::class3(0, 0x1122_3344, 0x0007, 0x1337, 0xDEAD_BEEF, message_router_path());
        let bytes = req.encode().unwrap();
        // 36-byte fixed header + connection path (Message Router = 4 bytes = 2 words).
        // priority(1)+ticks(1)+otcid(4)+tocid(4)+serial(2)+vendor(2)+origserial(4)+mult(1)+rsv(3)
        //  +otrpi(4)+otncp(2)+torpi(4)+toncp(2)+trigger(1)+pathwords(1) = 36, then 4 path bytes.
        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes[0], 0x0A);
        assert_eq!(&bytes[2..6], &[0, 0, 0, 0]); // O→T id = 0
        assert_eq!(&bytes[6..10], &0x1122_3344u32.to_le_bytes());
        assert_eq!(bytes[34], TRANSPORT_CLASS3_TRIGGER);
        assert_eq!(bytes[35], 2); // path words
        assert_eq!(&bytes[36..40], &[0x20, 0x02, 0x24, 0x01]); // Message Router path
    }

    #[test]
    fn forward_open_reply_roundtrips_through_decode() {
        let mut w = WireWriter::new();
        w.u32(0xAABB_CCDD); // O→T (target-assigned)
        w.u32(0x1122_3344); // T→O (echo)
        w.u16(0x0007);
        w.u16(0x1337);
        w.u32(0xDEAD_BEEF);
        w.u32(2000); // O→T API
        w.u32(2000); // T→O API
        w.u8(0); // app words
        w.u8(0); // reserved
        let s = ForwardOpenSuccess::decode(w.as_slice()).unwrap();
        assert_eq!(s.o_t_connection_id, 0xAABB_CCDD);
        assert_eq!(s.t_o_connection_id, 0x1122_3344);
        assert_eq!(s.o_t_api, 2000);
        assert!(s.app_data.is_empty());
    }

    #[test]
    fn forward_open_fail_decodes_remaining_path() {
        let mut w = WireWriter::new();
        w.u16(0x0007);
        w.u16(0x1337);
        w.u32(0xDEAD_BEEF);
        w.u8(2); // remaining path size
        w.u8(0); // reserved
        let f = ForwardRequestFail::decode(w.as_slice()).unwrap();
        assert_eq!(f.remaining_path_size, Some(2));
    }

    #[test]
    fn class1_trigger_bytes() {
        assert_eq!(TRANSPORT_CLASS1_TRIGGER, 0x01);
        assert_eq!(transport_class1_trigger(ProductionTrigger::Cyclic), 0x01);
        assert_eq!(transport_class1_trigger(ProductionTrigger::ChangeOfState), 0x11);
        assert_eq!(transport_class1_trigger(ProductionTrigger::Application), 0x21);
        // Each decodes as direction=originator(0), class=1.
        for t in [
            ProductionTrigger::Cyclic,
            ProductionTrigger::ChangeOfState,
            ProductionTrigger::Application,
        ] {
            let b = transport_class1_trigger(t);
            assert_eq!(b & 0x0F, 1, "class 1");
            assert_eq!(b & 0x80, 0, "originator direction");
        }
    }

    #[test]
    fn io_connection_path_with_and_without_config() {
        // config 151, output 150, input 100 — the OpENer/EIPScanner reference path.
        let with = io_connection_path(Some(151), 150, 100).encode().unwrap();
        assert_eq!(
            with.as_ref(),
            &[0x20, 0x04, 0x24, 151, 0x2C, 150, 0x2C, 100]
        );
        // Input-only (no config): just the assembly class and the two connection points.
        let without = io_connection_path(None, 150, 100).encode().unwrap();
        assert_eq!(without.as_ref(), &[0x20, 0x04, 0x2C, 150, 0x2C, 100]);
        // A 16-bit instance widens the segment.
        let wide = io_connection_path(Some(300), 150, 100).encode().unwrap();
        assert_eq!(&wide[0..6], &[0x20, 0x04, 0x25, 0x00, 0x2C, 0x01]);
    }

    #[test]
    fn io_ncp_roundtrips_all_forms() {
        for conn_type in [ConnType::P2P, ConnType::Multicast] {
            for variable in [VariableLength::Fixed, VariableLength::Variable] {
                for priority in [Priority::Low, Priority::Scheduled, Priority::Urgent] {
                    let p = NetworkConnectionParams::io(38, variable, priority, conn_type);
                    assert_eq!(NetworkConnectionParams::decode_u16(p.encode_u16().unwrap()), p);
                    assert_eq!(NetworkConnectionParams::decode_u32(p.encode_u32()), p);
                    assert!(!p.redundant_owner);
                }
            }
        }
    }

    #[test]
    fn class1_forward_open_golden_vector() {
        // Hand-assembled per §8.2/§8.4 (ODVA layout): a cyclic class-1 open, T→O id 0x11223344,
        // serial 7, vendor 0x1337, orig serial 0xDEADBEEF, ×16 multiplier (code 2), 20 ms RPIs
        // (20000 µs), O→T P2P fixed size 6 (2 seq + 4 header, heartbeat data), T→O P2P fixed size
        // 34 (2 seq + 32 data, modeless), path config 151 / output 150 / input 100.
        let o_t = NetworkConnectionParams::io(6, VariableLength::Fixed, Priority::Scheduled, ConnType::P2P);
        let t_o = NetworkConnectionParams::io(34, VariableLength::Fixed, Priority::Scheduled, ConnType::P2P);
        let req = ForwardOpenRequest::class1(
            0x1122_3344,
            0x0007,
            0x1337,
            0xDEAD_BEEF,
            TimeoutMultiplier::X16,
            20_000,
            o_t,
            20_000,
            t_o,
            TRANSPORT_CLASS1_TRIGGER,
            io_connection_path(Some(151), 150, 100),
            false,
        );
        assert_eq!(req.service(), service::FORWARD_OPEN);
        let bytes = req.encode().unwrap();
        // priority/tick, timeout tick
        assert_eq!(&bytes[0..2], &[0x0A, 0x0E]);
        // O→T id = 0 (target assigns), T→O id echoed back on the reply
        assert_eq!(&bytes[2..6], &[0, 0, 0, 0]);
        assert_eq!(&bytes[6..10], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&bytes[10..12], &0x0007u16.to_le_bytes());
        assert_eq!(&bytes[12..14], &0x1337u16.to_le_bytes());
        assert_eq!(&bytes[14..18], &0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(bytes[18], TimeoutMultiplier::X16.code()); // 2
        assert_eq!(&bytes[19..22], &[0, 0, 0]); // reserved
        assert_eq!(&bytes[22..26], &20_000u32.to_le_bytes()); // O→T RPI
        assert_eq!(&bytes[26..28], &o_t.encode_u16().unwrap().to_le_bytes());
        assert_eq!(&bytes[28..32], &20_000u32.to_le_bytes()); // T→O RPI
        assert_eq!(&bytes[32..34], &t_o.encode_u16().unwrap().to_le_bytes());
        assert_eq!(bytes[34], TRANSPORT_CLASS1_TRIGGER);
        assert_eq!(bytes[35], 4); // path words: 8 bytes / 2
        assert_eq!(&bytes[36..44], &[0x20, 0x04, 0x24, 151, 0x2C, 150, 0x2C, 100]);
        // Round-trip the reply that would answer it (actual PIs differ from requested RPIs).
        let mut w = WireWriter::new();
        w.u32(0xAABB_CCDD); // O→T id target-assigned
        w.u32(0x1122_3344); // T→O echo
        w.u16(0x0007);
        w.u16(0x1337);
        w.u32(0xDEAD_BEEF);
        w.u32(20_000); // O→T API
        w.u32(20_000); // T→O API
        w.u8(0);
        w.u8(0);
        let ok = ForwardOpenSuccess::decode(w.as_slice()).unwrap();
        assert_eq!(ok.o_t_connection_id, 0xAABB_CCDD);
        assert_eq!(ok.t_o_connection_id, 0x1122_3344);
        assert_eq!(ok.o_t_api, 20_000);
        assert_eq!(ok.t_o_api, 20_000);
    }

    #[test]
    fn large_forward_open_widens_ncp_to_u32() {
        // O→T size 1000 (> 505) forces LargeForwardOpen; the NCP fields become u32.
        let o_t = NetworkConnectionParams::io(1000, VariableLength::Fixed, Priority::Scheduled, ConnType::P2P);
        let t_o = NetworkConnectionParams::io(34, VariableLength::Fixed, Priority::Scheduled, ConnType::P2P);
        let req = ForwardOpenRequest::class1(
            0x1, 0x2, 0x3, 0x4, TimeoutMultiplier::X16, 20_000, o_t, 20_000, t_o,
            TRANSPORT_CLASS1_TRIGGER, io_connection_path(Some(151), 150, 100), true,
        );
        assert_eq!(req.service(), service::LARGE_FORWARD_OPEN);
        let bytes = req.encode().unwrap();
        // O→T RPI at byte 22, then a 4-byte NCP (large), T→O RPI, 4-byte NCP.
        assert_eq!(&bytes[22..26], &20_000u32.to_le_bytes());
        assert_eq!(&bytes[26..30], &o_t.encode_u32().to_le_bytes());
        assert_eq!(&bytes[30..34], &20_000u32.to_le_bytes());
        assert_eq!(&bytes[34..38], &t_o.encode_u32().to_le_bytes());
        // trigger + path-words follow the wider params.
        assert_eq!(bytes[38], TRANSPORT_CLASS1_TRIGGER);
        assert_eq!(bytes[39], 4);
    }

    #[test]
    fn connection_manager_path_is_canonical() {
        assert_eq!(connection_manager_path().encode().unwrap().as_ref(), &[0x20, 0x06, 0x24, 0x01]);
    }

    #[test]
    fn forward_close_encode_has_reserved_byte() {
        let open = ForwardOpenRequest::class3(0, 1, 2, 3, 4, message_router_path());
        let close = ForwardCloseRequest::for_open(&open);
        let bytes = close.encode().unwrap();
        // priority(1)+ticks(1)+serial(2)+vendor(2)+origserial(4)+pathwords(1)+reserved(1)=12, +4 path
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[10], 2); // path words
        assert_eq!(bytes[11], 0); // reserved
        assert_eq!(&bytes[12..16], &[0x20, 0x02, 0x24, 0x01]);
    }
}
