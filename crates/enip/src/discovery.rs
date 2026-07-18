//! Device discovery (PROTOCOL-DESIGN §5.3).
//!
//! Parses the `ListIdentity`, `ListServices`, and `ListInterfaces` reply data (each a CPF item
//! list, §5.4) into typed values. [`DeviceIdentity`] renders vendor and device type through a small
//! known-values table with an `Unknown(raw)` fallback (§4 invariant 5), and its embedded socket
//! address goes through the big-endian [`crate::cpf::SockAddrInfo`] decoder. Every field is read
//! through the checked cursor — a runt reply is [`WireError::Truncated`], never a panic.

use bytes::Bytes;

use crate::cpf::{Cpf, ItemType, SockAddrInfo};
use crate::error::WireError;
use crate::wire::WireReader;

const CONTEXT: &str = "identity";

/// A CIP vendor id with an optional known name (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorId(pub u16);

impl VendorId {
    /// The vendor's registered name, for the handful the crate knows.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self.0 {
            1 => Some("Rockwell Automation/Allen-Bradley"),
            5 => Some("Schneider Electric"),
            26 => Some("Festo"),
            47 => Some("SICK AG"),
            283 => Some("HMS Industrial Networks"),
            _ => None,
        }
    }
}

impl core::fmt::Display for VendorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:04X})", self.0),
            None => write!(f, "vendor 0x{:04X}", self.0),
        }
    }
}

/// A CIP device type with an optional known name (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceType(pub u16);

impl DeviceType {
    /// The device-type name, for the common CIP profiles.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self.0 {
            0x00 => Some("Generic Device"),
            0x02 => Some("AC Drive"),
            0x0C => Some("Communications Adapter"),
            0x0E => Some("Programmable Logic Controller"),
            0x64 => Some("Rockwell Programmable Automation Controller"),
            _ => None,
        }
    }
}

impl core::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:04X})", self.0),
            None => write!(f, "device type 0x{:04X}", self.0),
        }
    }
}

/// A decoded ListIdentity device identity (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Encapsulation protocol version supported (should be 1).
    pub protocol_version: u16,
    /// The device's advertised socket address (big-endian on the wire).
    pub socket_addr: SockAddrInfo,
    /// Manufacturer vendor id.
    pub vendor: VendorId,
    /// Device type.
    pub device_type: DeviceType,
    /// Product code.
    pub product_code: u16,
    /// Major revision.
    pub revision_major: u8,
    /// Minor revision.
    pub revision_minor: u8,
    /// Device status word.
    pub status: u16,
    /// Serial number.
    pub serial_number: u32,
    /// Product name (SHORT_STRING; checked UTF-8).
    pub product_name: String,
    /// Device state.
    pub state: u8,
}

impl DeviceIdentity {
    /// Parse a ListIdentity reply's data portion: a CPF list with at least one Identity item
    /// (`0x000C`, §5.3). The first Identity item is decoded.
    pub fn parse_reply(data: &[u8]) -> Result<Self, WireError> {
        let cpf = Cpf::decode(data)?;
        let item = cpf.find(ItemType::Identity).ok_or(WireError::Malformed {
            context: CONTEXT,
            detail: "ListIdentity reply has no Identity item",
        })?;
        Self::parse_item(&item.data)
    }

    /// Parse a single Identity item payload (§5.3).
    pub fn parse_item(data: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(data, CONTEXT);
        let protocol_version = r.u16()?;
        let socket_addr = SockAddrInfo::decode(r.take(16)?)?;
        let vendor = VendorId(r.u16()?);
        let device_type = DeviceType(r.u16()?);
        let product_code = r.u16()?;
        let revision_major = r.u8()?;
        let revision_minor = r.u8()?;
        let status = r.u16()?;
        let serial_number = r.u32()?;
        let product_name = r.short_string()?;
        let state = r.u8()?;
        Ok(Self {
            protocol_version,
            socket_addr,
            vendor,
            device_type,
            product_code,
            revision_major,
            revision_minor,
            status,
            serial_number,
            product_name,
            state,
        })
    }
}

/// A ListServices service item (`0x0100`, §5.2): the version, a capability flags word, and a
/// NULL-terminated ASCII service name (`Communications` for CIP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceItem {
    /// Protocol version (should be 1).
    pub protocol_version: u16,
    /// Capability flags word.
    pub capability: u16,
    /// The service name.
    pub name: String,
}

impl ServiceItem {
    /// Whether the service supports CIP encapsulation over TCP (capability bit 5).
    #[must_use]
    pub fn supports_tcp(&self) -> bool {
        self.capability & 0b0010_0000 != 0
    }

    /// Whether the service supports CIP class-0/1 over UDP (capability bit 8).
    #[must_use]
    pub fn supports_udp(&self) -> bool {
        self.capability & 0b1_0000_0000 != 0
    }
}

/// Parse a ListServices reply's data portion into its service items (§5.2). Each item is a
/// `0x0100` CPF item with a `u16 version`, `u16 capability`, and a fixed 16-byte NULL-terminated
/// name.
pub fn parse_list_services(data: &[u8]) -> Result<Vec<ServiceItem>, WireError> {
    let cpf = Cpf::decode(data)?;
    let mut out = Vec::new();
    for item in &cpf.items {
        if item.type_id != ItemType::Unknown(0x0100) {
            continue;
        }
        let mut r = WireReader::with_context(&item.data, "service item");
        let protocol_version = r.u16()?;
        let capability = r.u16()?;
        let name_bytes = r.take_rest();
        // Name is NULL-terminated ASCII within a fixed field; trim at the first NUL.
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name_slice = name_bytes.get(..end).unwrap_or(&[]);
        let name = core::str::from_utf8(name_slice)
            .map_err(|_| WireError::InvalidUtf8 {
                context: "service item",
            })?
            .to_owned();
        out.push(ServiceItem {
            protocol_version,
            capability,
            name,
        });
    }
    Ok(out)
}

/// A ListInterfaces item — the payload is device/interface-specific and optional (§5.2), so it is
/// surfaced as the raw typed CPF item for the caller to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceItem {
    /// The CPF item type id.
    pub type_id: ItemType,
    /// The raw payload.
    pub data: Bytes,
}

/// Parse a ListInterfaces reply's data portion into its raw items (§5.2).
pub fn parse_list_interfaces(data: &[u8]) -> Result<Vec<InterfaceItem>, WireError> {
    let cpf = Cpf::decode(data)?;
    Ok(cpf
        .items
        .into_iter()
        .map(|i| InterfaceItem {
            type_id: i.type_id,
            data: i.data,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cpf::{CpfItem, SockAddrInfo};
    use crate::wire::WireWriter;

    fn identity_item_bytes() -> Vec<u8> {
        let mut w = WireWriter::new();
        w.u16(1); // protocol version
        w.put_slice(&SockAddrInfo::ipv4(0xC0A8_0132, 44818).encode()); // 16 B, big-endian
        w.u16(0x0001); // vendor: Rockwell
        w.u16(0x000E); // device type: PLC
        w.u16(0x0037); // product code
        w.u8(20); // rev major
        w.u8(11); // rev minor
        w.u16(0x0060); // status
        w.u32(0x1234_5678); // serial
        w.u8(11);
        w.put_slice(b"1756-L71/B "); // 11-char product name
        w.u8(0x03); // state
        w.into_inner().to_vec()
    }

    #[test]
    fn parse_identity_item_typed() {
        let bytes = identity_item_bytes();
        let id = DeviceIdentity::parse_item(&bytes).unwrap();
        assert_eq!(id.protocol_version, 1);
        assert_eq!(id.vendor, VendorId(1));
        assert_eq!(id.vendor.name(), Some("Rockwell Automation/Allen-Bradley"));
        assert_eq!(id.device_type, DeviceType(0x0E));
        assert_eq!(id.product_code, 0x0037);
        assert_eq!(id.revision_major, 20);
        assert_eq!(id.serial_number, 0x1234_5678);
        assert_eq!(id.product_name, "1756-L71/B ");
        assert_eq!(id.state, 0x03);
        assert_eq!(id.socket_addr.sin_port, 44818);
    }

    #[test]
    fn parse_identity_reply_wraps_in_cpf() {
        let cpf = Cpf::from_items(vec![CpfItem::new(
            ItemType::Identity,
            Bytes::from(identity_item_bytes()),
        )]);
        let data = cpf.encode().unwrap();
        let id = DeviceIdentity::parse_reply(&data).unwrap();
        assert_eq!(id.vendor, VendorId(1));
    }

    #[test]
    fn runt_identity_is_truncated() {
        assert!(matches!(
            DeviceIdentity::parse_item(&[0x01, 0x00, 0x00]),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn unknown_vendor_renders_raw() {
        assert_eq!(VendorId(0x9999).name(), None);
        assert_eq!(VendorId(0x9999).to_string(), "vendor 0x9999");
    }
}
