//! Common Packet Format (PROTOCOL-DESIGN §5.4).
//!
//! Generic item-list encode/decode: `u16 item_count`, then `item_count × { u16 type_id,
//! u16 length, length bytes }`, decoded with per-item bounds checks so a lying `length` is
//! [`crate::error::WireError::Truncated`] rather than an over-read. Consumers assert the shape they
//! need (explicit replies are exactly `[address, data]`). [`ItemType`] is the total item-type
//! registry. [`SockAddrInfo`] carries the **one endianness exception** in the whole protocol — its
//! family/port/address are **big-endian** (§5.4) — kept here so no other module has to remember it.

use bytes::Bytes;

use crate::error::WireError;
use crate::wire::{WireReader, WireWriter};

const CONTEXT: &str = "cpf";

/// A CPF item type id (§5.4). Total — an unrecognized id is [`ItemType::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemType {
    /// `0x0000` null address — UCMM requests/replies.
    NullAddress,
    /// `0x000C` identity response (§5.3).
    Identity,
    /// `0x00A1` connected address — `u32 connection_id` (class-3).
    ConnectedAddress,
    /// `0x00B1` connected data — class-3 `u16 sequence + MR`, or a class-1 frame (§8.5).
    ConnectedData,
    /// `0x00B2` unconnected data — a Message Router request/reply.
    UnconnectedData,
    /// `0x8000` O→T sockaddr info (big-endian family/port/addr).
    SockAddrOtoT,
    /// `0x8001` T→O sockaddr info (big-endian family/port/addr).
    SockAddrTtoO,
    /// `0x8002` sequenced address — `u32 connection_id + u32 encapsulation_sequence` (class-0/1).
    SequencedAddress,
    /// Any other item id (§4 invariant 5).
    Unknown(u16),
}

impl ItemType {
    /// Decode from a wire item id — total.
    #[must_use]
    pub fn from_code(code: u16) -> Self {
        match code {
            0x0000 => Self::NullAddress,
            0x000C => Self::Identity,
            0x00A1 => Self::ConnectedAddress,
            0x00B1 => Self::ConnectedData,
            0x00B2 => Self::UnconnectedData,
            0x8000 => Self::SockAddrOtoT,
            0x8001 => Self::SockAddrTtoO,
            0x8002 => Self::SequencedAddress,
            other => Self::Unknown(other),
        }
    }

    /// The wire item id.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::NullAddress => 0x0000,
            Self::Identity => 0x000C,
            Self::ConnectedAddress => 0x00A1,
            Self::ConnectedData => 0x00B1,
            Self::UnconnectedData => 0x00B2,
            Self::SockAddrOtoT => 0x8000,
            Self::SockAddrTtoO => 0x8001,
            Self::SequencedAddress => 0x8002,
            Self::Unknown(v) => v,
        }
    }

    /// Whether this id is a sockaddr-info item (`0x8000`/`0x8001`) — the big-endian exception.
    #[must_use]
    pub fn is_sockaddr(self) -> bool {
        matches!(self, Self::SockAddrOtoT | Self::SockAddrTtoO)
    }
}

/// One CPF item: its typed id plus the raw payload bytes. Typed views (sockaddr, sequenced address)
/// are decoded on demand from `data` by the helpers below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpfItem {
    /// The item type.
    pub type_id: ItemType,
    /// The raw payload bytes (already bounds-checked against the declared item length).
    pub data: Bytes,
}

impl CpfItem {
    /// A new item.
    #[must_use]
    pub fn new(type_id: ItemType, data: Bytes) -> Self {
        Self { type_id, data }
    }

    /// The null-address item (empty payload).
    #[must_use]
    pub fn null_address() -> Self {
        Self::new(ItemType::NullAddress, Bytes::new())
    }

    /// An unconnected-data item carrying an MR request/reply.
    #[must_use]
    pub fn unconnected_data(data: Bytes) -> Self {
        Self::new(ItemType::UnconnectedData, data)
    }

    /// A connected-address item for `connection_id`.
    #[must_use]
    pub fn connected_address(connection_id: u32) -> Self {
        let mut w = WireWriter::with_capacity(4);
        w.u32(connection_id);
        Self::new(ItemType::ConnectedAddress, w.into_bytes())
    }

    /// A connected-data item carrying the payload.
    #[must_use]
    pub fn connected_data(data: Bytes) -> Self {
        Self::new(ItemType::ConnectedData, data)
    }

    fn write(&self, w: &mut WireWriter) -> Result<(), WireError> {
        let len = u16::try_from(self.data.len()).map_err(|_| WireError::Overflow { context: CONTEXT })?;
        w.u16(self.type_id.code());
        w.u16(len);
        w.put_slice(&self.data);
        Ok(())
    }
}

/// A decoded Common Packet Format item list (§5.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cpf {
    /// The items, in wire order.
    pub items: Vec<CpfItem>,
}

impl Cpf {
    /// An empty item list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A list from the given items.
    #[must_use]
    pub fn from_items(items: Vec<CpfItem>) -> Self {
        Self { items }
    }

    /// The number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The first item with the given type id, if present.
    #[must_use]
    pub fn find(&self, type_id: ItemType) -> Option<&CpfItem> {
        self.items.iter().find(|i| i.type_id == type_id)
    }

    /// Decode a CPF item list from `buf`, bounds-checking each item's declared length against the
    /// bytes that remain (§5.4). A truncated item is [`WireError::Truncated`], never an over-read.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(buf, CONTEXT);
        let cpf = Self::decode_from(&mut r)?;
        r.expect_end()?;
        Ok(cpf)
    }

    /// Decode a CPF item list from a cursor (does not assert end-of-buffer; the caller decides).
    pub fn decode_from(r: &mut WireReader<'_>) -> Result<Self, WireError> {
        r.at(CONTEXT);
        let item_count = r.u16()? as usize;
        // Each item is at least 4 bytes (type + length); the count cannot exceed remaining/4, so the
        // reservation is bounded by the input (invariant 3) — but we size conservatively regardless.
        let mut items = Vec::new();
        for _ in 0..item_count {
            let type_id = ItemType::from_code(r.u16()?);
            let len = r.u16()? as usize;
            let data = r.take(len)?;
            items.push(CpfItem::new(type_id, Bytes::copy_from_slice(data)));
        }
        Ok(Self { items })
    }

    /// Encode the item list. Fails only if an item's payload exceeds `u16::MAX` (our own value).
    pub fn encode(&self) -> Result<Bytes, WireError> {
        let count = u16::try_from(self.items.len()).map_err(|_| WireError::Overflow { context: CONTEXT })?;
        let mut w = WireWriter::new();
        w.u16(count);
        for item in &self.items {
            item.write(&mut w)?;
        }
        Ok(w.into_bytes())
    }

    /// Assert the exact two-item explicit-reply shape `[address, data]` and return the data item's
    /// payload (§5.4). The address item's id must be one of the expected address types; the data
    /// item must be `0x00B1`/`0x00B2`. Anything else is [`WireError::Malformed`].
    pub fn expect_explicit_data(&self) -> Result<&Bytes, WireError> {
        let [addr, data] = self.items.as_slice() else {
            return Err(WireError::Malformed {
                context: CONTEXT,
                detail: "explicit reply must contain exactly 2 items",
            });
        };
        let addr_ok = matches!(
            addr.type_id,
            ItemType::NullAddress | ItemType::ConnectedAddress
        );
        let data_ok = matches!(
            data.type_id,
            ItemType::UnconnectedData | ItemType::ConnectedData
        );
        if addr_ok && data_ok {
            Ok(&data.data)
        } else {
            Err(WireError::Malformed {
                context: CONTEXT,
                detail: "unexpected item ids in explicit reply",
            })
        }
    }
}

/// A sockaddr-info payload (§5.4). **The `sin_family`, `sin_port`, and `sin_addr` fields are
/// big-endian on the wire** — the one endianness exception in the whole protocol; encoding and
/// decoding here always use the big-endian cursor helpers so the exception lives in exactly one
/// place. `sin_zero` is 8 trailing zero bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrInfo {
    /// Address family — big-endian; `AF_INET` = 2.
    pub sin_family: i16,
    /// Port — big-endian.
    pub sin_port: u16,
    /// IPv4 address — big-endian (host order of the 32-bit address).
    pub sin_addr: u32,
    /// 8 trailing zero bytes.
    pub sin_zero: [u8; 8],
}

/// `AF_INET` — the only address family used (§5.4).
pub const AF_INET: i16 = 2;

impl SockAddrInfo {
    /// A sockaddr for the given IPv4 address and port (`AF_INET`, zeroed `sin_zero`).
    #[must_use]
    pub fn ipv4(addr: u32, port: u16) -> Self {
        Self {
            sin_family: AF_INET,
            sin_port: port,
            sin_addr: addr,
            sin_zero: [0; 8],
        }
    }

    /// Decode a 16-byte sockaddr-info payload — big-endian family/port/addr (§5.4).
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(data, "sockaddr info");
        let sin_family = r.i16_be()?;
        let sin_port = r.u16_be()?;
        let sin_addr = r.u32_be()?;
        let mut sin_zero = [0u8; 8];
        sin_zero.copy_from_slice(r.take(8)?);
        r.expect_end()?;
        Ok(Self {
            sin_family,
            sin_port,
            sin_addr,
            sin_zero,
        })
    }

    /// Encode the 16-byte sockaddr-info payload — big-endian family/port/addr (§5.4).
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut w = WireWriter::with_capacity(16);
        w.i16_be(self.sin_family);
        w.u16_be(self.sin_port);
        w.u32_be(self.sin_addr);
        w.put_slice(&self.sin_zero);
        w.into_bytes()
    }
}

/// A sequenced-address item payload (`0x8002`, §5.4): `u32 connection_id + u32 encap_sequence`,
/// both little-endian. Prefaces every class-0/1 UDP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequencedAddress {
    /// The connection id.
    pub connection_id: u32,
    /// The encapsulation sequence number.
    pub encap_sequence: u32,
}

impl SequencedAddress {
    /// Decode the 8-byte sequenced-address payload.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::with_context(data, "sequenced address");
        let connection_id = r.u32()?;
        let encap_sequence = r.u32()?;
        r.expect_end()?;
        Ok(Self {
            connection_id,
            encap_sequence,
        })
    }

    /// Encode the 8-byte sequenced-address payload.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut w = WireWriter::with_capacity(8);
        w.u32(self.connection_id);
        w.u32(self.encap_sequence);
        w.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn item_type_is_total_and_roundtrips() {
        for code in [0x0000u16, 0x000C, 0x00A1, 0x00B1, 0x00B2, 0x8000, 0x8001, 0x8002, 0xABCD] {
            assert_eq!(ItemType::from_code(code).code(), code);
        }
        assert_eq!(ItemType::from_code(0xABCD), ItemType::Unknown(0xABCD));
    }

    #[test]
    fn cpf_roundtrip_null_plus_unconnected() {
        let cpf = Cpf::from_items(vec![
            CpfItem::null_address(),
            CpfItem::unconnected_data(Bytes::from_static(&[1, 2, 3, 4, 5])),
        ]);
        let bytes = cpf.encode().unwrap();
        // 2 item count + (null: 4+0) + (0xB2: 4+5) = 2 + 4 + 9 = 15
        assert_eq!(bytes.len(), 15);
        let decoded = Cpf::decode(&bytes).unwrap();
        assert_eq!(decoded, cpf);
        assert_eq!(
            decoded.expect_explicit_data().unwrap().as_ref(),
            &[1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn truncated_item_length_is_typed() {
        // item_count=1, type=0xB2, length=10, but only 2 payload bytes present.
        let bytes = [0x01, 0x00, 0xB2, 0x00, 0x0A, 0x00, 0xAA, 0xBB];
        assert!(matches!(
            Cpf::decode(&bytes),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn sockaddr_is_big_endian() {
        let sa = SockAddrInfo::ipv4(0xC0A8_0132, 0x08AE); // 192.168.1.50 : 2222
        let bytes = sa.encode();
        // family=0x0002 BE, port=0x08AE BE, addr=0xC0A80132 BE
        assert_eq!(
            bytes.as_ref(),
            &[0x00, 0x02, 0x08, 0xAE, 0xC0, 0xA8, 0x01, 0x32, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(SockAddrInfo::decode(&bytes).unwrap(), sa);
    }

    #[test]
    fn sequenced_address_roundtrip() {
        let sa = SequencedAddress {
            connection_id: 0x1122_3344,
            encap_sequence: 0x0000_0007,
        };
        assert_eq!(SequencedAddress::decode(&sa.encode()).unwrap(), sa);
    }

    #[test]
    fn wrong_shape_is_malformed() {
        let cpf = Cpf::from_items(vec![CpfItem::null_address()]);
        assert!(matches!(
            cpf.expect_explicit_data(),
            Err(WireError::Malformed { .. })
        ));
    }
}
