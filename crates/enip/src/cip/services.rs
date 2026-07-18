//! Generic CIP attribute services (PROTOCOL-DESIGN §7.5).
//!
//! `Get_Attribute_Single` (`0x0E`), `Set_Attribute_Single` (`0x10`), and `Get_Attribute_All`
//! (`0x01`) against any `(class, instance[, attribute])` — the payload-agnostic escape hatch for
//! non-Logix devices and for Identity-object polling. The reply data is returned as raw [`Bytes`]
//! because attribute layouts are object-specific; typed interpretation is the caller's.

use bytes::Bytes;

use crate::cip::epath::EPath;
use crate::cip::message::MessageRequest;
use crate::client::EipClient;
use crate::error::{EnipError, Result};

/// `Get_Attribute_Single` (§7.5).
pub const SERVICE_GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
/// `Set_Attribute_Single` (§7.5).
pub const SERVICE_SET_ATTRIBUTE_SINGLE: u8 = 0x10;
/// `Get_Attribute_All` (§7.5).
pub const SERVICE_GET_ATTRIBUTE_ALL: u8 = 0x01;

impl EipClient {
    /// `Get_Attribute_Single` (§7.5) against `(class, instance, attribute)` — returns the raw
    /// attribute bytes.
    pub async fn get_attribute_single(
        &self,
        class: u16,
        instance: u16,
        attribute: u16,
    ) -> Result<Bytes> {
        let path = EPath::new()
            .class(class)
            .instance(instance)
            .attribute(attribute);
        let mr = MessageRequest::new(SERVICE_GET_ATTRIBUTE_SINGLE, path, Bytes::new());
        let reply = self.send_cip(mr, "get_attribute_single").await?;
        reply.expect_service(SERVICE_GET_ATTRIBUTE_SINGLE)?;
        if reply.status.is_ok() {
            Ok(reply.data)
        } else {
            Err(EnipError::Cip(reply.status))
        }
    }

    /// `Set_Attribute_Single` (§7.5): write raw `data` to `(class, instance, attribute)`.
    pub async fn set_attribute_single(
        &self,
        class: u16,
        instance: u16,
        attribute: u16,
        data: Bytes,
    ) -> Result<()> {
        let path = EPath::new()
            .class(class)
            .instance(instance)
            .attribute(attribute);
        let mr = MessageRequest::new(SERVICE_SET_ATTRIBUTE_SINGLE, path, data);
        let reply = self.send_cip(mr, "set_attribute_single").await?;
        reply.expect_service(SERVICE_SET_ATTRIBUTE_SINGLE)?;
        if reply.status.is_ok() {
            Ok(())
        } else {
            Err(EnipError::Cip(reply.status))
        }
    }

    /// `Get_Attribute_All` (§7.5) against `(class, instance)` — returns the concatenated attribute
    /// block for the caller to slice per the object definition.
    pub async fn get_attribute_all(&self, class: u16, instance: u16) -> Result<Bytes> {
        let path = EPath::new().class(class).instance(instance);
        let mr = MessageRequest::new(SERVICE_GET_ATTRIBUTE_ALL, path, Bytes::new());
        let reply = self.send_cip(mr, "get_attribute_all").await?;
        reply.expect_service(SERVICE_GET_ATTRIBUTE_ALL)?;
        if reply.status.is_ok() {
            Ok(reply.data)
        } else {
            Err(EnipError::Cip(reply.status))
        }
    }
}
