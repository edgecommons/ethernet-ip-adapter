//! CIP Security object model — typed reads of the **target's** security posture (originator side,
//! PROTOCOL-DESIGN §7.7 / DESIGN-cip-security.md §4.1).
//!
//! ODVA Volume 8 puts a device's security state in three CIP objects; this module adds *typed
//! decoding* of the relevant attributes on top of the shipped generic attribute services
//! ([`EipClient::get_attribute_single`](crate::EipClient::get_attribute_single), §7.5) — it adds **no
//! new transport**. Every decoder is a total `&[u8] -> Result<T, WireError>` over the checked
//! [`WireReader`] (§4): a truncated, over-long, or unknown-value attribute yields a typed error or an
//! `Unknown(_)` variant, never a panic (fuzzed by `fuzz_security_attrs`).
//!
//! | Object | Class | What we read |
//! |---|---|---|
//! | CIP Security Object | **0x5D** | state, security profiles (supported + configured) |
//! | EtherNet/IP Security Object | **0x5E** | state, capability flags, available/allowed cipher suites, verify-client / send-chain / check-expiration flags |
//! | Certificate Management Object | **0x5F** | push/pull capability flags, instance-1 name/state/encoding |
//!
//! A device that does not implement these objects answers the reads with a CIP status (0x05 path
//! destination unknown / 0x08 service not supported / 0x14 attribute not supported); the aggregate
//! [`EipClient::read_security_posture`] maps any such CIP status to "unavailable" (`None`) rather than
//! an error, so a generic CIP device (e.g. cpppo) reports an empty posture, never a failure.

use bytes::Bytes;

use crate::client::EipClient;
use crate::error::{EnipError, Result, WireError};
use crate::wire::WireReader;

/// CIP Security Object class code (ODVA Vol 8).
pub const CLASS_CIP_SECURITY: u16 = 0x5D;
/// EtherNet/IP Security Object class code.
pub const CLASS_EIP_SECURITY: u16 = 0x5E;
/// Certificate Management Object class code.
pub const CLASS_CERTIFICATE_MANAGEMENT: u16 = 0x5F;

// ---------------------------------------------------------------------------------------------------
// CIP Security Object (0x5D)
// ---------------------------------------------------------------------------------------------------

/// The CIP Security Object state (0x5D attribute 1, USINT). `#[non_exhaustive]` with an explicit
/// [`Unknown`](CipSecurityState::Unknown) — the value is data, never a decode failure (§4 invariant 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipSecurityState {
    /// `0` — factory default (no operational credentials provisioned).
    FactoryDefault,
    /// `1` — configuration in progress (a commissioning session is open).
    ConfigurationInProgress,
    /// `2` — configured (operational security credentials in place).
    Configured,
    /// `3` — incident (a security incident was detected).
    Incident,
    /// Any other code.
    Unknown(u8),
}

impl CipSecurityState {
    /// Decode from the wire byte — total.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::FactoryDefault,
            1 => Self::ConfigurationInProgress,
            2 => Self::Configured,
            3 => Self::Incident,
            other => Self::Unknown(other),
        }
    }
    /// The raw wire byte.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::FactoryDefault => 0,
            Self::ConfigurationInProgress => 1,
            Self::Configured => 2,
            Self::Incident => 3,
            Self::Unknown(v) => v,
        }
    }
    /// A short human description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::FactoryDefault => "Factory Default",
            Self::ConfigurationInProgress => "Configuration In Progress",
            Self::Configured => "Configured",
            Self::Incident => "Incident",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// A CIP-Security "Security Profiles" bitmap (0x5D attributes 2 supported / 3 configured — a WORD).
/// The known bits are named; unknown bits are preserved in [`bits`](SecurityProfiles::bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProfiles {
    /// The raw 16-bit profile bitmap.
    pub bits: u16,
}

impl SecurityProfiles {
    /// The (bit, name) table of the profiles defined by Vol 8.
    const KNOWN: &'static [(u16, &'static str)] = &[
        (0x0001, "EtherNet/IP Integrity"),
        (0x0002, "EtherNet/IP Confidentiality"),
        (0x0004, "CIP Authorization"),
        (0x0008, "CIP User Authentication"),
        (0x0010, "Resource-Constrained CIP Security"),
    ];

    /// The names of the set, known profile bits.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        Self::KNOWN
            .iter()
            .filter(|(bit, _)| self.bits & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

/// The decoded CIP Security Object (0x5D). `state` is always present (it is the object's probe
/// attribute); the profile bitmaps are `None` when the device does not expose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipSecurityObject {
    /// Attribute 1 — the overall security state.
    pub state: CipSecurityState,
    /// Attribute 2 — the profiles the device *supports*.
    pub profiles_supported: Option<SecurityProfiles>,
    /// Attribute 3 — the profiles currently *configured*.
    pub profiles_configured: Option<SecurityProfiles>,
}

/// Decode the CIP Security Object state (0x5D/1, USINT).
///
/// # Errors
/// [`WireError::Truncated`] if the attribute is empty.
pub fn decode_cip_security_state(bytes: &[u8]) -> core::result::Result<CipSecurityState, WireError> {
    let mut r = WireReader::with_context(bytes, "cip security state");
    Ok(CipSecurityState::from_code(r.u8()?))
}

/// Decode a Security Profiles bitmap (0x5D/2 or /3, WORD).
///
/// # Errors
/// [`WireError::Truncated`] if fewer than two bytes are present.
pub fn decode_security_profiles(bytes: &[u8]) -> core::result::Result<SecurityProfiles, WireError> {
    let mut r = WireReader::with_context(bytes, "cip security profiles");
    Ok(SecurityProfiles { bits: r.u16()? })
}

// ---------------------------------------------------------------------------------------------------
// EtherNet/IP Security Object (0x5E)
// ---------------------------------------------------------------------------------------------------

/// One IANA TLS cipher-suite id, as carried in the EtherNet/IP Security Object cipher-suite lists
/// (each suite is a struct of two USINTs = the 2-byte IANA id, big-endian per the IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuiteId {
    /// The 16-bit IANA cipher-suite identifier (e.g. `0xC02B`).
    pub id: u16,
}

impl CipherSuiteId {
    /// Build from the two wire bytes (first, second) — IANA order (`id = first<<8 | second`).
    #[must_use]
    pub fn from_bytes(first: u8, second: u8) -> Self {
        Self {
            id: u16::from_be_bytes([first, second]),
        }
    }

    /// The IANA suite name when known (the Vol 8 §2.4 set + the GCM / TLS 1.3 suites), else `None`.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Some(match self.id {
            0x003B => "TLS_RSA_WITH_NULL_SHA256",
            0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0xC006 => "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC037 => "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
            0xC03A => "TLS_ECDHE_PSK_WITH_NULL_SHA256",
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => return None,
        })
    }

    /// The suite name if known, else a `0xXXXX` hex rendering — always a printable label.
    #[must_use]
    pub fn label(self) -> String {
        self.name()
            .map(str::to_string)
            .unwrap_or_else(|| format!("0x{:04X}", self.id))
    }
}

/// A decoded cipher-suite list (0x5E attribute 3 available / 4 allowed): a USINT count followed by
/// that many 2-byte suite ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherSuiteList {
    /// The suites, in wire order.
    pub suites: Vec<CipherSuiteId>,
}

impl CipherSuiteList {
    /// The printable labels of every suite.
    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        self.suites.iter().map(|s| s.label()).collect()
    }
}

/// The decoded EtherNet/IP Security Object (0x5E). `state` is the probe attribute; every other field
/// is `None` when the device does not expose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EipSecurityObject {
    /// Attribute 1 — object state (raw code; the same value space as the CIP Security state).
    pub state: u8,
    /// Attribute 2 — capability flags (a bit string; exposed raw).
    pub capability_flags: Option<u32>,
    /// Attribute 3 — available cipher suites.
    pub available_cipher_suites: Option<CipherSuiteList>,
    /// Attribute 4 — allowed cipher suites (the ones the device will negotiate).
    pub allowed_cipher_suites: Option<CipherSuiteList>,
    /// Attribute 9 — verify client certificate (mutual-TLS enforcement).
    pub verify_client_certificate: Option<bool>,
    /// Attribute 10 — send certificate chain.
    pub send_certificate_chain: Option<bool>,
    /// Attribute 11 — check expiration.
    pub check_expiration: Option<bool>,
}

/// Decode a cipher-suite list (0x5E/3 or /4): USINT count + count × (USINT, USINT).
///
/// # Errors
/// [`WireError::Truncated`] if the declared count runs past the buffer.
pub fn decode_cipher_suite_list(bytes: &[u8]) -> core::result::Result<CipherSuiteList, WireError> {
    let mut r = WireReader::with_context(bytes, "cipher suite list");
    let count = usize::from(r.u8()?);
    let mut suites = Vec::with_capacity(count);
    for _ in 0..count {
        let first = r.u8()?;
        let second = r.u8()?;
        suites.push(CipherSuiteId::from_bytes(first, second));
    }
    Ok(CipherSuiteList { suites })
}

/// Decode a USINT boolean attribute (nonzero ⇒ true).
///
/// # Errors
/// [`WireError::Truncated`] if the attribute is empty.
pub fn decode_bool_attr(bytes: &[u8]) -> core::result::Result<bool, WireError> {
    let mut r = WireReader::with_context(bytes, "boolean attribute");
    Ok(r.u8()? != 0)
}

/// Decode a capability-flags bit string tolerant of width (USINT / WORD / DWORD), returned as a
/// `u32`.
///
/// # Errors
/// [`WireError::Truncated`] if the attribute is empty.
pub fn decode_flags(bytes: &[u8]) -> core::result::Result<u32, WireError> {
    let mut r = WireReader::with_context(bytes, "capability flags");
    match r.remaining() {
        0 => Err(WireError::Truncated {
            needed: 1,
            remaining: 0,
            context: "capability flags",
        }),
        1 => Ok(u32::from(r.u8()?)),
        2 | 3 => Ok(u32::from(r.u16()?)),
        _ => Ok(r.u32()?),
    }
}

/// Decode the EtherNet/IP Security Object state byte (0x5E/1).
///
/// # Errors
/// [`WireError::Truncated`] if the attribute is empty.
pub fn decode_eip_security_state(bytes: &[u8]) -> core::result::Result<u8, WireError> {
    let mut r = WireReader::with_context(bytes, "eip security state");
    r.u8()
}

// ---------------------------------------------------------------------------------------------------
// Certificate Management Object (0x5F)
// ---------------------------------------------------------------------------------------------------

/// The Certificate Management Object certificate encoding (0x5F instance attribute 5, USINT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateEncoding {
    /// `0` — PEM.
    Pem,
    /// `1` — PKCS#7.
    Pkcs7,
    /// Any other code.
    Unknown(u8),
}

impl CertificateEncoding {
    /// Decode from the wire byte — total.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Pem,
            1 => Self::Pkcs7,
            other => Self::Unknown(other),
        }
    }
    /// A short human description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Pem => "PEM",
            Self::Pkcs7 => "PKCS#7",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// The Certificate Management Object instance state (0x5F instance attribute 2, USINT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateState {
    /// `0` — non-existent (no certificate present).
    NonExistent,
    /// `1` — created.
    Created,
    /// `2` — configuring.
    Configuring,
    /// `3` — verified.
    Verified,
    /// Any other code.
    Unknown(u8),
}

impl CertificateState {
    /// Decode from the wire byte — total.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::NonExistent,
            1 => Self::Created,
            2 => Self::Configuring,
            3 => Self::Verified,
            other => Self::Unknown(other),
        }
    }
    /// A short human description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::NonExistent => "Non-Existent",
            Self::Created => "Created",
            Self::Configuring => "Configuring",
            Self::Verified => "Verified",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// The push/pull capability of a Certificate Management Object (0x5F class attribute 8, a bit string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateCapabilities {
    /// The raw capability-flags value.
    pub flags: u32,
}

impl CertificateCapabilities {
    /// Bit 0 — the device supports the **push** provisioning model (config tool writes certs in).
    #[must_use]
    pub fn push_supported(self) -> bool {
        self.flags & 0x0000_0001 != 0
    }
    /// Bit 1 — the device supports the **pull** provisioning model (device enrolls via EST).
    #[must_use]
    pub fn pull_supported(self) -> bool {
        self.flags & 0x0000_0002 != 0
    }
}

/// A summary of one Certificate Management Object certificate instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInstance {
    /// Instance attribute 1 — the certificate name (SHORT_STRING).
    pub name: Option<String>,
    /// Instance attribute 2 — the certificate state.
    pub state: Option<CertificateState>,
    /// Instance attribute 5 — the certificate encoding.
    pub encoding: Option<CertificateEncoding>,
}

/// The decoded Certificate Management Object summary (0x5F): the class-level push/pull capability and
/// the first certificate instance's identity/state/encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateManagementSummary {
    /// Class attribute 8 — push/pull capability flags.
    pub capabilities: Option<CertificateCapabilities>,
    /// Instance 1 — the primary certificate summary.
    pub instance1: Option<CertificateInstance>,
}

/// Decode a Certificate Management instance Name (0x5F/n/1, SHORT_STRING).
///
/// # Errors
/// [`WireError::Truncated`] if the declared length runs past the buffer, or
/// [`WireError::InvalidUtf8`] on non-UTF-8 bytes.
pub fn decode_certificate_name(bytes: &[u8]) -> core::result::Result<String, WireError> {
    let mut r = WireReader::with_context(bytes, "certificate name");
    r.short_string()
}

// ---------------------------------------------------------------------------------------------------
// Aggregate posture
// ---------------------------------------------------------------------------------------------------

/// The target device's full CIP Security posture — the three objects, each `None` when the device
/// does not implement it. [`is_available`](SecurityPosture::is_available) is false for a generic CIP
/// device that implements none of them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityPosture {
    /// The CIP Security Object (0x5D), when present.
    pub cip_security: Option<CipSecurityObject>,
    /// The EtherNet/IP Security Object (0x5E), when present.
    pub eip_security: Option<EipSecurityObject>,
    /// The Certificate Management Object (0x5F), when present.
    pub certificate_management: Option<CertificateManagementSummary>,
}

impl SecurityPosture {
    /// Whether the device implements any CIP Security object (i.e. the posture is meaningful).
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.cip_security.is_some()
            || self.eip_security.is_some()
            || self.certificate_management.is_some()
    }
}

impl EipClient {
    /// `Get_Attribute_Single` mapped to "attribute/object unavailable" (`Ok(None)`) for **any** CIP
    /// status, so a device that lacks the object/attribute reports absence rather than an error; only
    /// a connection-level failure is an `Err`.
    async fn get_attr_optional(
        &self,
        class: u16,
        instance: u16,
        attribute: u16,
    ) -> Result<Option<Bytes>> {
        match self.get_attribute_single(class, instance, attribute).await {
            Ok(b) => Ok(Some(b)),
            Err(EnipError::Cip(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read the CIP Security Object (0x5D). `Ok(None)` when the device does not implement it (the
    /// state probe is refused); connection-level failures propagate.
    ///
    /// # Errors
    /// A connection-level [`EnipError`] (I/O, timeout, connection lost, protocol violation).
    pub async fn read_cip_security_object(&self) -> Result<Option<CipSecurityObject>> {
        let Some(state_bytes) = self.get_attr_optional(CLASS_CIP_SECURITY, 1, 1).await? else {
            return Ok(None);
        };
        let Ok(state) = decode_cip_security_state(&state_bytes) else {
            return Ok(None);
        };
        let profiles_supported = self
            .get_attr_optional(CLASS_CIP_SECURITY, 1, 2)
            .await?
            .and_then(|b| decode_security_profiles(&b).ok());
        let profiles_configured = self
            .get_attr_optional(CLASS_CIP_SECURITY, 1, 3)
            .await?
            .and_then(|b| decode_security_profiles(&b).ok());
        Ok(Some(CipSecurityObject {
            state,
            profiles_supported,
            profiles_configured,
        }))
    }

    /// Read the EtherNet/IP Security Object (0x5E). `Ok(None)` when unimplemented; connection-level
    /// failures propagate.
    ///
    /// # Errors
    /// A connection-level [`EnipError`].
    pub async fn read_eip_security_object(&self) -> Result<Option<EipSecurityObject>> {
        let Some(state_bytes) = self.get_attr_optional(CLASS_EIP_SECURITY, 1, 1).await? else {
            return Ok(None);
        };
        let Ok(state) = decode_eip_security_state(&state_bytes) else {
            return Ok(None);
        };
        let capability_flags = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 2)
            .await?
            .and_then(|b| decode_flags(&b).ok());
        let available_cipher_suites = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 3)
            .await?
            .and_then(|b| decode_cipher_suite_list(&b).ok());
        let allowed_cipher_suites = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 4)
            .await?
            .and_then(|b| decode_cipher_suite_list(&b).ok());
        let verify_client_certificate = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 9)
            .await?
            .and_then(|b| decode_bool_attr(&b).ok());
        let send_certificate_chain = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 10)
            .await?
            .and_then(|b| decode_bool_attr(&b).ok());
        let check_expiration = self
            .get_attr_optional(CLASS_EIP_SECURITY, 1, 11)
            .await?
            .and_then(|b| decode_bool_attr(&b).ok());
        Ok(Some(EipSecurityObject {
            state,
            capability_flags,
            available_cipher_suites,
            allowed_cipher_suites,
            verify_client_certificate,
            send_certificate_chain,
            check_expiration,
        }))
    }

    /// Read the Certificate Management Object (0x5F) summary. `Ok(None)` when unimplemented;
    /// connection-level failures propagate.
    ///
    /// # Errors
    /// A connection-level [`EnipError`].
    pub async fn read_certificate_management(&self) -> Result<Option<CertificateManagementSummary>> {
        // Class attribute 8 (Capability Flags) is read at instance 0.
        let capabilities = self
            .get_attr_optional(CLASS_CERTIFICATE_MANAGEMENT, 0, 8)
            .await?
            .and_then(|b| decode_flags(&b).ok())
            .map(|flags| CertificateCapabilities { flags });
        let name = self
            .get_attr_optional(CLASS_CERTIFICATE_MANAGEMENT, 1, 1)
            .await?
            .and_then(|b| decode_certificate_name(&b).ok());
        let state = self
            .get_attr_optional(CLASS_CERTIFICATE_MANAGEMENT, 1, 2)
            .await?
            .and_then(|b| b.first().copied())
            .map(CertificateState::from_code);
        let encoding = self
            .get_attr_optional(CLASS_CERTIFICATE_MANAGEMENT, 1, 5)
            .await?
            .and_then(|b| b.first().copied())
            .map(CertificateEncoding::from_code);
        let instance1 = if name.is_some() || state.is_some() || encoding.is_some() {
            Some(CertificateInstance {
                name,
                state,
                encoding,
            })
        } else {
            None
        };
        if capabilities.is_none() && instance1.is_none() {
            return Ok(None);
        }
        Ok(Some(CertificateManagementSummary {
            capabilities,
            instance1,
        }))
    }

    /// Read the full CIP Security posture — all three objects, best-effort (§4.1). Devices without CIP
    /// Security return an empty posture ([`SecurityPosture::is_available`] false), never an error;
    /// only a connection-level failure propagates.
    ///
    /// # Errors
    /// A connection-level [`EnipError`] (the link broke mid-read).
    pub async fn read_security_posture(&self) -> Result<SecurityPosture> {
        Ok(SecurityPosture {
            cip_security: self.read_cip_security_object().await?,
            eip_security: self.read_eip_security_object().await?,
            certificate_management: self.read_certificate_management().await?,
        })
    }
}

/// The panic-free decode-exercise entry for `fuzz_security_attrs` (PROTOCOL-DESIGN §12.3): drive every
/// posture decoder over arbitrary bytes. Kept here beside the decoders so a new decoder is fuzzed by
/// construction.
pub fn fuzz_security_attrs(data: &[u8]) {
    let _ = decode_cip_security_state(data);
    let _ = decode_security_profiles(data);
    let _ = decode_eip_security_state(data);
    let _ = decode_cipher_suite_list(data);
    let _ = decode_bool_attr(data);
    let _ = decode_flags(data);
    let _ = decode_certificate_name(data);
    // The scalar-code mappers are total by construction; touch them for completeness.
    if let Some(&b) = data.first() {
        let _ = CipSecurityState::from_code(b).description();
        let _ = CertificateState::from_code(b).description();
        let _ = CertificateEncoding::from_code(b).description();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn cip_security_state_is_total_and_named() {
        assert_eq!(CipSecurityState::from_code(0), CipSecurityState::FactoryDefault);
        assert_eq!(CipSecurityState::from_code(2), CipSecurityState::Configured);
        assert_eq!(CipSecurityState::from_code(0x77), CipSecurityState::Unknown(0x77));
        assert_eq!(CipSecurityState::from_code(2).description(), "Configured");
        for code in 0u8..=0xFF {
            assert_eq!(CipSecurityState::from_code(code).code(), code);
        }
    }

    #[test]
    fn security_profiles_names_known_bits() {
        let p = SecurityProfiles { bits: 0x0003 };
        let names = p.names();
        assert!(names.contains(&"EtherNet/IP Integrity"));
        assert!(names.contains(&"EtherNet/IP Confidentiality"));
        assert_eq!(names.len(), 2);
        // An unknown high bit is preserved in `bits` but contributes no name.
        let p2 = SecurityProfiles { bits: 0x8000 };
        assert!(p2.names().is_empty());
        assert_eq!(p2.bits, 0x8000);
    }

    #[test]
    fn cipher_suite_id_maps_iana_bytes_and_names() {
        let gcm = CipherSuiteId::from_bytes(0xC0, 0x2B);
        assert_eq!(gcm.id, 0xC02B);
        assert_eq!(gcm.name(), Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
        assert_eq!(gcm.label(), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        let unknown = CipherSuiteId::from_bytes(0xAB, 0xCD);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.label(), "0xABCD");
    }

    #[test]
    fn cipher_suite_list_decodes_count_and_suites() {
        // count=2, then C02B (GCM) and C023 (CBC).
        let bytes = [0x02, 0xC0, 0x2B, 0xC0, 0x23];
        let list = decode_cipher_suite_list(&bytes).unwrap();
        assert_eq!(list.suites.len(), 2);
        assert_eq!(list.suites[0].id, 0xC02B);
        assert_eq!(list.suites[1].id, 0xC023);
        assert_eq!(
            list.labels(),
            vec![
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256".to_string(),
            ]
        );
    }

    #[test]
    fn cipher_suite_list_truncation_is_typed_not_panic() {
        // count says 3 but only one suite follows.
        let bytes = [0x03, 0xC0, 0x2B];
        assert!(matches!(
            decode_cipher_suite_list(&bytes),
            Err(WireError::Truncated { .. })
        ));
        // empty ⇒ truncated on the count byte.
        assert!(matches!(
            decode_cipher_suite_list(&[]),
            Err(WireError::Truncated { .. })
        ));
        // count=0 ⇒ empty list, ok.
        assert_eq!(decode_cipher_suite_list(&[0x00]).unwrap().suites.len(), 0);
    }

    #[test]
    fn bool_and_state_and_profiles_truncation_safe() {
        assert!(decode_bool_attr(&[]).is_err());
        assert!(decode_cip_security_state(&[]).is_err());
        assert!(decode_eip_security_state(&[]).is_err());
        assert!(matches!(
            decode_security_profiles(&[0x01]),
            Err(WireError::Truncated { .. })
        ));
        assert!(decode_bool_attr(&[0x01]).unwrap());
        assert!(!decode_bool_attr(&[0x00]).unwrap());
        // A profiles WORD ignores trailing bytes (devices may pad).
        assert_eq!(decode_security_profiles(&[0x02, 0x00, 0xFF]).unwrap().bits, 0x0002);
    }

    #[test]
    fn flags_decode_tolerates_width() {
        assert_eq!(decode_flags(&[0x05]).unwrap(), 0x0000_0005);
        assert_eq!(decode_flags(&[0x03, 0x00]).unwrap(), 0x0000_0003);
        assert_eq!(decode_flags(&[0x01, 0x00, 0x00, 0x00]).unwrap(), 1);
        assert!(decode_flags(&[]).is_err());
    }

    #[test]
    fn certificate_capabilities_push_pull_bits() {
        let caps = CertificateCapabilities { flags: 0x0000_0003 };
        assert!(caps.push_supported());
        assert!(caps.pull_supported());
        let push_only = CertificateCapabilities { flags: 0x0000_0001 };
        assert!(push_only.push_supported());
        assert!(!push_only.pull_supported());
    }

    #[test]
    fn certificate_state_and_encoding_total() {
        assert_eq!(CertificateState::from_code(0), CertificateState::NonExistent);
        assert_eq!(CertificateState::from_code(3), CertificateState::Verified);
        assert_eq!(CertificateState::from_code(9), CertificateState::Unknown(9));
        assert_eq!(CertificateEncoding::from_code(0), CertificateEncoding::Pem);
        assert_eq!(CertificateEncoding::from_code(1).description(), "PKCS#7");
        assert_eq!(CertificateEncoding::from_code(5), CertificateEncoding::Unknown(5));
    }

    #[test]
    fn certificate_name_decodes_short_string() {
        // SHORT_STRING: len=6, "Device".
        let bytes = [0x06, b'D', b'e', b'v', b'i', b'c', b'e'];
        assert_eq!(decode_certificate_name(&bytes).unwrap(), "Device");
        // truncated length.
        assert!(decode_certificate_name(&[0x06, b'D']).is_err());
    }

    #[test]
    fn posture_availability() {
        let empty = SecurityPosture::default();
        assert!(!empty.is_available());
        let one = SecurityPosture {
            cip_security: Some(CipSecurityObject {
                state: CipSecurityState::Configured,
                profiles_supported: None,
                profiles_configured: None,
            }),
            ..Default::default()
        };
        assert!(one.is_available());
    }

    #[test]
    fn fuzz_entry_never_panics_on_arbitrary_bytes() {
        for len in 0..24usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            fuzz_security_attrs(&data);
        }
    }
}
