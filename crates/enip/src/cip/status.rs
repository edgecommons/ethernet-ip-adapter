//! CIP General Status (PROTOCOL-DESIGN §6.4).
//!
//! [`GeneralStatus`] is a real, `#[non_exhaustive]` enum with an explicit `Unknown(u8)` (invariant
//! 5 of §4 — enums are total): a status is *data* the caller inspects, never a stringified message.
//! [`CipStatus`] pairs it with the extended-status words and carries the classification helpers the
//! adapter's quality mapping keys on (`is_ok`, `has_more`, `is_tag_not_found`, `is_routing_error`,
//! and the Logix `0xFF` extended decodes). `0x06` (partial transfer) is what drives fragmented
//! reads (D-ENIP-12).

/// A CIP general status code (§6.4). Rendered by [`GeneralStatus::description`] for the adapter's
/// `qualityRaw` string; classified structurally by [`CipStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneralStatus {
    /// `0x00` — success.
    Success,
    /// `0x01` — connection failure (extended status refines it).
    ConnectionFailure,
    /// `0x02` — resource unavailable.
    ResourceUnavailable,
    /// `0x03` — invalid parameter value.
    InvalidParameterValue,
    /// `0x04` — path segment error (a tag/attribute that does not exist).
    PathSegmentError,
    /// `0x05` — path destination unknown (an instance that does not exist).
    PathDestinationUnknown,
    /// `0x06` — partial transfer; more data remains (drives fragmented reads).
    PartialTransfer,
    /// `0x07` — connection lost.
    ConnectionLost,
    /// `0x08` — service not supported.
    ServiceNotSupported,
    /// `0x09` — invalid attribute value.
    InvalidAttributeValue,
    /// `0x0A` — attribute list error.
    AttributeListError,
    /// `0x0B` — already in the requested mode/state.
    AlreadyInState,
    /// `0x0C` — object state conflict.
    ObjectStateConflict,
    /// `0x0D` — object already exists.
    ObjectAlreadyExists,
    /// `0x0E` — attribute not settable.
    AttributeNotSettable,
    /// `0x0F` — privilege violation.
    PrivilegeViolation,
    /// `0x10` — device state conflict.
    DeviceStateConflict,
    /// `0x11` — reply data too large.
    ReplyDataTooLarge,
    /// `0x13` — not enough data (request too short).
    NotEnoughData,
    /// `0x14` — attribute not supported.
    AttributeNotSupported,
    /// `0x15` — too much data.
    TooMuchData,
    /// `0x1E` — embedded service error.
    EmbeddedServiceError,
    /// `0x26` — invalid path size.
    InvalidPathSize,
    /// `0xFF` — extended (vendor/Logix) error; the extended words carry the real code.
    ExtendedError,
    /// Any other code (§4 invariant 5).
    Unknown(u8),
}

impl GeneralStatus {
    /// Decode from the wire byte — total (unknown codes become [`GeneralStatus::Unknown`]).
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Success,
            0x01 => Self::ConnectionFailure,
            0x02 => Self::ResourceUnavailable,
            0x03 => Self::InvalidParameterValue,
            0x04 => Self::PathSegmentError,
            0x05 => Self::PathDestinationUnknown,
            0x06 => Self::PartialTransfer,
            0x07 => Self::ConnectionLost,
            0x08 => Self::ServiceNotSupported,
            0x09 => Self::InvalidAttributeValue,
            0x0A => Self::AttributeListError,
            0x0B => Self::AlreadyInState,
            0x0C => Self::ObjectStateConflict,
            0x0D => Self::ObjectAlreadyExists,
            0x0E => Self::AttributeNotSettable,
            0x0F => Self::PrivilegeViolation,
            0x10 => Self::DeviceStateConflict,
            0x11 => Self::ReplyDataTooLarge,
            0x13 => Self::NotEnoughData,
            0x14 => Self::AttributeNotSupported,
            0x15 => Self::TooMuchData,
            0x1E => Self::EmbeddedServiceError,
            0x26 => Self::InvalidPathSize,
            0xFF => Self::ExtendedError,
            other => Self::Unknown(other),
        }
    }

    /// The raw wire byte.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::ConnectionFailure => 0x01,
            Self::ResourceUnavailable => 0x02,
            Self::InvalidParameterValue => 0x03,
            Self::PathSegmentError => 0x04,
            Self::PathDestinationUnknown => 0x05,
            Self::PartialTransfer => 0x06,
            Self::ConnectionLost => 0x07,
            Self::ServiceNotSupported => 0x08,
            Self::InvalidAttributeValue => 0x09,
            Self::AttributeListError => 0x0A,
            Self::AlreadyInState => 0x0B,
            Self::ObjectStateConflict => 0x0C,
            Self::ObjectAlreadyExists => 0x0D,
            Self::AttributeNotSettable => 0x0E,
            Self::PrivilegeViolation => 0x0F,
            Self::DeviceStateConflict => 0x10,
            Self::ReplyDataTooLarge => 0x11,
            Self::NotEnoughData => 0x13,
            Self::AttributeNotSupported => 0x14,
            Self::TooMuchData => 0x15,
            Self::EmbeddedServiceError => 0x1E,
            Self::InvalidPathSize => 0x26,
            Self::ExtendedError => 0xFF,
            Self::Unknown(v) => v,
        }
    }

    /// A short human description (the parenthetical in the adapter's `qualityRaw` string).
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ConnectionFailure => "connection failure",
            Self::ResourceUnavailable => "resource unavailable",
            Self::InvalidParameterValue => "invalid parameter value",
            Self::PathSegmentError => "path segment error",
            Self::PathDestinationUnknown => "path destination unknown",
            Self::PartialTransfer => "partial transfer",
            Self::ConnectionLost => "connection lost",
            Self::ServiceNotSupported => "service not supported",
            Self::InvalidAttributeValue => "invalid attribute value",
            Self::AttributeListError => "attribute list error",
            Self::AlreadyInState => "already in requested state",
            Self::ObjectStateConflict => "object state conflict",
            Self::ObjectAlreadyExists => "object already exists",
            Self::AttributeNotSettable => "attribute not settable",
            Self::PrivilegeViolation => "privilege violation",
            Self::DeviceStateConflict => "device state conflict",
            Self::ReplyDataTooLarge => "reply data too large",
            Self::NotEnoughData => "not enough data",
            Self::AttributeNotSupported => "attribute not supported",
            Self::TooMuchData => "too much data",
            Self::EmbeddedServiceError => "embedded service error",
            Self::InvalidPathSize => "invalid path size",
            Self::ExtendedError => "extended error",
            Self::Unknown(_) => "unknown status",
        }
    }

    /// Whether this is the success status.
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// A CIP status: the general code plus the full extended-status word list (§6.4). The extended list
/// is kept whole; `primary_extended` is the first word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipStatus {
    /// The general status code.
    pub general: GeneralStatus,
    /// The extended-status words (kept in full; the first is the primary extended code).
    pub extended: Vec<u16>,
}

impl CipStatus {
    /// A status with no extended words.
    #[must_use]
    pub fn new(general: GeneralStatus) -> Self {
        Self {
            general,
            extended: Vec::new(),
        }
    }

    /// A status with extended words.
    #[must_use]
    pub fn with_extended(general: GeneralStatus, extended: Vec<u16>) -> Self {
        Self { general, extended }
    }

    /// The primary (first) extended-status word, if any.
    #[must_use]
    pub fn primary_extended(&self) -> Option<u16> {
        self.extended.first().copied()
    }

    /// Whether the status is success.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.general.is_ok()
    }

    /// Whether more data remains — `PartialTransfer` (drives fragmented reads, D-ENIP-12).
    #[must_use]
    pub fn has_more(&self) -> bool {
        matches!(self.general, GeneralStatus::PartialTransfer)
    }

    /// Whether this reads as "tag not found" for the adapter's browse/quality mapping.
    #[must_use]
    pub fn is_tag_not_found(&self) -> bool {
        matches!(
            self.general,
            GeneralStatus::PathSegmentError | GeneralStatus::PathDestinationUnknown
        )
    }

    /// Whether this is a routing error (Vol 1 §3-5.5): general 1 with an extended routing code, or
    /// general 2/4. When true, the ForwardOpen/Unconnected_Send failure carries a
    /// `remaining_path_size`.
    #[must_use]
    pub fn is_routing_error(&self) -> bool {
        matches!(
            (self.general, self.primary_extended()),
            (GeneralStatus::ConnectionFailure, Some(0x0204 | 0x0311 | 0x0312 | 0x0315))
                | (GeneralStatus::ResourceUnavailable | GeneralStatus::PathSegmentError, _)
        )
    }

    /// Whether this is a resource error (target busy / out of resources) — a transient class for
    /// the adapter's reconnect ladder.
    #[must_use]
    pub fn is_resource_error(&self) -> bool {
        matches!(self.general, GeneralStatus::ResourceUnavailable)
    }

    /// A description of the Logix `0xFF` extended code, when present (§6.4).
    #[must_use]
    pub fn logix_extended_detail(&self) -> Option<&'static str> {
        if !matches!(self.general, GeneralStatus::ExtendedError) {
            return None;
        }
        match self.primary_extended() {
            Some(0x2104) => Some("offset beyond end of tag"),
            Some(0x2105) => Some("element count beyond end of tag"),
            Some(0x2107) => Some("tag type mismatch"),
            _ => None,
        }
    }

    /// Whether the status is any error (non-success).
    #[must_use]
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}

impl core::fmt::Display for CipStatus {
    /// Renders `"0x04 (path segment error)"` — the adapter's `qualityRaw` string; appends the
    /// extended words when present.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "0x{:02X} ({})",
            self.general.code(),
            self.general.description()
        )?;
        if let Some(detail) = self.logix_extended_detail() {
            write!(f, ": {detail}")?;
        }
        if !self.extended.is_empty() {
            write!(f, " [ext")?;
            for w in &self.extended {
                write!(f, " 0x{w:04X}")?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_status_roundtrips_all_known_codes() {
        for code in 0u8..=0xFF {
            let g = GeneralStatus::from_code(code);
            assert_eq!(g.code(), code, "code {code:#x} did not roundtrip");
        }
    }

    #[test]
    fn unknown_code_is_total() {
        assert_eq!(GeneralStatus::from_code(0x77), GeneralStatus::Unknown(0x77));
        assert_eq!(GeneralStatus::from_code(0x77).description(), "unknown status");
    }

    #[test]
    fn classification_helpers() {
        let not_found = CipStatus::new(GeneralStatus::PathSegmentError);
        assert!(not_found.is_tag_not_found());
        assert!(not_found.is_routing_error()); // general 4 counts as routing per Vol 1

        let partial = CipStatus::new(GeneralStatus::PartialTransfer);
        assert!(partial.has_more());

        let routing = CipStatus::with_extended(GeneralStatus::ConnectionFailure, vec![0x0315]);
        assert!(routing.is_routing_error());

        let not_routing = CipStatus::with_extended(GeneralStatus::ConnectionFailure, vec![0x0100]);
        assert!(!not_routing.is_routing_error());
    }

    #[test]
    fn display_matches_quality_raw_shape() {
        let s = CipStatus::new(GeneralStatus::PathSegmentError);
        assert_eq!(s.to_string(), "0x04 (path segment error)");

        let ext = CipStatus::with_extended(GeneralStatus::ExtendedError, vec![0x2107]);
        assert_eq!(ext.to_string(), "0xFF (extended error): tag type mismatch [ext 0x2107]");
    }
}
