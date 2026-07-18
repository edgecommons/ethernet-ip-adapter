//! # The device seam: what a *protocol adapter* talks to
//!
//! [`DeviceSession`] is one live connection to one device. Implement it once per protocol — for
//! this adapter the protocol is **EtherNet/IP** (CIP explicit messaging), in `src/eip/`, and an
//! in-process [`crate::sim`] backend stands in for a PLC on a laptop. Everything above the seam
//! (the connection lifecycle, backoff, publishing, health) is written against the trait and never
//! learns the protocol.
//!
//! **The boundary rule, and it is worth enforcing in review:** a backend knows protocols. It does
//! **not** know EdgeCommons topics, the UNS, message envelopes, or metrics. If your `impl
//! DeviceSession` imports `edgecommons::uns`, the seam has leaked.
//!
//! ## Signals, not tags
//!
//! A **signal** is one data point — a measured value with identity, quality, and timestamps.
//! (A CIP controller calls it a "tag"; Modbus calls it a "register".) The word "tag" is reserved in
//! EdgeCommons for the envelope's *business metadata*, which is a different thing entirely.
//!
//! ## Quality is not optional
//!
//! Every sample carries a `quality` normalized to `GOOD | BAD | UNCERTAIN`, plus the native code
//! in `qualityRaw` for diagnosis. This is what lets a consumer gate on quality without knowing the
//! protocol — and it is why a read failure must be published as a `BAD` sample rather than
//! swallowed. A signal that silently stops updating is indistinguishable from one that is simply
//! not changing.

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::SignalSpec;

/// One reading from the device.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// The canonical, stable id the rest of the fleet keys on. For EtherNet/IP this is the CIP tag
    /// path, verbatim (e.g. `"LINE_SPEED"`, `"Program:Main.FillPV"`) — see D-EIP-9.
    pub signal_id: String,
    /// A human label (the config `name`).
    pub name: Option<String>,
    pub value: serde_json::Value,
    pub quality: Quality,
    /// The protocol-native status code, kept verbatim for diagnosis (e.g. `"0x00"`, `"0x04 path
    /// segment error"`, `"TIMEOUT"`).
    pub quality_raw: Option<String>,
}

/// Normalized quality. The protocol's own status code goes in `quality_raw`.
///
/// `Uncertain` is used for a value that decoded but whose scale/offset produced a non-finite
/// number (`NON_FINITE_AFTER_SCALE`, §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    Good,
    Bad,
    /// SLICE S3: constructed by the eip codec on a non-finite scale/offset result (§5.4).
    #[allow(dead_code)]
    Uncertain,
}

/// Why talking to the device failed — and whether reconnecting could help.
///
/// Only `Permanent` is constructed in this slice (the sim never fails transiently); `Transient` and
/// `Unsupported` are constructed by the eip backend (S3) and `browse` (S6).
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// The link is down, or the device is busy. Reconnect and retry.
    #[error("transient: {0}")]
    Transient(#[source] anyhow::Error),
    /// Misconfiguration: a bad endpoint, a rejected credential, an address that does not exist.
    /// Reconnecting will fail identically, so the supervisor backs off hard rather than hammering.
    #[error("permanent: {0}")]
    Permanent(#[source] anyhow::Error),
    /// The device/backend does not implement the operation (e.g. `browse` against a generic CIP
    /// device with no Logix tag-list service). Neither retried nor a link failure — surfaced to the
    /// caller as `BROWSE_UNSUPPORTED` (§7.3, §10.1).
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

impl DeviceError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

pub type Result<T> = std::result::Result<T, DeviceError>;

/// One page of discovered device tags (CIP Get Instance Attribute List — the Logix tag-list
/// service; §3.3, §7.5).
// SLICE S6: consumed by the `sb/browse` command handler (§7.5).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct BrowsePage {
    pub tags: Vec<BrowsedTag>,
    /// `None` => this was the last page.
    pub next_cursor: Option<String>,
}

/// One discovered tag. `array_dim` is `Some(n)` for a 1-D array tag; `type_name` is the CIP type
/// name as the device reports it (e.g. `"REAL"`, `"DINT"`, `"SSTRING"`), which the command layer
/// maps to `supported: bool` per §5.1.
// SLICE S6: consumed by the `sb/browse` command handler (§7.5).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct BrowsedTag {
    pub name: String,
    pub type_name: String,
    pub array_dim: Option<u32>,
    pub instance_id: u32,
}

/// A live connection to one device. **This is the trait a backend implements.**
#[async_trait]
pub trait DeviceSession: Send + Sync {
    /// Read the given configured signals once (a poll group's worth, or an `sb/read` subset).
    ///
    /// A read that fails for *one* signal comes back as that signal with [`Quality::Bad`] rather
    /// than failing the whole call — one dead tag must not blind you to the other ninety-nine.
    /// Return `Err` only when the *connection* is broken.
    async fn read_signals(&mut self, signals: &[SignalSpec]) -> Result<Vec<Reading>>;

    /// Write one value (already coerced/validated by the codec) to a signal. Confirmed: `Ok(())`
    /// means the device acknowledged the CIP write.
    ///
    /// # Errors
    ///
    /// If the write is rejected, or the link is down.
    async fn write_signal(&mut self, signal: &SignalSpec, value: &serde_json::Value) -> Result<()>;

    /// Enumerate device tags (CIP Get Instance Attribute List), one page.
    ///
    /// Default impl: `Err(DeviceError::Unsupported)` — the simulator implements it; generic CIP
    /// devices may not.
    ///
    /// # Errors
    ///
    /// [`DeviceError::Unsupported`] when the device has no tag-list service, or a link error.
    // SLICE S6: dispatched by the `sb/browse` command handler; the sim already implements it.
    #[allow(dead_code)]
    async fn browse(&mut self, _cursor: Option<String>, _max: usize) -> Result<BrowsePage> {
        Err(DeviceError::Unsupported(
            "this device does not implement tag discovery",
        ))
    }

    /// A minimal liveness probe (used by the paused keepalive, §7.4.3): the cheapest real round-trip
    /// the backend can do.
    ///
    /// # Errors
    ///
    /// If the link is down.
    // SLICE S6: dispatched by the paused keepalive (§7.4.3); the sim already implements it.
    #[allow(dead_code)]
    async fn probe(&mut self) -> Result<()>;

    /// Close the connection. Must be safe to call twice.
    async fn close(&mut self) {}
}

/// Opens sessions. One factory per protocol.
#[async_trait]
pub trait DeviceBackend: Send + Sync {
    /// The protocol's name, as it appears in config and in the published `device.adapter` field.
    fn kind(&self) -> &'static str;

    /// Connect to one device.
    ///
    /// # Errors
    ///
    /// If the device is unreachable ([`DeviceError::Transient`]) or the configuration is wrong
    /// ([`DeviceError::Permanent`]).
    async fn connect(&self, cfg: &ConnectionConfig) -> Result<Box<dyn DeviceSession>>;
}

/// How to reach one device. Deliberately open (`additionalProperties: true` in the schema): every
/// protocol needs different keys, and this is the one place the adapter is not strict. The typed
/// fields are the ones this adapter reads directly (§4.2); anything else rides in [`Self::extra`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfig {
    /// The endpoint: `"<host>"` or `"<host>:<port>"` (default CIP port 44818). Published in
    /// `device.endpoint`.
    pub endpoint: String,
    /// ControlLogix CPU slot ⇒ backplane connection path (`1,<slot>`). Absent ⇒ no routing path
    /// (`PortSegment::default()`) — correct for cpppo / CompactLogix-direct. A `u8` gives the
    /// 0–255 range check for free (§4.4).
    #[serde(default)]
    pub slot: Option<u8>,
    /// `true` ⇒ CIP connected messaging (ForwardOpen); `false` (default) ⇒ unconnected explicit
    /// messaging (D-EIP-8).
    #[serde(default)]
    pub connected: bool,
    /// Everything else the protocol needs. The simulator reads none of it; the EtherNet/IP backend
    /// (slice S3) may.
    // SLICE S3: the eip backend reads open connection keys (e.g. connection tuning).
    #[allow(dead_code)]
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ConnectionConfig {
    /// The `connectionMode` metric dimension / connectivity attribute (§8, §9.1).
    #[must_use]
    pub fn connection_mode(&self) -> &'static str {
        if self.connected {
            "connected"
        } else {
            "unconnected"
        }
    }
}
