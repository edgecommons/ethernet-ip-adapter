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

use std::time::Instant;

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::{IoConfig, IoFieldSpec, SignalSpec};

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

/// The security posture of a live session — the protocol-agnostic view the adapter surfaces on
/// `sb/status`, the `state` keepalive, and the metrics (DESIGN-cip-security.md §3.4). The seam stays
/// protocol-agnostic: the EtherNet/IP backend fills this from the negotiated TLS session; nothing
/// above the seam sees the `enip`/`rustls` types. A plaintext session reports `tls: false`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityStatus {
    /// `true` ⇒ the session runs over TLS (CIP Security explicit path); `false` ⇒ plaintext.
    pub tls: bool,
    /// The negotiated TLS version, e.g. `"1.3"` (`None` for plaintext / unavailable).
    pub tls_version: Option<String>,
    /// The negotiated cipher suite, e.g. `"TLS13_AES_128_GCM_SHA256"`.
    pub cipher_suite: Option<String>,
    /// Whether the peer (device) certificate was verified against the configured trust anchors — the
    /// adapter's `verifyPeer` policy (a no-verify session reports `false`).
    pub peer_verified: bool,
    /// A human peer identity — the device certificate subject when present, else the endpoint host.
    pub peer: Option<String>,
    /// The adapter's own client-certificate `notAfter`, RFC-3339 (drives Phase-2 rotation; surfaced
    /// now for operators). `None` when no client cert / not parseable.
    pub client_cert_not_after: Option<String>,
    /// The adapter's own client-certificate serial number, hex (Phase 2b — surfaced so an operator
    /// can correlate a rotation against the issuing CA's records). `None` when no client cert.
    pub client_cert_serial: Option<String>,
    /// Whole days until the adapter's client certificate expires (Phase 2b cert-expiry monitoring,
    /// DESIGN-cip-security.md §4.2). Negative ⇒ already expired. `None` when no client cert / not
    /// parseable.
    pub client_cert_expiry_days: Option<i64>,
    /// A summary of the managed trust store the session verified the device against (Phase 2b,
    /// DESIGN-cip-security.md §4.2): one entry per trust anchor (CA root) sourced from the vault or
    /// files, including any old+new roots live during a CA-rollover grace window. Empty for a
    /// no-verify session.
    pub trust_anchors: Vec<TrustAnchorSummary>,
    /// The **target's** decoded CIP Security posture (Phase 2a, DESIGN-cip-security.md §4.1), read
    /// once per connect. `None` when the device implements none of the 0x5D/0x5E/0x5F objects (a
    /// generic CIP device) — surfaced as `targetSupportsCipSecurity: false`, never an error.
    pub target: Option<TargetSecurityPosture>,
}

/// One trust anchor (CA root certificate) in the adapter's managed trust store (Phase 2b,
/// DESIGN-cip-security.md §4.2) — the protocol-agnostic view surfaced on `sb/status.security.trustStore`.
/// Multiple anchors are normal: a plant trust domain may carry several roots, and a CA rollover keeps
/// the old and new roots both live during the vault's version-grace window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchorSummary {
    /// The CA certificate subject (e.g. `CN=Plant Root CA`).
    pub subject: Option<String>,
    /// The CA certificate's `notAfter`, RFC-3339.
    pub not_after: Option<String>,
}

/// The **target device's** decoded CIP Security posture (Phase 2a, DESIGN-cip-security.md §4.1) — the
/// protocol-agnostic view the adapter surfaces on `sb/status.security.target`. The EtherNet/IP backend
/// fills it from the target's CIP Security (0x5D), EtherNet/IP Security (0x5E), and Certificate
/// Management (0x5F) objects; nothing above the seam sees the `enip`/`rustls` types. Read best-effort
/// on connect: a device that does not implement these objects yields no posture (`None` at the
/// `SecurityStatus.target` level), not an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSecurityPosture {
    /// The CIP Security Object state (e.g. `"Configured"`, `"Factory Default"`).
    pub state: Option<String>,
    /// The security profiles the device supports (named bits, e.g. `"EtherNet/IP Confidentiality"`).
    pub profiles: Vec<String>,
    /// The cipher suites the device will negotiate (IANA names, or `0xXXXX` when unrecognized).
    pub allowed_cipher_suites: Vec<String>,
    /// The cipher suites the device offers.
    pub available_cipher_suites: Vec<String>,
    /// Whether the device requires a client certificate (mutual-TLS enforcement, 0x5E attr 9).
    pub verify_client: Option<bool>,
    /// Whether the device sends its certificate chain (0x5E attr 10).
    pub send_certificate_chain: Option<bool>,
    /// Whether the device checks certificate expiration (0x5E attr 11).
    pub check_expiration: Option<bool>,
    /// The device certificate summary (push/pull capability + primary certificate instance).
    pub certificate: Option<TargetCertificateSummary>,
}

/// A summary of the target's Certificate Management Object (0x5F) — the provisioning model it supports
/// and its primary certificate instance's identity/state/encoding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetCertificateSummary {
    /// Whether the device supports the push provisioning model (config tool writes certs).
    pub push_supported: Option<bool>,
    /// Whether the device supports the pull provisioning model (device enrolls via EST).
    pub pull_supported: Option<bool>,
    /// The primary certificate instance name.
    pub name: Option<String>,
    /// The primary certificate instance state (e.g. `"Verified"`).
    pub state: Option<String>,
    /// The primary certificate encoding (e.g. `"PEM"`).
    pub encoding: Option<String>,
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

    /// The session's security posture (DESIGN-cip-security.md §3.4). Default: `None` (the backend has
    /// no security surface — e.g. the simulator). The EtherNet/IP backend returns the negotiated TLS
    /// facts for a `mode: tls` connection, or a plaintext marker otherwise.
    fn security(&self) -> Option<SecurityStatus> {
        None
    }

    /// Close the connection. Must be safe to call twice.
    async fn close(&mut self) {}
}

/// Opens sessions. One factory per protocol.
#[async_trait]
pub trait DeviceBackend: Send + Sync {
    /// The protocol's name, as it appears in config and in the published `device.adapter` field.
    fn kind(&self) -> &'static str;

    /// Connect to one device for **poll** mode (explicit messaging). Push instances never call this.
    ///
    /// # Errors
    ///
    /// If the device is unreachable ([`DeviceError::Transient`]) or the configuration is wrong
    /// ([`DeviceError::Permanent`]).
    async fn connect(&self, cfg: &ConnectionConfig) -> Result<Box<dyn DeviceSession>>;

    /// Open a **push** (class-1 implicit I/O) session against the device: ForwardOpen the connection
    /// from the `io` block and start consuming the input assembly at the RPI (§3.3, §4.6). Poll
    /// instances never call this; a backend that does not implement push returns
    /// [`DeviceError::Unsupported`] (the default).
    ///
    /// # Errors
    ///
    /// [`DeviceError::Transient`] if the device is unreachable / the ForwardOpen is refused for a
    /// transient reason; [`DeviceError::Permanent`] for a misconfiguration; [`DeviceError::Unsupported`]
    /// if the backend has no push implementation.
    async fn open_push(
        &self,
        _conn: &ConnectionConfig,
        _io: &IoConfig,
    ) -> Result<Box<dyn PushSession>> {
        Err(DeviceError::Unsupported(
            "this backend does not implement push (class-1 I/O) mode",
        ))
    }
}

/// One event on a **push** session's stream (§3.3) — the push analog of a poll `read_signals` result.
///
/// The seam speaks [`Reading`]s and connection lifecycle transitions, **never** the UNS (the boundary
/// rule): the backend has already decoded the input assembly's byte-offset fields into signals per §5,
/// applied scale/offset, and mapped quality (fresh frame ⇒ GOOD; Idle run/idle bit ⇒ UNCERTAIN;
/// non-finite scale ⇒ UNCERTAIN). The engine above the seam publishes them without seeing the `enip`
/// crate.
#[derive(Debug)]
pub enum IoUpdate {
    /// The class-1 connection came up on the first accepted frame; the negotiated actual packet
    /// intervals (milliseconds), from the ForwardOpen reply.
    Up {
        /// Actual O→T packet interval, ms.
        o2t_api_ms: u32,
        /// Actual T→O packet interval, ms.
        t2o_api_ms: u32,
    },
    /// One accepted input-assembly frame, decoded to one [`Reading`] per configured input field (§5).
    Data {
        /// One reading per input field, in declaration order.
        readings: Vec<Reading>,
        /// The class-1 sequence count of the frame.
        sequence: u16,
        /// Run (`true`) / Idle (`false`) from the frame's run/idle header (Idle ⇒ UNCERTAIN, §5.4).
        run_mode: bool,
        /// When the frame was accepted (monotonic) — the push `serverTs` (§5.4).
        // SLICE S4: consumed by the push publish engine as the sample's `serverTs`.
        #[allow(dead_code)]
        received_at: Instant,
    },
    /// The connection was lost (class-1 watchdog timeout / peer close / socket error). The push
    /// engine leaves its loop and reconnects (§10.1). Terminal.
    Lost {
        /// Why the link ended — always a [`DeviceError::Transient`] (§10.1 row 7).
        error: DeviceError,
    },
}

/// The most-recent decoded input frame — the source push `sb/read` answers from (§7.2, §7.3). Held
/// by the [`PushSession`] and returned by [`PushSession::last_input`]; because class-1 consumption
/// keeps running while an instance is paused (§7.4), the snapshot stays live and an on-demand read
/// works even while paused. There is no per-field device round-trip in implicit I/O — the last frame
/// *is* the read.
#[derive(Debug, Clone)]
pub struct InputSnapshot {
    /// One [`Reading`] per configured input field, from the last accepted frame (§5).
    pub readings: Vec<Reading>,
    /// When the frame was accepted (monotonic) — the push `serverTs` (§5.4/§7.2).
    pub received_at: Instant,
    /// Run (`true`) / Idle (`false`) from the frame's run/idle header. The per-reading quality already
    /// carries this (Idle ⇒ UNCERTAIN, §5.4); kept on the snapshot for diagnostics.
    #[allow(dead_code)]
    pub run_mode: bool,
}

/// A snapshot of the class-1 connection's live drop/produce counters (§8.8), surfaced from the
/// protocol stack's per-connection counters through the seam so the adapter's `EtherNetIpIo` measures
/// read REAL values, not 0 (the S5-flagged gap). The seam stays protocol-agnostic: the backend maps
/// `enip::IoStats` into this struct; nothing above the seam sees the `enip` crate. All fields are
/// **cumulative since the current ForwardOpen** (they reset when a lost link re-establishes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoLinkStats {
    /// O→T frames produced onto the wire (data or heartbeat) — `framesProduced` (§8.8).
    pub frames_produced: u64,
    /// T→O frames dropped as duplicate / stale / reordered by the signed-window rule —
    /// `staleFramesDropped` (§8.8).
    pub stale_frames: u64,
    /// T→O frames dropped for a size mismatch (or a runt frame) — `sizeMismatchDropped` (§8.8).
    pub size_mismatch: u64,
    /// Sum of forward sequence gaps observed (missed frames) — `sequenceGaps` (§8.8).
    pub sequence_gaps: u64,
    /// Datagrams dropped as malformed CPF (socket-wide) — `malformedFrames` (§8.8).
    pub malformed_frames: u64,
    /// Produce ticks skipped because a prior tick had not been serviced — `produceOverruns` (§8.8).
    pub produce_overruns: u64,
}

/// A live **push** (class-1 implicit I/O) session to one device. **This is the trait a push backend
/// implements** (§3.3). The engine owns the update receiver; the session owns translation from the
/// transport into seam types.
#[async_trait]
pub trait PushSession: Send + Sync {
    /// The consumed-I/O stream: decoded field updates + connection lifecycle. The engine drives this
    /// receiver; a `None` means the session's translator task ended (treat as a lost link).
    fn updates(&mut self) -> &mut tokio::sync::mpsc::Receiver<IoUpdate>;

    /// The most-recent decoded input frame (§7.2), or `None` until the first frame arrives / while the
    /// connection is down. Answered even while paused — the source for push `sb/read`. Cheap: it clones
    /// a held snapshot, it does not touch the wire.
    // SLICE S6: dispatched by the `sb/read` command handler for push instances.
    fn last_input(&self) -> Option<InputSnapshot>;

    /// Set one output-assembly field (already coerced/validated by the codec) into the producer
    /// buffer; it rides the next O→T frame. `Ok(())` means the field is staged (§7.3 honesty note).
    /// The full write path drives this in slice S6; it is exposed now.
    ///
    /// # Errors
    ///
    /// [`DeviceError::Unsupported`] when the device has no output assembly; [`DeviceError::Permanent`]
    /// when the value does not fit the field (a coercion/range error).
    // SLICE S6: dispatched by the `sb/write` command handler for push instances.
    #[allow(dead_code)]
    async fn set_output(&mut self, field: &IoFieldSpec, value: &serde_json::Value) -> Result<()>;

    /// A snapshot of the class-1 connection's live drop/produce counters (§8.8), or `None` for a
    /// backend that has no class-1 counters (e.g. the simulator). Cheap: reads shared atomics, no
    /// wire I/O. The push engine reads it each metrics interval so `EtherNetIpIo`'s `framesProduced` /
    /// `staleFramesDropped` / `sizeMismatchDropped` / `malformedFrames` / `produceOverruns` reflect
    /// the real stack counters (the S5-flagged gap).
    fn io_stats(&self) -> Option<IoLinkStats> {
        None
    }

    /// Close the connection (ForwardClose + socket teardown). Must be safe to call twice.
    async fn close(&mut self);
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
