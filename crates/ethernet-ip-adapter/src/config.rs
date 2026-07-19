//! # Typed component configuration (`component.*`)
//!
//! The adapter's config lives entirely under `component.*` (the canonical-schema convention,
//! `SOUTHBOUND.md` §4 — no top-level block, no schema sync). This module parses and validates it:
//! [`GlobalConfig`] (`component.global`) and [`DeviceConfig`] (each `component.instances[]` entry),
//! down through [`PollGroup`] and [`SignalSpec`] for **poll** mode, and [`IoConfig`] with its
//! assembly-field [`IoFieldSpec`] layout for **push** mode (`mode: "push"`, §4.6).
//!
//! A device is either **poll** (scheduled explicit-messaging reads of CIP tags, the default) or
//! **push** (class-1 implicit I/O — the device produces an assembly at the RPI and we map its
//! byte-offset fields to signals). The two are mutually exclusive per instance: a poll device
//! carries `pollGroups[]` and no `io`; a push device carries `io` and no `pollGroups[]`. The push
//! layout is turned into a validated [`enip::AssemblyLayout`] at parse time, so a field that does
//! not fit its assembly is a startup error, not a runtime surprise (D-EIP-18).
//!
//! Two rules run through everything here:
//!
//! * **Strict except `connection`.** Every struct is `#[serde(deny_unknown_fields)]` so a typo'd
//!   key is a fail-fast error, never a silent no-op — except [`crate::device::ConnectionConfig`],
//!   which is deliberately open (every protocol needs different keys).
//! * **Precedence.** An effective value resolves **signal ▸ poll group ▸ device `defaults` ▸
//!   `global.defaults` ▸ built-in** (§4.4). Each field is settable only at the levels §4 lists;
//!   [`DeviceConfig::effective_poll_ms`] and friends walk the chain and stop at the first set level.

use serde::Deserialize;
use serde_json::Value;

// ---- built-in defaults (the last rung of the precedence ladder, §4.1) ----
const BUILTIN_POLL_MS: u64 = 5_000;
// SLICE S4: the built-in fall-through for publishMode/batchMs, used by the poll engine's resolution.
#[allow(dead_code)]
const BUILTIN_PUBLISH_MODE: PublishMode = PublishMode::OnChange;
#[allow(dead_code)]
const BUILTIN_BATCH_MS: u64 = 0;

// ===================================================================================
// component.global (§4.1)
// ===================================================================================

/// `component.global`: fleet-wide defaults, timeouts, health thresholds, and the metrics cadence.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalConfig {
    /// Defaults applied to any device/group that does not override them.
    #[serde(default)]
    pub defaults: Defaults,
    /// Connection lifecycle timings.
    #[serde(default)]
    pub timeouts: Timeouts,
    /// Thresholds feeding the `southbound_health` metric.
    // SLICE S4/S6: consumed by the poll engine (staleness) and the paused keepalive.
    #[allow(dead_code)]
    #[serde(default)]
    pub health_thresholds: HealthThresholds,
    /// Operational-metrics emit cadence, seconds (§8.7). Consumed by the metrics emitter (slice S5).
    #[allow(dead_code)]
    #[serde(default = "d_metrics_interval_secs")]
    pub metrics_interval_secs: u64,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        // Consistent with the serde field defaults, so `GlobalConfig::default()` and parsing an
        // empty `{}` agree.
        Self {
            defaults: Defaults::default(),
            timeouts: Timeouts::default(),
            health_thresholds: HealthThresholds::default(),
            metrics_interval_secs: d_metrics_interval_secs(),
        }
    }
}

/// The publish/poll defaults, as *overridable* options (`None` ⇒ fall to the next precedence
/// level). The same struct models `global.defaults` and a device's `defaults` override.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Defaults {
    /// Poll cadence, ms.
    pub poll_interval_ms: Option<u64>,
    /// `onChange` (deadband-gated) vs `always` (every polled sample). Resolved by the poll engine (S4).
    #[allow(dead_code)]
    pub publish_mode: Option<PublishMode>,
    /// Coalescing window, ms (`0` = publish per poll cycle). Resolved by the poll engine (S4).
    #[allow(dead_code)]
    pub batch_ms: Option<u64>,
}

/// Connection lifecycle timings (§4.1). Concrete values with built-in defaults.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timeouts {
    /// Connect (incl. host lookup + RegisterSession) deadline, ms.
    #[serde(default = "d_connect_ms")]
    pub connect_ms: u64,
    /// Per-CIP-request deadline (read/write/browse), ms. Consumed by the EtherNet/IP backend (S3).
    #[allow(dead_code)]
    #[serde(default = "d_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// First reconnect window, ms.
    #[serde(default = "d_backoff_min_ms")]
    pub reconnect_backoff_min_ms: u64,
    /// Backoff ceiling, ms (jittered within the window).
    #[serde(default = "d_backoff_max_ms")]
    pub reconnect_backoff_max_ms: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect_ms: d_connect_ms(),
            request_timeout_ms: d_request_timeout_ms(),
            reconnect_backoff_min_ms: d_backoff_min_ms(),
            reconnect_backoff_max_ms: d_backoff_max_ms(),
        }
    }
}

/// Thresholds feeding `southbound_health` (§4.1). Consumed by the poll engine (S4) and the paused
/// keepalive (S6).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthThresholds {
    /// A signal with no GOOD read for longer than this counts as stale. Consumed by the poll engine (S4).
    #[allow(dead_code)]
    #[serde(default = "d_stale_secs")]
    pub stale_signal_secs: u64,
    /// Paused-state liveness probe cadence, ms (D-EIP-14). Consumed by the paused keepalive (S6).
    #[allow(dead_code)]
    #[serde(default = "d_keepalive_ms")]
    pub keepalive_probe_interval_ms: u64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            stale_signal_secs: d_stale_secs(),
            keepalive_probe_interval_ms: d_keepalive_ms(),
        }
    }
}

/// How samples that pass the read are published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublishMode {
    /// Publish only samples that pass the deadband/change gate.
    OnChange,
    /// Publish every polled sample.
    Always,
}

impl PublishMode {
    /// The `publishMode` metric dimension token (§8). Consumed by the metrics emitter (S5).
    #[allow(dead_code)]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PublishMode::OnChange => "onChange",
            PublishMode::Always => "always",
        }
    }
}

// ===================================================================================
// component.instances[] — one device (§4.2)
// ===================================================================================

/// One device == one entry of `component.instances[]`, with its own task, session, and connection
/// lifecycle.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceConfig {
    /// The `{instance}` UNS token + metric `instance` dimension. Stable, lower-kebab.
    pub id: String,
    /// Backend selector ([`crate::device::DeviceBackend::kind`]); `"sim"` selects the in-process
    /// simulator. Published as `device.adapter`.
    #[serde(default = "default_adapter")]
    pub adapter: String,
    /// The instance's update model (§4.2, D-EIP-2). `poll` (default) requires `pollGroups[]` and no
    /// `io`; `push` requires `io` and no `pollGroups[]` — enforced in [`Self::validate`].
    #[serde(default)]
    pub mode: DeviceMode,
    /// How to reach the device (the one deliberately open object).
    pub connection: crate::device::ConnectionConfig,
    /// Per-device overrides of the `global.defaults`.
    #[serde(default)]
    pub defaults: Defaults,
    /// The poll groups (poll mode: required, min 1; push mode: must be absent — enforced in
    /// [`Self::validate`]). Defaulted to empty so a push device may omit it entirely.
    #[serde(default)]
    pub poll_groups: Vec<PollGroup>,
    /// The class-1 I/O connection + assembly layout (push mode: required; poll mode: must be absent
    /// — enforced in [`Self::validate`]). See [`IoConfig`] (§4.6).
    #[serde(default)]
    pub io: Option<IoConfig>,
    /// Writes are **allow-listed by stable `signal.id`** — a tag path (poll) or an `a<inst>/<offset>/<type>`
    /// field id (push). An empty list means this device is read-only, which is the correct default
    /// for anything touching a control system.
    #[serde(default)]
    pub writes: Writes,
}

/// The instance update model (§4.2, D-EIP-2). Mutually exclusive: `poll` reads CIP tags on a
/// schedule; `push` consumes a class-1 implicit-I/O assembly the device produces at the RPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    /// Scheduled explicit-messaging polling (the default). Requires `pollGroups[]`.
    #[default]
    Poll,
    /// Class-1 implicit I/O. Requires the `io` block (§4.6).
    Push,
}

impl DeviceMode {
    /// The token as it appears in config / diagnostics — and the metric `mode` dimension (S5).
    // SLICE S3/S5: consumed by the push engine + metrics dimension.
    #[allow(dead_code)]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceMode::Poll => "poll",
            DeviceMode::Push => "push",
        }
    }
}

/// A poll group: a set of signals read together on one cadence (§4.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollGroup {
    /// The `pollGroup` metric dimension. Defaults to `group-<n>` (1-based) when absent — assigned by
    /// [`DeviceConfig::validate`].
    #[serde(default)]
    pub id: Option<String>,
    /// This group's cadence; falls to device ▸ global ▸ built-in.
    pub poll_interval_ms: Option<u64>,
    /// This group's publish gate; falls to device ▸ global ▸ built-in. Resolved by the poll engine (S4).
    #[allow(dead_code)]
    pub publish_mode: Option<PublishMode>,
    /// The signals in this group (required, min 1).
    pub signals: Vec<SignalSpec>,
}

/// One signal: a CIP tag mapped to an EdgeCommons data point (§4.4).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignalSpec {
    /// Human label AND the `data` topic channel (§6.1). Lower-kebab, unique per device.
    pub name: String,
    /// The CIP tag path, verbatim/case-sensitive. It IS the stable `signal.id` (D-EIP-9). Unique
    /// per device.
    pub tag_path: String,
    /// The CIP elementary type. `string`/UDT/multi-dim have no variant ⇒ a parse error rejects them
    /// (D-EIP-16).
    #[serde(rename = "type")]
    pub eip_type: EipType,
    /// Present ⇒ a 1-D array read of that many elements; the value is a JSON array. Consumed by the
    /// codec (S3).
    pub array_count: Option<u32>,
    /// Published value = `raw * scale + offset` (numeric only). Consumed by the codec (S3).
    pub scale: Option<f64>,
    /// See `scale`. Consumed by the codec (S3).
    pub offset: Option<f64>,
    /// The change/deadband gate for `onChange` publishing (§4.4). Consumed by the poll engine (S4).
    #[serde(default)]
    pub deadband: DeadbandSpec,
}

impl SignalSpec {
    /// The protocol-native `signal.address` object (§5.2): everything needed to re-address the tag
    /// — path + decode type, plus `arrayCount`/`slot` only when configured.
    #[must_use]
    pub fn address_json(&self, conn: &crate::device::ConnectionConfig) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("tagPath".to_string(), Value::String(self.tag_path.clone()));
        m.insert(
            "type".to_string(),
            Value::String(self.eip_type.wire().to_string()),
        );
        if let Some(n) = self.array_count {
            m.insert("arrayCount".to_string(), Value::from(n));
        }
        if let Some(slot) = conn.slot {
            m.insert("slot".to_string(), Value::from(slot));
        }
        Value::Object(m)
    }

    /// Whether scale/offset/deadband arithmetic applies — false for `bool` (§4.4).
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        self.eip_type != EipType::Bool
    }
}

/// The CIP elementary types this adapter decodes (§5.1). `string`/UDT/multi-dim arrays are
/// deliberately absent — their omission is exactly what rejects them at config-parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EipType {
    Bool,
    Sint,
    Usint,
    Int,
    Uint,
    Dint,
    Udint,
    Lint,
    Ulint,
    Real,
    Lreal,
}

impl EipType {
    /// The wire/address token (matches the config spelling), e.g. `"real"`, `"dint"`.
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            EipType::Bool => "bool",
            EipType::Sint => "sint",
            EipType::Usint => "usint",
            EipType::Int => "int",
            EipType::Uint => "uint",
            EipType::Dint => "dint",
            EipType::Udint => "udint",
            EipType::Lint => "lint",
            EipType::Ulint => "ulint",
            EipType::Real => "real",
            EipType::Lreal => "lreal",
        }
    }

    /// The corresponding [`enip::CipType`] the protocol crate decodes/encodes (§5.1). Every adapter
    /// type is a CIP elementary scalar, so the mapping is total — this is what lets a push field
    /// become an [`enip::FieldSpec`] and lets a poll read decode with the right wire type.
    #[must_use]
    pub fn cip_type(self) -> enip::CipType {
        match self {
            EipType::Bool => enip::CipType::Bool,
            EipType::Sint => enip::CipType::Sint,
            EipType::Usint => enip::CipType::Usint,
            EipType::Int => enip::CipType::Int,
            EipType::Uint => enip::CipType::Uint,
            EipType::Dint => enip::CipType::Dint,
            EipType::Udint => enip::CipType::Udint,
            EipType::Lint => enip::CipType::Lint,
            EipType::Ulint => enip::CipType::Ulint,
            EipType::Real => enip::CipType::Real,
            EipType::Lreal => enip::CipType::Lreal,
        }
    }
}

/// The deadband gate for a signal (§4.4). Modbus-identical semantics.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct DeadbandSpec {
    /// `none` (any change republishes) / `absolute` (`|new−old| ≥ value`) / `percent` (relative).
    #[serde(rename = "type")]
    pub kind: DeadbandKind,
    /// The threshold (≥ 0).
    pub value: f64,
}

impl Default for DeadbandSpec {
    fn default() -> Self {
        Self {
            kind: DeadbandKind::None,
            value: 0.0,
        }
    }
}

/// The deadband comparison kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeadbandKind {
    /// Any change republishes.
    #[default]
    None,
    /// Absolute delta threshold.
    Absolute,
    /// Relative-to-previous threshold.
    Percent,
}

/// The write allow-list.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Writes {
    /// Stable `signal.id`s (= tag paths) this device may write. Empty = read-only (the default).
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Writes {
    /// Whether the given stable `signal.id` (tag path or push field id) is writable.
    #[must_use]
    pub fn permits(&self, signal_id: &str) -> bool {
        self.allow.iter().any(|s| s == signal_id)
    }
}

// ===================================================================================
// Push mode — the `io` block (§4.6, D-EIP-18)
// ===================================================================================

/// The class-1 implicit-I/O connection + assembly layout for a `mode: "push"` device (§4.6). The
/// device produces its input (T→O) assembly at the RPI; we consume it, extract the configured
/// byte-offset [`IoFieldSpec`] fields, and publish them as signals. The optional output (O→T)
/// assembly carries values we produce toward the device (writable via `sb/write` when allow-listed).
///
/// The field layouts are validated into [`enip::AssemblyLayout`]s at parse time
/// ([`Self::input_layout`] / [`Self::output_layout`]), so a field that overruns its assembly is a
/// startup error.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoConfig {
    /// Requested T→O RPI (the device's produce cadence toward us), ms. The negotiated API from the
    /// ForwardOpen reply is what actually runs. Consumed by the class-1 engine (S3).
    pub rpi_ms: u64,
    /// Requested O→T RPI (our produce cadence toward the device), ms. Defaults to `rpiMs`.
    pub o2t_rpi_ms: Option<u64>,
    /// T→O connection type. `multicast` consume joins the group from the ForwardOpen reply; O→T is
    /// always P2P. Consumed by the class-1 ForwardOpen (S3).
    // SLICE S3: read by the class-1 engine when it builds the ForwardOpen.
    #[allow(dead_code)]
    #[serde(default)]
    pub connection_type: IoConnType,
    /// CIP connection priority, both directions. Consumed by the class-1 ForwardOpen (S3).
    // SLICE S3: read by the class-1 engine when it builds the ForwardOpen.
    #[allow(dead_code)]
    #[serde(default)]
    pub priority: IoPriority,
    /// Inactivity-watchdog multiplier — one of 4, 8, 16, 32, 64, 128, 256, 512 (validated). The
    /// watchdog is `multiplier × T→O API`.
    #[serde(default = "d_timeout_multiplier")]
    pub timeout_multiplier: u32,
    /// The assembly instance ids that anchor the connection path + the field-id scheme.
    pub assemblies: IoAssemblies,
    /// The T→O (input) direction — the device's data to us. Required.
    pub input: IoInput,
    /// The O→T (output) direction — our data to the device. Absent ⇒ a heartbeat O→T connection
    /// (no output data).
    #[serde(default)]
    pub output: Option<IoOutput>,
}

/// The assembly instances (§4.6). `output`/`input` are the O→T / T→O connection points; `config` is
/// included in the connection path when present (most targets require it).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoAssemblies {
    /// Config assembly instance (connection path only; no data plane). Optional. Consumed by the
    /// class-1 connection path (S3).
    // SLICE S3: added to the ForwardOpen connection path when present.
    #[allow(dead_code)]
    pub config: Option<u16>,
    /// O→T assembly instance (our outputs; the O→T connection point). Required.
    pub output: u16,
    /// T→O assembly instance (the device's inputs to us; the T→O connection point). Required.
    pub input: u16,
}

/// The T→O (input) direction: the size + framing of the assembly the device produces, plus its
/// field layout (§4.6).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoInput {
    /// Negotiated T→O data size in bytes (excl. sequence/header — the crate adds those per format).
    pub size_bytes: usize,
    /// T→O framing. Conventional targets produce `modeless`; `header32` carries a run/idle header.
    #[serde(default = "d_input_rt_format")]
    pub real_time_format: RealTimeFormat,
    /// Publish-eligibility floor per field, ms: at most one sample per field per window (0 = every
    /// accepted frame is eligible). The anti-flood gate for fast RPIs. Consumed by the push engine (S3).
    // SLICE S3: the per-field publish-eligibility gate.
    #[allow(dead_code)]
    #[serde(default)]
    pub sample_ms: u64,
    /// The input-assembly field layout (required, min 1). See [`IoFieldSpec`].
    pub signals: Vec<IoFieldSpec>,
}

/// The O→T (output) direction: what we produce toward the device (§4.6). `sizeBytes == 0` is a
/// heartbeat connection (no output data; `signals` must be absent).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoOutput {
    /// O→T data size in bytes. `0` ⇒ heartbeat connection.
    #[serde(default)]
    pub size_bytes: usize,
    /// O→T framing; `header32` carries the run/idle bit. Consumed by the produce scheduler (S3).
    // SLICE S3: selects the O→T frame format the produce scheduler emits.
    #[allow(dead_code)]
    #[serde(default = "d_output_rt_format")]
    pub real_time_format: RealTimeFormat,
    /// Initial run/idle state produced in the 32-bit header. Consumed by the produce scheduler (S3).
    // SLICE S3: the initial run/idle bit.
    #[allow(dead_code)]
    #[serde(default = "d_true")]
    pub run: bool,
    /// Output-assembly fields (writable via `sb/write` when allow-listed). Absent ⇒ no output data.
    #[serde(default)]
    pub signals: Vec<IoFieldSpec>,
}

/// One assembly-layout field — the push analog of [`SignalSpec`] (§4.6, D-EIP-18). The stable
/// `signal.id` is `a<assemblyInstance>/<offset>/<type>[.<bit>]`; `name` is the `data` topic channel
/// and friendly label. The byte `offset` names the position within the assembly data; the
/// value-transform additive term is spelled `valueOffset` here to avoid colliding with it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IoFieldSpec {
    /// Human label AND the `data` topic channel (§6.1). Lower-kebab, unique per device.
    pub name: String,
    /// Byte offset within the assembly data (≥ 0).
    pub offset: usize,
    /// The CIP elementary type of each element (§5.1). `string`/UDT/multi-dim have no variant ⇒ a
    /// parse error rejects them (D-EIP-16).
    #[serde(rename = "type")]
    pub eip_type: EipType,
    /// Bit extraction (0–7) within the byte at `offset` — `bool` only, single element.
    pub bit: Option<u8>,
    /// Present ⇒ a contiguous array of that many elements; the value is a JSON array.
    pub array_count: Option<u32>,
    /// Published value = `raw * scale + valueOffset` (numeric only). Consumed by the codec (S3).
    pub scale: Option<f64>,
    /// The additive term of the value transform (see `scale`). Named `valueOffset` to avoid
    /// colliding with the byte `offset`. Consumed by the codec (S3).
    pub value_offset: Option<f64>,
    /// The change/deadband gate (input side only; numeric types). Absent ⇒ default (any change).
    pub deadband: Option<DeadbandSpec>,
}

/// T→O connection type (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IoConnType {
    /// Point-to-point (the default).
    #[default]
    P2p,
    /// Multicast — the consume joins the group from the ForwardOpen reply's sockaddr item.
    Multicast,
}

impl IoConnType {
    /// The corresponding [`enip::ConnType`] the Connection Manager encodes (consumed by S3).
    // SLICE S3: the class-1 ForwardOpen maps the config type to the wire enum.
    #[allow(dead_code)]
    #[must_use]
    pub fn to_enip(self) -> enip::ConnType {
        match self {
            IoConnType::P2p => enip::ConnType::P2P,
            IoConnType::Multicast => enip::ConnType::Multicast,
        }
    }
}

/// CIP connection priority (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IoPriority {
    /// Low.
    Low,
    /// High.
    High,
    /// Scheduled (the default).
    #[default]
    Scheduled,
    /// Urgent.
    Urgent,
}

impl IoPriority {
    /// The corresponding [`enip::Priority`] (consumed by S3).
    // SLICE S3: the class-1 ForwardOpen maps the config priority to the wire enum.
    #[allow(dead_code)]
    #[must_use]
    pub fn to_enip(self) -> enip::Priority {
        match self {
            IoPriority::Low => enip::Priority::Low,
            IoPriority::High => enip::Priority::High,
            IoPriority::Scheduled => enip::Priority::Scheduled,
            IoPriority::Urgent => enip::Priority::Urgent,
        }
    }
}

/// Class-1 real-time framing (§4.6, PROTOCOL-DESIGN §8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RealTimeFormat {
    /// Sequence count then application data, no run/idle header.
    Modeless,
    /// Sequence count, a 32-bit run/idle header, then application data.
    Header32,
    /// Sequence count only — the O→T heartbeat used when a direction carries no data.
    Heartbeat,
}

impl RealTimeFormat {
    /// The corresponding [`enip::RealTimeFormat`] (consumed by S3).
    // SLICE S3: the class-1 frame codec maps the config format to the wire enum.
    #[allow(dead_code)]
    #[must_use]
    pub fn to_enip(self) -> enip::RealTimeFormat {
        match self {
            RealTimeFormat::Modeless => enip::RealTimeFormat::Modeless,
            RealTimeFormat::Header32 => enip::RealTimeFormat::Header32Bit,
            RealTimeFormat::Heartbeat => enip::RealTimeFormat::Heartbeat,
        }
    }
}

impl IoFieldSpec {
    /// The stable push `signal.id`: `a<assemblyInstance>/<offset>/<type>[.<bit>]` (D-EIP-18).
    #[must_use]
    pub fn signal_id(&self, assembly: u16) -> String {
        match self.bit {
            Some(bit) => format!("a{assembly}/{}/{}.{bit}", self.offset, self.eip_type.wire()),
            None => format!("a{assembly}/{}/{}", self.offset, self.eip_type.wire()),
        }
    }

    /// The protocol-native `signal.address` object (§5.2): assembly instance + byte offset + type,
    /// plus `bit`/`arrayCount`/`slot` only when configured. Consumed by the publish path (S3).
    // SLICE S3: stamped into `signal.address` of each push SouthboundSignalUpdate.
    #[allow(dead_code)]
    #[must_use]
    pub fn address_json(&self, assembly: u16, conn: &crate::device::ConnectionConfig) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("assembly".to_string(), Value::from(assembly));
        m.insert("offset".to_string(), Value::from(self.offset));
        m.insert(
            "type".to_string(),
            Value::String(self.eip_type.wire().to_string()),
        );
        if let Some(bit) = self.bit {
            m.insert("bit".to_string(), Value::from(bit));
        }
        if let Some(n) = self.array_count {
            m.insert("arrayCount".to_string(), Value::from(n));
        }
        if let Some(slot) = conn.slot {
            m.insert("slot".to_string(), Value::from(slot));
        }
        Value::Object(m)
    }

    /// Whether scale/valueOffset/deadband arithmetic applies — false for `bool` (§4.6, §4.4).
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        self.eip_type != EipType::Bool
    }

    /// This field as an [`enip::FieldSpec`] with the given `key` (its declaration index). The crate
    /// validates the whole set against the assembly size in [`enip::AssemblyLayout::new`].
    #[must_use]
    fn to_enip_field(&self, key: usize) -> enip::FieldSpec {
        enip::FieldSpec {
            key,
            offset: self.offset,
            ty: self.eip_type.cip_type(),
            bit: self.bit,
            count: self.array_count.map_or(1, |n| n as usize),
        }
    }
}

impl IoConfig {
    /// The negotiated inactivity-watchdog multiplier as the typed [`enip::TimeoutMultiplier`], or an
    /// error if the configured value is not one of the eight CIP-legal multipliers (§4.6).
    ///
    /// # Errors
    ///
    /// [`String`] naming the illegal multiplier.
    pub fn timeout_multiplier_enip(&self) -> std::result::Result<enip::TimeoutMultiplier, String> {
        Ok(match self.timeout_multiplier {
            4 => enip::TimeoutMultiplier::X4,
            8 => enip::TimeoutMultiplier::X8,
            16 => enip::TimeoutMultiplier::X16,
            32 => enip::TimeoutMultiplier::X32,
            64 => enip::TimeoutMultiplier::X64,
            128 => enip::TimeoutMultiplier::X128,
            256 => enip::TimeoutMultiplier::X256,
            512 => enip::TimeoutMultiplier::X512,
            other => {
                return Err(format!(
                    "io.timeoutMultiplier `{other}` is not one of 4, 8, 16, 32, 64, 128, 256, 512"
                ))
            }
        })
    }

    /// Effective O→T RPI: `o2tRpiMs` ▸ `rpiMs` (§4.6).
    #[must_use]
    pub fn effective_o2t_rpi_ms(&self) -> u64 {
        self.o2t_rpi_ms.unwrap_or(self.rpi_ms)
    }

    /// Build + validate the T→O (input) [`enip::AssemblyLayout`] from `input.signals[]` against
    /// `input.sizeBytes` (§4.6, D-EIP-18). Overlaps are allowed; out-of-range fields are rejected.
    ///
    /// # Errors
    ///
    /// [`String`] describing the offending field when the layout does not validate.
    pub fn input_layout(&self) -> std::result::Result<enip::AssemblyLayout, String> {
        build_layout(&self.input.signals, self.input.size_bytes, "io.input")
    }

    /// Build + validate the O→T (output) [`enip::AssemblyLayout`], or `None` for a heartbeat
    /// connection (no output signals). Same rules as [`Self::input_layout`].
    ///
    /// # Errors
    ///
    /// [`String`] describing the offending field when the layout does not validate.
    pub fn output_layout(&self) -> std::result::Result<Option<enip::AssemblyLayout>, String> {
        match &self.output {
            Some(out) if !out.signals.is_empty() => {
                Ok(Some(build_layout(&out.signals, out.size_bytes, "io.output")?))
            }
            _ => Ok(None),
        }
    }

    /// The stable `signal.id`s of the output fields — the push analog of "configured tagPaths" for
    /// the `writes.allow[]` reconciliation (§4.4).
    fn output_field_ids(&self) -> Vec<String> {
        self.output
            .as_ref()
            .map(|out| {
                out.signals
                    .iter()
                    .map(|f| f.signal_id(self.assemblies.output))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The §4.6 startup validations for a push device. Assumes the caller has already established
    /// `mode == push` and `pollGroups` is absent.
    fn validate(&self, device_id: &str) -> std::result::Result<(), String> {
        // Watchdog multiplier must be CIP-legal.
        self.timeout_multiplier_enip()?;

        // RPIs must be ≥ 1 ms.
        if self.rpi_ms == 0 {
            return Err(format!("device `{device_id}`: io.rpiMs must be ≥ 1"));
        }
        if self.effective_o2t_rpi_ms() == 0 {
            return Err(format!("device `{device_id}`: io.o2tRpiMs must be ≥ 1"));
        }

        // Input framing is T→O; heartbeat is an O→T-only format.
        if self.input.real_time_format == RealTimeFormat::Heartbeat {
            return Err(format!(
                "device `{device_id}`: io.input.realTimeFormat `heartbeat` is O→T only (use modeless or header32)"
            ));
        }
        if self.input.size_bytes == 0 {
            return Err(format!("device `{device_id}`: io.input.sizeBytes must be ≥ 1"));
        }
        if self.input.signals.is_empty() {
            return Err(format!("device `{device_id}`: io.input.signals is empty (min 1)"));
        }

        // A size-0 (heartbeat) output must carry no data fields.
        if let Some(out) = &self.output {
            if out.size_bytes == 0 && !out.signals.is_empty() {
                return Err(format!(
                    "device `{device_id}`: io.output.sizeBytes is 0 (heartbeat) but output.signals is non-empty"
                ));
            }
        }

        // Field-level checks: unique names/ids, bool-transform rejection, deadband-side rules.
        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let input_inst = self.assemblies.input;
        let output_inst = self.assemblies.output;
        for (fields, inst, side) in [
            (self.input.signals.as_slice(), input_inst, IoSide::Input),
            (
                self.output.as_ref().map_or(&[][..], |o| o.signals.as_slice()),
                output_inst,
                IoSide::Output,
            ),
        ] {
            for field in fields {
                if !names.insert(field.name.as_str()) {
                    return Err(format!(
                        "device `{device_id}`: duplicate signal name `{}`",
                        field.name
                    ));
                }
                let id = field.signal_id(inst);
                if !ids.insert(id.clone()) {
                    return Err(format!("device `{device_id}`: duplicate signal id `{id}`"));
                }
                if !field.is_numeric()
                    && (field.scale.is_some() || field.value_offset.is_some())
                {
                    return Err(format!(
                        "device `{device_id}`: field `{}` is bool - scale/valueOffset do not apply",
                        field.name
                    ));
                }
                match side {
                    IoSide::Input => {
                        if let Some(db) = &field.deadband {
                            if !field.is_numeric() && db.kind != DeadbandKind::None {
                                return Err(format!(
                                    "device `{device_id}`: field `{}` is bool - deadband does not apply",
                                    field.name
                                ));
                            }
                        }
                    }
                    IoSide::Output => {
                        // Deadband is an input-side (publish-gating) concept only (§4.6).
                        if field.deadband.is_some() {
                            return Err(format!(
                                "device `{device_id}`: output field `{}` may not carry a deadband (input side only)",
                                field.name
                            ));
                        }
                    }
                }
            }
        }

        // The bounds proof: build both assembly layouts. Any out-of-range/overlong/invalid-bit field
        // is a startup error here (D-EIP-18) — the crate's construction check.
        self.input_layout()
            .map_err(|e| format!("device `{device_id}`: {e}"))?;
        self.output_layout()
            .map_err(|e| format!("device `{device_id}`: {e}"))?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IoSide {
    Input,
    Output,
}

/// Turn a field list + assembly size into a validated [`enip::AssemblyLayout`], mapping the crate's
/// typed [`enip::AssemblyError`] to a config-validation message (`context` names the direction).
fn build_layout(
    fields: &[IoFieldSpec],
    size_bytes: usize,
    context: &str,
) -> std::result::Result<enip::AssemblyLayout, String> {
    let specs: Vec<enip::FieldSpec> = fields
        .iter()
        .enumerate()
        .map(|(idx, f)| f.to_enip_field(idx))
        .collect();
    enip::AssemblyLayout::new(specs, size_bytes).map_err(|e| {
        // The error's `key` is the field index; name the offending field for a legible message.
        let named = match &e {
            enip::AssemblyError::FieldOutOfBounds { key }
            | enip::AssemblyError::ZeroCount { key }
            | enip::AssemblyError::InvalidBitField { key }
            | enip::AssemblyError::NonElementaryType { key } => {
                fields.get(*key).map(|f| f.name.as_str())
            }
            _ => None,
        };
        match named {
            Some(name) => format!("{context} field `{name}`: {e}"),
            None => format!("{context}: {e}"),
        }
    })
}

// ===================================================================================
// Parse + validate + precedence
// ===================================================================================

impl GlobalConfig {
    /// Parse `component.global`. An absent/empty subtree yields all built-in defaults.
    ///
    /// # Errors
    ///
    /// [`String`] describing the unknown-key / type error when the subtree is malformed.
    pub fn from_value(value: &Value) -> std::result::Result<GlobalConfig, String> {
        if value.is_null() || matches!(value, Value::Object(m) if m.is_empty()) {
            return Ok(GlobalConfig::default());
        }
        serde_json::from_value(value.clone()).map_err(|e| format!("component.global: {e}"))
    }
}

impl DeviceConfig {
    /// Parse **and validate** one `component.instances[]` entry: deserialize (which rejects unknown
    /// keys, unsupported `type`s, and out-of-range `slot`), then run the §4.4 startup validations
    /// and assign default poll-group ids.
    ///
    /// # Errors
    ///
    /// [`String`] describing the first validation failure (a malformed device is skipped with this
    /// message by the supervisor; a component with zero valid devices refuses to start).
    pub fn from_value(value: &Value) -> std::result::Result<DeviceConfig, String> {
        let mut cfg: DeviceConfig = serde_json::from_value(value.clone()).map_err(|e| {
            // serde's message already names the offending key / unknown enum variant clearly, e.g.
            // "unknown variant `string`, expected one of `bool`, `sint`, ...".
            format!("invalid device config: {e}")
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The §4.4 startup validations + poll-group id assignment. Returned warnings are logged by the
    /// caller (they are not rejections).
    fn validate(&mut self) -> std::result::Result<(), String> {
        // The `connection.security` block (CIP Security Phase 1): validate it fail-fast — TLS is
        // refused on a push instance, requires a client identity, and (with verifyPeer) a CA source
        // (DESIGN-cip-security.md §3.3).
        let is_push = matches!(self.mode, DeviceMode::Push);
        if let Some(sec) = crate::eip::tls::SecurityConfig::from_connection(&self.connection)? {
            sec.validate(&self.id, is_push)?;
        }
        // Mode is exclusive: poll ⇒ pollGroups + no io; push ⇒ io + no pollGroups (§4.2). Reject
        // clearly either way before the mode-specific checks.
        match self.mode {
            DeviceMode::Poll => {
                if self.io.is_some() {
                    return Err(format!(
                        "device `{}` is mode `poll` but declares an `io` block (io is push-only)",
                        self.id
                    ));
                }
                self.validate_poll()
            }
            DeviceMode::Push => {
                if !self.poll_groups.is_empty() {
                    return Err(format!(
                        "device `{}` is mode `push` but declares `pollGroups` (pollGroups is poll-only)",
                        self.id
                    ));
                }
                let Some(io) = &self.io else {
                    return Err(format!(
                        "device `{}` is mode `push` but has no `io` block (required)",
                        self.id
                    ));
                };
                io.validate(&self.id)
            }
        }
    }

    /// The §4.4 poll-mode startup validations + poll-group id assignment.
    fn validate_poll(&mut self) -> std::result::Result<(), String> {
        if self.poll_groups.is_empty() {
            return Err(format!("device `{}` has no pollGroups (min 1)", self.id));
        }

        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut tag_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for (idx, group) in self.poll_groups.iter().enumerate() {
            if group.id.is_none() {
                // assigned below (borrow split); check only here.
            }
            if group.signals.is_empty() {
                return Err(format!(
                    "device `{}` poll group #{} has no signals (min 1)",
                    self.id,
                    idx + 1
                ));
            }
            for sig in &group.signals {
                if !names.insert(sig.name.as_str()) {
                    return Err(format!(
                        "device `{}`: duplicate signal name `{}`",
                        self.id, sig.name
                    ));
                }
                if !tag_paths.insert(sig.tag_path.as_str()) {
                    return Err(format!(
                        "device `{}`: duplicate tagPath `{}`",
                        self.id, sig.tag_path
                    ));
                }
                if !sig.is_numeric() {
                    if sig.scale.is_some() || sig.offset.is_some() {
                        return Err(format!(
                            "device `{}`: signal `{}` is bool - scale/offset do not apply",
                            self.id, sig.name
                        ));
                    }
                    if sig.deadband.kind != DeadbandKind::None {
                        return Err(format!(
                            "device `{}`: signal `{}` is bool - deadband does not apply",
                            self.id, sig.name
                        ));
                    }
                }
            }
        }

        // Assign default poll-group ids (`group-<n>`, 1-based) where absent.
        for (idx, group) in self.poll_groups.iter_mut().enumerate() {
            if group.id.is_none() {
                group.id = Some(format!("group-{}", idx + 1));
            }
        }

        Ok(())
    }

    /// `writes.allow[]` entries that match no configured writable id — a poll `tagPath`, or a push
    /// output field id (`a<inst>/<offset>/<type>`, §4.4/D-EIP-18). These are **warned, not
    /// rejected** (§4.4 — they may be intentional for `sb/write`-by-explicit-ref). The caller logs
    /// each.
    #[must_use]
    pub fn unmatched_allow_entries(&self) -> Vec<String> {
        let configured: std::collections::HashSet<String> = match self.mode {
            DeviceMode::Poll => self.signals().map(|s| s.tag_path.clone()).collect(),
            DeviceMode::Push => self
                .io
                .as_ref()
                .map(IoConfig::output_field_ids)
                .unwrap_or_default()
                .into_iter()
                .collect(),
        };
        self.writes
            .allow
            .iter()
            .filter(|a| !configured.contains(a.as_str()))
            .cloned()
            .collect()
    }

    /// Every configured signal across all poll groups.
    pub fn signals(&self) -> impl Iterator<Item = &SignalSpec> {
        self.poll_groups.iter().flat_map(|g| g.signals.iter())
    }

    /// Find a configured signal by its stable id (tag path). Consumed by the write path (S6
    /// extends it to explicit refs).
    #[must_use]
    pub fn find_signal(&self, tag_path: &str) -> Option<&SignalSpec> {
        self.signals().find(|s| s.tag_path == tag_path)
    }

    /// Effective poll cadence for a group: **group ▸ device.defaults ▸ global.defaults ▸ built-in**.
    #[must_use]
    pub fn effective_poll_ms(&self, group: &PollGroup, global: &GlobalConfig) -> u64 {
        group
            .poll_interval_ms
            .or(self.defaults.poll_interval_ms)
            .or(global.defaults.poll_interval_ms)
            .unwrap_or(BUILTIN_POLL_MS)
    }

    /// Effective publish mode for a group: **group ▸ device.defaults ▸ global.defaults ▸ built-in**.
    /// Consumed by the poll engine (S4).
    #[allow(dead_code)]
    #[must_use]
    pub fn effective_publish_mode(&self, group: &PollGroup, global: &GlobalConfig) -> PublishMode {
        group
            .publish_mode
            .or(self.defaults.publish_mode)
            .or(global.defaults.publish_mode)
            .unwrap_or(BUILTIN_PUBLISH_MODE)
    }

    /// Effective batch window: **device.defaults ▸ global.defaults ▸ built-in** (batchMs is not a
    /// per-group key, §4.3). Consumed by the poll engine (S4).
    #[allow(dead_code)]
    #[must_use]
    pub fn effective_batch_ms(&self, global: &GlobalConfig) -> u64 {
        self.defaults
            .batch_ms
            .or(global.defaults.batch_ms)
            .unwrap_or(BUILTIN_BATCH_MS)
    }
}

fn default_adapter() -> String {
    "ethernet-ip".into()
}
fn d_metrics_interval_secs() -> u64 {
    60
}
fn d_connect_ms() -> u64 {
    5_000
}
fn d_request_timeout_ms() -> u64 {
    2_000
}
fn d_backoff_min_ms() -> u64 {
    1_000
}
fn d_backoff_max_ms() -> u64 {
    60_000
}
fn d_stale_secs() -> u64 {
    60
}
fn d_keepalive_ms() -> u64 {
    60_000
}
// ---- push `io` defaults (§4.6) ----
fn d_timeout_multiplier() -> u32 {
    16
}
fn d_input_rt_format() -> RealTimeFormat {
    RealTimeFormat::Modeless
}
fn d_output_rt_format() -> RealTimeFormat {
    RealTimeFormat::Header32
}
fn d_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device(value: Value) -> std::result::Result<DeviceConfig, String> {
        DeviceConfig::from_value(&value)
    }

    fn minimal_device() -> Value {
        json!({
            "id": "plc-1",
            "adapter": "ethernet-ip",
            "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [
                { "signals": [
                    { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" }
                ] }
            ]
        })
    }

    #[test]
    fn a_minimal_device_parses_with_defaults() {
        let d = device(minimal_device()).unwrap();
        assert_eq!(d.id, "plc-1");
        assert_eq!(d.adapter, "ethernet-ip");
        assert!(!d.connection.connected, "unconnected is the default (D-EIP-8)");
        assert_eq!(d.connection.slot, None);
        // The default poll-group id is assigned.
        assert_eq!(d.poll_groups[0].id.as_deref(), Some("group-1"));
        // Read-only by default.
        assert!(d.writes.allow.is_empty());
    }

    #[test]
    fn adapter_defaults_to_ethernet_ip() {
        let mut v = minimal_device();
        v.as_object_mut().unwrap().remove("adapter");
        assert_eq!(device(v).unwrap().adapter, "ethernet-ip");
    }

    #[test]
    fn global_defaults_and_timeouts_parse() {
        let g = GlobalConfig::from_value(&json!({})).unwrap();
        assert_eq!(g.metrics_interval_secs, 60);
        assert_eq!(g.timeouts.connect_ms, 5_000);
        assert_eq!(g.timeouts.request_timeout_ms, 2_000);
        assert_eq!(g.timeouts.reconnect_backoff_min_ms, 1_000);
        assert_eq!(g.timeouts.reconnect_backoff_max_ms, 60_000);
        assert_eq!(g.health_thresholds.stale_signal_secs, 60);
        assert_eq!(g.health_thresholds.keepalive_probe_interval_ms, 60_000);
        // Absent defaults leave the Options empty (built-in fallback resolves them).
        assert_eq!(g.defaults.poll_interval_ms, None);
    }

    #[test]
    fn precedence_signal_group_device_global_builtin() {
        // built-in (5000) when nothing is set.
        let d = device(minimal_device()).unwrap();
        let g = GlobalConfig::default();
        assert_eq!(d.effective_poll_ms(&d.poll_groups[0], &g), 5_000);

        // global.defaults sets it.
        let g = GlobalConfig::from_value(&json!({ "defaults": { "pollIntervalMs": 3000 } })).unwrap();
        assert_eq!(d.effective_poll_ms(&d.poll_groups[0], &g), 3_000);

        // device.defaults overrides global.
        let d2 = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "defaults": { "pollIntervalMs": 2000 },
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" }
            ] } ]
        }))
        .unwrap();
        assert_eq!(d2.effective_poll_ms(&d2.poll_groups[0], &g), 2_000);

        // group overrides device.
        let d3 = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "defaults": { "pollIntervalMs": 2000 },
            "pollGroups": [ { "pollIntervalMs": 500, "signals": [
                { "name": "a", "tagPath": "A", "type": "real" }
            ] } ]
        }))
        .unwrap();
        assert_eq!(d3.effective_poll_ms(&d3.poll_groups[0], &g), 500);
    }

    #[test]
    fn precedence_publish_mode_and_batch_ms() {
        let g = GlobalConfig::from_value(
            &json!({ "defaults": { "publishMode": "always", "batchMs": 100 } }),
        )
        .unwrap();
        let d = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [
                { "publishMode": "onChange", "signals": [
                    { "name": "a", "tagPath": "A", "type": "real" } ] },
                { "signals": [
                    { "name": "b", "tagPath": "B", "type": "real" } ] }
            ]
        }))
        .unwrap();
        // group override wins for the first group; global wins for the second.
        assert_eq!(
            d.effective_publish_mode(&d.poll_groups[0], &g),
            PublishMode::OnChange
        );
        assert_eq!(
            d.effective_publish_mode(&d.poll_groups[1], &g),
            PublishMode::Always
        );
        // batchMs has no group level: global's 100 applies.
        assert_eq!(d.effective_batch_ms(&g), 100);
        // built-in 0 when unset anywhere.
        assert_eq!(d.effective_batch_ms(&GlobalConfig::default()), 0);
    }

    #[test]
    fn address_json_includes_array_count_and_slot_only_when_set() {
        let d = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h", "slot": 0 },
            "pollGroups": [ { "signals": [
                { "name": "zone-temps", "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 8 },
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" }
            ] } ]
        }))
        .unwrap();
        let sigs: Vec<&SignalSpec> = d.signals().collect();
        assert_eq!(
            sigs[0].address_json(&d.connection),
            json!({ "tagPath": "ZONE_TEMPS", "type": "real", "arrayCount": 8, "slot": 0 })
        );
        // no arrayCount; slot present because the device configures it.
        assert_eq!(
            sigs[1].address_json(&d.connection),
            json!({ "tagPath": "LINE_SPEED", "type": "real", "slot": 0 })
        );
    }

    #[test]
    fn address_json_omits_slot_when_absent() {
        let d = device(minimal_device()).unwrap();
        let s: Vec<&SignalSpec> = d.signals().collect();
        assert_eq!(
            s[0].address_json(&d.connection),
            json!({ "tagPath": "LINE_SPEED", "type": "real" })
        );
    }

    // ---- §4.4 rejecting validations (one test each) ----

    #[test]
    fn rejects_unknown_key() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollIntervalMS": 1000,
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        }));
        assert!(bad.is_err(), "a typo'd key is a mistake, not a no-op");
    }

    #[test]
    fn rejects_string_type() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "recipe", "tagPath": "RECIPE", "type": "string" } ] } ]
        }));
        let msg = bad.unwrap_err();
        assert!(msg.contains("string"), "the error names the bad type: {msg}");
    }

    #[test]
    fn rejects_udt_type() {
        // A UDT/struct type name is likewise not a variant.
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "x", "tagPath": "X", "type": "MyUdt" } ] } ]
        }));
        assert!(bad.is_err());
    }

    #[test]
    fn rejects_multidim_array_type() {
        // Multi-dimensional arrays have no representation (arrayCount is a single int); a nested
        // arrayCount is rejected as a type error.
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "grid", "tagPath": "GRID", "type": "real", "arrayCount": [2, 2] } ] } ]
        }));
        assert!(bad.is_err());
    }

    #[test]
    fn rejects_duplicate_name() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "dup", "tagPath": "A", "type": "real" },
                { "name": "dup", "tagPath": "B", "type": "real" } ] } ]
        }));
        assert!(bad.unwrap_err().contains("duplicate signal name"));
    }

    #[test]
    fn rejects_duplicate_tag_path() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [
                { "signals": [ { "name": "a", "tagPath": "SAME", "type": "real" } ] },
                { "signals": [ { "name": "b", "tagPath": "SAME", "type": "real" } ] }
            ]
        }));
        assert!(bad.unwrap_err().contains("duplicate tagPath"));
    }

    #[test]
    fn rejects_scale_on_bool() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "flag", "tagPath": "FLAG", "type": "bool", "scale": 2.0 } ] } ]
        }));
        assert!(bad.unwrap_err().contains("bool"));
    }

    #[test]
    fn rejects_deadband_on_bool() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "flag", "tagPath": "FLAG", "type": "bool",
                  "deadband": { "type": "absolute", "value": 1.0 } } ] } ]
        }));
        assert!(bad.unwrap_err().contains("bool"));
    }

    #[test]
    fn rejects_slot_out_of_range() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h", "slot": 256 },
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        }));
        assert!(bad.is_err(), "slot must be 0-255 (a u8)");
    }

    #[test]
    fn rejects_no_poll_groups() {
        let bad = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": []
        }));
        assert!(bad.unwrap_err().contains("no pollGroups"));
    }

    #[test]
    fn unmatched_allow_entries_are_warned_not_rejected() {
        // `MOTOR_RUN` is configured; `GHOST` is not. Parsing SUCCEEDS; the ghost is merely reported.
        let d = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "motor", "tagPath": "MOTOR_RUN", "type": "dint" } ] } ],
            "writes": { "allow": ["MOTOR_RUN", "GHOST"] }
        }))
        .unwrap();
        assert_eq!(d.unmatched_allow_entries(), vec!["GHOST".to_string()]);
        assert!(d.writes.permits("MOTOR_RUN"));
    }

    #[test]
    fn connection_is_open_but_device_is_strict() {
        // Unknown keys under `connection` are allowed (open); at the device level they are not.
        let d = device(json!({
            "id": "plc-1",
            "connection": { "endpoint": "h", "vendorQuirk": true, "connected": true, "slot": 3 },
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        }))
        .unwrap();
        assert_eq!(d.connection.extra["vendorQuirk"], json!(true));
        assert!(d.connection.connected);
        assert_eq!(d.connection.connection_mode(), "connected");
        assert_eq!(d.connection.slot, Some(3));
    }

    // ===============================================================================
    // Push mode — the `io` block (§4.6, D-EIP-18)
    // ===============================================================================

    /// A minimal valid `io` block: a 32-byte input assembly + a 32-byte output assembly, mirroring
    /// the §4.6 worked config's `100/150/151` layout.
    fn an_io_block() -> Value {
        json!({
            "rpiMs": 100,
            "assemblies": { "config": 151, "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 32,
                "sampleMs": 500,
                "signals": [
                    { "name": "din-word", "offset": 0, "type": "udint" },
                    { "name": "motor-run", "offset": 0, "type": "bool", "bit": 0 },
                    { "name": "fault", "offset": 0, "type": "bool", "bit": 1,
                      "deadband": { "type": "none" } },
                    { "name": "line-counts", "offset": 4, "type": "udint", "arrayCount": 7 }
                ]
            },
            "output": {
                "sizeBytes": 32, "run": true,
                "signals": [ { "name": "dout-word", "offset": 0, "type": "udint" } ]
            }
        })
    }

    fn a_push_device(io: Value) -> std::result::Result<DeviceConfig, String> {
        device(json!({
            "id": "palletizer-io",
            "adapter": "ethernet-ip",
            "mode": "push",
            "connection": { "endpoint": "opener-sim:44818" },
            "io": io,
            "writes": { "allow": ["a150/0/udint"] }
        }))
    }

    #[test]
    fn mode_defaults_to_poll() {
        // A device that never mentions `mode` is a poll device.
        let d = device(minimal_device()).unwrap();
        assert_eq!(d.mode, DeviceMode::Poll);
        assert_eq!(d.mode.as_str(), "poll");
        assert!(d.io.is_none());
    }

    #[test]
    fn a_push_device_parses_with_io_defaults() {
        let d = a_push_device(an_io_block()).unwrap();
        assert_eq!(d.mode, DeviceMode::Push);
        assert_eq!(d.mode.as_str(), "push");
        assert!(d.poll_groups.is_empty(), "push carries no poll groups");
        let io = d.io.as_ref().unwrap();
        // §4.6 defaults.
        assert_eq!(io.connection_type, IoConnType::P2p);
        assert_eq!(io.priority, IoPriority::Scheduled);
        assert_eq!(io.timeout_multiplier, 16);
        assert_eq!(io.input.real_time_format, RealTimeFormat::Modeless);
        assert_eq!(io.input.sample_ms, 500);
        let out = io.output.as_ref().unwrap();
        assert_eq!(out.real_time_format, RealTimeFormat::Header32);
        assert!(out.run);
        // o2tRpiMs defaults to rpiMs.
        assert_eq!(io.effective_o2t_rpi_ms(), 100);
    }

    #[test]
    fn o2t_rpi_overrides_when_set() {
        let mut io = an_io_block();
        io["o2tRpiMs"] = json!(250);
        let d = a_push_device(io).unwrap();
        assert_eq!(d.io.as_ref().unwrap().effective_o2t_rpi_ms(), 250);
    }

    #[test]
    fn push_signal_ids_follow_the_scheme() {
        // a<assemblyInstance>/<offset>/<type>[.<bit>] (D-EIP-18).
        let d = a_push_device(an_io_block()).unwrap();
        let io = d.io.as_ref().unwrap();
        let in_inst = io.assemblies.input;
        let fields = &io.input.signals;
        assert_eq!(fields[0].signal_id(in_inst), "a100/0/udint");
        assert_eq!(fields[1].signal_id(in_inst), "a100/0/bool.0"); // bit
        assert_eq!(fields[2].signal_id(in_inst), "a100/0/bool.1");
        assert_eq!(fields[3].signal_id(in_inst), "a100/4/udint"); // array field
        // output field id uses the output instance.
        let out = io.output.as_ref().unwrap();
        assert_eq!(out.signals[0].signal_id(io.assemblies.output), "a150/0/udint");
    }

    #[test]
    fn push_field_address_json_includes_optional_keys_only_when_set() {
        let d = a_push_device(an_io_block()).unwrap();
        let io = d.io.as_ref().unwrap();
        let in_inst = io.assemblies.input;
        let f = &io.input.signals;
        // scalar, no bit / array / slot.
        assert_eq!(
            f[0].address_json(in_inst, &d.connection),
            json!({ "assembly": 100, "offset": 0, "type": "udint" })
        );
        // a bit field carries `bit`.
        assert_eq!(
            f[1].address_json(in_inst, &d.connection),
            json!({ "assembly": 100, "offset": 0, "type": "bool", "bit": 0 })
        );
        // an array field carries `arrayCount`.
        assert_eq!(
            f[3].address_json(in_inst, &d.connection),
            json!({ "assembly": 100, "offset": 4, "type": "udint", "arrayCount": 7 })
        );
    }

    #[test]
    fn config_builds_a_valid_assembly_layout() {
        // The §4.6 layout must construct into a valid enip::AssemblyLayout (bounds proven).
        let d = a_push_device(an_io_block()).unwrap();
        let io = d.io.as_ref().unwrap();
        let layout = io.input_layout().expect("input layout builds");
        assert_eq!(layout.data_size(), 32);
        // 4 input fields → 4 enip FieldSpecs, keyed by declaration index; overlaps (word + 2 bits) OK.
        assert_eq!(layout.fields().len(), 4);
        // The output layout builds too.
        assert!(io.output_layout().expect("output layout builds").is_some());
    }

    #[test]
    fn heartbeat_output_has_no_layout() {
        // sizeBytes 0, no signals ⇒ a heartbeat connection with no output assembly layout.
        let mut io = an_io_block();
        io["output"] = json!({ "sizeBytes": 0 });
        let d = a_push_device(io).unwrap();
        assert!(d.io.as_ref().unwrap().output_layout().unwrap().is_none());
    }

    #[test]
    fn output_absent_is_a_heartbeat() {
        let mut io = an_io_block();
        io.as_object_mut().unwrap().remove("output");
        let d = a_push_device(io).unwrap();
        let io = d.io.as_ref().unwrap();
        assert!(io.output.is_none());
        assert!(io.output_layout().unwrap().is_none());
    }

    #[test]
    fn enip_mapping_helpers_are_faithful() {
        let mut io = an_io_block();
        io["connectionType"] = json!("multicast");
        io["priority"] = json!("urgent");
        io["timeoutMultiplier"] = json!(64);
        io["input"]["realTimeFormat"] = json!("header32");
        let d = a_push_device(io).unwrap();
        let io = d.io.as_ref().unwrap();
        assert_eq!(io.connection_type.to_enip(), enip::ConnType::Multicast);
        assert_eq!(io.priority.to_enip(), enip::Priority::Urgent);
        assert_eq!(
            io.timeout_multiplier_enip().unwrap(),
            enip::TimeoutMultiplier::X64
        );
        assert_eq!(
            io.input.real_time_format.to_enip(),
            enip::RealTimeFormat::Header32Bit
        );
        assert_eq!(
            io.output.as_ref().unwrap().real_time_format.to_enip(),
            enip::RealTimeFormat::Header32Bit
        );
    }

    #[test]
    fn push_writes_allow_matches_output_field_ids() {
        // `a150/0/udint` is a real output field; `a150/99/real` is not — the ghost is warned.
        let d = device(json!({
            "id": "palletizer-io",
            "mode": "push",
            "connection": { "endpoint": "h" },
            "io": an_io_block(),
            "writes": { "allow": ["a150/0/udint", "a150/99/real"] }
        }))
        .unwrap();
        assert_eq!(d.unmatched_allow_entries(), vec!["a150/99/real".to_string()]);
        assert!(d.writes.permits("a150/0/udint"));
    }

    // ---- §4.6 rejecting validations (one test each) ----

    #[test]
    fn rejects_push_without_io() {
        let bad = device(json!({
            "id": "x", "mode": "push",
            "connection": { "endpoint": "h" }
        }));
        assert!(bad.unwrap_err().contains("no `io` block"));
    }

    #[test]
    fn rejects_push_with_poll_groups() {
        let bad = device(json!({
            "id": "x", "mode": "push",
            "connection": { "endpoint": "h" },
            "io": an_io_block(),
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        }));
        assert!(bad.unwrap_err().contains("declares `pollGroups`"));
    }

    #[test]
    fn rejects_poll_with_io() {
        let bad = device(json!({
            "id": "x",
            "connection": { "endpoint": "h" },
            "io": an_io_block(),
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        }));
        assert!(bad.unwrap_err().contains("declares an `io` block"));
    }

    #[test]
    fn rejects_poll_without_poll_groups_explicit_mode() {
        // An explicit poll mode with no groups is still the §4.4 "no pollGroups" error.
        let bad = device(json!({
            "id": "x", "mode": "poll",
            "connection": { "endpoint": "h" }
        }));
        assert!(bad.unwrap_err().contains("no pollGroups"));
    }

    #[test]
    fn rejects_io_field_offset_out_of_range() {
        // A udint at offset 30 needs bytes 30..34 but the assembly is 32 bytes — the AssemblyLayout
        // construction check rejects it at startup (D-EIP-18).
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "overflow", "offset": 30, "type": "udint" }
        ]);
        let msg = a_push_device(io).unwrap_err();
        assert!(msg.contains("out of bounds"), "names the bounds failure: {msg}");
        assert!(msg.contains("overflow"), "names the offending field: {msg}");
    }

    #[test]
    fn rejects_io_array_that_overruns_assembly() {
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "too-long", "offset": 0, "type": "udint", "arrayCount": 9 }
        ]);
        assert!(a_push_device(io).unwrap_err().contains("out of bounds"));
    }

    #[test]
    fn rejects_bit_on_non_bool_field() {
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "bad-bit", "offset": 0, "type": "udint", "bit": 0 }
        ]);
        assert!(a_push_device(io).unwrap_err().contains("invalid bit selector"));
    }

    #[test]
    fn rejects_unknown_io_key() {
        let mut io = an_io_block();
        io["rpiMS"] = json!(50); // typo'd casing
        assert!(a_push_device(io).is_err(), "a typo'd io key is a mistake");
    }

    #[test]
    fn rejects_unknown_io_field_key() {
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "f", "offset": 0, "type": "udint", "byteOffset": 4 }
        ]);
        assert!(a_push_device(io).is_err());
    }

    #[test]
    fn rejects_illegal_timeout_multiplier() {
        let mut io = an_io_block();
        io["timeoutMultiplier"] = json!(10); // not one of 4,8,16,...,512
        assert!(a_push_device(io).unwrap_err().contains("timeoutMultiplier"));
    }

    #[test]
    fn rejects_string_type_in_io_field() {
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "recipe", "offset": 0, "type": "string" }
        ]);
        assert!(a_push_device(io).unwrap_err().contains("string"));
    }

    #[test]
    fn rejects_scale_on_bool_io_field() {
        let mut io = an_io_block();
        io["input"]["signals"] = json!([
            { "name": "flag", "offset": 0, "type": "bool", "bit": 0, "scale": 2.0 }
        ]);
        assert!(a_push_device(io).unwrap_err().contains("bool"));
    }

    #[test]
    fn rejects_deadband_on_output_field() {
        // Deadband is an input-side (publish-gating) concept only (§4.6).
        let mut io = an_io_block();
        io["output"]["signals"] = json!([
            { "name": "dout", "offset": 0, "type": "udint",
              "deadband": { "type": "absolute", "value": 1.0 } }
        ]);
        assert!(a_push_device(io).unwrap_err().contains("deadband"));
    }

    #[test]
    fn rejects_heartbeat_format_on_input() {
        let mut io = an_io_block();
        io["input"]["realTimeFormat"] = json!("heartbeat");
        assert!(a_push_device(io).unwrap_err().contains("heartbeat"));
    }

    #[test]
    fn rejects_output_size_zero_with_signals() {
        let mut io = an_io_block();
        io["output"] = json!({
            "sizeBytes": 0,
            "signals": [ { "name": "d", "offset": 0, "type": "udint" } ]
        });
        assert!(a_push_device(io).unwrap_err().contains("heartbeat"));
    }

    #[test]
    fn rejects_duplicate_field_name_across_directions() {
        let mut io = an_io_block();
        io["output"]["signals"] = json!([
            { "name": "din-word", "offset": 0, "type": "udint" } // clashes with an input field
        ]);
        assert!(a_push_device(io).unwrap_err().contains("duplicate signal name"));
    }

    #[test]
    fn rejects_missing_required_input_assembly() {
        // The `input` assembly instance is required.
        let mut io = an_io_block();
        io["assemblies"] = json!({ "output": 150 });
        assert!(a_push_device(io).is_err());
    }

    // ---- schema validation of the worked configs (§4.5 poll, §4.6 push) ----

    /// Validate a full component config file against `config.schema.json`: its `component.global`
    /// against the schema root, and each `component.instances[]` entry against `#/$defs/device`.
    fn assert_config_matches_schema(config_text: &str) {
        let schema: Value =
            serde_json::from_str(include_str!("../config.schema.json")).expect("schema is JSON");
        let cfg: Value = serde_json::from_str(config_text).expect("config is JSON");

        // `component.global` against the schema root.
        let root = jsonschema::validator_for(&schema).expect("schema compiles");
        let global = &cfg["component"]["global"];
        let errs: Vec<String> = root.iter_errors(global).map(|e| e.to_string()).collect();
        assert!(errs.is_empty(), "global does not match schema: {errs:?}");

        // Each instance against `#/$defs/device`, resolving internal $refs via a wrapper doc.
        let defs = schema["$defs"].clone();
        let device_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": defs,
            "$ref": "#/$defs/device"
        });
        let dev = jsonschema::validator_for(&device_schema).expect("device schema compiles");
        for inst in cfg["component"]["instances"].as_array().unwrap() {
            let errs: Vec<String> = dev.iter_errors(inst).map(|e| e.to_string()).collect();
            assert!(errs.is_empty(), "instance {} fails schema: {errs:?}", inst["id"]);
            // And the parser accepts it too (schema + parser agree).
            DeviceConfig::from_value(inst).expect("instance parses");
        }
    }

    #[test]
    fn worked_poll_config_matches_schema() {
        assert_config_matches_schema(include_str!("../test-configs/config.json"));
    }

    #[test]
    fn worked_push_config_matches_schema() {
        assert_config_matches_schema(include_str!("../test-configs/config-push.json"));
    }

    #[test]
    fn worked_tls_config_matches_schema() {
        // The CIP Security TLS variant validates against the schema AND parses (security block +
        // `mode: tls`), exercising the `connection.security` def and the tls-on-poll validation.
        assert_config_matches_schema(include_str!("../test-configs/config-tls.json"));
    }

    #[test]
    fn schema_rejects_push_without_io_and_poll_with_io() {
        let schema: Value =
            serde_json::from_str(include_str!("../config.schema.json")).expect("schema is JSON");
        let device_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": "#/$defs/device"
        });
        let dev = jsonschema::validator_for(&device_schema).expect("device schema compiles");

        // push without io — schema conditional forbids it.
        let push_no_io = json!({ "id": "x", "mode": "push", "connection": { "endpoint": "h" } });
        assert!(!dev.is_valid(&push_no_io), "schema requires io for push");

        // poll with io — schema conditional forbids it.
        let poll_with_io = json!({
            "id": "x", "connection": { "endpoint": "h" },
            "io": an_io_block(),
            "pollGroups": [ { "signals": [
                { "name": "a", "tagPath": "A", "type": "real" } ] } ]
        });
        assert!(!dev.is_valid(&poll_with_io), "schema forbids io on a poll device");
    }
}
