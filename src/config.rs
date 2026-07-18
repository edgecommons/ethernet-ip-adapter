//! # Typed component configuration (`component.*`)
//!
//! The adapter's config lives entirely under `component.*` (the canonical-schema convention,
//! `SOUTHBOUND.md` §4 — no top-level block, no schema sync). This module parses and validates it:
//! [`GlobalConfig`] (`component.global`) and [`DeviceConfig`] (each `component.instances[]` entry),
//! down through [`PollGroup`] and [`SignalSpec`].
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
    /// How to reach the device (the one deliberately open object).
    pub connection: crate::device::ConnectionConfig,
    /// Per-device overrides of the `global.defaults`.
    #[serde(default)]
    pub defaults: Defaults,
    /// The poll groups (required, min 1 — enforced in [`Self::validate`]).
    pub poll_groups: Vec<PollGroup>,
    /// Writes are **allow-listed by stable `signal.id`** (= tag path). An empty list means this
    /// device is read-only, which is the correct default for anything touching a control system.
    #[serde(default)]
    pub writes: Writes,
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
    /// Whether the given stable `signal.id` (tag path) is writable.
    #[must_use]
    pub fn permits(&self, signal_id: &str) -> bool {
        self.allow.iter().any(|s| s == signal_id)
    }
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

    /// `writes.allow[]` entries that match no configured tagPath. These are **warned, not
    /// rejected** (§4.4 — they may be intentional for `sb/write`-by-explicit-ref). The caller logs
    /// each.
    #[must_use]
    pub fn unmatched_allow_entries(&self) -> Vec<String> {
        let configured: std::collections::HashSet<&str> =
            self.signals().map(|s| s.tag_path.as_str()).collect();
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
}
