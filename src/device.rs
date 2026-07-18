//! # The device seam: what a *protocol adapter* talks to
//!
//! [`DeviceSession`] is one live connection to one device. Implement it once per protocol —
//! Modbus, OPC UA, whatever you are bridging — and everything above it (the connection lifecycle,
//! backoff, publishing, health) is written against the trait and never learns your protocol.
//!
//! **The boundary rule, and it is worth enforcing in review:** a backend knows protocols. It does
//! **not** know EdgeCommons topics, the UNS, message envelopes, or metrics. If your `impl
//! DeviceSession` imports `edgecommons::uns`, the seam has leaked.
//!
//! ## Signals, not tags
//!
//! A **signal** is one data point — a measured value with identity, quality, and timestamps.
//! (OPC UA calls it a "tag"; Modbus calls it a "register".) The word "tag" is reserved in
//! EdgeCommons for the envelope's *business metadata*, which is a different thing entirely.
//!
//! ## Quality is not optional
//!
//! Every sample carries a `quality` normalized to `GOOD | BAD | UNCERTAIN`, plus the native code
//! in `qualityRaw` for diagnosis. This is what lets a consumer gate on quality without knowing
//! your protocol — and it is why a read failure must be published as a `BAD` sample rather than
//! swallowed. A signal that silently stops updating is indistinguishable from one that is simply
//! not changing.

use async_trait::async_trait;
use serde::Deserialize;

/// One reading from the device.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// The canonical, stable id the rest of the fleet keys on (e.g. `ns=3;i=1001`).
    pub signal_id: String,
    /// A human label.
    pub name: Option<String>,
    pub value: serde_json::Value,
    pub quality: Quality,
    /// The protocol-native status code, kept verbatim for diagnosis.
    pub quality_raw: Option<String>,
}

/// Normalized quality. The protocol's own status code goes in `quality_raw`.
///
/// `Uncertain` is unused by the simulated backend and used constantly by real ones: a stale
/// cached read, a value outside its calibrated range, a sensor that answered but warned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `Uncertain` is for your backend, not the simulator's
pub enum Quality {
    Good,
    Bad,
    Uncertain,
}

/// Why talking to the device failed — and whether reconnecting could help.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // the simulator never fails transiently; a real device does, constantly
pub enum DeviceError {
    /// The link is down, or the device is busy. Reconnect and retry.
    #[error("transient: {0}")]
    Transient(#[source] anyhow::Error),
    /// Misconfiguration: a bad endpoint, a rejected credential, an address that does not exist.
    /// Reconnecting will fail identically, so the supervisor backs off hard rather than hammering.
    #[error("permanent: {0}")]
    Permanent(#[source] anyhow::Error),
}

impl DeviceError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

pub type Result<T> = std::result::Result<T, DeviceError>;

/// A live connection to one device. **This is the trait you implement.**
#[async_trait]
pub trait DeviceSession: Send + Sync {
    /// Read the configured signals once.
    ///
    /// A read that fails for *one* signal should return that signal with [`Quality::Bad`] rather
    /// than failing the whole call — one dead register must not blind you to the other ninety-nine.
    /// Return `Err` only when the *connection* is broken.
    async fn read_signals(&mut self) -> Result<Vec<Reading>>;

    /// Write a value back to the device.
    ///
    /// # Errors
    ///
    /// If the write is rejected, or the link is down.
    async fn write_signal(&mut self, signal_id: &str, value: &serde_json::Value) -> Result<()>;

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

/// How to reach one device. Deliberately open (`additionalProperties` in the schema): every
/// protocol needs different keys, and this is the one place the adapter should not be strict.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfig {
    /// The endpoint, in whatever form the protocol uses. Published in `device.endpoint`.
    pub endpoint: String,
    /// Everything else the protocol needs: a unit id, a security policy, a slave address.
    /// The simulator reads none of it; yours will.
    #[serde(flatten)]
    #[allow(dead_code)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

// --- The simulated backend -------------------------------------------------------------------
//
// A real adapter replaces this with its protocol. It ships so that `cargo run` works with no
// hardware, and so the tests have something to talk to — and a backend you can run on a laptop is
// worth more than one you can only run next to a PLC.

pub struct SimBackend;

#[async_trait]
impl DeviceBackend for SimBackend {
    fn kind(&self) -> &'static str {
        "sim"
    }

    async fn connect(&self, cfg: &ConnectionConfig) -> Result<Box<dyn DeviceSession>> {
        if cfg.endpoint.is_empty() {
            // A missing endpoint will never fix itself: permanent, so the supervisor does not
            // spend the next hour reconnecting to nothing.
            return Err(DeviceError::Permanent(anyhow::anyhow!("no endpoint configured")));
        }
        Ok(Box::new(SimSession { tick: 0 }))
    }
}

pub struct SimSession {
    tick: u64,
}

#[async_trait]
impl DeviceSession for SimSession {
    async fn read_signals(&mut self) -> Result<Vec<Reading>> {
        self.tick += 1;
        let value = 20.0 + 5.0 * ((self.tick as f64) / 10.0).sin();
        Ok(vec![
            Reading {
                signal_id: "temperature-1".into(),
                name: Some("Ambient temperature".into()),
                value: serde_json::json!(value),
                quality: Quality::Good,
                quality_raw: Some("OK".into()),
            },
            // A signal the simulated device cannot currently read. It is published as BAD rather
            // than omitted, because "I could not read this" is information and silence is not.
            Reading {
                signal_id: "pressure-1".into(),
                name: Some("Line pressure".into()),
                value: serde_json::Value::Null,
                quality: Quality::Bad,
                quality_raw: Some("SENSOR_FAULT".into()),
            },
        ])
    }

    async fn write_signal(&mut self, signal_id: &str, value: &serde_json::Value) -> Result<()> {
        tracing::info!(signal_id, ?value, "sim: write accepted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(endpoint: &str) -> ConnectionConfig {
        ConnectionConfig { endpoint: endpoint.into(), extra: serde_json::Map::new() }
    }

    #[tokio::test]
    async fn the_sim_backend_connects_and_reads() {
        let mut s = SimBackend.connect(&conn("sim://device")).await.unwrap();
        let readings = s.read_signals().await.unwrap();
        assert_eq!(readings.len(), 2);
        assert_eq!(readings[0].signal_id, "temperature-1");
        assert_eq!(readings[0].quality, Quality::Good);
    }

    #[tokio::test]
    async fn a_failed_read_is_published_as_bad_quality_not_omitted() {
        // The signal is still reported — with BAD quality and the native code — because a signal
        // that silently vanishes is indistinguishable from one that is not changing.
        let mut s = SimBackend.connect(&conn("sim://device")).await.unwrap();
        let readings = s.read_signals().await.unwrap();
        let bad = readings.iter().find(|r| r.signal_id == "pressure-1").unwrap();
        assert_eq!(bad.quality, Quality::Bad);
        assert_eq!(bad.quality_raw.as_deref(), Some("SENSOR_FAULT"));
    }

    #[tokio::test]
    async fn a_misconfiguration_is_permanent_so_the_supervisor_does_not_hammer_it() {
        // `unwrap_err` is not available here: a `Box<dyn DeviceSession>` is not `Debug`, so the
        // Ok-type cannot be printed. Match instead.
        let Err(e) = SimBackend.connect(&conn("")).await else {
            panic!("connecting with no endpoint must fail");
        };
        assert!(!e.is_transient(), "a missing endpoint will never fix itself by retrying");
    }

    #[tokio::test]
    async fn readings_advance() {
        let mut s = SimBackend.connect(&conn("sim://device")).await.unwrap();
        let a = s.read_signals().await.unwrap()[0].value.clone();
        let b = s.read_signals().await.unwrap()[0].value.clone();
        assert_ne!(a, b);
    }
}
