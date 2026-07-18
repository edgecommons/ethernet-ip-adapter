//! # The in-process simulator backend
//!
//! [`SimBackend`] / [`SimSession`] model the cpppo Allen-Bradley tag layout (§11.1) so `cargo run`
//! works with no PLC and no network, and the unit tests have something to talk to. A backend you
//! can run on a laptop is worth more than one you can only run next to a controller.
//!
//! It implements the same [`DeviceSession`] seam the real EtherNet/IP backend (`src/eip/`, slice
//! S3) will: it reads whatever [`SignalSpec`]s a poll group asks for (synthesizing plausible values
//! per type, including a live array and a writable setpoint that reflects the last write), answers
//! `browse` with the cpppo tag set, and answers `probe`.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::config::{EipType, SignalSpec};
use crate::device::{
    BrowsePage, BrowsedTag, ConnectionConfig, DeviceBackend, DeviceError, DeviceSession, Quality,
    Reading, Result,
};

/// The cpppo tag layout (§11.1): `(name, type_name, array_dim)`. `RECIPE=SSTRING` is present
/// precisely to prove the browse/validation story for an unsupported type — its `type_name` maps to
/// `supported: false` at the command layer.
const SIM_TAGS: &[(&str, &str, Option<u32>)] = &[
    ("LINE_SPEED", "REAL", None),
    ("FILL_TEMP", "REAL", None),
    ("TANK_LEVEL", "REAL", None),
    ("PRODUCT_COUNT", "DINT", None),
    ("FILL_SETPOINT", "REAL", None),
    ("ZONE_TEMPS", "REAL", Some(8)),
    ("MOTOR_RUN", "DINT", None),
    ("RECIPE", "SSTRING", None),
];

/// Opens [`SimSession`]s.
pub struct SimBackend;

#[async_trait]
impl DeviceBackend for SimBackend {
    fn kind(&self) -> &'static str {
        "sim"
    }

    async fn connect(&self, cfg: &ConnectionConfig) -> Result<Box<dyn DeviceSession>> {
        if cfg.endpoint.is_empty() {
            // A missing endpoint will never fix itself: permanent, so the supervisor does not spend
            // the next hour reconnecting to nothing.
            return Err(DeviceError::Permanent(anyhow::anyhow!(
                "no endpoint configured"
            )));
        }
        Ok(Box::new(SimSession::default()))
    }
}

/// One simulated session. Holds a monotonically advancing `tick` (so reads change over time) and a
/// map of values written back through `sb/write`, so a write is observable on the next poll.
#[derive(Default)]
pub struct SimSession {
    tick: u64,
    /// Last written value per tag path — a written setpoint reads back as what was written.
    written: std::collections::HashMap<String, Value>,
}

impl SimSession {
    /// Whether the device exposes this tag (present in the cpppo layout).
    fn known(tag_path: &str) -> bool {
        SIM_TAGS.iter().any(|(name, _, _)| *name == tag_path)
    }

    /// Read one signal into a [`Reading`]: a written value reads back verbatim; a known tag
    /// synthesizes a plausible value; an unknown tag comes back **BAD, not swallowed** (a configured
    /// signal pointing at a nonexistent tag is exactly the per-tag failure §5.4/§12.3 exercises).
    fn read_one(&self, spec: &SignalSpec) -> Reading {
        let base = Reading {
            signal_id: spec.tag_path.clone(),
            name: Some(spec.name.clone()),
            value: Value::Null,
            quality: Quality::Good,
            quality_raw: Some("0x00".into()),
        };
        if let Some(v) = self.written.get(&spec.tag_path) {
            return Reading {
                value: v.clone(),
                ..base
            };
        }
        if !Self::known(&spec.tag_path) {
            return Reading {
                value: Value::Null,
                quality: Quality::Bad,
                quality_raw: Some("0x04 path segment error".into()),
                ..base
            };
        }
        Reading {
            value: self.synth(spec),
            ..base
        }
    }

    /// Synthesize a value shaped by the configured type / `arrayCount`.
    fn synth(&self, spec: &SignalSpec) -> Value {
        let phase = (self.tick as f64) / 10.0;
        match spec.array_count {
            Some(n) => Value::Array(
                (0..n)
                    .map(|i| self.scalar(spec.eip_type, phase + f64::from(i)))
                    .collect(),
            ),
            None => self.scalar(spec.eip_type, phase),
        }
    }

    /// One scalar element of the configured type.
    fn scalar(&self, ty: EipType, phase: f64) -> Value {
        let wave = 20.0 + 5.0 * phase.sin();
        match ty {
            EipType::Bool => json!(self.tick % 2 == 0),
            EipType::Real | EipType::Lreal => json!(wave),
            // Integer types: a stable-ish integer value derived from the wave / tick.
            EipType::Dint | EipType::Int | EipType::Sint | EipType::Lint => json!(wave as i64),
            EipType::Udint | EipType::Uint | EipType::Usint | EipType::Ulint => {
                json!(self.tick)
            }
        }
    }
}

#[async_trait]
impl DeviceSession for SimSession {
    async fn read_signals(&mut self, signals: &[SignalSpec]) -> Result<Vec<Reading>> {
        self.tick += 1;
        Ok(signals.iter().map(|spec| self.read_one(spec)).collect())
    }

    async fn write_signal(&mut self, signal: &SignalSpec, value: &Value) -> Result<()> {
        tracing::info!(tag_path = %signal.tag_path, ?value, "sim: write accepted");
        self.written.insert(signal.tag_path.clone(), value.clone());
        Ok(())
    }

    async fn browse(&mut self, _cursor: Option<String>, max: usize) -> Result<BrowsePage> {
        // The sim returns its whole tag set in one page (cpppo's set is tiny). `RECIPE=SSTRING`
        // is included; the command layer marks it unsupported by its type name.
        let tags = SIM_TAGS
            .iter()
            .take(max.max(1))
            .enumerate()
            .map(|(i, (name, type_name, array_dim))| BrowsedTag {
                name: (*name).to_string(),
                type_name: (*type_name).to_string(),
                array_dim: *array_dim,
                instance_id: i as u32 + 1,
            })
            .collect();
        Ok(BrowsePage {
            tags,
            next_cursor: None,
        })
    }

    async fn probe(&mut self) -> Result<()> {
        // The cheapest round-trip: for the sim, always alive.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(endpoint: &str) -> ConnectionConfig {
        ConnectionConfig {
            endpoint: endpoint.into(),
            slot: None,
            connected: false,
            extra: serde_json::Map::new(),
        }
    }

    fn spec(name: &str, tag: &str, ty: &str, array_count: Option<u32>) -> SignalSpec {
        let mut v = json!({ "name": name, "tagPath": tag, "type": ty });
        if let Some(n) = array_count {
            v.as_object_mut()
                .unwrap()
                .insert("arrayCount".into(), json!(n));
        }
        serde_json::from_value(v).unwrap()
    }

    #[tokio::test]
    async fn connects_and_reads_the_requested_signals() {
        let mut s = SimBackend.connect(&conn("127.0.0.1:44818")).await.unwrap();
        let specs = vec![
            spec("line-speed", "LINE_SPEED", "real", None),
            spec("product-count", "PRODUCT_COUNT", "dint", None),
        ];
        let readings = s.read_signals(&specs).await.unwrap();
        assert_eq!(readings.len(), 2);
        assert_eq!(readings[0].signal_id, "LINE_SPEED");
        assert_eq!(readings[0].name.as_deref(), Some("line-speed"));
        assert_eq!(readings[0].quality, Quality::Good);
        assert!(readings[1].value.is_number());
    }

    #[tokio::test]
    async fn an_array_signal_reads_back_a_json_array() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let specs = vec![spec("zone-temps", "ZONE_TEMPS", "real", Some(8))];
        let r = s.read_signals(&specs).await.unwrap();
        let arr = r[0].value.as_array().expect("array value");
        assert_eq!(arr.len(), 8);
    }

    #[tokio::test]
    async fn a_written_setpoint_reads_back_the_written_value() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        s.write_signal(&sp, &json!(55.5)).await.unwrap();
        let r = s.read_signals(&[sp]).await.unwrap();
        assert_eq!(r[0].value, json!(55.5), "the write is observable on the next poll");
    }

    #[tokio::test]
    async fn browse_lists_the_tags_including_the_unsupported_recipe() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let page = s.browse(None, 1000).await.unwrap();
        assert_eq!(page.tags.len(), SIM_TAGS.len());
        assert!(page.next_cursor.is_none());
        let recipe = page.tags.iter().find(|t| t.name == "RECIPE").unwrap();
        assert_eq!(recipe.type_name, "SSTRING", "the unsupported type is surfaced by name");
        let zones = page.tags.iter().find(|t| t.name == "ZONE_TEMPS").unwrap();
        assert_eq!(zones.array_dim, Some(8));
    }

    #[tokio::test]
    async fn a_signal_for_an_unknown_tag_reads_bad_not_swallowed() {
        // A configured signal pointing at a tag the device does not expose is still reported — with
        // BAD quality and the native code — because silence is indistinguishable from "not changing".
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let sp = vec![spec("ghost", "NO_SUCH_TAG", "real", None)];
        let r = s.read_signals(&sp).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].quality, Quality::Bad);
        assert_eq!(r[0].value, Value::Null);
        assert_eq!(r[0].quality_raw.as_deref(), Some("0x04 path segment error"));
    }

    #[tokio::test]
    async fn probe_answers() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        assert!(s.probe().await.is_ok());
    }

    #[tokio::test]
    async fn a_missing_endpoint_is_permanent() {
        let Err(e) = SimBackend.connect(&conn("")).await else {
            panic!("connecting with no endpoint must fail");
        };
        assert!(!e.is_transient(), "a missing endpoint will never fix itself by retrying");
    }

    #[tokio::test]
    async fn readings_advance_over_time() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let sp = vec![spec("line-speed", "LINE_SPEED", "real", None)];
        let a = s.read_signals(&sp).await.unwrap()[0].value.clone();
        let b = s.read_signals(&sp).await.unwrap()[0].value.clone();
        assert_ne!(a, b);
    }
}
