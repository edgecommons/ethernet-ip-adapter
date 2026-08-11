//! # The in-process simulator backend
//!
//! [`SimBackend`] / [`SimSession`] model the cpppo Allen-Bradley tag layout (§11.1) so `cargo run`
//! works with no PLC and no network, and the unit tests have something to talk to. A backend you
//! can run on a laptop is worth more than one you can only run next to a controller.
//!
//! It implements the same [`DeviceSession`] seam the real EtherNet/IP backend (`src/eip/`, slice
//! S3) will: it reads whatever [`SignalSpec`]s a poll group asks for (synthesizing plausible values
//! per type, including a live array and a writable setpoint that reflects the last write), answers
//! `browse` with the cpppo tag set — paged by the same cursor/`max` contract the real backend
//! honours — and answers `probe`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{EipType, IoConfig, IoFieldSpec, SignalSpec};
use crate::device::{
    BrowsePage, BrowsedTag, ConnectionConfig, DeviceBackend, DeviceError, DeviceIdentity,
    DeviceSession, InputSnapshot, IoUpdate, PushSession, Quality, Reading, Result,
};
use crate::eip::push::assembly_to_readings;

/// The simulator's identity (D-EIP-34) — **an honest fake, and it says so on the nameplate**.
///
/// The one thing a simulated identity must not do is pass for a real device. cpppo, the container
/// this backend models, identifies itself as a Rockwell `1756-L61/B LOGIX5561` under vendor `0x0001`,
/// which is exactly the impersonation that makes identity untrustworthy as a decision input — and
/// exactly the reason the in-process sim declines to join in. So:
///
/// * **vendor `0x0000`** — the reserved id, assigned to nobody. Never `0x0001`: claiming to be
///   Rockwell would put a lie in an operator's status page and a fleet's inventory.
/// * **device type `0x00`** (Generic Device) — the profile for "nothing in particular".
/// * **product code `0`, revision `0.0`, serial `0`** — placeholders that read as placeholders.
/// * **a product name that names itself a simulator**, so a screenshot of `sb/status` is
///   self-explanatory.
fn sim_identity() -> DeviceIdentity {
    DeviceIdentity {
        vendor_id: 0x0000,
        vendor_name: None,
        device_type: 0x0000,
        device_type_name: Some("Generic Device".to_string()),
        product_code: 0,
        revision_major: 0,
        revision_minor: 0,
        serial_number: 0,
        product_name: "EdgeCommons in-process simulator (not a device)".to_string(),
    }
}

/// The cpppo tag layout (§11.1): `(name, type_name, array_dim)`. `array_dim` is the **array
/// dimensionality** the symbol type declares — the same thing the real backend derives from
/// `SymbolType::dims()` (0–3, `None` for a scalar), not an element count, which a CIP symbol type
/// word cannot carry. `ZONE_TEMPS : REAL[8]` is therefore one-dimensional. `RECIPE=SSTRING` is
/// present precisely to prove the browse/validation story for an unsupported type — its `type_name`
/// maps to `supported: false` at the command layer.
const SIM_TAGS: &[(&str, &str, Option<u32>)] = &[
    ("LINE_SPEED", "REAL", None),
    ("FILL_TEMP", "REAL", None),
    ("TANK_LEVEL", "REAL", None),
    ("PRODUCT_COUNT", "DINT", None),
    ("FILL_SETPOINT", "REAL", None),
    ("ZONE_TEMPS", "REAL", Some(1)),
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

    async fn open_push(
        &self,
        cfg: &ConnectionConfig,
        io: &IoConfig,
    ) -> Result<Box<dyn PushSession>> {
        if cfg.endpoint.is_empty() {
            return Err(DeviceError::Permanent(anyhow::anyhow!(
                "no endpoint configured"
            )));
        }
        Ok(Box::new(SimPushSession::open(io)?))
    }
}

/// The in-process push (class-1 I/O) simulator: it emits **scripted [`IoUpdate`] frames** from a
/// moving assembly buffer through the *same* [`assembly_to_readings`] extraction path the real
/// backend uses, so `cargo run` on a push config works with no OpENer — mirroring how [`SimSession`]
/// stands in for a PLC. It announces `Up` once, then produces one `Data` frame per tick.
pub struct SimPushSession {
    updates: mpsc::Receiver<IoUpdate>,
    task: JoinHandle<()>,
    /// The output (O→T) layout + fields, so `set_output` validates + stages exactly like the real
    /// backend (the sim just holds the staged buffer; there is no wire).
    out_layout: Option<enip::AssemblyLayout>,
    out_fields: Vec<IoFieldSpec>,
    out_buf: Vec<u8>,
    /// The most-recent produced input frame (§7.2), for push `sb/read`.
    snapshot: Arc<Mutex<Option<InputSnapshot>>>,
}

impl SimPushSession {
    /// Build the sim push session from the validated `io` block and spawn its frame producer.
    fn open(io: &IoConfig) -> Result<Self> {
        let in_layout = io
            .input_layout()
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
        let out_layout = io
            .output_layout()
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e)))?;
        let in_fields = io.input.signals.clone();
        let in_inst = io.assemblies.input;
        let size = io.input.size_bytes;
        let out_fields = io
            .output
            .as_ref()
            .map(|o| o.signals.clone())
            .unwrap_or_default();
        let out_size = io.output.as_ref().map_or(0, |o| o.size_bytes);
        let o2t_api_ms = u32::try_from(io.effective_o2t_rpi_ms()).unwrap_or(u32::MAX);
        let t2o_api_ms = u32::try_from(io.rpi_ms).unwrap_or(u32::MAX);
        // Produce faster than 200 ms so `cargo run` shows frames quickly; never busier than 20 ms.
        let period = Duration::from_millis(io.rpi_ms.clamp(20, 200));

        let (tx, rx) = mpsc::channel(16);
        let snapshot: Arc<Mutex<Option<InputSnapshot>>> = Arc::new(Mutex::new(None));
        let snap_task = Arc::clone(&snapshot);
        let task = tokio::spawn(async move {
            if tx
                .send(IoUpdate::Up {
                    o2t_api_ms,
                    t2o_api_ms,
                })
                .await
                .is_err()
            {
                return;
            }
            let mut tick: u64 = 0;
            loop {
                tokio::time::sleep(period).await;
                tick = tick.wrapping_add(1);
                // A moving assembly buffer: a rolling byte pattern so decoded values change over time.
                let mut buf = vec![0u8; size];
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = tick.wrapping_add(i as u64) as u8;
                }
                let readings = assembly_to_readings(&in_layout, &in_fields, in_inst, &buf, true);
                let received_at = Instant::now();
                // Keep the latest snapshot live for push `sb/read` (answered even while paused).
                *snap_task.lock().unwrap() = Some(InputSnapshot {
                    readings: readings.clone(),
                    received_at,
                    run_mode: true,
                });
                let update = IoUpdate::Data {
                    readings,
                    sequence: tick as u16,
                    run_mode: true,
                    received_at,
                };
                if tx.send(update).await.is_err() {
                    return;
                }
            }
        });

        Ok(Self {
            updates: rx,
            task,
            out_layout,
            out_fields,
            out_buf: vec![0u8; out_size],
            snapshot,
        })
    }
}

#[async_trait]
impl PushSession for SimPushSession {
    fn updates(&mut self) -> &mut mpsc::Receiver<IoUpdate> {
        &mut self.updates
    }

    fn last_input(&self) -> Option<InputSnapshot> {
        self.snapshot.lock().unwrap().clone()
    }

    fn identity(&self) -> Option<DeviceIdentity> {
        Some(sim_identity())
    }

    async fn set_output(&mut self, field: &IoFieldSpec, value: &Value) -> Result<()> {
        let layout = self
            .out_layout
            .as_ref()
            .ok_or(DeviceError::Unsupported("device has no output assembly"))?;
        let key = self
            .out_fields
            .iter()
            .position(|f| {
                f.offset == field.offset && f.eip_type == field.eip_type && f.bit == field.bit
            })
            .ok_or_else(|| DeviceError::Permanent(anyhow::anyhow!("unknown output field")))?;
        let cip = crate::eip::types::encode_write(
            value,
            field.eip_type,
            field.scale,
            field.value_offset,
            field.array_count,
        )
        .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e.to_string())))?;
        layout
            .encode_into(&[(key, cip)], &mut self.out_buf)
            .map_err(|e| DeviceError::Permanent(anyhow::anyhow!(e.to_string())))?;
        tracing::info!(name = %field.name, ?value, "sim push: output staged");
        Ok(())
    }

    async fn close(&mut self) {
        self.task.abort();
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
            // The simulator answers from a tag table, not a wire: there is no declared type code to
            // observe, so it reports none (D-EIP-35). This is also the honest shape of the sim's
            // fidelity gap on the packed BOOL path — it serves byte-per-element and cannot exercise
            // the translation at all.
            observed_type: None,
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

    async fn browse(&mut self, cursor: Option<String>, max: usize) -> Result<BrowsePage> {
        // The sim mirrors the poll backend's cursor contract exactly (§7.3) — same parser, same
        // truncation rule — so a paged browse walk driven against the simulator exercises the real
        // paging and cannot mask an adapter paging bug: the cursor is the decimal symbol-instance id
        // to resume from, an uncursored walk starts at instance 0 (the bottom of the instance space,
        // one below this set's first symbol), an unreadable cursor is the caller's error, and a page
        // cut short by `max` resumes from the last tag actually returned. `RECIPE=SSTRING` is
        // included; the command layer marks it unsupported by its type name.
        let start = crate::eip::session::parse_browse_cursor(cursor.as_deref())?;
        let limit = max.max(1);
        let mut tags: Vec<BrowsedTag> = SIM_TAGS
            .iter()
            .enumerate()
            .map(|(i, (name, type_name, array_dim))| BrowsedTag {
                name: (*name).to_string(),
                type_name: (*type_name).to_string(),
                array_dim: *array_dim,
                instance_id: i as u32 + 1,
            })
            .filter(|t| t.instance_id >= start)
            .collect();
        let truncated = tags.len() > limit;
        tags.truncate(limit);
        let next_cursor = truncated
            .then(|| tags.last().and_then(|t| t.instance_id.checked_add(1)))
            .flatten()
            .map(|n| n.to_string());
        Ok(BrowsePage { tags, next_cursor })
    }

    async fn probe(&mut self) -> Result<()> {
        // The cheapest round-trip: for the sim, always alive.
        Ok(())
    }

    fn identity(&self) -> Option<DeviceIdentity> {
        Some(sim_identity())
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

    /// A `bool` array signal is **accepted and functional**, not merely parsed (D-EIP-16): it is
    /// configurable, it polls, and against a byte-per-element peer it reads back a JSON array of
    /// booleans. The label on it is experimental because that outcome is what a *simulator* gives —
    /// cpppo, which this backend models, has a fidelity gap here (a Logix controller packs BOOL
    /// arrays into DWORDs and the same signal reads BAD), so this test proves availability, never
    /// hardware correctness.
    #[tokio::test]
    async fn a_bool_array_signal_is_configurable_and_polls() {
        let cfg = crate::config::DeviceConfig::from_value(&json!({
            "id": "plc-1", "adapter": "sim",
            "connection": { "endpoint": "h" },
            "pollGroups": [ { "signals": [
                { "name": "alarms", "tagPath": "MOTOR_RUN", "type": "bool", "arrayCount": 4 } ] } ]
        }))
        .expect("a bool array is configurable");
        assert_eq!(cfg.experimental_signal_warnings().len(), 1, "and warned");

        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let specs: Vec<SignalSpec> = cfg.signals().cloned().collect();
        let r = s.read_signals(&specs).await.unwrap();
        assert_eq!(r[0].quality, Quality::Good);
        let arr = r[0].value.as_array().expect("a JSON array of booleans");
        assert_eq!(arr.len(), 4);
        assert!(arr.iter().all(serde_json::Value::is_boolean));
    }

    #[tokio::test]
    async fn a_written_setpoint_reads_back_the_written_value() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let sp = spec("fill-setpoint", "FILL_SETPOINT", "real", None);
        s.write_signal(&sp, &json!(55.5)).await.unwrap();
        let r = s.read_signals(&[sp]).await.unwrap();
        assert_eq!(
            r[0].value,
            json!(55.5),
            "the write is observable on the next poll"
        );
    }

    #[tokio::test]
    async fn browse_lists_the_tags_including_the_unsupported_recipe() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let page = s.browse(None, 1000).await.unwrap();
        assert_eq!(page.tags.len(), SIM_TAGS.len());
        assert!(page.next_cursor.is_none());
        let recipe = page.tags.iter().find(|t| t.name == "RECIPE").unwrap();
        assert_eq!(
            recipe.type_name, "SSTRING",
            "the unsupported type is surfaced by name"
        );
        let zones = page.tags.iter().find(|t| t.name == "ZONE_TEMPS").unwrap();
        assert_eq!(
            zones.array_dim,
            Some(1),
            "`REAL[8]` is ONE-dimensional: `array_dim` is the dimensionality the symbol type \
             declares (what the real backend reads from `SymbolType::dims()`), not the element \
             count — a sim that reported 8 here would make a 1-D array look multi-dimensional to \
             the `supported` rule the command layer applies (§7.5)"
        );
    }

    /// The sim pages exactly like the real backend (§4.3): a `max`-limited walk enumerates every tag
    /// **exactly once**, resuming from the last tag each page returned, and a cursor it cannot read
    /// is the caller's error rather than a silent restart at the top of the set.
    #[tokio::test]
    async fn browse_pages_with_cursor_and_rejects_garbage() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();

        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let page = s.browse(cursor.clone(), 2).await.unwrap();
            pages += 1;
            assert!(pages <= SIM_TAGS.len() + 1, "the walk must terminate");
            assert!(page.tags.len() <= 2, "`max` is honoured truthfully");
            walked.extend(page.tags.iter().map(|t| t.name.clone()));
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let expected: Vec<String> = SIM_TAGS.iter().map(|(n, _, _)| (*n).to_string()).collect();
        assert_eq!(
            walked, expected,
            "every tag exactly once, in order, no skips or repeats"
        );

        // A resume cursor is honoured mid-set.
        let mid = s.browse(Some("7".to_string()), 100).await.unwrap();
        assert_eq!(mid.tags.len(), 2, "instances 7 and 8 remain");
        assert_eq!(mid.tags[0].name, "MOTOR_RUN");
        assert!(mid.next_cursor.is_none());

        let err = s.browse(Some("x".to_string()), 100).await.unwrap_err();
        assert!(
            !err.is_transient(),
            "a corrupt cursor never fixes itself by retrying"
        );
        assert!(err.to_string().contains("invalid browse cursor"), "{err}");
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

    /// **The simulator's identity is an honest fake** (D-EIP-34). It must be legible as a nameplate
    /// — poll and push alike carry one, so the identity surfaces are exercised by `cargo run` with no
    /// hardware — while never being mistakable for a real device.
    ///
    /// The impersonation this guards against is not hypothetical: cpppo, the container this backend
    /// models, answers the Identity Object as a Rockwell `1756-L61/B LOGIX5561` under vendor
    /// `0x0001`. A simulator that copied it would put a fabricated Rockwell controller into an
    /// operator's status page and a fleet's inventory.
    #[tokio::test]
    async fn the_simulator_identifies_itself_as_a_simulator_and_impersonates_nobody() {
        let poll = SimBackend.connect(&conn("h")).await.unwrap();
        let id = poll.identity().expect("the sim names itself");

        assert_ne!(
            id.vendor_id, 0x0001,
            "the simulator must never claim Rockwell's vendor id (what cpppo does)"
        );
        assert_eq!(id.vendor_id, 0x0000, "the reserved id, assigned to nobody");
        assert!(
            id.vendor_name.is_none(),
            "a reserved vendor id has no registered name to render"
        );
        let name = id.product_name.to_lowercase();
        assert!(
            name.contains("simulator") && name.contains("not a device"),
            "the product name says what it is on its face: {}",
            id.product_name
        );
        assert_eq!(id.serial_number, 0, "a placeholder that reads as one");
        assert_eq!(id.product_code, 0);
        assert_eq!(id.revision(), "0.0");

        // The push simulator reports the SAME nameplate: one simulator, one identity, whichever mode
        // a runnable config selects.
        let push = SimBackend
            .open_push(&conn("opener"), &push_io())
            .await
            .unwrap();
        assert_eq!(push.identity(), Some(id));
    }

    #[tokio::test]
    async fn a_missing_endpoint_is_permanent() {
        let Err(e) = SimBackend.connect(&conn("")).await else {
            panic!("connecting with no endpoint must fail");
        };
        assert!(
            !e.is_transient(),
            "a missing endpoint will never fix itself by retrying"
        );
    }

    #[tokio::test]
    async fn readings_advance_over_time() {
        let mut s = SimBackend.connect(&conn("h")).await.unwrap();
        let sp = vec![spec("line-speed", "LINE_SPEED", "real", None)];
        let a = s.read_signals(&sp).await.unwrap()[0].value.clone();
        let b = s.read_signals(&sp).await.unwrap()[0].value.clone();
        assert_ne!(a, b);
    }

    fn push_io() -> IoConfig {
        serde_json::from_value(json!({
            "rpiMs": 20,
            "assemblies": { "output": 150, "input": 100 },
            "input": {
                "sizeBytes": 8,
                "signals": [
                    { "name": "din-word", "offset": 0, "type": "udint" },
                    { "name": "line-speed", "offset": 4, "type": "real" }
                ]
            },
            "output": {
                "sizeBytes": 8,
                "signals": [ { "name": "dout-word", "offset": 0, "type": "udint" } ]
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn sim_push_session_announces_up_then_produces_data_frames() {
        let io = push_io();
        let mut session = SimBackend.open_push(&conn("opener"), &io).await.unwrap();

        // First: the connection comes up with the negotiated intervals.
        match session.updates().recv().await.expect("an update") {
            IoUpdate::Up { t2o_api_ms, .. } => assert_eq!(t2o_api_ms, 20),
            other => panic!("expected Up, got {other:?}"),
        }
        // Then: scripted data frames, each carrying one Reading per input field.
        match session.updates().recv().await.expect("a data frame") {
            IoUpdate::Data { readings, .. } => {
                assert_eq!(readings.len(), 2);
                assert_eq!(readings[0].name.as_deref(), Some("din-word"));
                assert_eq!(readings[0].signal_id, "a100/0/udint");
            }
            other => panic!("expected Data, got {other:?}"),
        }
        session.close().await;
    }

    #[tokio::test]
    async fn sim_push_set_output_validates_and_stages() {
        let io = push_io();
        let mut session = SimBackend.open_push(&conn("opener"), &io).await.unwrap();
        let field = io.output.as_ref().unwrap().signals[0].clone();
        session.set_output(&field, &json!(42)).await.unwrap();
        // A value out of range for the field type is a typed failure, not a clamp.
        let bad = session.set_output(&field, &json!(-1)).await;
        assert!(bad.is_err(), "udint cannot hold -1");
        session.close().await;
    }
}
