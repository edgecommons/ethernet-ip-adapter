//! # Test doubles (`#[cfg(test)]` only) — excluded from the coverage denominator (§12.2)
//!
//! Recording [`MetricService`] + [`EventSink`] implementations plus small constructors, shared by the
//! `app` and `commands` unit tests so the pause-reflection surfaces and the `write-audit`/command
//! metrics can be observed without a live messaging inbox.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edgecommons::prelude::{Config, Metric, MetricService, Severity};
use serde_json::{json, Value};

use crate::app::EventSink;
use crate::config::{DeviceConfig, GlobalConfig};
use crate::metrics::DeviceMetrics;

/// A [`MetricService`] that records every emit, so a test can read the last `southbound_health`
/// (e.g. the `paused` gauge).
#[derive(Default)]
pub struct RecordingMetrics {
    pub emitted: Mutex<Vec<(String, HashMap<String, f64>)>>,
}

impl RecordingMetrics {
    /// The most recent emit of `name`, or `None`.
    pub fn last(&self, name: &str) -> Option<HashMap<String, f64>> {
        self.emitted
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }
}

#[async_trait]
impl MetricService for RecordingMetrics {
    fn define_metric(&self, _metric: Metric) {}
    fn is_metric_defined(&self, _name: &str) -> bool {
        true
    }
    async fn emit_metric(&self, name: &str, values: HashMap<String, f64>) -> edgecommons::Result<()> {
        self.emitted.lock().unwrap().push((name.to_string(), values));
        Ok(())
    }
    async fn emit_metric_now(&self, name: &str, values: HashMap<String, f64>) -> edgecommons::Result<()> {
        self.emitted.lock().unwrap().push((name.to_string(), values));
        Ok(())
    }
    async fn flush_metrics(&self) -> edgecommons::Result<()> {
        Ok(())
    }
    async fn shutdown(&self) {}
}

/// An [`EventSink`] that records every emitted event / alarm as `(kind, type, context)`.
#[derive(Default)]
pub struct RecordingEvents {
    pub events: Mutex<Vec<(String, String, Value)>>,
}

impl RecordingEvents {
    /// Whether an event of `event_type` was emitted.
    pub fn has(&self, event_type: &str) -> bool {
        self.events.lock().unwrap().iter().any(|(_, t, _)| t == event_type)
    }
    /// The context of the last event of `event_type`.
    pub fn last_ctx(&self, event_type: &str) -> Option<Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, t, _)| t == event_type)
            .map(|(_, _, c)| c.clone())
    }
    /// How many events of `event_type` were emitted.
    pub fn count(&self, event_type: &str) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, t, _)| t == event_type).count()
    }
}

#[async_trait]
impl EventSink for RecordingEvents {
    async fn emit(&self, _severity: Severity, event_type: &str, _message: Option<String>, context: Option<Value>) {
        self.events
            .lock()
            .unwrap()
            .push(("emit".into(), event_type.to_string(), context.unwrap_or(Value::Null)));
    }
    async fn raise_alarm(&self, _severity: Severity, event_type: &str, _message: Option<String>, context: Option<Value>) {
        self.events
            .lock()
            .unwrap()
            .push(("raise".into(), event_type.to_string(), context.unwrap_or(Value::Null)));
    }
    async fn clear_alarm(&self, _severity: Severity, event_type: &str, context: Option<Value>) {
        self.events
            .lock()
            .unwrap()
            .push(("clear".into(), event_type.to_string(), context.unwrap_or(Value::Null)));
    }
}

/// A minimal [`Config`] for building a [`DeviceMetrics`] in tests.
pub fn config() -> Arc<Config> {
    Arc::new(
        Config::from_value(
            "com.example.EthernetIpAdapter",
            "thing-1",
            json!({ "metricEmission": { "target": "log", "namespace": "test" } }),
        )
        .unwrap(),
    )
}

/// Build a [`DeviceMetrics`] over a fresh [`RecordingMetrics`] for `device`, returning both.
pub fn device_metrics(
    device: DeviceConfig,
    health: Arc<crate::app::Health>,
) -> (Arc<RecordingMetrics>, Arc<DeviceMetrics>) {
    let svc = Arc::new(RecordingMetrics::default());
    let global = GlobalConfig::default();
    let dm = Arc::new(DeviceMetrics::new(svc.clone(), config(), device, &global, health));
    (svc, dm)
}
