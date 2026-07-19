//! # The publish sink (§6.1, §6.2) — the live-broker seam (excluded from coverage, §12.2)
//!
//! A **one-function driver seam**: [`publish`] assembles the `SouthboundSignalUpdate` (via the pure,
//! unit-tested [`crate::publish::build_update`]) and drives `data.publish().await` on the live `data()`
//! facade, measuring the publish latency. It carries no branching — the assembly and gate decisions are
//! tested in [`crate::publish`]; only the `.await` on the broker lives here (validated by the HOST /
//! full-system E2E and the S9 deployed regression, like `file-replicator`'s `dest/*/client.rs`).

use std::time::{Duration, Instant};

use edgecommons::prelude::{DataFacade, Sample};
use serde_json::Value;

use crate::publish::{build_update, DeviceParts};

/// The single publish call both engines use (§6.1): assemble the update and publish it, returning the
/// result and the **publish latency** — the wall time of the `data.publish().await` (§6.2, recorded
/// into `southbound_health.publishLatencyMs` / `EtherNetIpPublish.publishLatencyMs`).
pub(crate) async fn publish(
    data: &DataFacade,
    stable_id: &str,
    name: &str,
    address: Value,
    device: &DeviceParts<'_>,
    samples: Vec<Sample>,
) -> (std::result::Result<(), String>, Duration) {
    let update = build_update(stable_id, name, address, device, samples);
    let start = Instant::now();
    let res = data.publish(update).await;
    let latency = start.elapsed();
    (res.map_err(|e| e.to_string()), latency)
}
