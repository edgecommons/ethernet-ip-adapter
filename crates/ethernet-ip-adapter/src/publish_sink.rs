//! # The production publish sink (§6.1) — the live-broker [`Publisher`]
//!
//! The whole file is the one implementation of [`crate::publish::Publisher`] that needs a live
//! broker: it hands the already-assembled `SouthboundSignalUpdate` to the `data()` facade. There is
//! no branching and no assembly here — [`crate::publish::publish_via`] builds the update and measures
//! the latency, and the gate decisions live in [`crate::publish`]; only the `.await` on the facade is
//! here. It stays inside the coverage denominator and reads uncovered, because the `data()` facade
//! cannot be constructed offline (the core library exposes no offline `EdgeCommons` constructor to
//! dependents). It is exercised by the HOST / full-system E2E and the deployed regression.

use edgecommons::prelude::{DataFacade, SignalUpdate};

use crate::publish::Publisher;

/// Production [`Publisher`] over the `data()` facade. The only line of publish code that needs a
/// live broker.
pub(crate) struct FacadePublisher(pub DataFacade);

#[async_trait::async_trait]
impl Publisher for FacadePublisher {
    async fn publish_update(&self, update: SignalUpdate) -> std::result::Result<(), String> {
        self.0.publish(update).await.map_err(|e| e.to_string())
    }
}
