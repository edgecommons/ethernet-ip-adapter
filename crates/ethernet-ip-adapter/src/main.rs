//! # EthernetIpAdapter — entry point
//!
//! An AWS IoT Greengrass v2 component built on the `edgecommons` Rust library.
//! Initializes the runtime from the standard CLI contract (`-c`/`--platform`/`--transport`/`-t`),
//! then hands control to [`app::App`]. The component runs until a shutdown signal
//! (Ctrl-C / SIGTERM); dropping the [`edgecommons::EdgeCommons`] runtime then releases
//! all resources (RAII).
//!
//! ## Running locally (HOST platform, MQTT transport, against a local MQTT broker)
//! From the workspace root (`-p` selects this binary; the config paths are relative to it):
//! ```bash
//! cargo run -p ethernet-ip-adapter -- \
//!   --platform HOST --transport MQTT ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
//!   -c FILE ./crates/ethernet-ip-adapter/test-configs/config.json \
//!   -t my-thing
//! ```

mod app;
mod config;
mod device;
mod sim;

use edgecommons::prelude::*;

/// The component's full name (matches `recipe.yaml` / `gdk-config.json`).
const COMPONENT_NAME: &str = "com.mbreissi.edgecommons.EthernetIpAdapter";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let gg = EdgeCommonsBuilder::new(COMPONENT_NAME)
        .args(std::env::args_os())
        .build()
        .await?;

    tracing::info!(
        component = gg.component_name(),
        identity = %gg.config().identity().path(),
        "EthernetIpAdapter starting"
    );

    let app = app::App::new(&gg)?;
    app.run(&gg).await?;

    tracing::info!("EthernetIpAdapter stopped");
    Ok(())
}
