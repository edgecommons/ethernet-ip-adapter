//! # The certificate-lifecycle driver (CIP Security Phase 2b/2c, §4.2/§4.3)
//!
//! One task per TLS poll instance. On the `reloadIntervalSecs` cadence it enrolls/renews the
//! adapter's own client certificate (Phase 2c, EST) and watches the vault for rotated material and
//! expiry-threshold crossings (Phase 2b):
//!
//! * **EST first, rotation second, deliberately** — a fresh enrollment's vault write is observed by
//!   the watcher *this same tick*, so a renewal ends in a `cert-rotated` + reconnect rather than
//!   waiting a whole cadence for the new material to take effect;
//! * on a **rotation** (the client cert and/or a trust-store CA changed) it bumps `certReloads`,
//!   emits `cert-rotated`, and sends a `reconnect` so the next handshake uses the fresh material
//!   (the connect path always rebuilds the `ClientConfig` from the latest vault contents);
//! * on the transition into **near-expiry** (`renewBeforeDays`) it emits `cert-expiring`, and into
//!   **expired** it emits `cert-expired`;
//! * every tick it refreshes the `certExpiryDays` gauge.
//!
//! It never blocks polling: a vault-read error is logged and the loop continues on the current
//! material (offline-first). The decisions it composes are pure and live in
//! [`crate::eip::rotation::CertWatcher`] and [`crate::eip::est::EstScheduler`]; what this file owns
//! is the *sequencing* — enroll-then-observe, the event/metric/status bookkeeping around each
//! action, the retry spacing, and the teardown paths — and all of it is decided over injected seams
//! (the vault is a `CredentialService`, events/metrics are traits, the reconnect trigger is the
//! device's control channel), so it runs under unit test in `#[cfg(test)] mod tests` below.

use std::sync::Arc;
use std::time::{Duration, Instant};

use edgecommons::credentials::CredentialService;
use edgecommons::prelude::Severity;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::app::{DeviceControl, EventSink, Health};
use crate::config::DeviceConfig;
use crate::metrics::DeviceMetrics;

/// The lifecycle body (Phase 2b rotation/expiry + Phase 2c EST enroll/renew), parameterized on an
/// optional shared [`Health`] so the EST state can be surfaced on `sb/status.security.est`.
///
/// `cancel` ends the task at the tick boundary (§10.3). A cancel landing **mid-EST-exchange** (itself
/// bounded at 20 s) is deliberately not selected against; that task is instead reaped by
/// [`crate::lifecycle::stop_tasks`]'s abort at the end of the teardown budget. That is safe: the EST
/// client holds no device session, its vault write is atomic in the credential service, and
/// enrollment is idempotent — an interrupted exchange simply re-enrolls on the next start.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_security_lifecycle(
    cfg: DeviceConfig,
    creds: Option<Arc<dyn CredentialService>>,
    control: tokio::sync::mpsc::Sender<DeviceControl>,
    events: Arc<dyn EventSink>,
    dm: Arc<DeviceMetrics>,
    health: Option<Arc<Health>>,
    cancel: CancellationToken,
) {
    use crate::eip::est::{enroll_once, next_renew_rfc3339, EstDecision, EstScheduler, EstStatus};
    use crate::eip::rotation::{read_reload_state, CertWatcher, WatchAction};
    use crate::eip::tls::{
        SecurityConfig, DEFAULT_RELOAD_INTERVAL_SECS, DEFAULT_RENEW_BEFORE_DAYS,
    };

    let Some(sec) = SecurityConfig::from_connection(&cfg.connection)
        .ok()
        .flatten()
        .filter(SecurityConfig::is_tls)
    else {
        return;
    };
    let interval_secs = sec
        .reload_interval_secs
        .unwrap_or(DEFAULT_RELOAD_INTERVAL_SECS);

    // CIP Security Phase 2c: EST enrollment/renewal (off unless `est.enabled`).
    let est = sec.est_enabled().cloned();
    let est_renew_days = est
        .as_ref()
        .map_or(DEFAULT_RENEW_BEFORE_DAYS, |e| e.renew_before_days(&sec));
    let est_backoff = est
        .as_ref()
        .map_or(Duration::from_secs(3600), |e| e.retry_backoff());
    // A generous fixed deadline for the whole EST exchange (connect + handshake + request/reply); EST
    // is a background provisioning step, never on the polling hot path.
    let connect_timeout = Duration::from_secs(20);
    let mut est_last_attempt: Option<Instant> = None;
    if let (Some(e), Some(h)) = (&est, &health) {
        h.set_est(Some(EstStatus {
            enabled: true,
            server: e.server.clone(),
            ..EstStatus::default()
        }));
    }

    // With EST disabled and rotation-watching disabled, there is nothing to do.
    if interval_secs == 0 && est.is_none() {
        // Rotation is then picked up only on a natural reconnect (the connect path rebuilds anyway).
        return;
    }
    // When only EST is on but the reload watcher is disabled, still tick (default cadence) to enroll.
    let tick_secs = if interval_secs == 0 {
        DEFAULT_RELOAD_INTERVAL_SECS
    } else {
        interval_secs
    };
    let renew_before_days = sec
        .client
        .as_ref()
        .and_then(|c| c.renew_before_days)
        .map_or(DEFAULT_RENEW_BEFORE_DAYS, i64::from);

    let mut watcher = CertWatcher::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(tick_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let now = time::OffsetDateTime::now_utc();

        // ---- Phase 2c: EST enrollment/renewal, BEFORE the rotation re-read so a fresh enrollment's
        // vault write is observed by the watcher this same tick (⇒ Rotated ⇒ reconnect). ----
        if let Some(e) = &est {
            // The current cert's days-to-expiry drives the enroll decision (None ⇒ initial enroll).
            let current_days = read_reload_state(&sec, creds.as_ref(), now)
                .ok()
                .and_then(|s| s.client.map(|c| c.expiry_days))
                .filter(|d| *d != i64::MAX);
            let since = est_last_attempt.map(|t| t.elapsed());
            if let EstDecision::Enroll { reenroll } =
                EstScheduler::decide(current_days, est_renew_days, since, est_backoff)
            {
                est_last_attempt = Some(Instant::now());
                match enroll_once(e, &sec, creds.as_ref(), reenroll, connect_timeout).await {
                    Ok(out) => {
                        dm.on_est_enrollment(true);
                        let next_renew =
                            next_renew_rfc3339(out.not_after.as_deref(), est_renew_days);
                        if let Some(h) = &health {
                            let prev = h.est().unwrap_or_default();
                            h.set_est(Some(EstStatus {
                                enabled: true,
                                server: e.server.clone(),
                                last_enroll: now
                                    .format(&time::format_description::well_known::Rfc3339)
                                    .ok(),
                                next_renew,
                                last_error: None,
                                enrollments: prev.enrollments + 1,
                                failures: prev.failures,
                            }));
                        }
                        events
                            .emit(
                                Severity::Info,
                                "cert-enrolled",
                                Some(format!(
                                    "EST {} succeeded for {} — wrote the new certificate to `{}`",
                                    if reenroll {
                                        "re-enrollment"
                                    } else {
                                        "enrollment"
                                    },
                                    cfg.connection.endpoint,
                                    out.written_to
                                )),
                                Some(json!({
                                    "instance": cfg.id, "security": "tls",
                                    "serial": out.serial, "notAfter": out.not_after,
                                    "reenroll": reenroll
                                })),
                            )
                            .await;
                    }
                    Err(err) => {
                        dm.on_est_enrollment(false);
                        if let Some(h) = &health {
                            let prev = h.est().unwrap_or_default();
                            h.set_est(Some(EstStatus {
                                enabled: true,
                                server: e.server.clone(),
                                last_enroll: prev.last_enroll,
                                next_renew: prev.next_renew,
                                last_error: Some(err.clone()),
                                enrollments: prev.enrollments,
                                failures: prev.failures + 1,
                            }));
                        }
                        events
                            .emit(
                                Severity::Warning,
                                "cert-enroll-failed",
                                Some(format!(
                                    "EST enrollment for {} failed: {err} — keeping the current \
                                     certificate; will retry",
                                    cfg.connection.endpoint
                                )),
                                Some(json!({ "instance": cfg.id, "security": "tls" })),
                            )
                            .await;
                    }
                }
            }
        }

        // ---- Phase 2b: rotation / expiry watch (also picks up a fresh EST enrollment's vault write). ----
        let state = match read_reload_state(&sec, creds.as_ref(), now) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(instance = %cfg.id, error = %e, "cert-lifecycle re-read failed (ignored)");
                continue;
            }
        };
        let outcome = watcher.observe(&state, renew_before_days);
        if let Some(days) = outcome.expiry_days {
            dm.set_cert_expiry_days(days);
        }
        for action in outcome.actions {
            match action {
                WatchAction::Rotated { serial, not_after } => {
                    dm.on_cert_reload();
                    events
                        .emit(
                            Severity::Info,
                            "cert-rotated",
                            Some(format!(
                                "client certificate / trust store rotated for {} — reconnecting to \
                                 apply the new material",
                                cfg.connection.endpoint
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls",
                                "serial": serial, "notAfter": not_after
                            })),
                        )
                        .await;
                    // Trigger a graceful reconnect (the reply is not needed here).
                    let (reply, _rx) = tokio::sync::oneshot::channel();
                    if control
                        .send(DeviceControl::Reconnect { reply })
                        .await
                        .is_err()
                    {
                        // The device task ended — nothing left to serve.
                        return;
                    }
                }
                WatchAction::Expiring { days, not_after } => {
                    events
                        .emit(
                            Severity::Warning,
                            "cert-expiring",
                            Some(format!(
                                "adapter client certificate expires in {days} day(s) — rotate it \
                                 (e.g. ec-secrets) before it lapses"
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls",
                                "daysRemaining": days, "notAfter": not_after
                            })),
                        )
                        .await;
                }
                WatchAction::Expired { days, not_after } => {
                    events
                        .emit(
                            Severity::Warning,
                            "cert-expired",
                            Some(format!(
                                "adapter client certificate EXPIRED {} day(s) ago — TLS connects will \
                                 fail until it is rotated",
                                -days
                            )),
                            Some(json!({
                                "instance": cfg.id, "security": "tls", "notAfter": not_after
                            })),
                        )
                        .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The cert-lifecycle driver, run against a real [`LocalVault`] in a tempdir and (for the
    //! Phase-2c legs) the in-process rustls EST responder from [`crate::testutil::pki`].
    //!
    //! **Clocks.** The rotation-only legs run on a paused clock: the driver's `reloadIntervalSecs: 1`
    //! ticker and the test's own sleeps are the only timers, so "let it finish tick N, then rotate
    //! the vault" is deterministic. The EST legs run on the **real** clock — they perform real
    //! loopback TLS I/O, which a paused clock would race past.

    use super::*;
    use crate::app::Health;
    use crate::config::GlobalConfig;
    use crate::device::ConnectionConfig;
    use crate::metrics::CONNECTION;
    use crate::testutil::{device_metrics_with, pki, RecordingEvents, RecordingMetrics};
    use edgecommons::credentials::{
        CredentialService, DefaultCredentialService, FileKeyProvider, KeyProvider, LocalVault,
        PutOptions,
    };
    use serde_json::{json, Value};
    use tokio::sync::mpsc;

    /// A vault in a tempdir (the dir must outlive the vault, hence the returned guard).
    fn vault(seed: u8) -> (Arc<dyn CredentialService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(FileKeyProvider::from_bytes([seed; 32])) as Arc<dyn KeyProvider>;
        let v = LocalVault::open(dir.path().join("vault"), provider, 3).unwrap();
        (Arc::new(DefaultCredentialService::new(v)), dir)
    }

    /// A TLS poll instance carrying `security`.
    fn tls_device(security: Value) -> DeviceConfig {
        DeviceConfig::from_value(&json!({
            "id": "plc-1",
            "connection": { "endpoint": "127.0.0.1:2221", "security": security },
            "pollGroups": [ { "signals": [
                { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real" } ] } ]
        }))
        .expect("a valid TLS device config")
    }

    /// One minted client identity: cert + key PEM, with `notAfter` `days_from_now` out (negative ⇒
    /// already expired), signed by a fresh CA.
    struct Material {
        cert_pem: String,
        key_pem: String,
        ca_pem: String,
    }

    fn mint(days_from_now: i64) -> Material {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use time::Duration as TD;

        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut cp = CertificateParams::new(vec!["eip-originator".to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        cp.not_before = now - TD::days(1);
        cp.not_after = now + TD::days(days_from_now);
        let key = KeyPair::generate().unwrap();
        let cert = cp.signed_by(&key, &ca_cert, &ca_key).unwrap();

        Material {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            ca_pem: ca_cert.pem(),
        }
    }

    /// Write `m` into the vault as the inline-`$secret` client identity + trust root.
    fn put_material(creds: &Arc<dyn CredentialService>, m: &Material) {
        creds
            .put("tls/cert", m.cert_pem.as_bytes(), PutOptions::default())
            .unwrap();
        creds
            .put("tls/key", m.key_pem.as_bytes(), PutOptions::default())
            .unwrap();
        creds
            .put("tls/root", m.ca_pem.as_bytes(), PutOptions::default())
            .unwrap();
    }

    /// Write `m` into the vault as a `{certPem, keyPem}` bundle at `name` (the `certSecret` style
    /// EST enrolls into).
    fn put_bundle(creds: &Arc<dyn CredentialService>, name: &str, m: &Material) {
        let bundle = json!({ "certPem": m.cert_pem, "keyPem": m.key_pem });
        creds
            .put(
                name,
                serde_json::to_vec(&bundle).unwrap().as_slice(),
                PutOptions::default(),
            )
            .unwrap();
    }

    /// The inline-`$secret` security block the rotation legs watch, at a one-second cadence.
    fn watch_security(renew_before_days: Option<u32>) -> Value {
        let mut client = json!({
            "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" }
        });
        if let Some(d) = renew_before_days {
            client["renewBeforeDays"] = json!(d);
        }
        json!({
            "mode": "tls", "reloadIntervalSecs": 1,
            "client": client,
            "ca": { "cert": { "$secret": "tls/root" } }
        })
    }

    /// Everything one lifecycle run needs; the driver is spawned so the test can drive the vault
    /// between ticks.
    struct Rig {
        cfg: DeviceConfig,
        creds: Arc<dyn CredentialService>,
        _dir: tempfile::TempDir,
        health: Arc<Health>,
        metrics: Arc<RecordingMetrics>,
        dm: Arc<DeviceMetrics>,
        events: Arc<RecordingEvents>,
        tx: Option<mpsc::Sender<DeviceControl>>,
        rx: mpsc::Receiver<DeviceControl>,
        cancel: CancellationToken,
    }

    impl Rig {
        fn new(cfg: DeviceConfig, seed: u8) -> Self {
            let (creds, dir) = vault(seed);
            let health = Arc::new(Health::default());
            let global = GlobalConfig::default();
            let (metrics, dm) = device_metrics_with(cfg.clone(), &global, Arc::clone(&health));
            let (tx, rx) = mpsc::channel(8);
            Self {
                cfg,
                creds,
                _dir: dir,
                health,
                metrics,
                dm,
                events: Arc::new(RecordingEvents::default()),
                tx: Some(tx),
                rx,
                cancel: CancellationToken::new(),
            }
        }

        /// Spawn the driver; the returned handle completes when it returns.
        fn spawn(&self) -> tokio::task::JoinHandle<()> {
            tokio::spawn(run_security_lifecycle(
                self.cfg.clone(),
                Some(Arc::clone(&self.creds)),
                self.tx.clone().expect("the control sender is still open"),
                Arc::clone(&self.events) as Arc<dyn EventSink>,
                Arc::clone(&self.dm),
                Some(Arc::clone(&self.health)),
                self.cancel.clone(),
            ))
        }

        /// Drop the control sender the driver was given (the device task ending).
        fn close_control(&mut self) {
            self.tx = None;
        }

        /// The `certExpiryDays` gauge as the metric surface would report it right now.
        async fn cert_expiry_gauge(&self) -> Option<f64> {
            self.dm.emit_now().await;
            self.metrics
                .last(CONNECTION)
                .and_then(|v| v.get("certExpiryDays").copied())
        }

        /// One `<measure>Total` from the last `EtherNetIpConnection` row (§8's Total/Interval pair
        /// convention — the Total is monotonic across the run). Flushes first, so a counter bumped
        /// since the last emit is visible.
        async fn conn_total(&self, measure: &str) -> f64 {
            self.dm.emit_now().await;
            self.metrics
                .last(CONNECTION)
                .expect("EtherNetIpConnection was never emitted")
                .get(&format!("{measure}Total"))
                .copied()
                .unwrap_or_else(|| panic!("EtherNetIpConnection carries no {measure}Total"))
        }
    }

    // ---- the no-op cases ----

    /// A plaintext instance, or a TLS instance with the watcher disabled and no EST, must return —
    /// not sit in a ticker doing nothing for the life of the process, once per instance.
    #[tokio::test(start_paused = true)]
    async fn not_tls_or_watch_disabled_without_est_returns_immediately() {
        for security in [
            json!({ "mode": "plaintext" }),
            json!({ "mode": "tls", "reloadIntervalSecs": 0,
                    "client": { "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" } },
                    "ca": { "cert": { "$secret": "tls/root" } } }),
        ] {
            let rig = Rig::new(tls_device(security.clone()), 71);
            tokio::time::timeout(Duration::from_secs(5), rig.spawn())
                .await
                .unwrap_or_else(|_| panic!("the driver never returned for {security}"))
                .unwrap();
        }
        // The same holds for a connection with no `security` block at all.
        let cfg = DeviceConfig::from_value(&json!({
            "id": "plc-1", "connection": { "endpoint": "127.0.0.1:44818" },
            "pollGroups": [ { "signals": [
                { "name": "s", "tagPath": "S", "type": "real" } ] } ]
        }))
        .unwrap();
        let rig = Rig::new(cfg, 72);
        tokio::time::timeout(Duration::from_secs(5), rig.spawn())
            .await
            .unwrap()
            .unwrap();
    }

    // ---- Phase 2b: rotation + expiry ----

    /// The Phase-2b core loop: material swapped in the vault ⇒ `certReloads` + `cert-rotated` + a
    /// `Reconnect` on the control channel, because only a reconnect makes the new material take
    /// effect (the connect path rebuilds the `ClientConfig` from the vault).
    #[tokio::test(start_paused = true)]
    async fn rotation_emits_cert_rotated_and_requests_reconnect() {
        let mut rig = Rig::new(tls_device(watch_security(None)), 73);
        put_material(&rig.creds, &mint(400));
        let driver = rig.spawn();

        // Tick 1 (immediate) establishes the baseline; then rotate the vault material.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !rig.events.has("cert-rotated"),
            "the first observation is a baseline, not a rotation"
        );
        put_material(&rig.creds, &mint(500));

        // Tick 2 sees the change.
        let msg = tokio::time::timeout(Duration::from_secs(5), rig.rx.recv())
            .await
            .expect("a reconnect was requested")
            .expect("the control channel is open");
        assert!(matches!(msg, DeviceControl::Reconnect { .. }));
        assert!(rig.events.has("cert-rotated"));
        assert_eq!(
            rig.events.last_ctx("cert-rotated").unwrap()["security"],
            json!("tls")
        );
        rig.cancel.cancel();
        driver.await.unwrap();
        assert!(
            rig.conn_total("certReloads").await >= 1.0,
            "the rotation is counted for the fleet view"
        );
    }

    /// §4.2 threshold edges: a cert inside `renewBeforeDays` warns once, an expired one warns once
    /// more, and the `certExpiryDays` gauge tracks both — negative when it has lapsed.
    #[tokio::test(start_paused = true)]
    async fn expiring_then_expired_events_fire_on_transitions_and_gauge_updates() {
        let mut rig = Rig::new(tls_device(watch_security(Some(30))), 74);
        put_material(&rig.creds, &mint(10));
        let driver = rig.spawn();

        // Tick 1: the baseline already evaluates expiry, so a cert that is ALREADY near expiry at
        // startup warns immediately rather than one cadence later.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(rig.events.count("cert-expiring"), 1);
        let days = rig
            .cert_expiry_gauge()
            .await
            .expect("the gauge is set on the first tick");
        assert!((9.0..=10.0).contains(&days), "≈10 days to expiry: {days}");

        // Rotate to an already-expired cert: Rotated + Expired, each once.
        put_material(&rig.creds, &mint(-2));
        tokio::time::timeout(Duration::from_secs(5), rig.rx.recv())
            .await
            .expect("the rotation still requests a reconnect")
            .unwrap();
        // Let the tick that follows re-observe the same (expired) material.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(
            rig.events.count("cert-expired"),
            1,
            "expired warns once, not every tick"
        );
        assert_eq!(
            rig.events.count("cert-expiring"),
            1,
            "and the earlier warning does not repeat"
        );
        let days = rig
            .cert_expiry_gauge()
            .await
            .expect("the gauge follows the rotated cert");
        assert!(days < 0.0, "an expired cert reports negative days: {days}");
        rig.cancel.cancel();
        driver.await.unwrap();
    }

    /// Offline-first: a vault hiccup (a missing/unreadable secret) is logged and skipped — it must
    /// not kill the driver, or a transient vault error would silently end certificate management
    /// for the life of the process.
    #[tokio::test(start_paused = true)]
    async fn vault_read_error_is_ignored_and_the_loop_continues() {
        let mut rig = Rig::new(tls_device(watch_security(None)), 75);
        // Nothing in the vault yet ⇒ the first tick's read fails.
        let driver = rig.spawn();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            rig.events.events.lock().unwrap().is_empty(),
            "a failed read emits nothing"
        );

        // Provide material (tick 2 baselines it), then rotate it (tick 3 must still be running).
        put_material(&rig.creds, &mint(400));
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        put_material(&rig.creds, &mint(500));

        let msg = tokio::time::timeout(Duration::from_secs(5), rig.rx.recv())
            .await
            .expect("the driver survived the vault error and kept watching")
            .unwrap();
        assert!(matches!(msg, DeviceControl::Reconnect { .. }));
        rig.cancel.cancel();
        driver.await.unwrap();
    }

    /// §10.3 teardown: the token ends the task at the tick boundary.
    #[tokio::test(start_paused = true)]
    async fn cancel_stops_at_the_tick_boundary() {
        let rig = Rig::new(tls_device(watch_security(None)), 76);
        put_material(&rig.creds, &mint(400));
        let driver = rig.spawn();
        tokio::time::sleep(Duration::from_millis(500)).await;
        rig.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .expect("a cancelled lifecycle task returns")
            .unwrap();
    }

    /// The device task going away takes its lifecycle task with it: the `Reconnect` send fails and
    /// the driver returns, instead of leaking one ticking task per replaced instance.
    #[tokio::test(start_paused = true)]
    async fn device_task_gone_ends_the_lifecycle_task() {
        let mut rig = Rig::new(tls_device(watch_security(None)), 77);
        put_material(&rig.creds, &mint(400));
        let driver = rig.spawn();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The device task ends: its receiver drops, and so does the rig's spare sender.
        rig.close_control();
        drop(rig.rx);
        // A rotation now has nowhere to send its reconnect.
        put_material(&rig.creds, &mint(500));

        tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .expect("the lifecycle task ended with its device task")
            .unwrap();
        assert!(
            rig.events.has("cert-rotated"),
            "it did observe the rotation before returning"
        );
    }

    // ---- Phase 2c: EST enrollment (real clock — real loopback TLS) ----

    /// The documented Phase-2c ⇒ Phase-2b handoff, end to end against the in-process EST responder:
    /// a renewal writes the issued certificate into the vault, and the SAME tick's rotation read
    /// observes it ⇒ `cert-rotated` ⇒ a reconnect, so the freshly enrolled certificate is actually
    /// used instead of sitting in the vault until the next natural reconnect.
    #[tokio::test]
    async fn est_enroll_success_updates_status_events_and_the_same_tick_watcher_reconnects() {
        let certs = pki::mint_certs();
        let port = pki::spawn_est_server(&certs, pki::est_http_200(pki::GOLDEN_PKCS7_B64)).await;
        let security = json!({
            "mode": "tls", "reloadIntervalSecs": 1,
            "client": { "certSecret": "ot/originator" },
            "ca": { "secret": "est/ca" },
            "est": {
                "enabled": true,
                "server": format!("https://127.0.0.1:{port}/.well-known/est"),
                "trust": { "secret": "est/ca" },
                "renewBeforeDays": 30,
                "auth": { "bootstrap": {
                    "cert": { "$secret": "boot/cert" }, "key": { "$secret": "boot/key" } } },
                "into": { "certSecret": "ot/originator" }
            }
        });
        let mut rig = Rig::new(tls_device(security), 78);
        rig.creds
            .put(
                "boot/cert",
                certs.client_cert_pem.as_bytes(),
                PutOptions::default(),
            )
            .unwrap();
        rig.creds
            .put(
                "boot/key",
                certs.client_key_pem.as_bytes(),
                PutOptions::default(),
            )
            .unwrap();
        rig.creds
            .put("est/ca", certs.ca_pem.as_bytes(), PutOptions::default())
            .unwrap();
        // A healthy certificate: tick 1 enrolls nothing and just baselines the watcher.
        put_bundle(&rig.creds, "ot/originator", &mint(400));
        let driver = rig.spawn();

        // Mid-cadence, the cert moves inside the renew window — tick 2 must re-enroll.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !rig.events.has("cert-enrolled"),
            "a healthy certificate is not renewed"
        );
        put_bundle(&rig.creds, "ot/originator", &mint(5));

        let msg = tokio::time::timeout(Duration::from_secs(15), rig.rx.recv())
            .await
            .expect("the enrollment's vault write drove a reconnect")
            .unwrap();
        assert!(matches!(msg, DeviceControl::Reconnect { .. }));
        rig.cancel.cancel();
        driver.await.unwrap();

        // The enrollment itself.
        let enrolled = rig
            .events
            .last_ctx("cert-enrolled")
            .expect("cert-enrolled emitted");
        assert_eq!(enrolled["serial"], json!(pki::GOLDEN_SERIAL));
        assert_eq!(
            enrolled["reenroll"],
            json!(true),
            "a current cert re-enrolls, not enrolls"
        );
        // …observed by the watcher on the same tick, naming the ENROLLED certificate.
        assert_eq!(
            rig.events
                .last_ctx("cert-rotated")
                .expect("cert-rotated emitted")["serial"],
            json!(pki::GOLDEN_SERIAL),
            "the watcher saw the enrolled material, not the pre-enrollment cert"
        );
        // …and the status surface an operator reads.
        let est = rig.health.est().expect("est status");
        assert!(est.enabled && est.enrollments == 1 && est.failures == 0);
        assert!(est.last_enroll.is_some() && est.next_renew.is_some());
        assert!(est.last_error.is_none());
        assert!(rig.conn_total("estEnrollments").await >= 1.0);
        assert!(rig.conn_total("certReloads").await >= 1.0);
    }

    /// §4.3 backoff plumbing: a failing EST server is retried on the configured spacing, NOT on
    /// every tick — otherwise a down EST server means one enrollment storm per instance.
    #[tokio::test]
    async fn est_failure_emits_enroll_failed_and_respects_retry_backoff() {
        // A port nothing listens on (bound, then released) ⇒ a fast, deterministic failure.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);

        let security = json!({
            "mode": "tls", "reloadIntervalSecs": 1,
            "client": { "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" } },
            "ca": { "cert": { "$secret": "tls/root" } },
            "est": {
                "enabled": true,
                "server": format!("https://127.0.0.1:{port}/.well-known/est"),
                "trust": { "cert": { "$secret": "tls/root" } },
                "renewBeforeDays": 30,
                "retryBackoffMins": 60,
                "into": { "cert": "tls/cert", "key": "tls/key" }
            }
        });
        let rig = Rig::new(tls_device(security), 79);
        // Inside the renew window ⇒ every tick would enroll if the backoff were not honoured.
        put_material(&rig.creds, &mint(5));
        let driver = rig.spawn();

        // Three ticks (t = 0, 1, 2 s) — one attempt.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        rig.cancel.cancel();
        driver.await.unwrap();

        assert_eq!(
            rig.events.count("cert-enroll-failed"),
            1,
            "one attempt across three ticks — the retry backoff is honoured"
        );
        assert_eq!(rig.conn_total("estFailures").await, 1.0);
        assert_eq!(rig.conn_total("estEnrollments").await, 0.0);
        let est = rig.health.est().expect("est status");
        assert_eq!((est.enrollments, est.failures), (0, 1));
        assert!(
            est.last_error.is_some(),
            "the failure is surfaced on sb/status"
        );
        assert!(
            !rig.events.has("cert-enrolled"),
            "a failed enrollment keeps the current certificate"
        );
    }

    /// A guard on the fixture itself: the connection parses into the TLS security block these tests
    /// assume (a typo'd block would silently make every leg above a no-op).
    #[test]
    fn the_test_fixture_really_is_a_tls_instance() {
        let cfg = tls_device(watch_security(None));
        let conn: &ConnectionConfig = &cfg.connection;
        let sec = crate::eip::tls::SecurityConfig::from_connection(conn)
            .unwrap()
            .expect("a security block");
        assert!(sec.is_tls());
        assert_eq!(sec.reload_interval_secs, Some(1));
    }
}
