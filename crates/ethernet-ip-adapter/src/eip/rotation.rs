//! # Client-cert lifecycle: rotation detection + expiry monitoring (Phase 2b, §4.2/§4.3)
//!
//! The adapter's TLS material lives in the credentials vault, and a plant PKI rotates it (centrally,
//! or via `ec-secrets`) **without restarting the component**. This module is the pure decision core
//! that makes that observable and actionable:
//!
//! * [`read_reload_state`] reads the *current* vault material — the client certificate plus every
//!   trust-store CA — and summarizes it: a change-detection fingerprint (client cert + all CAs) and
//!   the client cert's `notAfter`/serial/days-to-expiry. It is cheap (no full `ClientConfig` build).
//! * [`CertWatcher`] compares successive [`ReloadState`]s and emits de-duped [`WatchAction`]s: a
//!   **rotation** (the material changed ⇒ the driver reconnects so the next handshake uses it), a
//!   **cert-expiring** warning (within `renewBeforeDays`, fired once on the transition), and a
//!   **cert-expired** warning (fired once). The connect path itself always rebuilds the
//!   `ClientConfig` from the latest vault material, so a triggered reconnect is all it takes for a
//!   rotation to take effect.
//!
//! The supervisor's `security_lifecycle` task is the thin driver: tick → [`read_reload_state`] →
//! [`CertWatcher::observe`] → emit events / bump metrics / send a `reconnect`. All the logic that can
//! be decided without a socket lives here and is unit-tested.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use edgecommons::credentials::CredentialService;
use time::OffsetDateTime;

use super::tls::{
    cert_not_after, cert_not_after_time, cert_serial, certs_from_pem, days_until, source_ca_pems,
    source_client_material, SecurityConfig,
};

/// The client certificate's lifecycle facts, parsed from the vault's current material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertInfo {
    /// The certificate's `notAfter`, RFC-3339 (`None` if unparseable).
    pub not_after: Option<String>,
    /// The certificate's serial number, hex (`None` if unparseable).
    pub serial: Option<String>,
    /// Whole days until expiry (negative ⇒ expired). `i64::MAX` when `notAfter` is unparseable, so an
    /// undecodable cert is never treated as "expiring".
    pub expiry_days: i64,
}

/// A snapshot of the TLS material the lifecycle task watches (Phase 2b): a change-detection
/// fingerprint over the client certificate + every trust-store CA, plus the parsed client-cert facts.
#[derive(Debug, Clone)]
pub struct ReloadState {
    /// A non-crypto hash of the client cert PEM + all CA PEMs — for detecting a rotation, not a
    /// security boundary.
    pub fingerprint: u64,
    /// The parsed client-certificate facts (`None` for a `verifyPeer:false` anonymous connection).
    pub client: Option<ClientCertInfo>,
}

/// Read the current TLS material from the vault/files and summarize it (Phase 2b, §4.2). Reads the
/// client certificate + trust anchors only (not a full `ClientConfig`), so it is cheap enough to run
/// on the `reloadIntervalSecs` cadence. `now` dates the expiry-days computation.
///
/// # Errors
///
/// A config-legible message when a required vault is absent, a secret/version is missing, or a value
/// is not UTF-8 PEM.
pub fn read_reload_state(
    sec: &SecurityConfig,
    creds: Option<&Arc<dyn CredentialService>>,
    now: OffsetDateTime,
) -> Result<ReloadState, String> {
    let (cert_pem, _key_pem, bundle_ca) = source_client_material(sec, creds)?;

    let mut ca_pems: Vec<String> = Vec::new();
    if let Some(ca) = bundle_ca {
        ca_pems.push(ca);
    }
    if let Some(ca) = &sec.ca {
        ca_pems.extend(source_ca_pems(ca, creds)?);
    }

    // Fingerprint over client cert + every trust-store CA: a change to either (a rotated originator
    // cert OR a CA rollover) trips a reconnect so the fresh material is used (§4.2).
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cert_pem.hash(&mut hasher);
    for p in &ca_pems {
        p.hash(&mut hasher);
    }
    let fingerprint = hasher.finish();

    let client = match &cert_pem {
        Some(pem) => {
            let chain = certs_from_pem(pem, "client certificate")?;
            chain.first().map(|leaf| {
                let der = leaf.as_ref();
                let expiry_days = cert_not_after_time(der)
                    .map(|na| days_until(na, now))
                    .unwrap_or(i64::MAX);
                ClientCertInfo {
                    not_after: cert_not_after(der),
                    serial: cert_serial(der),
                    expiry_days,
                }
            })
        }
        None => None,
    };

    Ok(ReloadState { fingerprint, client })
}

/// Whether the client cert is comfortably valid, nearing expiry, or expired. Kept across ticks so the
/// `cert-expiring`/`cert-expired` events fire once on the transition, not every tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ExpiryState {
    #[default]
    Unknown,
    Ok,
    Expiring,
    Expired,
}

/// One thing the lifecycle driver should do this tick (Phase 2b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAction {
    /// The vault material changed (client cert and/or a trust-store CA) — reconnect so the next
    /// handshake uses it, and emit `cert-rotated`. Carries the new client-cert identity for the event.
    Rotated {
        serial: Option<String>,
        not_after: Option<String>,
    },
    /// The client cert is within `renewBeforeDays` of expiry — emit `cert-expiring` (once).
    Expiring { days: i64, not_after: Option<String> },
    /// The client cert has expired — emit `cert-expired` (once).
    Expired { days: i64, not_after: Option<String> },
}

/// The lifecycle state a driver keeps across ticks — pure; the supervisor feeds it [`ReloadState`]s.
#[derive(Debug, Default)]
pub struct CertWatcher {
    last_fingerprint: Option<u64>,
    expiry_state: ExpiryState,
}

/// The outcome of one [`CertWatcher::observe`]: the actions to take + the current expiry-days gauge
/// value (for the `EtherNetIpConnection.certExpiryDays` metric).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchOutcome {
    pub actions: Vec<WatchAction>,
    pub expiry_days: Option<i64>,
}

impl CertWatcher {
    /// Compare `state` against the last observation and return the de-duped actions + the expiry gauge
    /// value. `renew_before_days` is the `cert-expiring` threshold.
    ///
    /// The **first** observation establishes the fingerprint baseline (not a rotation) but *does*
    /// evaluate expiry, so a cert already near/at expiry at startup fires its event immediately.
    pub fn observe(&mut self, state: &ReloadState, renew_before_days: i64) -> WatchOutcome {
        let mut actions = Vec::new();

        // Rotation: the fingerprint moved since the last tick (skip the baseline-establishing first).
        if let Some(prev) = self.last_fingerprint {
            if prev != state.fingerprint {
                let (serial, not_after) = state
                    .client
                    .as_ref()
                    .map(|c| (c.serial.clone(), c.not_after.clone()))
                    .unwrap_or((None, None));
                actions.push(WatchAction::Rotated { serial, not_after });
            }
        }
        self.last_fingerprint = Some(state.fingerprint);

        // Expiry: fire the one-shot event on the transition into Expiring / Expired.
        let expiry_days = state.client.as_ref().map(|c| c.expiry_days);
        if let Some(c) = &state.client {
            let new_state = if c.expiry_days < 0 {
                ExpiryState::Expired
            } else if c.expiry_days <= renew_before_days {
                ExpiryState::Expiring
            } else {
                ExpiryState::Ok
            };
            if new_state != self.expiry_state {
                match new_state {
                    ExpiryState::Expired => actions.push(WatchAction::Expired {
                        days: c.expiry_days,
                        not_after: c.not_after.clone(),
                    }),
                    ExpiryState::Expiring => actions.push(WatchAction::Expiring {
                        days: c.expiry_days,
                        not_after: c.not_after.clone(),
                    }),
                    ExpiryState::Ok | ExpiryState::Unknown => {}
                }
                self.expiry_state = new_state;
            }
        }

        WatchOutcome { actions, expiry_days }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::device::ConnectionConfig;
    use edgecommons::credentials::{
        CredentialService, DefaultCredentialService, FileKeyProvider, KeyProvider, LocalVault,
        PutOptions,
    };
    use serde_json::json;

    // ---- cert fixtures (rcgen; a chosen validity window drives the expiry tests) ----

    struct Fx {
        cert_pem: String,
        key_pem: String,
        ca_pem: String,
    }

    /// Mint a client cert whose `notAfter` is `days_from_now` days out (negative ⇒ already expired),
    /// signed by a fresh test CA.
    fn mint(days_from_now: i64) -> Fx {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use time::Duration as TD;

        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut cp = CertificateParams::new(vec!["eip-originator".to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        cp.not_before = now - TD::days(1);
        cp.not_after = now + TD::days(days_from_now);
        let client_key = KeyPair::generate().unwrap();
        let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        Fx {
            cert_pem: client_cert.pem(),
            key_pem: client_key.serialize_pem(),
            ca_pem: ca_cert.pem(),
        }
    }

    fn vault() -> (Arc<dyn CredentialService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(FileKeyProvider::from_bytes([5u8; 32])) as Arc<dyn KeyProvider>;
        let v = LocalVault::open(dir.path().join("vault"), provider, 3).unwrap();
        (Arc::new(DefaultCredentialService::new(v)), dir)
    }

    fn sec(v: serde_json::Value) -> SecurityConfig {
        let c: ConnectionConfig = serde_json::from_value(json!({ "endpoint": "h", "security": v }))
            .unwrap();
        SecurityConfig::from_connection(&c).unwrap().unwrap()
    }

    // ---- read_reload_state ----

    #[test]
    fn read_reload_state_parses_serial_notafter_and_days() {
        let (creds, _d) = vault();
        let fx = mint(400);
        creds.put("tls/cert", fx.cert_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/key", fx.key_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/root", fx.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        let s = sec(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" } },
            "ca": { "cert": { "$secret": "tls/root" } } }));
        let st = read_reload_state(&s, Some(&creds), OffsetDateTime::now_utc()).unwrap();
        let c = st.client.expect("client cert present");
        assert!(c.serial.is_some());
        assert!(c.not_after.is_some());
        assert!((398..=401).contains(&c.expiry_days), "~400 days out: {}", c.expiry_days);
    }

    #[test]
    fn fingerprint_changes_when_the_client_cert_rotates() {
        let (creds, _d) = vault();
        let a = mint(400);
        creds.put("tls/cert", a.cert_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/key", a.key_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/root", a.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        let s = sec(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" } },
            "ca": { "cert": { "$secret": "tls/root" } } }));
        let fp1 = read_reload_state(&s, Some(&creds), OffsetDateTime::now_utc()).unwrap().fingerprint;

        // Rotate the client cert (a fresh mint ⇒ different bytes).
        let b = mint(500);
        creds.put("tls/cert", b.cert_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/key", b.key_pem.as_bytes(), PutOptions::default()).unwrap();
        let fp2 = read_reload_state(&s, Some(&creds), OffsetDateTime::now_utc()).unwrap().fingerprint;
        assert_ne!(fp1, fp2, "a rotated client cert changes the fingerprint");
    }

    #[test]
    fn fingerprint_changes_when_the_trust_store_rotates() {
        let (creds, _d) = vault();
        let a = mint(400);
        creds.put("tls/cert", a.cert_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("tls/key", a.key_pem.as_bytes(), PutOptions::default()).unwrap();
        creds.put("ot/trust", a.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        let s = sec(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/cert" }, "key": { "$secret": "tls/key" } },
            "ca": { "trustStore": "ot/trust" } }));
        let fp1 = read_reload_state(&s, Some(&creds), OffsetDateTime::now_utc()).unwrap().fingerprint;

        // A CA rollover: a second root version added to the trust store.
        let b = mint(400);
        creds.put("ot/trust", b.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        let fp2 = read_reload_state(&s, Some(&creds), OffsetDateTime::now_utc()).unwrap().fingerprint;
        assert_ne!(fp1, fp2, "a rotated CA changes the fingerprint");
    }

    // ---- CertWatcher ----

    fn state(fp: u64, days: i64) -> ReloadState {
        ReloadState {
            fingerprint: fp,
            client: Some(ClientCertInfo {
                not_after: Some("2030-01-01T00:00:00Z".to_string()),
                serial: Some("01AB".to_string()),
                expiry_days: days,
            }),
        }
    }

    #[test]
    fn first_observation_is_a_baseline_not_a_rotation() {
        let mut w = CertWatcher::default();
        let out = w.observe(&state(1, 400), 30);
        assert!(out.actions.is_empty(), "first tick establishes the baseline: {:?}", out.actions);
        assert_eq!(out.expiry_days, Some(400));
    }

    #[test]
    fn a_changed_fingerprint_yields_rotated_and_a_reconnect() {
        let mut w = CertWatcher::default();
        w.observe(&state(1, 400), 30);
        let out = w.observe(&state(2, 500), 30);
        assert_eq!(
            out.actions,
            vec![WatchAction::Rotated {
                serial: Some("01AB".to_string()),
                not_after: Some("2030-01-01T00:00:00Z".to_string())
            }]
        );
        // No further rotation while the fingerprint holds.
        assert!(w.observe(&state(2, 500), 30).actions.is_empty());
    }

    #[test]
    fn near_expiry_fires_cert_expiring_once() {
        let mut w = CertWatcher::default();
        let out = w.observe(&state(1, 20), 30);
        assert_eq!(
            out.actions,
            vec![WatchAction::Expiring { days: 20, not_after: Some("2030-01-01T00:00:00Z".to_string()) }]
        );
        // Still expiring next tick (same fingerprint) ⇒ no repeat event.
        assert!(w.observe(&state(1, 19), 30).actions.is_empty());
    }

    #[test]
    fn expired_fires_cert_expired_once() {
        let mut w = CertWatcher::default();
        let out = w.observe(&state(1, -3), 30);
        assert_eq!(
            out.actions,
            vec![WatchAction::Expired { days: -3, not_after: Some("2030-01-01T00:00:00Z".to_string()) }]
        );
        assert!(w.observe(&state(1, -4), 30).actions.is_empty(), "no repeat expired event");
    }

    #[test]
    fn rotation_to_a_fresh_cert_rearms_the_expiring_warning() {
        let mut w = CertWatcher::default();
        // Establish baseline while already expiring.
        assert_eq!(w.observe(&state(1, 10), 30).actions.len(), 1); // Expiring
        // Rotate to a healthy cert (fingerprint changes, days healthy): Rotated, expiry back to Ok.
        let out = w.observe(&state(2, 400), 30);
        assert_eq!(out.actions.len(), 1);
        assert!(matches!(out.actions[0], WatchAction::Rotated { .. }));
        // A later expiry re-fires (the warning re-armed).
        let out = w.observe(&state(2, 5), 30);
        assert!(out.actions.iter().any(|a| matches!(a, WatchAction::Expiring { .. })));
    }

    #[test]
    fn rotation_directly_into_expired_reports_both() {
        let mut w = CertWatcher::default();
        w.observe(&state(1, 400), 30); // baseline healthy
        let out = w.observe(&state(2, -1), 30); // rotated to an expired cert
        assert!(out.actions.iter().any(|a| matches!(a, WatchAction::Rotated { .. })));
        assert!(out.actions.iter().any(|a| matches!(a, WatchAction::Expired { .. })));
    }

    #[test]
    fn no_client_cert_yields_no_expiry_actions() {
        let mut w = CertWatcher::default();
        let out = w.observe(&ReloadState { fingerprint: 1, client: None }, 30);
        assert!(out.actions.is_empty());
        assert_eq!(out.expiry_days, None);
    }
}
