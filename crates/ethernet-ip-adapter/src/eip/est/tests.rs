//! Unit tests for the EST (RFC 7030) client (CIP Security Phase 2c, DESIGN-cip-security.md §4.3).
//!
//! Coverage: config parse/validate + destination resolution, URL parsing, CSR generation, HTTP
//! request encoding + response parsing, PKCS#7 parsing (a **golden vector** produced by OpenSSL
//! `crl2pkcs7`), the enroll-response interpreter, the renew-window scheduler, the vault write-back,
//! and — the key end-to-end handoff — `enroll_once` against an **in-process rustls EST responder**
//! proving the enrolled cert lands in the vault so Phase 2b's [`crate::eip::rotation`] watcher reloads
//! it. The live suite (`tests/live_est.rs`) runs the same flow against a real EST server.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use edgecommons::credentials::{
    CredentialService, DefaultCredentialService, FileKeyProvider, KeyProvider, LocalVault, PutOptions,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};

use crate::device::ConnectionConfig;

// ---- helpers -----------------------------------------------------------------------------------

fn est_of(v: serde_json::Value) -> EstConfig {
    serde_json::from_value(v).unwrap()
}

/// Parse a full `SecurityConfig` (with an `est` block) from a connection.
fn sec_of(security: serde_json::Value) -> SecurityConfig {
    let c: ConnectionConfig =
        serde_json::from_value(json!({ "endpoint": "10.0.0.1", "security": security })).unwrap();
    SecurityConfig::from_connection(&c).unwrap().unwrap()
}

fn vault(seed: u8) -> (Arc<dyn CredentialService>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(FileKeyProvider::from_bytes([seed; 32])) as Arc<dyn KeyProvider>;
    let v = LocalVault::open(dir.path().join("vault"), provider, 3).unwrap();
    (Arc::new(DefaultCredentialService::new(v)), dir)
}

struct Certs {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    client_cert_pem: String,
    client_key_pem: String,
}

/// Mint a CA, a server leaf with an IP SAN for 127.0.0.1, and a client (bootstrap) identity.
fn mint_certs() -> Certs {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType};
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut sp = CertificateParams::new(vec![]).unwrap();
    sp.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = sp.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let cp = CertificateParams::new(vec!["eip-bootstrap".to_string()]).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    Certs {
        ca_pem: ca_cert.pem(),
        ca_der: ca_cert.der().clone(),
        server_chain: vec![server_cert.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

// A GOLDEN certs-only PKCS#7 (DER, base64), produced with OpenSSL:
//   openssl crl2pkcs7 -nocrl -certfile <CN=eip-originator, serial 540D9C…> -outform DER
// This is the exact `application/pkcs7-mime` shape an EST /simpleenroll returns.
const GOLDEN_PKCS7_B64: &str = "MIIBpwYJKoZIhvcNAQcCoIIBmDCCAZQCAQExADALBgkqhkiG9w0BBwGgggF8MIIBeDCCAR6gAwIBAgIUVA2cqvkfkRI6mkS7lfUe/n7qwnUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQRVNUIFRlc3QgUm9vdCBDQTAeFw0yNjA3MTkxNzA1MTBaFw0yODEwMjExNzA1MTBaMBkxFzAVBgNVBAMMDmVpcC1vcmlnaW5hdG9yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZIXphvHufMQQMj/LVXTIEOgjhpGP9iVOqqpgVpiivTB74trvg7nwmWnH5ETuvBg91Fy7wnQg+X5tQxDkXBEGe6NCMEAwHQYDVR0OBBYEFJz8r/HNFFu8ncEoCEI2Fj/Bvgp4MB8GA1UdIwQYMBaAFMbbMncP1I7iT1e0SvnldGXjuYofMAoGCCqGSM49BAMCA0gAMEUCIQDI6CbYr5yNThMcllSXBotG12/m/I4Ki1OQ7jvHfm4BqwIgCzwdSZZr2Z2rWxH41m9ddKPsZ+CaxxEt+J1CBA43sk4xAA==";
// The leaf certificate's serial (uppercase hex) inside the golden vector.
const GOLDEN_SERIAL: &str = "540D9CAAF91F91123A9A44BB95F51EFE7EEAC275";

fn golden_pkcs7_der() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(GOLDEN_PKCS7_B64).unwrap()
}

// ---- config parse + validate -------------------------------------------------------------------

#[test]
fn est_absent_leaves_security_est_none() {
    let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "x" } }));
    assert!(s.est.is_none());
    assert!(s.est_enabled().is_none());
}

#[test]
fn est_disabled_by_default_and_validates_as_noop() {
    let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "x" },
        "est": { "server": "https://est:8443/.well-known/est" } }));
    assert!(s.est.is_some());
    assert!(s.est_enabled().is_none(), "enabled defaults false");
    // A disabled est block never fails validation, even with an odd URL.
    let bad = est_of(json!({ "server": "http://not-tls" }));
    assert!(bad.validate("plc", &s).is_ok());
}

#[test]
fn est_enabled_requires_https_server() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" } }));
    let missing = est_of(json!({ "enabled": true }));
    assert!(missing.validate("plc", &sec).unwrap_err().contains("est.server"));
    let plain = est_of(json!({ "enabled": true, "server": "http://est/.well-known/est" }));
    assert!(plain.validate("plc", &sec).unwrap_err().contains("https"));
}

#[test]
fn est_enabled_valid_config_passes() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/client" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://est.plant:8085/.well-known/est",
        "label": "eip", "renewBeforeDays": 20 }));
    assert!(est.validate("plc", &sec).is_ok());
    assert_eq!(est.renew_before_days(&sec), 20);
}

#[test]
fn est_auth_bootstrap_and_basic_collision_rejected() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "auth": { "bootstrap": { "certSecret": "boot" }, "basic": { "$secret": "creds" } } }));
    assert!(est.validate("plc", &sec).unwrap_err().contains("BOTH bootstrap and basic"));
}

#[test]
fn est_bootstrap_incomplete_rejected() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "auth": { "bootstrap": { "certFile": "only-cert.pem" } } }));
    assert!(est.validate("plc", &sec).unwrap_err().contains("bootstrap"));
}

#[test]
fn est_unknown_key_rejected() {
    // The est block is strict (deny_unknown_fields).
    let c: Result<ConnectionConfig, _> = serde_json::from_value(json!({
        "endpoint": "h", "security": { "mode": "tls", "client": { "certSecret": "x" },
        "est": { "enabled": true, "server": "https://e", "bogus": 1 } } }));
    let sc = c.unwrap();
    assert!(SecurityConfig::from_connection(&sc).is_err());
}

// ---- destination resolution --------------------------------------------------------------------

#[test]
fn destination_defaults_to_client_bundle_secret() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/originator" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert_eq!(
        est.resolve_destination(&sec).unwrap(),
        ResolvedDestination::Bundle("ot/originator".to_string())
    );
}

#[test]
fn destination_defaults_to_client_inline_pair() {
    let sec = sec_of(json!({ "mode": "tls",
        "client": { "cert": { "$secret": "ot/cert" }, "key": { "$secret": "ot/key" } } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert_eq!(
        est.resolve_destination(&sec).unwrap(),
        ResolvedDestination::Pair { cert: "ot/cert".into(), key: "ot/key".into() }
    );
}

#[test]
fn destination_explicit_into_bundle_and_pair() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certFile": "c", "keyFile": "k" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "into": { "certSecret": "vault/bundle" } }));
    assert_eq!(est.resolve_destination(&sec).unwrap(), ResolvedDestination::Bundle("vault/bundle".into()));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "into": { "cert": "c1", "key": "k1" } }));
    assert_eq!(
        est.resolve_destination(&sec).unwrap(),
        ResolvedDestination::Pair { cert: "c1".into(), key: "k1".into() }
    );
}

#[test]
fn destination_file_client_without_into_is_rejected() {
    // A file-only client identity gives EST nowhere in the vault to write ⇒ needs est.into.
    let sec = sec_of(json!({ "mode": "tls", "client": { "certFile": "c", "keyFile": "k" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert!(est.validate("plc", &sec).unwrap_err().contains("write-back destination"));
}

// ---- URL parsing -------------------------------------------------------------------------------

#[test]
fn url_parse_host_port_path_and_label() {
    let e = EstEndpoint::parse("https://est.plant.example:8085/.well-known/est", Some("eip")).unwrap();
    assert_eq!(e.host, "est.plant.example");
    assert_eq!(e.port, 8085);
    assert_eq!(e.base_path, "/.well-known/est/eip");
    assert_eq!(e.op_path("simpleenroll"), "/.well-known/est/eip/simpleenroll");
    assert_eq!(e.host_header(), "est.plant.example:8085");
}

#[test]
fn url_parse_default_port_and_path() {
    let e = EstEndpoint::parse("https://est.example", None).unwrap();
    assert_eq!(e.port, 443);
    assert_eq!(e.base_path, "/.well-known/est");
    assert_eq!(e.host_header(), "est.example");
}

#[test]
fn url_parse_ipv6_literal_with_port() {
    let e = EstEndpoint::parse("https://[fe80::1]:8443/.well-known/est", None).unwrap();
    assert_eq!(e.host, "fe80::1");
    assert_eq!(e.port, 8443);
}

#[test]
fn url_parse_ip_gives_ip_server_name() {
    let e = EstEndpoint::parse("https://127.0.0.1:9000/.well-known/est", None).unwrap();
    assert!(matches!(e.server_name().unwrap(), ServerName::IpAddress(_)));
    let e = EstEndpoint::parse("https://est.host/.well-known/est", None).unwrap();
    assert!(matches!(e.server_name().unwrap(), ServerName::DnsName(_)));
}

#[test]
fn url_parse_rejects_non_https_and_empty_host() {
    assert!(EstEndpoint::parse("http://est/.well-known/est", None).is_err());
    assert!(EstEndpoint::parse("https:///path", None).is_err());
    assert!(EstEndpoint::parse("https://est:99999/x", None).is_err(), "port out of u16 range");
}

// ---- CSR generation ----------------------------------------------------------------------------

#[test]
fn csr_generation_yields_a_key_and_a_parseable_pkcs10() {
    let csr = generate_key_and_csr("eip-originator").unwrap();
    assert!(csr.key_pem.contains("PRIVATE KEY"));
    assert!(!csr.csr_der.is_empty());
    // The CSR DER is a real PKCS#10 CertificationRequest carrying the requested CN (parsed with the
    // x509-cert decoder the adapter already depends on).
    use x509_cert::der::Decode;
    let req = x509_cert::request::CertReq::from_der(&csr.csr_der).unwrap();
    assert!(req.info.subject.to_string().contains("eip-originator"), "subject: {}", req.info.subject);
}

// ---- HTTP request encoding ---------------------------------------------------------------------

#[test]
fn encode_simpleenroll_request_has_pkcs10_base64_body() {
    let e = EstEndpoint::parse("https://est:8443/.well-known/est", None).unwrap();
    let csr = b"\x30\x82\x01\x00"; // arbitrary DER-ish bytes
    let bytes = encode_request(&e, EstOp::SimpleEnroll, Some(csr), None);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("POST /.well-known/est/simpleenroll HTTP/1.1\r\n"));
    assert!(text.contains("Host: est:8443\r\n"));
    assert!(text.contains("Content-Type: application/pkcs10\r\n"));
    assert!(text.contains("Content-Transfer-Encoding: base64\r\n"));
    let expect_b64 = base64::engine::general_purpose::STANDARD.encode(csr);
    assert!(text.contains(&format!("Content-Length: {}\r\n", expect_b64.len())));
    assert!(text.trim_end().ends_with(&expect_b64));
}

#[test]
fn encode_cacerts_is_a_bodyless_get() {
    let e = EstEndpoint::parse("https://est/.well-known/est", Some("eip")).unwrap();
    let bytes = encode_request(&e, EstOp::CaCerts, None, None);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("GET /.well-known/est/eip/cacerts HTTP/1.1\r\n"));
    assert!(!text.contains("Content-Type"));
}

#[test]
fn encode_request_adds_basic_auth_header() {
    let e = EstEndpoint::parse("https://est/.well-known/est", None).unwrap();
    let bytes = encode_request(&e, EstOp::SimpleReenroll, Some(b"x"), Some(("user", "pass")));
    let text = String::from_utf8_lossy(&bytes);
    let token = base64::engine::general_purpose::STANDARD.encode("user:pass");
    assert!(text.contains(&format!("Authorization: Basic {token}\r\n")));
    assert!(text.contains("simplereenroll"));
}

// ---- HTTP response parsing ---------------------------------------------------------------------

#[test]
fn parse_200_base64_response() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: base64\r\nContent-Length: 4\r\n\r\nQUJDRA==";
    let r = parse_response(raw).unwrap();
    assert_eq!(r.status, 200);
    assert!(r.base64_body);
    assert_eq!(r.body, b"QUJDRA==");
}

#[test]
fn parse_202_retry_after() {
    let raw = b"HTTP/1.1 202 Accepted\r\nRetry-After: 120\r\n\r\n";
    let r = parse_response(raw).unwrap();
    assert_eq!(r.status, 202);
    assert_eq!(r.retry_after_secs, Some(120));
}

#[test]
fn parse_response_rejects_malformed() {
    assert!(parse_response(b"no headers here").is_err());
    assert!(parse_response(b"GARBAGE LINE\r\n\r\n").is_err());
}

// ---- PKCS#7 golden vector ----------------------------------------------------------------------

#[test]
fn parse_pkcs7_golden_vector_extracts_the_issued_cert() {
    let der = golden_pkcs7_der();
    let certs = parse_pkcs7_certs(&der).unwrap();
    assert_eq!(certs.len(), 1, "the certs-only bag holds one certificate");
    // The extracted DER is a real X.509 whose serial matches the OpenSSL-issued cert.
    let serial = crate::eip::tls::certs_from_pem(&chain_to_pem(&certs), "golden")
        .ok()
        .and_then(|c| c.first().and_then(|c| crate::eip::tls::cert_serial(c.as_ref())));
    assert_eq!(serial.as_deref(), Some(GOLDEN_SERIAL));
}

#[test]
fn parse_pkcs7_rejects_non_pkcs7() {
    // A bare X.509 cert (not a PKCS#7 ContentInfo) is refused.
    let c = mint_certs();
    let err = parse_pkcs7_certs(c.ca_der.as_ref()).unwrap_err();
    assert!(err.contains("PKCS#7") || err.contains("SignedData"), "{err}");
}

#[test]
fn chain_to_pem_roundtrips() {
    let der = golden_pkcs7_der();
    let certs = parse_pkcs7_certs(&der).unwrap();
    let pem = chain_to_pem(&certs);
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    let reparsed = crate::eip::tls::certs_from_pem(&pem, "roundtrip").unwrap();
    assert_eq!(reparsed.len(), 1);
}

// ---- enroll-response interpreter + decode ------------------------------------------------------

#[test]
fn interpret_enroll_status_mapping() {
    let ok = HttpResponse {
        status: 200,
        base64_body: true,
        retry_after_secs: None,
        body: GOLDEN_PKCS7_B64.as_bytes().to_vec(),
    };
    assert_eq!(interpret_enroll_response(&ok).unwrap().len(), 1);

    let pending = HttpResponse { status: 202, base64_body: false, retry_after_secs: Some(30), body: vec![] };
    assert!(matches!(interpret_enroll_response(&pending), Err(EstError::RetryAfter(30))));

    let unauth = HttpResponse { status: 401, base64_body: false, retry_after_secs: None, body: vec![] };
    assert!(matches!(interpret_enroll_response(&unauth), Err(EstError::Unauthorized(401))));

    let boom = HttpResponse { status: 500, base64_body: false, retry_after_secs: None, body: vec![] };
    assert!(matches!(interpret_enroll_response(&boom), Err(EstError::Status(500))));
}

#[test]
fn decode_body_tolerates_wrapped_base64() {
    // EST bodies may wrap base64 across lines; embedded whitespace must be stripped.
    let wrapped = GOLDEN_PKCS7_B64
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("\r\n");
    let resp = HttpResponse { status: 200, base64_body: true, retry_after_secs: None, body: wrapped.into_bytes() };
    let certs = interpret_enroll_response(&resp).unwrap();
    assert_eq!(certs.len(), 1);
}

#[test]
fn est_error_transient_classification() {
    assert!(EstError::Io("x".into()).is_transient());
    assert!(EstError::RetryAfter(10).is_transient());
    assert!(EstError::Status(503).is_transient());
    assert!(!EstError::Status(404).is_transient());
    assert!(!EstError::Unauthorized(401).is_transient());
    assert!(!EstError::Parse("x".into()).is_transient());
}

// ---- scheduler ---------------------------------------------------------------------------------

#[test]
fn scheduler_initial_enroll_when_no_cert() {
    let d = EstScheduler::decide(None, 30, None, Duration::from_secs(60));
    assert_eq!(d, EstDecision::Enroll { reenroll: false });
}

#[test]
fn scheduler_reenroll_within_window() {
    let d = EstScheduler::decide(Some(20), 30, None, Duration::from_secs(60));
    assert_eq!(d, EstDecision::Enroll { reenroll: true });
}

#[test]
fn scheduler_initial_enroll_when_expired() {
    let d = EstScheduler::decide(Some(-2), 30, None, Duration::from_secs(60));
    assert_eq!(d, EstDecision::Enroll { reenroll: false });
}

#[test]
fn scheduler_idle_when_healthy() {
    assert_eq!(
        EstScheduler::decide(Some(200), 30, None, Duration::from_secs(60)),
        EstDecision::Idle
    );
}

#[test]
fn scheduler_backoff_suppresses_a_recent_attempt() {
    // Within the backoff window, even a needed enroll waits.
    let d = EstScheduler::decide(None, 30, Some(Duration::from_secs(5)), Duration::from_secs(60));
    assert_eq!(d, EstDecision::Idle);
    // After the backoff, it proceeds.
    let d = EstScheduler::decide(None, 30, Some(Duration::from_secs(120)), Duration::from_secs(60));
    assert_eq!(d, EstDecision::Enroll { reenroll: false });
}

// ---- next-renew + status -----------------------------------------------------------------------

#[test]
fn next_renew_is_notafter_minus_window() {
    let na = "2030-06-01T00:00:00Z";
    let nr = next_renew_rfc3339(Some(na), 30).unwrap();
    assert!(nr.starts_with("2030-05-02"), "30 days before June 1: {nr}");
    assert!(next_renew_rfc3339(None, 30).is_none());
    assert!(next_renew_rfc3339(Some("not-a-date"), 30).is_none());
}

#[test]
fn est_status_json_shape() {
    let s = EstStatus {
        enabled: true,
        server: Some("https://est".into()),
        last_enroll: Some("2026-07-19T00:00:00Z".into()),
        next_renew: Some("2027-06-01T00:00:00Z".into()),
        last_error: None,
        enrollments: 2,
        failures: 1,
    };
    let v = s.to_json();
    assert_eq!(v["enabled"], json!(true));
    assert_eq!(v["enrollments"], json!(2));
    assert_eq!(v["failures"], json!(1));
    assert_eq!(v["server"], json!("https://est"));
}

// ---- resolve trust + auth material -------------------------------------------------------------

#[test]
fn resolve_trust_prefers_est_trust_then_connection_ca() {
    let (creds, _d) = vault(40);
    let c = mint_certs();
    creds.put("est/ca", c.ca_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("conn/ca", c.ca_pem.as_bytes(), PutOptions::default()).unwrap();

    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" },
        "ca": { "secret": "conn/ca" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "trust": { "secret": "est/ca" } }));
    let t = resolve_est_trust(&est, &sec, Some(&creds)).unwrap();
    assert_eq!(t.len(), 1);

    // Without est.trust it falls back to the connection CA.
    let est2 = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert_eq!(resolve_est_trust(&est2, &sec, Some(&creds)).unwrap().len(), 1);
}

#[test]
fn resolve_auth_basic_reads_the_basic_auth_view() {
    let (creds, _d) = vault(41);
    let ba = json!({ "username": "estuser", "password": "s3cr3t" });
    creds.put("est/creds", serde_json::to_vec(&ba).unwrap().as_slice(), PutOptions::default()).unwrap();
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "auth": { "basic": { "$secret": "est/creds" } } }));
    match resolve_auth_material(&est, &sec, Some(&creds)).unwrap() {
        EstAuthMaterial::Basic { username, password, .. } => {
            assert_eq!(username, "estuser");
            assert_eq!(password, "s3cr3t");
        }
        other => panic!("expected Basic, got {other:?}"),
    }
}

#[test]
fn resolve_auth_defaults_to_current_client_identity() {
    let (creds, _d) = vault(42);
    let c = mint_certs();
    creds.put("ot/cert", c.client_cert_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("ot/key", c.client_key_pem.as_bytes(), PutOptions::default()).unwrap();
    let sec = sec_of(json!({ "mode": "tls",
        "client": { "cert": { "$secret": "ot/cert" }, "key": { "$secret": "ot/key" } } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert!(matches!(
        resolve_auth_material(&est, &sec, Some(&creds)).unwrap(),
        EstAuthMaterial::ClientCert { .. }
    ));
}

// ---- vault write-back --------------------------------------------------------------------------

#[test]
fn write_enrolled_bundle_is_readable_as_a_tls_bundle() {
    let (creds, _d) = vault(43);
    let dest = ResolvedDestination::Bundle("ot/originator".into());
    write_enrolled(&dest, "CERTPEM", "KEYPEM", Some(&creds)).unwrap();
    let bundle = creds.get_tls_bundle("ot/originator").unwrap().unwrap();
    assert_eq!(bundle.cert_pem, "CERTPEM");
    assert_eq!(bundle.key_pem, "KEYPEM");
}

#[test]
fn write_enrolled_pair_writes_two_secrets() {
    let (creds, _d) = vault(44);
    let dest = ResolvedDestination::Pair { cert: "ot/cert".into(), key: "ot/key".into() };
    write_enrolled(&dest, "CERTPEM", "KEYPEM", Some(&creds)).unwrap();
    assert_eq!(creds.get_string("ot/cert").unwrap().as_deref(), Some("CERTPEM"));
    assert_eq!(creds.get_string("ot/key").unwrap().as_deref(), Some("KEYPEM"));
}

#[test]
fn write_enrolled_without_vault_errors() {
    let dest = ResolvedDestination::Bundle("x".into());
    assert!(write_enrolled(&dest, "c", "k", None).is_err());
}

// ---- EstClient builder + transport error paths -------------------------------------------------

#[test]
fn est_client_new_rejects_empty_trust() {
    let certs = mint_certs();
    let endpoint = EstEndpoint::parse("https://127.0.0.1:9/.well-known/est", None).unwrap();
    let auth = EstAuthMaterial::ClientCert {
        cert_pem: certs.client_cert_pem.clone(),
        key_pem: certs.client_key_pem.clone(),
    };
    match EstClient::new(endpoint, &[], &auth, Duration::from_secs(1)) {
        Err(err) => assert!(err.contains("trust anchors"), "{err}"),
        Ok(_) => panic!("empty trust should be rejected"),
    }
}

#[test]
fn est_client_new_rejects_bad_client_key() {
    let certs = mint_certs();
    let endpoint = EstEndpoint::parse("https://127.0.0.1:9/.well-known/est", None).unwrap();
    let auth = EstAuthMaterial::ClientCert {
        cert_pem: certs.client_cert_pem.clone(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nnotakey\n-----END PRIVATE KEY-----\n".into(),
    };
    assert!(EstClient::new(endpoint, std::slice::from_ref(&certs.ca_pem), &auth, Duration::from_secs(1)).is_err());
}

#[tokio::test]
async fn est_client_request_connect_refused_is_transport_error() {
    let certs = mint_certs();
    // Port 1 is not listening ⇒ a connect failure surfaces as an IO/transport error, not a panic.
    let endpoint = EstEndpoint::parse("https://127.0.0.1:1/.well-known/est", None).unwrap();
    let auth = EstAuthMaterial::ClientCert {
        cert_pem: certs.client_cert_pem.clone(),
        key_pem: certs.client_key_pem.clone(),
    };
    let client = EstClient::new(endpoint, std::slice::from_ref(&certs.ca_pem), &auth, Duration::from_secs(2)).unwrap();
    let err = client.request(EstOp::CaCerts, None).await.unwrap_err();
    assert!(err.contains("connecting") || err.contains("EST"), "{err}");
    // And request_certificate maps it to a transient EstError::Io.
    let e2 = client.request_certificate(false, b"x").await.unwrap_err();
    assert!(matches!(e2, EstError::Io(_)) && e2.is_transient());
}

#[test]
fn resolve_est_trust_without_any_source_errors() {
    let sec = sec_of(json!({ "mode": "tls", "client": { "certFile": "c", "keyFile": "k" }, "verifyPeer": false }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    assert!(resolve_est_trust(&est, &sec, None).is_err());
}

#[test]
fn resolve_auth_without_auth_or_client_errors() {
    let sec = sec_of(json!({ "mode": "tls", "verifyPeer": false }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est" }));
    let err = resolve_auth_material(&est, &sec, None).unwrap_err();
    assert!(err.contains("no auth") || err.contains("client identity"), "{err}");
}

#[test]
fn resolve_auth_bootstrap_sources_the_identity() {
    let (creds, _d) = vault(45);
    let c = mint_certs();
    creds.put("boot/cert", c.client_cert_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("boot/key", c.client_key_pem.as_bytes(), PutOptions::default()).unwrap();
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/c" } }));
    let est = est_of(json!({ "enabled": true, "server": "https://e/.well-known/est",
        "auth": { "bootstrap": { "cert": { "$secret": "boot/cert" }, "key": { "$secret": "boot/key" } } } }));
    assert!(matches!(
        resolve_auth_material(&est, &sec, Some(&creds)).unwrap(),
        EstAuthMaterial::ClientCert { .. }
    ));
}

// ---- END-TO-END: enroll_once against an in-process rustls EST responder -------------------------
//
// This proves the whole Phase-2c handoff without any container: a real TLS server on localhost
// answers /simpleenroll with the golden PKCS#7; `enroll_once` connects, POSTs the CSR, extracts the
// issued cert, and WRITES it to the vault; and Phase 2b's rotation watcher detects the vault change
// (⇒ it would reconnect with the new material). It also exercises `EstClient`/`request`/`cacerts`.

/// Spawn a one-shot TLS EST responder on 127.0.0.1 that returns `response_bytes` for any request.
/// Returns the bound port.
async fn spawn_est_server(certs: &Certs, response_bytes: Vec<u8>) -> u16 {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_der.clone()).unwrap();
    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.server_chain.clone(), certs.server_key.clone_key())
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                // Read the request headers (until the terminator) so the client's write completes.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                for _ in 0..64 {
                    match tls.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tls.write_all(&response_bytes).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            }
        }
    });
    port
}

fn est_http_200(body_b64: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: base64\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_b64.len(),
        body_b64
    )
    .into_bytes()
}

#[tokio::test]
async fn enroll_once_writes_the_issued_cert_and_2b_reloads_it() {
    let certs = mint_certs();
    let port = spawn_est_server(&certs, est_http_200(GOLDEN_PKCS7_B64)).await;

    let (creds, _d) = vault(50);
    // Bootstrap identity + EST server trust + a pre-existing (old) client bundle at the destination.
    creds.put("boot/cert", certs.client_cert_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("boot/key", certs.client_key_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("est/ca", certs.ca_pem.as_bytes(), PutOptions::default()).unwrap();
    let old_bundle = json!({ "certPem": certs.client_cert_pem, "keyPem": certs.client_key_pem });
    creds.put("ot/originator", serde_json::to_vec(&old_bundle).unwrap().as_slice(), PutOptions::default()).unwrap();

    let sec = sec_of(json!({ "mode": "tls",
        "client": { "certSecret": "ot/originator" },
        "ca": { "secret": "est/ca" } }));
    let est = est_of(json!({ "enabled": true,
        "server": format!("https://127.0.0.1:{port}/.well-known/est"),
        "trust": { "secret": "est/ca" },
        "auth": { "bootstrap": { "cert": { "$secret": "boot/cert" }, "key": { "$secret": "boot/key" } } },
        "into": { "certSecret": "ot/originator" } }));

    // The material fingerprint BEFORE enrollment (Phase 2b watcher baseline).
    let before = crate::eip::rotation::read_reload_state(&sec, Some(&creds), time::OffsetDateTime::now_utc()).unwrap();

    // Enroll (initial): POST the CSR, get the golden cert, write it to the vault.
    let out = enroll_once(&est, &sec, Some(&creds), false, Duration::from_secs(5)).await.unwrap();
    assert_eq!(out.chain_len, 1);
    assert_eq!(out.serial.as_deref(), Some(GOLDEN_SERIAL));
    assert_eq!(out.written_to, "ot/originator");

    // The vault now holds the ISSUED cert (a real bundle Phase 2b reads).
    let bundle = creds.get_tls_bundle("ot/originator").unwrap().unwrap();
    let issued_serial = crate::eip::tls::certs_from_pem(&bundle.cert_pem, "issued")
        .unwrap()
        .first()
        .and_then(|c| crate::eip::tls::cert_serial(c.as_ref()));
    assert_eq!(issued_serial.as_deref(), Some(GOLDEN_SERIAL), "vault holds the enrolled cert");

    // Phase 2b handoff: the fingerprint changed ⇒ the rotation watcher reports Rotated (⇒ reconnect).
    let after = crate::eip::rotation::read_reload_state(&sec, Some(&creds), time::OffsetDateTime::now_utc()).unwrap();
    assert_ne!(before.fingerprint, after.fingerprint, "the enrolled material changed the fingerprint");
    let mut watcher = crate::eip::rotation::CertWatcher::default();
    watcher.observe(&before, 30);
    let outcome = watcher.observe(&after, 30);
    assert!(
        outcome.actions.iter().any(|a| matches!(a, crate::eip::rotation::WatchAction::Rotated { .. })),
        "2b watcher detects the EST rotation: {:?}",
        outcome.actions
    );
}

#[tokio::test]
async fn est_client_cacerts_fetches_the_ca_bag() {
    let certs = mint_certs();
    let port = spawn_est_server(&certs, est_http_200(GOLDEN_PKCS7_B64)).await;
    let endpoint = EstEndpoint::parse(&format!("https://127.0.0.1:{port}/.well-known/est"), None).unwrap();
    let auth = EstAuthMaterial::ClientCert {
        cert_pem: certs.client_cert_pem.clone(),
        key_pem: certs.client_key_pem.clone(),
    };
    let client = EstClient::new(endpoint, std::slice::from_ref(&certs.ca_pem), &auth, Duration::from_secs(5)).unwrap();
    let bag = client.cacerts().await.unwrap();
    assert_eq!(bag.len(), 1);
}

// ---- LIVE: enroll against the real globalsign/est `estserver` container (self-skipping) ----------
//
// Independent-implementation validation (DESIGN-cip-security.md §5.2 Target C): a real Go RFC 7030
// server + mock CA, mutual-TLS, over a real socket. Runs only when the container is up:
//   docker compose up --build est-server         (or: docker run -p 8443:8443 ec-est-server)
// and is SILENTLY SKIPPED otherwise (matching the inline live tests in tls.rs), so the normal suite
// stays green with no live infra. It is excluded from the coverage gate via the `live_est` regex.

const EST_CERT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-infra/est/certs");

async fn est_server_up() -> bool {
    tokio::time::timeout(
        Duration::from_millis(400),
        tokio::net::TcpStream::connect("127.0.0.1:8443"),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

fn read_est_cert(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("{EST_CERT_DIR}/{name}")).ok()
}

#[tokio::test]
async fn live_est_enroll_against_globalsign_estserver() {
    if !est_server_up().await {
        eprintln!("SKIP live_est_enroll: no EST server on 127.0.0.1:8443 (run `docker compose up --build est-server`)");
        return;
    }
    let (Some(ca), Some(cc), Some(ck)) =
        (read_est_cert("ca.pem"), read_est_cert("client.pem"), read_est_cert("client.key"))
    else {
        eprintln!("SKIP live_est_enroll: test certs missing (run test-infra/est/gen-certs.sh)");
        return;
    };

    let (creds, _d) = vault(60);
    creds.put("boot/cert", cc.as_bytes(), PutOptions::default()).unwrap();
    creds.put("boot/key", ck.as_bytes(), PutOptions::default()).unwrap();
    creds.put("est/ca", ca.as_bytes(), PutOptions::default()).unwrap();

    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/originator" },
        "ca": { "secret": "est/ca" } }));
    let est = est_of(json!({ "enabled": true,
        "server": "https://127.0.0.1:8443/.well-known/est",
        "trust": { "secret": "est/ca" },
        "fetchCaCerts": true,
        "auth": { "bootstrap": { "cert": { "$secret": "boot/cert" }, "key": { "$secret": "boot/key" } } },
        "into": { "certSecret": "ot/originator" } }));

    let out = enroll_once(&est, &sec, Some(&creds), false, Duration::from_secs(10))
        .await
        .expect("live EST enrollment");
    assert!(out.chain_len >= 1, "the server issued a certificate");
    assert!(out.serial.is_some(), "the issued cert has a serial");

    // The issued cert landed in the vault as a real, parseable bundle (Phase 2b would reload it).
    let bundle = creds.get_tls_bundle("ot/originator").unwrap().unwrap();
    let issued = crate::eip::tls::certs_from_pem(&bundle.cert_pem, "live-issued").unwrap();
    assert!(!issued.is_empty(), "vault holds the live-enrolled cert");
    eprintln!(
        "LIVE EST OK: enrolled serial {} ({} cert(s)) via globalsign estserver :8443",
        out.serial.as_deref().unwrap_or("?"),
        out.chain_len
    );
}

#[tokio::test]
async fn enroll_once_surfaces_a_202_retry() {
    let certs = mint_certs();
    let resp = b"HTTP/1.1 202 Accepted\r\nRetry-After: 45\r\nConnection: close\r\n\r\n".to_vec();
    let port = spawn_est_server(&certs, resp).await;
    let (creds, _d) = vault(51);
    creds.put("boot/cert", certs.client_cert_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("boot/key", certs.client_key_pem.as_bytes(), PutOptions::default()).unwrap();
    creds.put("est/ca", certs.ca_pem.as_bytes(), PutOptions::default()).unwrap();
    let sec = sec_of(json!({ "mode": "tls", "client": { "certSecret": "ot/originator" } }));
    let est = est_of(json!({ "enabled": true,
        "server": format!("https://127.0.0.1:{port}/.well-known/est"),
        "trust": { "secret": "est/ca" },
        "auth": { "bootstrap": { "cert": { "$secret": "boot/cert" }, "key": { "$secret": "boot/key" } } },
        "into": { "certSecret": "ot/originator" } }));
    let err = enroll_once(&est, &sec, Some(&creds), false, Duration::from_secs(5)).await.unwrap_err();
    assert!(err.contains("pending") || err.contains("retry"), "{err}");
    // Nothing was written to the destination on a 202.
    assert!(creds.get("ot/originator").unwrap().is_none());
}
