//! Live integration test: the real `enip::EipClient::connect_tls` against a real **stunnel** TLS
//! terminator fronting **cpppo** (CIP Security Phase 1, DESIGN-cip-security.md §5.2). This is the
//! first time the TLS explicit path (`client/tls.rs`) meets an INDEPENDENT TLS implementation
//! (OpenSSL/stunnel) carrying an INDEPENDENT EtherNet/IP implementation (cpppo) — not a rustls-vs-
//! rustls duplex fixture. EtherNet/IP-over-TLS is byte-identical EtherNet/IP inside a standard TLS
//! tunnel on TCP 2221, so this exercises exactly the layer Phase 1 changes.
//!
//! ## Self-skipping (the sibling live-sim pattern, §11.3)
//! At suite start we probe `TcpStream::connect(127.0.0.1:2221)`. If nothing is listening the test
//! prints `skipped (no stunnel)` and returns — so `cargo test --workspace` stays green on a machine
//! with no peer. Bring the peer up (from the repo root):
//!
//! ```bash
//! ./test-infra/enip-tls/gen-certs.sh
//! docker compose up --build -d enip-sim enip-tls enip-tls-cbc
//! cargo test -p ec-enip --features tls --test live_tls -- --nocapture
//! ```
//!
//! ## What it proves (DESIGN-cip-security.md §5.2 negative matrix)
//! * a successful **mutual-TLS** connect + tag read + write/read-back over TLS;
//! * **wrong CA** ⇒ the device cert does not verify ⇒ typed `Tls { PeerUnverified }`;
//! * **missing client cert** ⇒ stunnel's `verify=2` rejects ⇒ the connection fails;
//! * **CBC-only legacy terminator** (:2223, no GCM/TLS1.3) ⇒ typed `Tls { NoCipherOverlap }`.
//!
//! Excluded from the coverage denominator (`tests[/\\]live_tls`, §12.2).
#![cfg(feature = "tls")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use enip::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use enip::rustls::{ClientConfig, RootCertStore};
use enip::{
    CipType, CipValue, ClientOptions, EipClient, EnipError, TagAddress, TlsErrorKind, TlsOptions,
};

const TLS_ADDR: &str = "127.0.0.1:2221";
const CBC_ADDR: &str = "127.0.0.1:2223";

/// Probe a TCP port; `false` when nothing is listening (§11.3 self-skip).
async fn up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(400), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

fn certs_dir() -> PathBuf {
    // crates/enip/tests -> repo root -> test-infra/enip-tls/certs
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-infra/enip-tls/certs")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(certs_dir().join(path))
        .unwrap_or_else(|e| panic!("reading certs/{path} (run gen-certs.sh): {e}"))
}

fn certs_from(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .collect::<Result<_, _>>()
        .unwrap()
}

fn key_from(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

fn ring() -> Arc<enip::rustls::crypto::CryptoProvider> {
    Arc::new(enip::rustls::crypto::ring::default_provider())
}

/// A client config trusting `ca_pem`, presenting the test client cert (mutual TLS) when `mtls`.
fn client_config(ca_pem: &str, mtls: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in certs_from(ca_pem) {
        roots.add(c).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let cfg = if mtls {
        builder
            .with_client_auth_cert(certs_from(&read("client.pem")), key_from(&read("client.key")))
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(cfg)
}

fn localhost() -> ServerName<'static> {
    ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into())
}

fn opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(3),
        ..ClientOptions::default()
    }
}

/// The happy path + every negative case, so a single peer bring-up proves the whole §5.2 matrix.
#[tokio::test]
async fn tls_live_mutual_read_write_and_negative_matrix() {
    if !up(TLS_ADDR).await {
        eprintln!("live_tls: skipped (no stunnel on {TLS_ADDR}) — run gen-certs.sh + docker compose up enip-sim enip-tls enip-tls-cbc");
        return;
    }
    let ca = read("ca.pem");

    // ---- 1. mutual TLS connect + read + write/read-back ----
    let tls = TlsOptions {
        config: client_config(&ca, true),
        server_name: localhost(),
    };
    let client = EipClient::connect_tls(TLS_ADDR, opts(), tls)
        .await
        .expect("mutual-TLS connect_tls");

    let info = client.tls_session_info().expect("negotiated tls info");
    eprintln!(
        "live_tls: connected over TLS {} / {} (peer cert present: {})",
        info.protocol_version.as_deref().unwrap_or("?"),
        info.cipher_suite.as_deref().unwrap_or("?"),
        info.peer_cert_der.is_some()
    );
    assert!(info.protocol_version.is_some());
    assert!(info.cipher_suite.is_some());

    // Seed then read back (cpppo boots every tag at 0).
    let tag = TagAddress::parse("FILL_SETPOINT").unwrap();
    client
        .write_tag(&tag, CipType::Real, &CipValue::Real(48.5))
        .await
        .expect("write over TLS");
    let got = client.read_tag(&tag, 1).await.expect("read over TLS");
    match got.value {
        CipValue::Real(v) => assert_eq!(v, 48.5, "write/read-back over TLS"),
        other => panic!("unexpected value {other:?}"),
    }
    // A different tag reads GOOD on the same TLS session.
    let ls = client
        .read_tag(&TagAddress::parse("LINE_SPEED").unwrap(), 1)
        .await
        .expect("LINE_SPEED read over TLS");
    assert!(matches!(ls.value, CipValue::Real(_)));
    client.close().await;
    eprintln!("live_tls: mutual-TLS read/write PASSED");

    // ---- 2. wrong CA ⇒ PeerUnverified ----
    let other_ca = read("other-ca.pem");
    let tls = TlsOptions {
        config: client_config(&other_ca, true),
        server_name: localhost(),
    };
    let err = match EipClient::connect_tls(TLS_ADDR, opts(), tls).await {
        Ok(_) => panic!("wrong CA must be rejected"),
        Err(e) => e,
    };
    assert!(
        matches!(err, EnipError::Tls { kind: TlsErrorKind::PeerUnverified, .. }),
        "wrong CA ⇒ PeerUnverified, got {err:?}"
    );
    eprintln!("live_tls: wrong-CA rejection PASSED ({err})");

    // ---- 3. missing client cert ⇒ stunnel verify=2 rejects ----
    let tls = TlsOptions {
        config: client_config(&ca, false), // no client cert presented
        server_name: localhost(),
    };
    let err = match EipClient::connect_tls(TLS_ADDR, opts(), tls).await {
        Ok(_) => panic!("missing client cert must be rejected"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            EnipError::Tls { .. } | EnipError::Io(_) | EnipError::ConnectionLost { .. }
        ),
        "missing client cert ⇒ connection failure, got {err:?}"
    );
    eprintln!("live_tls: missing-client-cert rejection PASSED ({err})");

    // ---- 4. CBC-only legacy terminator ⇒ NoCipherOverlap ----
    if up(CBC_ADDR).await {
        let tls = TlsOptions {
            config: client_config(&ca, true),
            server_name: localhost(),
        };
        let err = match EipClient::connect_tls(CBC_ADDR, opts(), tls).await {
            Ok(_) => panic!("CBC-only terminator must fail to negotiate"),
            Err(e) => e,
        };
        assert!(
            matches!(err, EnipError::Tls { kind: TlsErrorKind::NoCipherOverlap, .. }),
            "CBC-only ⇒ NoCipherOverlap, got {err:?}"
        );
        eprintln!("live_tls: CBC-only NoCipherOverlap PASSED ({err})");
    } else {
        eprintln!("live_tls: CBC leg skipped (no stunnel on {CBC_ADDR})");
    }
}
