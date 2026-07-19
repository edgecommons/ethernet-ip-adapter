//! Live integration test: `enip::EipClient::read_security_posture` against a real **OpENer
//! `CIPSecurity` branch** target (CIP Security Phase 2a, DESIGN-cip-security.md §4.1/§5.2).
//!
//! OpENer's `CIPSecurity` branch implements the three CIP Security objects (0x5D CIP Security, 0x5E
//! EtherNet/IP Security, 0x5F Certificate Management) as real CIP objects served over the ordinary
//! plaintext encapsulation session — it does NOT implement the TLS/DTLS transport (that half of Vol 8
//! is stubbed on the branch, spike §5.2). So it is the independent-implementation peer for the Phase-2a
//! **posture decoders** (`cip/security.rs`): this drives the real `Get_Attribute_Single` reads of
//! 0x5D/0x5E/0x5F and asserts the typed decode against an implementation that is NOT ours.
//!
//! ## Self-skipping (the sibling live-sim pattern, §11.3)
//! At start we probe `TcpStream::connect(127.0.0.1:44818)`; if nothing is listening the test prints
//! `skipped` and returns, so `cargo test --workspace` stays green without the peer. Bring it up:
//!
//! ```bash
//! docker build -t opener-cipsec test-infra/opener-cipsecurity
//! docker run -d --name opener-cipsec -p 44822:44818 opener-cipsec eth0   # or: docker compose up opener-cipsec
//! cargo test -p ec-enip --test live_cip_security -- --nocapture
//! ```
//!
//! Excluded from the coverage denominator (`tests[/\\]live_cip_security`, §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use enip::{CipSecurityState, ClientOptions, EipClient};

// Host :44822 (compose `opener-cipsec`) — distinct from cpppo :44818, ab_server :44820, sharp :44821.
const ADDR: &str = "127.0.0.1:44822";

async fn up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(400), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

fn opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(3),
        ..ClientOptions::default()
    }
}

#[tokio::test]
async fn opener_cipsecurity_posture_reads() {
    if !up(ADDR).await {
        eprintln!(
            "live_cip_security: skipped (no OpENer-CIPSecurity on {ADDR}) — \
             docker build -t opener-cipsec test-infra/opener-cipsecurity && \
             docker run -d -p 44818:44818 opener-cipsec eth0"
        );
        return;
    }

    let client = EipClient::connect(ADDR, opts())
        .await
        .expect("connect to OpENer CIPSecurity");

    let posture = client
        .read_security_posture()
        .await
        .expect("read security posture");

    eprintln!("live_cip_security: posture = {posture:#?}");
    assert!(
        posture.is_available(),
        "OpENer CIPSecurity must implement at least one CIP Security object"
    );

    // --- CIP Security Object (0x5D) ---
    let cip = posture
        .cip_security
        .as_ref()
        .expect("0x5D CIP Security Object present");
    // Out of the box OpENer reports Factory Default (state 0), but any decoded state is a pass; the
    // point is the typed decode against a non-ours implementation.
    eprintln!(
        "live_cip_security: 0x5D state = {:?} ({})",
        cip.state,
        cip.state.description()
    );
    assert!(
        !matches!(cip.state, CipSecurityState::Unknown(_)),
        "state {:?} decoded to a known variant",
        cip.state
    );

    // The CIP Security profiles bitmap decodes to named bits (OpENer ships the EtherNet/IP
    // Confidentiality profile, bit 0x0002).
    let supported = cip
        .profiles_supported
        .expect("0x5D attr 2 security profiles present");
    eprintln!("live_cip_security: 0x5D profiles = {:?}", supported.names());
    assert!(
        supported.names().contains(&"EtherNet/IP Confidentiality"),
        "OpENer advertises the EtherNet/IP Confidentiality profile"
    );

    // --- EtherNet/IP Security Object (0x5E) ---
    let eip = posture
        .eip_security
        .as_ref()
        .expect("0x5E EtherNet/IP Security Object present");
    // In the Factory Default state the cipher-suite lists are empty (they are populated at
    // commissioning); the point of the live check is that the list STRUCTURE decodes (count-prefixed)
    // against a non-ours implementation, and the boolean flags decode.
    assert!(
        eip.available_cipher_suites.is_some(),
        "0x5E available cipher-suite list decodes (possibly empty in Factory Default)"
    );
    assert!(
        eip.allowed_cipher_suites.is_some(),
        "0x5E allowed cipher-suite list decodes"
    );
    assert_eq!(eip.verify_client_certificate, Some(false), "0x5E attr 9 decodes");
    assert_eq!(eip.check_expiration, Some(false), "0x5E attr 11 decodes");

    // --- Certificate Management Object (0x5F) ---
    let cert = posture
        .certificate_management
        .as_ref()
        .expect("0x5F Certificate Management Object present");
    let caps = cert.capabilities.expect("0x5F class attr 8 capability flags");
    eprintln!(
        "live_cip_security: 0x5F push={} pull={}",
        caps.push_supported(),
        caps.pull_supported()
    );
    let inst = cert.instance1.as_ref().expect("0x5F instance 1 present");
    assert_eq!(inst.name.as_deref(), Some("Default Device Certificate"), "0x5F/1/1 name");
    assert_eq!(inst.encoding, Some(enip::CertificateEncoding::Pem), "0x5F/1/5 encoding");

    client.close().await;
    eprintln!("live_cip_security: OpENer CIPSecurity posture-read PASSED");
}
