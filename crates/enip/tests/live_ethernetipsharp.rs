//! Live integration test: the real `enip::EipClient` against **EthernetIPSharp** — a third, fully
//! INDEPENDENT EtherNet/IP implementation (C#, github.com/CristianMori/EthernetIpSharp), driven as a
//! Logix server (DESIGN §11.7). This is the **browse gap-closer**: EthernetIPSharp's
//! LogixDispatcher/SymbolObject serves the Logix tag-LIST service — Get Instance Attribute List
//! (`0x55`) on the Symbol class (`0x6B`) — which neither cpppo nor libplctag's ab_server implements.
//! So this suite is the FIRST genuine on-the-wire validation of `enip::list_tags` against a real,
//! non-ours `0x55` implementation (previously exercised only against `duplex` fixtures), AND an
//! independent-implementation conformance cross-check of the read/write paths (a third opinion beyond
//! `enip`'s own assumptions and cpppo/ab_server).
//!
//! ## Self-skipping (the cpppo/OpENer/ab_server sibling pattern, §11.3)
//! At suite start we TCP-probe `ETHERNETIPSHARP_ADDR` (default `127.0.0.1:44821` — the §11.2 compose
//! host mapping for `enip-sharp`, distinct from cpppo `:44818` / OpENer `:44819` / ab_server `:44820`).
//! If nothing answers, the test prints a skip and returns `Ok`, so `cargo test --workspace` stays green
//! with no sim. Bring it up:
//!
//! ```bash
//! docker build -t ethernetip-sharp-sim test-infra/ethernetip-sharp
//! docker run --rm -p 44821:44818 ethernetip-sharp-sim
//! ```
//!
//! ## What it proves (§11.3 poll paths + the browse gap-closer)
//! connect (RegisterSession) · scalar REAL / DINT reads with **exact** host-seeded values · REAL[8]
//! array read · write + read-back of `FILL_SETPOINT` · a per-tag CIP error on a nonexistent tag while
//! a real tag stays GOOD · and crucially **`list_tags` (browse)**: a real `0x55` reply, enumerating the
//! defined tags with their symbol types — scalars value-supported, the REAL[8] array value-unsupported
//! (array dims) — the first live proof that `enip` emits a well-formed `0x55` request and correctly
//! decodes a genuine Get-Instance-Attribute-List page.
//!
//! Excluded from the coverage denominator (`tests[/\\]live_(cpppo|opener|ab_server|ethernetipsharp)`,
//! §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]

use std::time::Duration;

use enip::{CipType, CipValue, ClientOptions, EipClient, EnipError, Scope, TagAddress};

/// EthernetIPSharp's encapsulation endpoint. `127.0.0.1:44821` by default (the §11.2 compose host
/// mapping), overridable, e.g. `ETHERNETIPSHARP_ADDR=192.168.1.50:44818`.
fn sharp_addr() -> String {
    std::env::var("ETHERNETIPSHARP_ADDR").unwrap_or_else(|_| "127.0.0.1:44821".to_string())
}

/// Probe the sim's TCP port; `false` (and a printed skip) when nothing is listening (§11.3).
async fn sim_up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(400), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// EthernetIPSharp dispatches bare Message-Router requests over UCMM (like cpppo, no backplane), so no
/// route is set.
fn opts() -> ClientOptions {
    ClientOptions {
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(3),
        ..ClientOptions::default()
    }
}

fn tag(name: &str) -> TagAddress {
    TagAddress::parse(name).unwrap()
}

/// The read/write poll surface against the independent EthernetIPSharp implementation.
#[tokio::test]
async fn sharp_live_read_write() {
    let addr = sharp_addr();
    if !sim_up(&addr).await {
        eprintln!("live_ethernetipsharp: skipped (no EthernetIPSharp on {addr})");
        return;
    }
    println!("== live_ethernetipsharp: connecting to real EthernetIPSharp at {addr} ==");
    let client = EipClient::connect(&addr, opts())
        .await
        .expect("RegisterSession + session handshake against live EthernetIPSharp");
    println!("connected: session established (RegisterSession ok)");

    // ---- scalar REAL read (host-seeded LINE_SPEED=123.5) ------------------------------------------
    let r = client.read_tag(&tag("LINE_SPEED"), 1).await.expect("read LINE_SPEED");
    println!("read LINE_SPEED -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    assert_eq!(r.value, CipValue::Real(123.5));

    // ---- DINT read (host-seeded PRODUCT_COUNT=4242) -----------------------------------------------
    let r = client.read_tag(&tag("PRODUCT_COUNT"), 1).await.expect("read PRODUCT_COUNT");
    println!("read PRODUCT_COUNT -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Dint);
    assert_eq!(r.value, CipValue::Dint(4242));

    // ---- array read (host-seeded ZONE_TEMPS=[10..17]) ---------------------------------------------
    let r = client.read_tag(&tag("ZONE_TEMPS"), 8).await.expect("read ZONE_TEMPS[8]");
    println!("read ZONE_TEMPS[8] -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    let expect: Vec<CipValue> = (0..8).map(|i| CipValue::Real(10.0 + i as f32)).collect();
    assert_eq!(r.value, CipValue::Array(CipType::Real, expect));

    // ---- write + read-back of FILL_SETPOINT -------------------------------------------------------
    client
        .write_tag(&tag("FILL_SETPOINT"), CipType::Real, &CipValue::Real(55.5))
        .await
        .expect("write FILL_SETPOINT=55.5");
    let r = client.read_tag(&tag("FILL_SETPOINT"), 1).await.expect("read-back FILL_SETPOINT");
    println!("write+read-back FILL_SETPOINT -> {:?}", r.value);
    assert_eq!(r.value, CipValue::Real(55.5));

    // ---- per-tag error: a nonexistent tag is BAD while a real tag stays GOOD ----------------------
    let bad = client.read_tag(&tag("NO_SUCH_TAG"), 1).await;
    println!("read NO_SUCH_TAG -> {bad:?}");
    match bad {
        Err(EnipError::Cip(status)) => {
            println!("  -> per-tag CIP error (general status 0x{:02X}) as expected", status.general.code());
        }
        Err(other) => panic!("expected a per-tag CIP error for NO_SUCH_TAG, got {other:?}"),
        Ok(v) => panic!("expected NO_SUCH_TAG to fail, decoded {v:?}"),
    }
    let good = client.read_tag(&tag("LINE_SPEED"), 1).await.expect("LINE_SPEED still GOOD after a BAD tag");
    assert_eq!(good.value, CipValue::Real(123.5));
    println!("  -> LINE_SPEED still GOOD after the BAD tag: {:?}", good.value);

    client.close().await;
    println!("== live_ethernetipsharp read/write (independent-impl cross-check): PASS ==");
}

/// **The browse gap-closer.** EthernetIPSharp serves Get Instance Attribute List (`0x55`) on the Symbol
/// class (`0x6B`), so `enip::list_tags` gets a real wire reply for the first time (cpppo and ab_server
/// both refuse `0x55`). We page to completion and assert the defined tags are enumerated with sensible
/// symbol types: numeric scalars value-supported, the REAL[8] array value-unsupported (array dims).
#[tokio::test]
async fn sharp_live_tag_browse_enumerates() {
    let addr = sharp_addr();
    if !sim_up(&addr).await {
        eprintln!("live_ethernetipsharp (browse): skipped (no EthernetIPSharp on {addr})");
        return;
    }
    println!("== live_ethernetipsharp browse: connecting to real EthernetIPSharp at {addr} ==");
    let client = EipClient::connect(&addr, opts()).await.expect("connect for browse");

    // Page the tag list to completion (the FIRST real 0x55 exchange for enip::list_tags).
    let mut all: Vec<(String, enip::SymbolType)> = Vec::new();
    let (records, mut next) = client
        .list_tags(0, &Scope::Controller)
        .await
        .expect("list_tags 0x55 against EthernetIPSharp (browse gap-closer)");
    println!("browse page 1 returned {} record(s), next={next:?}", records.len());
    for s in &records {
        all.push((s.name.clone(), s.symbol_type));
    }
    let mut pages = 1;
    while let Some(n) = next {
        let (recs, nxt) = client.list_tags(n, &Scope::Controller).await.expect("browse page");
        for s in &recs {
            all.push((s.name.clone(), s.symbol_type));
        }
        next = nxt;
        pages += 1;
        if pages > 50 {
            break;
        }
    }

    println!("browse enumerated {} tag(s) over {pages} page(s):", all.len());
    for (name, st) in &all {
        println!(
            "  {name:<16} symbol_type=0x{:04X}  cip_type={:?}  dims={}  value_supported={}",
            st.0,
            st.cip_type(),
            st.dims(),
            st.is_value_supported()
        );
    }

    let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
    for expected in ["LINE_SPEED", "PRODUCT_COUNT", "FILL_SETPOINT", "MOTOR_RUN", "ZONE_TEMPS"] {
        assert!(names.contains(&expected), "browse lists {expected}; got {names:?}");
    }

    // A scalar REAL is value-supported (atomic, non-array elementary).
    let line = all.iter().find(|(n, _)| n == "LINE_SPEED").map(|(_, st)| *st).unwrap();
    assert_eq!(line.cip_type(), Some(CipType::Real));
    assert!(line.is_value_supported(), "LINE_SPEED (scalar REAL) is value-supported");

    // A scalar DINT is value-supported.
    let count = all.iter().find(|(n, _)| n == "PRODUCT_COUNT").map(|(_, st)| *st).unwrap();
    assert_eq!(count.cip_type(), Some(CipType::Dint));
    assert!(count.is_value_supported(), "PRODUCT_COUNT (scalar DINT) is value-supported");

    // The REAL[8] array is reported with array dims ⇒ value-unsupported (the same class as an SSTRING).
    let zone = all.iter().find(|(n, _)| n == "ZONE_TEMPS").map(|(_, st)| *st).unwrap();
    assert!(zone.dims() >= 1, "ZONE_TEMPS is an array (dims >= 1), got dims={}", zone.dims());
    assert!(!zone.is_value_supported(), "ZONE_TEMPS (REAL[8]) is value-unsupported (array dims)");

    client.close().await;
    println!("== live_ethernetipsharp browse: PASS (real 0x55 — browse gap CLOSED) ==");
}
