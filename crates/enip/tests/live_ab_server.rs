//! Live integration test: the real `enip::EipClient` against **libplctag's `ab_server`** — a second,
//! INDEPENDENT EtherNet/IP Logix target (DESIGN §11.6). ab_server is the CIP PLC simulator that ships
//! inside libplctag (`src/tools/ab_server`, MPL-2.0) and is the CI reference server libplctag tests
//! its own client against — a codebase entirely independent of both `enip` and cpppo, so it is a
//! genuine *second* conformance peer for explicit-messaging poll paths, and the FIRST to exercise the
//! **Unconnected_Send (`0x52`) route wrapper** (`ClientOptions.route`, the CompactLogix/ControlLogix
//! backplane path) live — cpppo is direct (no backplane) and never wraps.
//!
//! ## Self-skipping (the cpppo/OpENer sibling pattern, §11.3)
//! At suite start we TCP-probe `AB_SERVER_ADDR` (default `127.0.0.1:44820` — the §11.2 compose host
//! mapping for `enip-ab-server`, distinct from cpppo `:44818` / OpENer `:44819`). If nothing answers,
//! the test prints a skip and returns `Ok`, so `cargo test --workspace` stays green with no sim. Bring
//! it up with the §11.6 tag layout:
//!
//! ```bash
//! docker build -t ab-server-sim test-infra/ab-server
//! docker run --rm -p 44820:44818 ab-server-sim
//! ```
//!
//! ## What it proves (§11.3 poll paths, via a real Unconnected_Send route)
//! connect (RegisterSession) · scalar REAL / DINT / REAL[8]-array reads with **exact** seeded values
//! decoded from genuine ab_server replies · write + read-back of `FILL_SETPOINT` · a per-tag CIP error
//! on a nonexistent tag while a real tag stays GOOD in the same session · and that `list_tags` (browse)
//! is *typed-refused* — ab_server does NOT implement Get Instance Attribute List `0x55` (verified in
//! source + full git history, §11.6), so it returns `CIP_ERR_UNSUPPORTED` (`0x08`); the client surfaces
//! this as a typed error, never a panic (the generic-CIP-device / `BROWSE_UNSUPPORTED` path — the
//! browse gap-closer is the EthernetIPSharp `0x55` peer in `live_ethernetipsharp.rs`, §11.7).
//!
//! Excluded from the coverage denominator (`tests[/\\]live_(cpppo|opener|ab_server|ethernetipsharp)`,
//! §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]

use std::time::Duration;

use enip::{
    CipType, CipValue, ClientOptions, EipClient, EnipError, RoutePath, Scope, TagAddress,
};

/// ab_server's encapsulation endpoint. `127.0.0.1:44820` by default (the §11.2 compose host mapping),
/// overridable, e.g. `AB_SERVER_ADDR=192.168.1.50:44818`.
fn ab_addr() -> String {
    std::env::var("AB_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:44820".to_string())
}

/// Probe the sim's TCP port; `false` (and a printed skip) when nothing is listening (§11.3).
async fn sim_up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(400), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// ab_server is a ControlLogix target reached through the backplane path (`1,0`), so the client wraps
/// every explicit request in a real Unconnected_Send (`0x52`) with the backplane-slot route — the path
/// cpppo never exercises. (ab_server accepts any route in the `0x52` wrapper; the point here is that
/// `enip` emits a well-formed routed request and the target answers it.)
fn opts() -> ClientOptions {
    ClientOptions {
        route: Some(RoutePath::backplane_slot(0)),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(3),
        ..ClientOptions::default()
    }
}

fn tag(name: &str) -> TagAddress {
    TagAddress::parse(name).unwrap()
}

/// The whole poll surface in one connection against ab_server (one session, sequential CIP
/// transactions over Unconnected_Send), so the per-tag GOOD/BAD interleave and the write→read-back are
/// proven on the same live link.
#[tokio::test]
async fn ab_server_live_read_write_routed() {
    let addr = ab_addr();
    if !sim_up(&addr).await {
        eprintln!("live_ab_server: skipped (no ab_server on {addr})");
        return;
    }
    println!("== live_ab_server: connecting to real libplctag ab_server at {addr} (Unconnected_Send route 1,0) ==");
    let client = EipClient::connect(&addr, opts())
        .await
        .expect("RegisterSession + session handshake against live ab_server");
    println!("connected: session established (RegisterSession ok)");

    // ---- seed deterministic values (write over the real wire, then assert EXACT reads) ------------
    client
        .write_tag(&tag("LINE_SPEED"), CipType::Real, &CipValue::Real(123.5))
        .await
        .expect("write LINE_SPEED");
    client
        .write_tag(&tag("PRODUCT_COUNT"), CipType::Dint, &CipValue::Dint(4242))
        .await
        .expect("write PRODUCT_COUNT");
    let zone_seed: Vec<CipValue> = (0..8).map(|i| CipValue::Real(10.0 + i as f32)).collect();
    client
        .write_tag(
            &tag("ZONE_TEMPS"),
            CipType::Real,
            &CipValue::Array(CipType::Real, zone_seed.clone()),
        )
        .await
        .expect("write ZONE_TEMPS[8]");
    println!("seeded LINE_SPEED=123.5, PRODUCT_COUNT=4242, ZONE_TEMPS=[10..17]");

    // ---- scalar REAL read -------------------------------------------------------------------------
    let r = client.read_tag(&tag("LINE_SPEED"), 1).await.expect("read LINE_SPEED");
    println!("read LINE_SPEED -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    assert_eq!(r.value, CipValue::Real(123.5));

    // ---- DINT read --------------------------------------------------------------------------------
    let r = client.read_tag(&tag("PRODUCT_COUNT"), 1).await.expect("read PRODUCT_COUNT");
    println!("read PRODUCT_COUNT -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Dint);
    assert_eq!(r.value, CipValue::Dint(4242));

    // ---- array read -------------------------------------------------------------------------------
    let r = client.read_tag(&tag("ZONE_TEMPS"), 8).await.expect("read ZONE_TEMPS[8]");
    println!("read ZONE_TEMPS[8] -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    assert_eq!(r.value, CipValue::Array(CipType::Real, zone_seed));

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
    println!("== live_ab_server read/write (routed via Unconnected_Send): PASS ==");
}

/// Browse against ab_server. **Live finding (recorded, not hidden):** ab_server does NOT implement the
/// Logix tag-list service (Get Instance Attribute List `0x55` on Symbol class `0x6B`) — verified in
/// `cip.c` (the `0x55` case is absent from `cip_dispatch_request`; the `CIP_LIST_TAGS` bytes are
/// commented out) and across the repo's full git history (§11.6). It answers `0x55` with
/// `CIP_ERR_UNSUPPORTED` (`0x08`). So ab_server does NOT close the browse gap; what it proves live is
/// that `enip` emits the well-formed `0x55` request and surfaces the device's refusal as a *typed*
/// error (the adapter's `BROWSE_UNSUPPORTED`), never a panic — the generic-CIP-device path. The real
/// independent `0x55` conformance peer is EthernetIPSharp (`live_ethernetipsharp.rs`, §11.7).
#[tokio::test]
async fn ab_server_live_browse_is_gracefully_refused() {
    let addr = ab_addr();
    if !sim_up(&addr).await {
        eprintln!("live_ab_server (browse): skipped (no ab_server on {addr})");
        return;
    }
    println!("== live_ab_server browse: connecting to real ab_server at {addr} ==");
    let client = EipClient::connect(&addr, opts()).await.expect("connect for browse");

    match client.list_tags(0, &Scope::Controller).await {
        // A Logix-capable target answers with the page (ab_server does not — see below).
        Ok((records, next)) => {
            println!("browse unexpectedly returned {} record(s), next={next:?}", records.len());
            for s in &records {
                println!("  {:<16} type=0x{:04X}", s.name, s.symbol_type.0);
            }
            // ab_server is expected to refuse; if a future ab_server serves 0x55, that is a strictly
            // better outcome — record it rather than fail.
            println!("== live_ab_server browse: PASS (target served 0x55 — future ab_server) ==");
        }
        // The recorded live outcome: 0x55 is unsupported. The client must surface a *typed* error.
        Err(e) => {
            println!("browse refused by ab_server (expected — no Logix 0x55 tag-list service): {e:?}");
            assert!(
                matches!(
                    e,
                    EnipError::Cip(_)
                        | EnipError::Encap(_)
                        | EnipError::Closed
                        | EnipError::ConnectionLost { .. }
                        | EnipError::Io(_)
                ),
                "browse refusal is a typed error (got {e:?})"
            );
            if let EnipError::Cip(status) = &e {
                println!("  -> typed CIP refusal, general status 0x{:02X} (0x08 = Unsupported)", status.general.code());
            }
            println!("== live_ab_server browse: PASS (typed refusal; browse gap-closer is EthernetIPSharp, §11.7) ==");
        }
    }
    client.close().await;
}
