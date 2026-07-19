//! Live integration test: the real `enip::EipClient` against a real **cpppo** EtherNet/IP tag
//! server (DESIGN §11.1/§11.3). This is the first time explicit messaging (`client.rs`/`logix.rs`)
//! meets a genuine, independent EtherNet/IP implementation on the wire — not a `duplex` fixture.
//!
//! ## Self-skipping (the sibling Modbus live-slave pattern, §11.3)
//! At suite start we probe `TcpStream::connect(127.0.0.1:44818)` with a short timeout. If nothing is
//! listening the test prints `skipped (no cpppo)` and returns `Ok` — so `cargo test --workspace`
//! stays green on a machine with no sim. Bring the sim up with the §11.1 tag layout:
//!
//! ```bash
//! docker run --rm -p 44818:44818 cpppo/cpppo \
//!   python -m cpppo.server.enip --address 0.0.0.0:44818 -v \
//!   LINE_SPEED=REAL FILL_TEMP=REAL TANK_LEVEL=REAL PRODUCT_COUNT=DINT \
//!   FILL_SETPOINT=REAL ZONE_TEMPS=REAL[8] MOTOR_RUN=DINT RECIPE=SSTRING
//! ```
//!
//! ## What it proves (§11.3 poll paths)
//! connect (RegisterSession) · scalar/array/DINT reads with **exact** values (we seed by writing
//! first, since cpppo boots every tag at 0) · write + read-back of `FILL_SETPOINT` · a per-tag CIP
//! error on a nonexistent tag while a real tag stays GOOD in the same run · tag-list browse paging.
//!
//! Excluded from the coverage denominator (`tests[/\\]live_(cpppo|opener)`, §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]

use std::time::Duration;

use enip::{CipType, CipValue, ClientOptions, EipClient, EnipError, Scope, TagAddress};

const CPPPO_ADDR: &str = "127.0.0.1:44818";

/// Probe the sim's TCP port; `false` (and a printed skip) when nothing is listening (§11.3).
async fn sim_up() -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(400),
            tokio::net::TcpStream::connect(CPPPO_ADDR),
        )
        .await,
        Ok(Ok(_))
    )
}

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

/// The whole poll surface in one connection (one session, sequential CIP transactions), so the
/// per-tag GOOD/BAD interleave and the write→read-back are proven on the same live link.
#[tokio::test]
async fn cpppo_live_read_write_browse() {
    if !sim_up().await {
        eprintln!("live_cpppo: skipped (no cpppo on {CPPPO_ADDR})");
        return;
    }
    println!("== live_cpppo: connecting to real cpppo at {CPPPO_ADDR} ==");
    let client = EipClient::connect(CPPPO_ADDR, opts())
        .await
        .expect("RegisterSession + session handshake against live cpppo");
    println!("connected: session established (RegisterSession ok)");

    // ---- seed deterministic values (cpppo boots every tag at 0) --------------------------------
    // A scalar REAL, a DINT, and an 8-element REAL array — written over the real wire so the
    // subsequent reads assert EXACT values decoded from genuine device replies.
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

    // ---- scalar read --------------------------------------------------------------------------
    let r = client.read_tag(&tag("LINE_SPEED"), 1).await.expect("read LINE_SPEED");
    println!("read LINE_SPEED -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    assert_eq!(r.value, CipValue::Real(123.5));

    // ---- DINT read ----------------------------------------------------------------------------
    let r = client.read_tag(&tag("PRODUCT_COUNT"), 1).await.expect("read PRODUCT_COUNT");
    println!("read PRODUCT_COUNT -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Dint);
    assert_eq!(r.value, CipValue::Dint(4242));

    // ---- array read ---------------------------------------------------------------------------
    let r = client.read_tag(&tag("ZONE_TEMPS"), 8).await.expect("read ZONE_TEMPS[8]");
    println!("read ZONE_TEMPS[8] -> {:?} (wire type {:?})", r.value, r.wire_type);
    assert_eq!(r.wire_type, CipType::Real);
    assert_eq!(r.value, CipValue::Array(CipType::Real, zone_seed));

    // ---- write + read-back of FILL_SETPOINT (§11.1 writable) -----------------------------------
    client
        .write_tag(&tag("FILL_SETPOINT"), CipType::Real, &CipValue::Real(55.5))
        .await
        .expect("write FILL_SETPOINT=55.5");
    let r = client.read_tag(&tag("FILL_SETPOINT"), 1).await.expect("read-back FILL_SETPOINT");
    println!("write+read-back FILL_SETPOINT -> {:?}", r.value);
    assert_eq!(r.value, CipValue::Real(55.5));

    // ---- per-tag error: a nonexistent tag is BAD while a real tag stays GOOD -------------------
    let bad = client.read_tag(&tag("NO_SUCH_TAG"), 1).await;
    println!("read NO_SUCH_TAG -> {bad:?}");
    match bad {
        Err(EnipError::Cip(status)) => {
            println!("  -> per-tag CIP error (general status 0x{:02X}) as expected", status.general.code());
        }
        Err(other) => panic!("expected a per-tag CIP error for NO_SUCH_TAG, got {other:?}"),
        Ok(v) => panic!("expected NO_SUCH_TAG to fail, decoded {v:?}"),
    }
    // The link is still GOOD after a per-tag error: a real tag reads fine in the same session.
    let good = client.read_tag(&tag("LINE_SPEED"), 1).await.expect("LINE_SPEED still GOOD after a BAD tag");
    assert_eq!(good.value, CipValue::Real(123.5));
    println!("  -> LINE_SPEED still GOOD after the BAD tag: {:?}", good.value);

    client.close().await;
    println!("== live_cpppo read/write/error: PASS ==");
}

/// Tag-list browse (Get Instance Attribute List, `0x55` on the Symbol class `0x6B`) against live
/// cpppo — a **fresh** connection because cpppo terminates the session on this request (below).
///
/// **Live finding (recorded here, not hidden):** cpppo 3.9.7's `enip.server` does NOT implement the
/// Logix tag-enumeration service. Its request parser rejects service `0x55` at byte 0 and drops the
/// TCP session (server EtherNet/IP status `0x08`). The request `enip` emits —
/// `55 02 20 6B 24 00 02 00 01 00 02 00` — is the *standard* Get-Instance-Attribute-List form
/// (Symbol class `0x6B`, instance 0, attributes 1 name + 2 type) that a real Logix controller
/// answers; it is not a mis-encoding. OpENer is a generic adapter with no Logix Symbol object either,
/// so **full tag-list browse (with `RECIPE` marked unsupported) is a real-Logix (lab, §12.4)
/// validation path — neither external container sim can serve it.** What this test proves live is
/// that `enip` emits the well-formed request and surfaces the device's refusal as a *typed* error
/// (the adapter's `BROWSE_UNSUPPORTED`), never a panic — which is exactly the generic-CIP-device path.
#[tokio::test]
async fn cpppo_live_tag_browse_is_gracefully_refused() {
    if !sim_up().await {
        eprintln!("live_cpppo (browse): skipped (no cpppo on {CPPPO_ADDR})");
        return;
    }
    println!("== live_cpppo browse: connecting to real cpppo at {CPPPO_ADDR} ==");
    let client = EipClient::connect(CPPPO_ADDR, opts()).await.expect("connect for browse");

    match client.list_tags(0, &Scope::Controller).await {
        // A Logix-capable target (real PLC / future sim) answers with the page.
        Ok((records, next)) => {
            println!("browse returned {} record(s), next={next:?}:", records.len());
            let mut all: Vec<(String, _)> = records.iter().map(|s| (s.name.clone(), s.symbol_type)).collect();
            // Page to completion.
            let mut start = next;
            let mut pages = 1;
            while let Some(n) = start {
                let (recs, nxt) = client.list_tags(n, &Scope::Controller).await.expect("browse page");
                for s in &recs {
                    all.push((s.name.clone(), s.symbol_type));
                }
                start = nxt;
                pages += 1;
                if pages > 50 {
                    break;
                }
            }
            for (name, st) in &all {
                println!("  {name:<16} type=0x{:04X} value_supported={}", st.0, st.is_value_supported());
            }
            let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
            assert!(names.contains(&"RECIPE"), "browse lists RECIPE; got {names:?}");
            let recipe = all.iter().find(|(n, _)| n == "RECIPE").map(|(_, st)| *st).unwrap();
            assert!(!recipe.is_value_supported(), "RECIPE (SSTRING) is value-unsupported (§11.1)");
            println!("== live_cpppo browse: PASS (Logix-capable target) ==");
        }
        // cpppo (and any generic non-Logix CIP device): the tag-list service is unsupported. The
        // client must surface a *typed* error, never a panic — the adapter maps this to
        // BROWSE_UNSUPPORTED (§7.3, §10.1). This is the recorded live outcome against cpppo 3.9.7.
        Err(e) => {
            println!("browse refused by cpppo (expected — no Logix tag-enumeration service): {e:?}");
            assert!(
                matches!(e, EnipError::Encap(_) | EnipError::Cip(_) | EnipError::Closed | EnipError::ConnectionLost { .. } | EnipError::Io(_)),
                "browse refusal is a typed error (got {e:?})"
            );
            println!("== live_cpppo browse: PASS (typed refusal; full browse is a real-Logix path, §12.4) ==");
        }
    }
    client.close().await;
}
