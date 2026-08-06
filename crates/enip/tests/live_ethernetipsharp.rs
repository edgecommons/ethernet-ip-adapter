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
//! ## Self-skipping, and the required mode that removes it (§11.3)
//! At suite start we TCP-probe `ETHERNETIPSHARP_ADDR` (default `127.0.0.1:44821` — the §11.2 compose
//! host mapping for `enip-sharp`, distinct from cpppo `:44818` / OpENer `:44819` / ab_server `:44820`).
//! If nothing answers, the test prints a skip and returns `Ok`, so `cargo test --workspace` stays green
//! with no sim. **`ENIP_LIVE_REQUIRED=1` turns that skip into a failure** ([`live_required`]), so the
//! CI live gate cannot pass vacuously. Bring it up:
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
//! decodes a genuine Get-Instance-Attribute-List page. It additionally proves the **32-bit logical
//! instance segment** (`0x26`, §6.2) that browse cursors above `0xFFFF` ride: an independent CIP
//! decoder accepts it as a well-formed path and answers at the CIP layer.
//!
//! Excluded from the coverage denominator (`tests[/\\]live_(cpppo|opener|ab_server|ethernetipsharp)`,
//! §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]

use std::time::Duration;

use enip::{CipType, CipValue, ClientOptions, EipClient, EnipError, GeneralStatus, Scope, TagAddress};

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

/// CI hardening (§11.3): under `ENIP_LIVE_REQUIRED=1` a missing peer is a **FAILURE**, never a
/// silent skip — the live gate cannot pass vacuously. Unset (or empty, or `0`) keeps the
/// bench-friendly self-skip, so `cargo test --workspace` stays green with no sims up.
fn live_required() -> bool {
    std::env::var("ENIP_LIVE_REQUIRED").is_ok_and(|v| !v.is_empty() && v != "0")
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
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no EthernetIPSharp on {addr} — \
             docker compose up -d enip-sharp"
        );
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
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no EthernetIPSharp on {addr} (browse leg) — \
             docker compose up -d enip-sharp"
        );
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

/// **The browse-cursor bench leg (F7).** `list_tags` carries a full `u32` symbol-instance cursor and
/// addresses it with the 8-, 16-, or 32-bit logical instance segment by magnitude (`0x24`/`0x25`/
/// `0x26`, §6.2). Fixtures prove the arithmetic; this proves the two things only a real, independent
/// CIP decoder can:
///
/// 1. **The enumeration is complete and exactly-once against a real `0x55` server** — every defined
///    tag appears once, with strictly ascending instance ids, and the walk terminates from the
///    reply's own status rather than from a caller-side page cap.
/// 2. **A cursor above the 16-bit space reaches the wire as a well-formed path.** A request built
///    for `start_instance = 0x0001_0000` emits `26 00 00 00 01 00` where an 8-bit cursor emits
///    `24 xx`. EthernetIPSharp parses it and answers at the CIP layer — the reply is a *CIP status
///    about the instance*, never a path-segment or path-size error, and never a framing failure that
///    would drop the session. That is an independent implementation agreeing with our encoding of a
///    segment no bench peer can otherwise exercise (none serves more than 65 535 symbol instances).
///
/// **Recorded peer capability:** EthernetIPSharp serves the enumeration only from the class-level
/// start instance and returns its whole symbol table in one page, so resuming mid-set is not a
/// capability it has. The test asserts what the peer actually does in either case and never passes
/// silently: a mid-set resume must be either a correct resumed page or a *typed* CIP refusal.
#[tokio::test]
async fn sharp_live_browse_cursor_walk_and_32bit_instance_segment() {
    let addr = sharp_addr();
    if !sim_up(&addr).await {
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no EthernetIPSharp on {addr} (browse-cursor leg) — \
             docker compose up -d enip-sharp"
        );
        eprintln!("live_ethernetipsharp (browse cursor): skipped (no EthernetIPSharp on {addr})");
        return;
    }
    println!("== live_ethernetipsharp browse cursor: connecting to real EthernetIPSharp at {addr} ==");
    let client = EipClient::connect(&addr, opts()).await.expect("connect for the cursor walk");

    // ---- 1. the reference walk: page from the start of the instance space to completion ----------
    let mut all: Vec<(u32, String)> = Vec::new();
    let mut cursor: Option<u32> = Some(0);
    let mut pages = 0usize;
    while let Some(start) = cursor {
        let (records, next) = client
            .list_tags(start, &Scope::Controller)
            .await
            .unwrap_or_else(|e| panic!("list_tags({start}) against the live 0x55 server: {e:?}"));
        pages += 1;
        println!("  page {pages}: start={start} -> {} record(s), next={next:?}", records.len());
        for s in &records {
            all.push((s.instance_id, s.name.clone()));
        }
        cursor = next;
        assert!(pages <= 50, "the walk must terminate on the reply's own status");
    }

    let names: Vec<&str> = all.iter().map(|(_, n)| n.as_str()).collect();
    for expected in ["LINE_SPEED", "PRODUCT_COUNT", "FILL_SETPOINT", "MOTOR_RUN", "ZONE_TEMPS"] {
        assert!(names.contains(&expected), "the walk enumerates {expected}; got {names:?}");
    }
    // Exactly once, and in ascending instance order — the property the cursor rules depend on.
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "no tag is enumerated twice: {names:?}");
    let ids: Vec<u32> = all.iter().map(|(i, _)| *i).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "instance ids ascend: {ids:?}");
    println!("  reference walk: {} tag(s) over {pages} page(s), ids {ids:?}", all.len());

    // ---- 2. resume from a cursor mid-set ---------------------------------------------------------
    // The §7.3 contract a compliant server offers: re-issuing at `last_id + 1` continues where the
    // page stopped. Whether this peer HAS that capability is what we record.
    let mid = ids[ids.len() / 2];
    match client.list_tags(mid, &Scope::Controller).await {
        Ok((records, next)) => {
            println!("  resume at {mid}: {} record(s), next={next:?}", records.len());
            assert!(
                records.iter().all(|s| s.instance_id >= mid),
                "a resumed page returns nothing before its cursor: {:?}",
                records.iter().map(|s| s.instance_id).collect::<Vec<_>>()
            );
            let resumed: Vec<&str> = records.iter().map(|s| s.name.as_str()).collect();
            assert!(
                resumed.iter().all(|n| names.contains(n)),
                "a resumed page is a suffix of the full set: {resumed:?} vs {names:?}"
            );
        }
        Err(EnipError::Cip(status)) => {
            // The recorded outcome for this peer: its Symbol object answers the enumeration only at
            // the class-level start instance. A typed CIP status is still the right shape — the
            // request was well formed and routed; the peer simply declines. This is a peer-limit
            // path, not a missing peer: it stays a recorded capability gap even under
            // ENIP_LIVE_REQUIRED=1, which only demands that the peer was REACHED.
            println!(
                "  resume at {mid}: declined with CIP general status 0x{:02X} — this peer serves \
                 the enumeration only from the class-level start instance (one page, no cursor)",
                status.general.code()
            );
        }
        Err(other) => panic!("a mid-set resume must be a page or a typed CIP refusal, got {other:?}"),
    }

    // ---- 3. the 32-bit instance segment on the wire (the F7 encoding proof) ----------------------
    // `list_tags` builds `EPath::new().class(0x6B).instance(start)`, which emits the 32-bit logical
    // instance form for anything above 0xFFFF. Nothing in this tag set lives there, so what the peer
    // answers is "no such instance" — but it has to PARSE the path to say so.
    for start in [0x0001_0000u32, u32::MAX] {
        match client.list_tags(start, &Scope::Controller).await {
            Err(EnipError::Cip(status)) => {
                println!(
                    "  32-bit cursor {start:#010X} (0x26 segment): CIP general status 0x{:02X}",
                    status.general.code()
                );
                assert_ne!(
                    status.general,
                    GeneralStatus::PathSegmentError,
                    "an independent decoder must not read the 0x26 segment as a malformed path"
                );
                assert_ne!(
                    status.general,
                    GeneralStatus::InvalidPathSize,
                    "the 0x26 segment is self-padding, so the path stays word-aligned"
                );
            }
            // A peer that really did serve instances that high would answer with a page; the cursor
            // must then still be honoured verbatim rather than masked back into the 16-bit space.
            Ok((records, next)) => {
                println!("  32-bit cursor {start:#010X}: {} record(s), next={next:?}", records.len());
                assert!(
                    records.iter().all(|s| s.instance_id >= start),
                    "a 32-bit cursor is not masked: {:?}",
                    records.iter().map(|s| s.instance_id).collect::<Vec<_>>()
                );
            }
            Err(other) => panic!(
                "the 0x26 instance segment must reach the peer as a well-formed request; \
                 got a non-CIP failure: {other:?}"
            ),
        }
    }

    // The 32-bit requests did not wedge the session: the reference walk still answers.
    let (records, _) = client
        .list_tags(0, &Scope::Controller)
        .await
        .expect("the session survives a 32-bit-cursor request");
    assert_eq!(records.len(), all.len(), "the tag set is unchanged after the 32-bit probes");

    client.close().await;
    println!("== live_ethernetipsharp browse cursor: PASS (exactly-once walk + live 0x26 segment) ==");
}
