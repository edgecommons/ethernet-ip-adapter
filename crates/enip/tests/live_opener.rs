//! Live integration test: the real `enip::IoManager` class-1 implicit-I/O runtime against a real
//! **OpENer** adapter/target (DESIGN §11.3/§11.5). This is the first time `io.rs`/`cm.rs` meet a
//! genuine, independent EtherNet/IP *target* on the wire — ForwardOpen, cyclic T→O consume, O→T
//! produce, and the inactivity watchdog — not a `duplex`/crafted-bytes fixture.
//!
//! ## Self-skipping, and the required mode that removes it (§11.3)
//! We TCP-probe the OpENer encapsulation port (`OPENER_ADDR`, default `127.0.0.1:44818`). If nothing
//! answers the test prints a skip and returns — `cargo test --workspace` stays green without the
//! target. **`ENIP_LIVE_REQUIRED=1` turns that skip into a failure** ([`live_required`]), so the CI
//! live gate cannot pass vacuously. Required mode additionally demands `OPENER_STOP_CMD`, without
//! which the watchdog assertion retires itself while the run stays green — a harness
//! misconfiguration, not a peer limit. Build + run OpENer (native on Linux, or `--network host` on a
//! Linux docker host so the class-1 UDP :2222 loop is symmetric — see `test-infra/opener/Dockerfile`):
//!
//! ```bash
//! # native (WSL/Linux): build via the same source the Dockerfile uses, then
//! ./OpENer <iface>                 # binds <iface>'s IPv4; serves assemblies 100/150/151
//! # then, from the same host:
//! OPENER_ADDR=127.0.0.1:44818 OPENER_STOP_CMD='pkill -x OpENer' \
//!   cargo test -p ec-enip --test live_opener -- --nocapture
//! ```
//!
//! ## The OpENer sample assemblies (pinned from source, §11.5)
//! input (T→O produced) **100**, 32 B · output (O→T consumed) **150**, 32 B · config **151**, 10 B;
//! exclusive-owner (150→100→151). The sample's `AfterAssemblyDataReceived` **mirrors the O→T output
//! we send straight into the T→O input it produces**, so a produced value is observable in the very
//! next consumed frame — that is how the produce path is proven live.
//!
//! ## What it proves (§11.3 push paths)
//! ForwardOpen a class-1 connection · `IoEvent::Up` with the negotiated APIs · cyclic `Data` frames
//! with **advancing class-1 sequence** · O→T produce observed via OpENer's output→input mirror ·
//! the watchdog firing `IoEvent::Lost { Timeout }` once the target goes silent · the class-3
//! inactivity keepalive (§7.6) keeping an idle connected session alive across multiple windows ·
//! the latest-wins event queue (§8.6) handing a stalled consumer the freshest frames.
//!
//! Excluded from the coverage denominator (`tests[/\\]live_(cpppo|opener)`, §12.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use enip::{
    AssemblyPath, ClientOptions, ConnType, DirectionSpec, EipClient, IoConnectionSpec, IoEvent,
    IoManager, LostReason, Priority, ProductionTrigger, RealTimeFormat, TimeoutMultiplier,
    VariableLength,
};

/// OpENer's encapsulation endpoint. Defaults to `127.0.0.1:44819` — the §11.2 compose host mapping
/// for `enip-io-sim`, deliberately distinct from cpppo's `:44818` so this suite self-skips (rather
/// than mis-firing against a cpppo poll sim) on a machine where only cpppo is up. Override for a
/// native/remote target, e.g. `OPENER_ADDR=192.168.1.50:44818`.
fn opener_addr() -> String {
    std::env::var("OPENER_ADDR").unwrap_or_else(|_| "127.0.0.1:44819".to_string())
}

/// A shell command that makes OpENer go silent (to fire the originator watchdog), e.g.
/// `pkill -x OpENer` (native) or `docker kill opener-test` (container). When unset, the watchdog
/// assertion is skipped with a printed note rather than faked — except under
/// `ENIP_LIVE_REQUIRED=1`, where its absence is a harness misconfiguration and therefore a failure
/// ([`live_required`]).
fn opener_stop_cmd() -> Option<String> {
    std::env::var("OPENER_STOP_CMD")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn opener_up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr)
        )
        .await,
        Ok(Ok(_))
    )
}

/// CI hardening (§11.3): under `ENIP_LIVE_REQUIRED=1` a missing peer is a **FAILURE**, never a
/// silent skip — the live gate cannot pass vacuously. Unset (or empty, or `0`) keeps the
/// bench-friendly self-skip, so `cargo test --workspace` stays green with no sims up.
fn live_required() -> bool {
    std::env::var("ENIP_LIVE_REQUIRED").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// The OpENer exclusive-owner class-1 spec at the suite's ordinary 100 ms RPI.
fn opener_spec() -> IoConnectionSpec {
    opener_spec_at(Duration::from_millis(100))
}

/// The OpENer exclusive-owner class-1 spec: O→T (output 150) carries data + run/idle (Header32Bit);
/// T→O (input 100) is pure 32-byte data (Modeless); config 151 in the connection path. `rpi` is
/// requested in both directions — the overflow test asks for a much faster cadence than the
/// functional test needs.
fn opener_spec_at(rpi: Duration) -> IoConnectionSpec {
    IoConnectionSpec {
        assembly: AssemblyPath {
            config: Some(151),
            output: 150,
            input: 100,
            route: vec![],
        },
        // T→O: OpENer produces the 32-byte input assembly, pure data.
        t2o: DirectionSpec {
            rpi,
            data_size: 32,
            format: RealTimeFormat::Modeless,
            conn_type: ConnType::P2P,
            priority: Priority::Scheduled,
            variable: VariableLength::Fixed,
        },
        // O→T: we produce the 32-byte output assembly with a run/idle header (exclusive owner).
        o2t: DirectionSpec {
            rpi,
            data_size: 32,
            format: RealTimeFormat::Header32Bit,
            conn_type: ConnType::P2P,
            priority: Priority::Scheduled,
            variable: VariableLength::Fixed,
        },
        timeout_multiplier: TimeoutMultiplier::X16,
        trigger: ProductionTrigger::Cyclic,
        vendor_id: 0x1337,
    }
}

#[tokio::test]
async fn opener_live_class1_forward_open_consume_produce_watchdog() {
    let addr = opener_addr();
    if !opener_up(&addr).await {
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no OpENer on {addr} — \
             docker run -d --name opener-live --network host <opener image> <iface> \
             (set OPENER_ADDR to the host's primary IPv4:44818)"
        );
        eprintln!("live_opener: skipped (no OpENer on {addr})");
        return;
    }
    println!("== live_opener: class-1 I/O against real OpENer at {addr} ==");

    // The owning TCP session (carries the ForwardOpen over UCMM).
    let client = EipClient::connect(
        &addr,
        ClientOptions {
            connect_timeout: Duration::from_secs(3),
            ..ClientOptions::default()
        },
    )
    .await
    .expect("connect TCP session to OpENer");
    println!("TCP session + RegisterSession ok");

    // Bind the implicit-I/O UDP socket on an EPHEMERAL port. `forward_open` advertises this port to
    // the target in the T→O Sockaddr Info item (§8.2), so the target produces T→O to it — letting the
    // scanner and OpENer share a host without both fighting for the standard :2222 (which the target
    // holds). This is the exact path the adapter's push backend uses (`IoManager::bind("0.0.0.0:0")`).
    let manager = IoManager::bind("0.0.0.0:0")
        .await
        .expect("bind implicit-I/O UDP socket");
    println!(
        "bound implicit-I/O UDP socket at {} (advertised to OpENer via T→O sockaddr)",
        manager.local_addr()
    );

    // ---- ForwardOpen the class-1 connection ----------------------------------------------------
    let mut handle = match manager.forward_open(&client, opener_spec()).await {
        Ok(h) => h,
        Err(e) => panic!("ForwardOpen against OpENer was refused/failed: {e:?}"),
    };
    let (o2t_api, t2o_api) = handle.apis();
    println!(
        "ForwardOpen ACCEPTED — connection id {:#010x}; APIs o2t={o2t_api:?} t2o={t2o_api:?}",
        handle.connection_id()
    );

    // ---- consume: wait for Up, then collect frames with advancing sequence ---------------------
    let mut up_seen = false;
    let mut seqs: Vec<u16> = Vec::new();
    let mut first_data: Option<Vec<u8>> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while seqs.len() < 10 && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), handle.events().recv()).await {
            Ok(Some(IoEvent::Up { o2t_api, t2o_api })) => {
                up_seen = true;
                println!("IoEvent::Up — first T→O frame accepted (o2t_api={o2t_api:?}, t2o_api={t2o_api:?})");
            }
            Ok(Some(IoEvent::Data(u))) => {
                if first_data.is_none() {
                    first_data = Some(u.data.to_vec());
                }
                seqs.push(u.sequence);
            }
            Ok(Some(IoEvent::Lost { reason })) => panic!("unexpected early Lost: {reason:?}"),
            Ok(None) => panic!("event stream ended before frames arrived"),
            Err(_) => break,
        }
    }
    println!("consumed {} T→O frames; sequences = {seqs:?}", seqs.len());
    assert!(up_seen, "IoEvent::Up fired on the first accepted frame");
    assert!(
        seqs.len() >= 3,
        "at least a few cyclic T→O frames arrived (got {})",
        seqs.len()
    );
    // The class-1 sequence advances monotonically (the signed-window accept rule, D-ENIP-7).
    for w in seqs.windows(2) {
        assert!(
            w[1].wrapping_sub(w[0]) as i16 > 0,
            "sequence advances: {} -> {}",
            w[0],
            w[1]
        );
    }
    let stats = handle.stats();
    println!(
        "stats after consume: accepted={} produced={} stale={} size_mismatch={} seq_gaps={} malformed={}",
        stats.frames_accepted, stats.frames_produced, stats.stale_frames, stats.size_mismatch,
        stats.sequence_gaps, stats.malformed_frames
    );
    assert!(
        stats.frames_accepted >= 3,
        "counters reflect the accepted frames"
    );
    assert!(
        stats.frames_produced >= 1,
        "we produced O→T frames at the API cadence"
    );

    // ---- produce: OpENer mirrors our O→T output into its T→O input (sample_application) ---------
    // Send a recognizable output pattern; within a few frames the consumed input reflects it.
    let mut out = vec![0u8; 32];
    out[0] = 0xAB;
    out[1] = 0xCD;
    out[2] = 0x12;
    out[3] = 0x34;
    handle.set_run(true).expect("set run bit");
    handle.set_output(out.clone()).expect("stage O→T output");
    println!("staged O→T output [AB CD 12 34 ..]; watching for the mirror in T→O input");

    let mut mirrored = false;
    let mirror_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < mirror_deadline {
        match tokio::time::timeout(Duration::from_secs(3), handle.events().recv()).await {
            Ok(Some(IoEvent::Data(u))) => {
                if u.data.len() >= 4
                    && u.data[0] == 0xAB
                    && u.data[1] == 0xCD
                    && u.data[2] == 0x12
                    && u.data[3] == 0x34
                {
                    mirrored = true;
                    println!("O→T produce CONFIRMED via mirror: T→O input now starts [AB CD 12 34] (seq {})", u.sequence);
                    break;
                }
            }
            Ok(Some(IoEvent::Lost { reason })) => {
                panic!("unexpected Lost during produce: {reason:?}")
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        mirrored,
        "OpENer's sample mirrors O→T output→T→O input; our produced pattern was observed back \
         (proves the O→T produce path). first_data was {:02X?}",
        first_data.as_deref().unwrap_or(&[])
    );

    // ---- watchdog: silence the target, assert IoEvent::Lost { Timeout } ------------------------
    if let Some(cmd) = opener_stop_cmd() {
        println!("silencing OpENer via `{cmd}` to fire the inactivity watchdog...");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status();
        println!("stop command exited: {status:?}");
        // Watchdog = timeout_multiplier(16) × t2o_api. Give it generous slack.
        let mut lost = false;
        let wd_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < wd_deadline {
            match tokio::time::timeout(Duration::from_secs(5), handle.events().recv()).await {
                Ok(Some(IoEvent::Lost { reason })) => {
                    println!("IoEvent::Lost fired: {reason:?}");
                    assert_eq!(reason, LostReason::Timeout, "silence ⇒ watchdog Timeout");
                    lost = true;
                    break;
                }
                Ok(Some(_)) => {} // drain any in-flight frames
                Ok(None) => {
                    println!("event stream ended (connection removed on watchdog)");
                    lost = true;
                    break;
                }
                Err(_) => {}
            }
        }
        assert!(
            lost,
            "the inactivity watchdog fired IoEvent::Lost after the target went silent"
        );
        println!("== live_opener: PASS (ForwardOpen + consume + produce + watchdog) ==");
    } else {
        // Harness configuration, NOT peer reachability — and therefore the one soft path that
        // required mode DOES harden. Every other soft path in these suites is a peer legitimately
        // refusing a service it does not implement, which the gate must never punish. A missing
        // `OPENER_STOP_CMD`, by contrast, silently retires the watchdog assertion while the job
        // stays green: exactly the vacuous-gate failure `ENIP_LIVE_REQUIRED` exists to eliminate.
        // Unset required mode keeps the bench soft, so a local run without a stop command is
        // unaffected.
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but OPENER_STOP_CMD is unset or empty — the live watchdog leg \
             needs a shell command that silences the OpENer target on {addr} so the originator's \
             inactivity watchdog fires, e.g. OPENER_STOP_CMD='docker kill opener-live' (container) \
             or OPENER_STOP_CMD='pkill -x OpENer' (native)"
        );
        println!(
            "OPENER_STOP_CMD unset — skipping the live watchdog assertion (the watchdog is proven \
             deterministically in io.rs unit tests with a paused clock). ForwardOpen + consume + \
             produce all PASSED live."
        );
        handle.close(&client).await.ok();
    }

    manager.shutdown().await;
    client.close().await;
}

/// **The class-3 inactivity keepalive on the wire (§7.6, D-ENIP-18).**
///
/// A class-3 ForwardOpen arms an inactivity watchdog on the **target**: `timeout_multiplier ×
/// O→T API`. With the shipped defaults (`class3_rpi` 2 s × `class3_timeout_multiplier` ×16) that is a
/// 32 s window, and the client probes at ¾ of it — a connected `Get_Attribute_Single` of the Identity
/// object's Revision attribute after 24 s of idleness. This opens a real class-3 session against
/// OpENer, idles **75 s** (≈ 2.3 windows), and then uses the connection again.
///
/// **Proven regardless of the peer's own watchdog behaviour:** the keepalive frames are real, are
/// well-formed enough for an independent implementation to decode and answer, ride the connected
/// path, fire on the ¾-window cadence, and leave the session usable after a multi-window idle.
///
/// **Proven only if this peer enforces the class-3 inactivity timeout:** the F5 outage itself. To
/// establish that, run this same test against the pre-fix commit — if the post-idle read FAILS there
/// and passes here, target-enforced survival is proven on the bench. Record which of the two levels
/// was observed in the PR description.
///
/// Runs ~80 s; it is gated by the ordinary suite self-skip only.
#[tokio::test]
async fn opener_live_class3_idle_survives_the_inactivity_window() {
    let addr = opener_addr();
    if !opener_up(&addr).await {
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no OpENer on {addr} (class-3 keepalive leg) — \
             docker run -d --name opener-live --network host <opener image> <iface> \
             (set OPENER_ADDR to the host's primary IPv4:44818)"
        );
        eprintln!("live_opener (class-3 keepalive): skipped (no OpENer on {addr})");
        return;
    }
    println!("== live_opener: class-3 idle survival against real OpENer at {addr} ==");

    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(5),
        connected_messaging: true,
        ..ClientOptions::default()
    };
    // The scenario is the DEFAULT tuning — no knob is set for it, on purpose (there is no adapter
    // config key either): 2 s requested RPI × ×16 ⇒ a 32 s window, probes due every 24 s.
    assert_eq!(
        opts.class3_rpi,
        Duration::from_secs(2),
        "the default requested class-3 RPI"
    );
    assert_eq!(
        opts.class3_timeout_multiplier,
        TimeoutMultiplier::X16,
        "the default class-3 timeout multiplier"
    );

    let client = match EipClient::connect(&addr, opts).await {
        Ok(c) => c,
        Err(e) => {
            // A peer-limit path, NOT a missing peer — stays soft even under ENIP_LIVE_REQUIRED=1.
            // Required mode enforces that the peer was REACHED; it never demands a service the peer
            // does not implement. (OpENer does accept class-3; cpppo does not.)
            println!(
                "BENCH GAP: this peer refused the class-3 ForwardOpen to the Message Router \
                 ({e:?}) — the idle-survival leg cannot run against it. Run the same scenario \
                 against cpppo (`live_cpppo::cpppo_live_class3_idle_survives_the_inactivity_window`); \
                 if that peer refuses it too, report the survival leg as a bench gap and stand on the \
                 offline `class3_keepalive.rs` suite alone."
            );
            return;
        }
    };
    assert!(
        client.is_connected_messaging(),
        "the session rides a class-3 connection"
    );
    println!("class-3 ForwardOpen ACCEPTED — explicit requests now ride SendUnitData");

    // Baseline: one ordinary connected request, which also sets the activity clock the keepalive
    // measures idleness from.
    let baseline = client
        .get_attribute_single(0x01, 1, 4)
        .await
        .expect("baseline Identity/Revision read over the class-3 connection");
    println!(
        "baseline Get_Attribute_Single(Identity, 1, 4) -> {} byte(s)",
        baseline.len()
    );
    // **The connect-time identity read (D-ENIP-26 / D-EIP-34), against OpENer.** Folded into this
    // leg rather than given a test of its own so it rides the class-3 path *and* the CI name filter
    // that selects this test; what OpENer answers is recorded, not demanded — an identity or a
    // tolerated refusal — and either way the connection must still serve requests, which the whole
    // rest of this leg then proves across a 75 s idle.
    match client.read_identity().await {
        Ok(id) => println!("live_opener identity: {id}"),
        Err(enip::EnipError::Cip(status)) => {
            println!("live_opener identity: REFUSED by the peer ({status}) — tolerated by design");
        }
        Err(e) => panic!("the identity read failed at the connection level: {e:?}"),
    }

    let before = client.stats().keepalives_sent;

    let idle = Duration::from_secs(75);
    println!("idling {idle:?} — no request at all; keepalives are due every 24 s...");
    tokio::time::sleep(idle).await;

    let after = client.get_attribute_single(0x01, 1, 4).await;
    let stats = client.stats();
    println!(
        "post-idle read: {:?}; keepalives_sent {} -> {} (stale_replies={}, timeouts={}, seq_mismatches={})",
        after.as_ref().map(bytes::Bytes::len),
        before,
        stats.keepalives_sent,
        stats.stale_replies,
        stats.timeouts,
        stats.connected_seq_mismatches
    );
    assert!(
        after.is_ok(),
        "the class-3 connection is still usable after a multi-window idle: {after:?}"
    );
    assert!(
        stats.keepalives_sent >= 2,
        "at least two ¾-window keepalives completed across a 75 s idle (got {})",
        stats.keepalives_sent
    );
    assert_eq!(
        stats.connected_seq_mismatches, 0,
        "keepalive replies correlate on the connected sequence like any other request"
    );

    client.close().await;
    println!(
        "== live_opener class-3 keepalive: PASS (keepalives flowed; session survived the idle) =="
    );
}

/// **Latest-wins overflow under a real flood (§8.6).** A consumer that stops draining must end up
/// reading the FRESHEST telemetry, not a stale backlog: at capacity the queue evicts the OLDEST
/// queued sample and counts it as `overflowed_events`.
///
/// This opens the class-1 connection at a 10 ms RPI, ignores the event stream for 10 s (≈ 1000
/// frames ≫ the 256-deep queue), then drains. The discriminator is the FIRST sample the consumer
/// sees: with latest-wins it sits just past the evicted prefix (`overflowed_events` samples in), so
/// its sequence is far into the run. Draining-the-newest-dropped instead hands the consumer sequence
/// ≈ 1 while `overflowed_events` is in the hundreds — a real-wire before/after discriminator.
#[tokio::test]
async fn opener_live_slow_consumer_receives_fresh_frames() {
    let addr = opener_addr();
    if !opener_up(&addr).await {
        assert!(
            !live_required(),
            "ENIP_LIVE_REQUIRED=1 but no OpENer on {addr} (latest-wins flood leg) — \
             docker run -d --name opener-live --network host <opener image> <iface> \
             (set OPENER_ADDR to the host's primary IPv4:44818)"
        );
        eprintln!("live_opener (latest-wins): skipped (no OpENer on {addr})");
        return;
    }
    println!("== live_opener: latest-wins overflow against real OpENer at {addr} ==");

    let client = EipClient::connect(
        &addr,
        ClientOptions {
            connect_timeout: Duration::from_secs(3),
            ..ClientOptions::default()
        },
    )
    .await
    .expect("connect TCP session to OpENer");
    let manager = IoManager::bind("0.0.0.0:0")
        .await
        .expect("bind implicit-I/O UDP socket");

    // 10 ms both ways: 10 s of silence from the consumer is ~1000 frames against a 256-deep queue,
    // so the evicted prefix is unambiguously larger than the surviving window.
    let spec = opener_spec_at(Duration::from_millis(10));
    let mut handle = match manager.forward_open(&client, spec).await {
        Ok(h) => h,
        Err(e) => {
            // A peer-limit path, NOT a missing peer — stays soft even under ENIP_LIVE_REQUIRED=1.
            println!(
                "BENCH GAP: this peer refused a 10 ms-RPI class-1 ForwardOpen ({e:?}); the flood \
                 leg needs a cadence fast enough to overflow a 256-deep queue. The policy itself is \
                 proven offline in `io.rs` (`overflow_prefers_the_newest_data_and_counts`)."
            );
            manager.shutdown().await;
            client.close().await;
            return;
        }
    };
    let (o2t_api, t2o_api) = handle.apis();
    println!("ForwardOpen ACCEPTED — APIs o2t={o2t_api:?} t2o={t2o_api:?}; stalling the consumer");

    // The stall: not one recv() while the target floods us.
    tokio::time::sleep(Duration::from_secs(10)).await;

    let mut seqs: Vec<u16> = Vec::new();
    let mut saw_up = false;
    while let Ok(ev) = handle.events().try_recv() {
        match ev {
            IoEvent::Up { .. } => saw_up = true,
            IoEvent::Data(u) => seqs.push(u.sequence),
            IoEvent::Lost { reason } => panic!("unexpected Lost during the stall: {reason:?}"),
        }
    }
    let stats = handle.stats();
    println!(
        "drained {} queued sample(s) after the stall; sequences {:?}..{:?}; accepted={} overflowed={}",
        seqs.len(),
        seqs.first(),
        seqs.last(),
        stats.frames_accepted,
        stats.overflowed_events
    );
    assert!(
        saw_up,
        "the Up control event survived the flood — it is never evicted"
    );
    assert!(
        seqs.len() >= 2,
        "the queue held samples for the stalled consumer (got {})",
        seqs.len()
    );
    assert!(
        stats.overflowed_events > 0,
        "a 10 s stall at a 10 ms RPI overflows the 256-deep queue"
    );

    let first = seqs[0];
    let last = seqs[seqs.len().saturating_sub(1)];
    assert!(
        u64::from(first).saturating_add(8) >= stats.overflowed_events,
        "the first sample the consumer sees comes AFTER the evicted prefix: sequence {first} vs \
         {} evicted (dropping the newest instead would hand over sequence ~1)",
        stats.overflowed_events
    );
    assert!(
        u32::from(last.wrapping_sub(first)) <= 512,
        "the surviving window is the queue's depth, not the whole run: {first}..{last}"
    );

    handle.close(&client).await.ok();
    manager.shutdown().await;
    client.close().await;
    println!("== live_opener latest-wins: PASS (stalled consumer read the freshest frames) ==");
}
