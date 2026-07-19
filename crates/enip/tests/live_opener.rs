//! Live integration test: the real `enip::IoManager` class-1 implicit-I/O runtime against a real
//! **OpENer** adapter/target (DESIGN §11.3/§11.5). This is the first time `io.rs`/`cm.rs` meet a
//! genuine, independent EtherNet/IP *target* on the wire — ForwardOpen, cyclic T→O consume, O→T
//! produce, and the inactivity watchdog — not a `duplex`/crafted-bytes fixture.
//!
//! ## Self-skipping (§11.3)
//! We TCP-probe the OpENer encapsulation port (`OPENER_ADDR`, default `127.0.0.1:44818`). If nothing
//! answers the test prints a skip and returns — `cargo test --workspace` stays green without the
//! target. Build + run OpENer (native on Linux, or `--network host` on a Linux docker host so the
//! class-1 UDP :2222 loop is symmetric — see `test-infra/opener/Dockerfile`):
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
//! the watchdog firing `IoEvent::Lost { Timeout }` once the target goes silent.
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
/// assertion is skipped with a printed note rather than faked.
fn opener_stop_cmd() -> Option<String> {
    std::env::var("OPENER_STOP_CMD").ok().filter(|s| !s.is_empty())
}

async fn opener_up(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// The OpENer exclusive-owner class-1 spec: O→T (output 150) carries data + run/idle (Header32Bit);
/// T→O (input 100) is pure 32-byte data (Modeless); config 151 in the connection path.
fn opener_spec() -> IoConnectionSpec {
    let rpi = Duration::from_millis(100);
    IoConnectionSpec {
        assembly: AssemblyPath { config: Some(151), output: 150, input: 100, route: vec![] },
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
        eprintln!("live_opener: skipped (no OpENer on {addr})");
        return;
    }
    println!("== live_opener: class-1 I/O against real OpENer at {addr} ==");

    // The owning TCP session (carries the ForwardOpen over UCMM).
    let client = EipClient::connect(
        &addr,
        ClientOptions { connect_timeout: Duration::from_secs(3), ..ClientOptions::default() },
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
    println!("bound implicit-I/O UDP socket at {} (advertised to OpENer via T→O sockaddr)", manager.local_addr());

    // ---- ForwardOpen the class-1 connection ----------------------------------------------------
    let mut handle = match manager.forward_open(&client, opener_spec()).await {
        Ok(h) => h,
        Err(e) => panic!("ForwardOpen against OpENer was refused/failed: {e:?}"),
    };
    let (o2t_api, t2o_api) = handle.apis();
    println!("ForwardOpen ACCEPTED — connection id {:#010x}; APIs o2t={o2t_api:?} t2o={t2o_api:?}", handle.connection_id());

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
    assert!(seqs.len() >= 3, "at least a few cyclic T→O frames arrived (got {})", seqs.len());
    // The class-1 sequence advances monotonically (the signed-window accept rule, D-ENIP-7).
    for w in seqs.windows(2) {
        assert!(w[1].wrapping_sub(w[0]) as i16 > 0, "sequence advances: {} -> {}", w[0], w[1]);
    }
    let stats = handle.stats();
    println!(
        "stats after consume: accepted={} produced={} stale={} size_mismatch={} seq_gaps={} malformed={}",
        stats.frames_accepted, stats.frames_produced, stats.stale_frames, stats.size_mismatch,
        stats.sequence_gaps, stats.malformed_frames
    );
    assert!(stats.frames_accepted >= 3, "counters reflect the accepted frames");
    assert!(stats.frames_produced >= 1, "we produced O→T frames at the API cadence");

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
                if u.data.len() >= 4 && u.data[0] == 0xAB && u.data[1] == 0xCD && u.data[2] == 0x12 && u.data[3] == 0x34 {
                    mirrored = true;
                    println!("O→T produce CONFIRMED via mirror: T→O input now starts [AB CD 12 34] (seq {})", u.sequence);
                    break;
                }
            }
            Ok(Some(IoEvent::Lost { reason })) => panic!("unexpected Lost during produce: {reason:?}"),
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
        let status = std::process::Command::new("sh").arg("-c").arg(&cmd).status();
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
        assert!(lost, "the inactivity watchdog fired IoEvent::Lost after the target went silent");
        println!("== live_opener: PASS (ForwardOpen + consume + produce + watchdog) ==");
    } else {
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
