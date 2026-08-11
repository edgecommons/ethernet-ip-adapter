# enip — the owned EtherNet/IP + CIP protocol stack (design)

**Status: authoritative internal design (v1.0, 2026-07-18).** This document specifies the
**owned, pure-Rust EtherNet/IP + CIP protocol library crate** that `ethernet-ip-adapter` is built
on. It is the wire-contract spec: an implementation team must be able to build the stack from this
document without guessing a field offset. `DESIGN.md` (the adapter design) consumes this crate
through the `device.rs` seam and never re-specifies the protocol; where the two documents touch,
this one owns the protocol and `DESIGN.md` owns the adapter behavior.

**Why an owned stack (decision context).** Both mature OSS options were vetted and rejected:
`rseip` (Rust, explicit messaging only) is frozen, panics on a truncated `SendRRData` reply
(`context.rs` indexes `pkt.data[0..4]` unchecked), has UTF-8 UB in tag-list decoding
(`from_utf8_unchecked` over device-supplied bytes in `symbol.rs`), and correlates connected replies
with a `debug_assert!` only — in release builds a stale reply can be returned as the answer to a
*different* request. `EIPScanner` (C++) implements class-1 I/O but overruns its buffer on a runt
UDP frame, silently swallows sequence and size validation ("TODO: Check TypeIDs and sequence"), and
is likewise unmaintained. Neither is acceptable on a wire where every inbound byte is
device/attacker-controlled. We studied both for wire-format correctness (they agree with each other
and with the ODVA published material on every layout below) and write **original** code; nothing is
depended on or copied.

Grounding artifacts (verified 2026-07-18, do not work from memory):

- Vetted references (MIT; study-only): `rseip` — encapsulation, CIP explicit messaging, Logix
  services, EPATH; `EIPScanner` — ForwardOpen, network-connection-parameter bit packing, class-1
  UDP framing and timeout logic. Their **defects are pinned in §2 and §5.9 so we do not repeat
  them.**
- ODVA: *EtherNet/IP Quick Start for Vendors* (PUB00213), *CIP Networks Library* Vol 1 (CIP) &
  Vol 2 (EtherNet/IP adaptation) — the normative source for every layout in §5–§9.
- Sibling workspace convention: `core/cli/` (virtual Cargo workspace, `crates/*`).

---

## Table of contents

1. [Goals, non-goals & isolation contract](#1-goals-non-goals--isolation-contract)
2. [Decisions register (D-ENIP-1…D-ENIP-22)](#2-decisions-register)
3. [Workspace & crate layout](#3-workspace--crate-layout)
4. [Memory-safe decoding: the `WireReader` invariant](#4-memory-safe-decoding-the-wirereader-invariant)
5. [Encapsulation layer](#5-encapsulation-layer)
6. [CIP layer](#6-cip-layer)
7. [Explicit messaging (poll)](#7-explicit-messaging-poll)
8. [Implicit messaging (push / class-1 I/O)](#8-implicit-messaging-push--class-1-io)
9. [Assembly layout mapping](#9-assembly-layout-mapping)
10. [Error & failure model; correlation & timeouts](#10-error--failure-model-correlation--timeouts)
11. [Async model & public API](#11-async-model--public-api)
12. [Testing, fuzzing & conformance vectors](#12-testing-fuzzing--conformance-vectors)

---

## 1. Goals, non-goals & isolation contract

**Goals (v1).**

- **Both messaging modes**: CIP **explicit messaging** (request/reply reads & writes — unconnected
  UCMM and connected class-3) and **class-1 implicit I/O** (cyclic produced/consumed assemblies
  over UDP at an RPI), faithful to the ODVA spec.
- **Memory-safe by construction**: `#![forbid(unsafe_code)]`; every decode bounds-checked; a
  malformed/truncated/hostile packet yields a typed `Err`, never a panic or UB (§4).
- **Correct correlation**: every reply provably matched to its request; a late/stale reply is never
  returned as the answer to a different request (§10).
- **Independently testable and fuzzable**: 90%+ unit coverage with no hardware, cargo-fuzz targets
  on every decoder, golden conformance vectors (§12).
- Allen-Bradley **Logix tag services** (symbolic read/write, fragmented transfers, tag
  enumeration) plus **generic CIP** attribute services and device discovery.

**TLS on the explicit path (in scope, feature `tls`).** CIP Security Phase 1 (ODVA Vol 8) is
supported behind the off-by-default `tls` cargo feature: `EipClient::connect_tls` wraps the
encapsulation TCP session in a `rustls` `TlsStream` via the transport-generic session-actor seam
(§5.7, §11.1 — the actor is generic over `AsyncRead + AsyncWrite + Unpin`, so the whole session
machinery rides inside TLS unchanged). The crate takes a prepared `rustls::ClientConfig` and stays
EdgeCommons-free; cert material/vault sourcing is the adapter's job (**D-ENIP-15**, the dependency
decision below; DESIGN-cip-security.md). Only **AEAD** suites are negotiable: the `rustls` ring
provider with the `tls12` feature on (both manifests) offers the three TLS 1.3 suites plus six
TLS 1.2 ECDHE suites — four AES-GCM, two ChaCha20-Poly1305 — and the adapter's optional
`cipherSuites` allow-list can only narrow that set, so **CBC, NULL and PSK are unreachable**. That
covers what Vol 8 ≥ 1.13 mandates; legacy CBC/NULL/PSK-only firmware is the documented interop
boundary, surfaced as the typed `EnipError::Tls { NoCipherOverlap }`.

**Reading the target's security posture (Phase 2a, in scope, no feature gate).** The crate decodes the
target's CIP Security object model — the **CIP Security Object (0x5D)**, **EtherNet/IP Security Object
(0x5E)**, and **Certificate Management Object (0x5F)** — as typed, bounds-checked posture reads over
the shipped generic `Get_Attribute_Single` service (§7.5, §7.7). This is pure decoding (no new
transport, no new dependency, always available); the crate reads the *originator's* view of the target
and never acts as a CIP Security *target* or writes the commissioning objects (that stays a non-goal).

**Cert lifecycle / rotation (Phase 2b) and EST enrollment (Phase 2c) are adapter-side — no crate
change.** The vault-native managed trust store, the client-cert rotation-without-restart, cert-expiry
monitoring (DESIGN §D-EIP-23), and the **EST (RFC 7030) enrollment/renewal client** (DESIGN §D-EIP-24,
DESIGN-cip-security.md §4.2/§4.3) live entirely in the **adapter**: it re-sources the cert/key/CA
material — now optionally *obtaining* it from a plant EST server and writing it back to the vault — and
rebuilds the opaque `rustls::ClientConfig` it already hands to `connect_tls`. The crate's TLS surface
(`connect_tls`, `TlsOptions`, `TlsSessionInfo`) is unchanged — it takes a fresh `ClientConfig` on the
next connect and neither knows nor cares that the material rotated or where it came from. EST is HTTPS
credential provisioning, not EtherNet/IP, so it is not in this crate. This keeps the isolation contract
intact (the crate never reads a vault, a key byte's provenance, or an EST server).

**Non-goals (v1).** UDT/structure *value* decoding (struct tags are detected and reported, not
decoded); Logix STRING values; CIP Multiple Service Packet batching; **DTLS on the implicit (class-1)
I/O path** — CIP Security for class-1 needs DTLS, which `rustls` does not provide and which has no OSS
validation peer, so implicit I/O remains plaintext UDP 2222 and a TLS-configured push instance is
refused; the device-side certificate/security-object *commissioning* model (writing a target's security
objects — the adapter's own EST enrollment (Phase 2c) is adapter-side, above); CIP Sync/Motion; acting
as a full *target* (the crate ships a minimal
test-target for validation only, §12.5); DeviceNet/ControlNet adaptations of CIP.

**The isolation contract.** The protocol crate is pure protocol. It deliberately knows **nothing**
about: EdgeCommons (no `edgecommons` dependency), the UNS, message envelopes, `SouthboundSignalUpdate`,
metrics subsystems, command verbs, the adapter config schema, `serde_json::Value`, or the adapter's
Tokio task topology. Its vocabulary is sessions, services, EPATHs, CIP values, connections, and
frames. The adapter binary consumes it only through `device.rs` (`DESIGN.md` §3.3), converting
`CipValue` ⇄ JSON and `EnipError` → `DeviceError` at that seam. This isolation is what makes the
stack testable, fuzzable, and reusable outside the adapter.

Dependency budget (normative — additions need a decision): `tokio` (net, time, sync, rt),
`tokio-util` (codec), `bytes`, `thiserror`, `tracing`, `rand` (connection serials/ids). Dev/test
extras: `arbitrary`, `cargo-fuzz` harness, `serde`/`serde_json` for vector manifests only. No
`unsafe`, no C dependencies, builds on stable Windows/MSVC + Linux.

**D-ENIP-15 (TLS dependency decision).** The off-by-default `tls` feature adds `tokio-rustls` +
`rustls` (pinned to the `ring` crypto provider, `default-features = false` — so no `aws-lc-rs`/NASM C
toolchain) to the crate; default features stay TLS-free and dependency-lean. `ring` is pure-Rust and
already in the workspace lock (via the edgecommons MQTT stack), so the zero-C-deps /
builds-on-Windows-and-Linux property is preserved. Dev-only: `rcgen` + `rustls-pemfile` mint/parse
throwaway test certs for the handshake-over-duplex unit tests and the `live_tls.rs` suite.

---

## 2. Decisions register

| # | Decision | Rationale / alternatives |
|---|---|---|
| **D-ENIP-1** | **One protocol crate (`crates/enip`, package `ec-enip`), module-split internally — not separate `eip`/`cip` crates.** | The split rseip chose (core/eip/cip/client crates) buys nothing here: CIP without the EtherNet/IP adaptation has no second consumer (we do not target DeviceNet), and one crate gives one coverage denominator, one fuzz corpus tree, and no cross-crate churn. Module boundaries (§3) keep the layering reviewable; a future crate split along those module lines stays cheap if a second transport ever appears. |
| **D-ENIP-2** | **`#![forbid(unsafe_code)]` at the crate root — no exceptions, no `unsafe` islands.** | Nothing in this protocol needs `unsafe`: framing is length-prefixed byte handling, decode is cursor reads, UDP/TCP are Tokio. rseip's only `unsafe` (tag-list UTF-8) is exactly the bug class we are eliminating. `forbid` (not `deny`) so no module can opt back in. |
| **D-ENIP-3** | **All decoding goes through the checked `WireReader` cursor (§4); direct slice indexing of wire data is banned** (`clippy::indexing_slicing` + `clippy::arithmetic_side_effects` denied in decode modules). | Makes the no-panic invariant *reviewable*: any indexing or unchecked arithmetic on wire-derived lengths is a lint failure, not a code-review catch. |
| **D-ENIP-4** | **Decode by wire-declared type, not caller expectation:** `read_tag` returns the `CipValue` the reply's type code declares; the caller compares against its expectation. | A type mismatch becomes *data* (the adapter maps it to a BAD sample) instead of a decode error deep in a generic; kills the monomorphized `read_tag::<TagValue<T>>` dispatch pattern and its blind trust of the wire. |
| **D-ENIP-5** | **Explicit correlation matches the full reply header** with one in-flight request per session: `sender_context` **and** the encapsulation command **and** the session handle (the latter waived for the §5.2 discovery commands, which are sessionless-capable). A reply that fails any of those is discarded (counted, logged), never delivered. Connected class-3 replies must match the connected-data sequence count or be discarded — a hard check, not a `debug_assert!`. | Fixes rseip's worst defect (silent wrong-tag values in release builds). Context alone is not identity: a peer that echoes a context on the wrong command, or from a session we no longer own, must not be able to complete a request. One-in-flight keeps the model simple and is sufficient at adapter poll rates; pipelining is a v2 option the correlation design already permits (§10.3). |
| **D-ENIP-6** | **Every request has a caller-supplied deadline enforced inside the session task**, bounding the **write** as well as the wait: the deadline is computed at enqueue, the actor hand-off and the frame write run under it, and a write that misses it is `ConnectionLost` (a cancelled write can leave a partial frame — framing is unrecoverable). On a read timeout the request completes `Err(Timeout)` and the session enters *stale-reply quarantine* (§10.4) rather than being torn down. Shutdown is bounded by fixed constants: 500 ms for the UnRegisterSession write, 2 s for the close hand-off. The caller's wait on the reply channel is a **liveness backstop**, not a second deadline: it sits one `REPLY_BACKSTOP_GRACE` (50 ms) past the deadline so the actor's classification — not a tie between two timers expiring on the same instant — is what the caller observes, at the cost of a request being able to complete up to 50 ms late. | Isolated slowness must not cost a reconnect, but a late reply must never surface as an answer, and an unbounded write to a stalled peer is the same hang the deadline exists to prevent. Quarantine + full-header matching achieves the first two; the fixed shutdown bounds ensure teardown cannot hang behind a wedged actor. |
| **D-ENIP-7** | **Class-1 receive validation is mandatory**: CPF shape, connection-id lookup, size-vs-negotiated check, and 16-bit sequence acceptance via the signed-window rule `(new − last) as i16 > 0`; stale/duplicate/mis-sized frames are dropped **and counted**, never delivered and never silent. This extends to socket-level errors: every `recv_from`/`send_to` failure is counted (`recv_errors`/`send_errors`) and classified as per-datagram (survivable — `ConnectionReset`/`ConnectionRefused`/`ConnectionAborted`/`Interrupted`/`WouldBlock`) or socket-fatal. | EIPScanner swallows all three checks. Counters make the drops observable (the adapter surfaces them as metrics). A silently ignored socket error is the same defect one layer down: Windows' ICMP-driven `WSAECONNRESET` must not kill a healthy socket, and a genuinely broken socket must not look like silence. |
| **D-ENIP-8** | **I/O connection liveness is originator-monitored**: no valid T2O frame within `timeout_multiplier × T2O_API` ⇒ the connection is declared lost, a typed `Lost` event is emitted, and the connection is closed. Production continues at O2T API regardless of consumption. A dead socket is the collective case: it emits `Lost { Io }` to **every** connection on it before the manager task exits. | The spec's inactivity watchdog, implemented on our side (EIPScanner's shape, made typed and non-silent). API values come from the ForwardOpen **reply** (actual PI), not the request. Connections share one socket, so its death is every connection's death — reporting it once, or not at all, would leave consumers waiting on a stream that can never produce again. |
| **D-ENIP-9** | **The class-1 produce path always sends at the O2T API cadence** (data, or a heartbeat when the O2T size is 0), incrementing the encapsulation sequence every frame and the class-1 sequence count every produce. | The target runs the same watchdog against us; a paused/idle adapter that stops producing kills its own connection. Run/idle is signaled in the 32-bit header (§8.5), not by stopping. |
| **D-ENIP-10** | **Frame order for class-1 connected data is `[u16 class-1 sequence][u32 run/idle header, if the format includes it][data]`** — sequence first. | ODVA Vol 2: the run/idle header is *inserted between the sequence count and the data*. EIPScanner encodes this correctly on produce but decodes header-first on consume — a reference bug we pin here so nobody "fixes" our order to match it. |
| **D-ENIP-11** | **The crate exposes a bounds-checked `AssemblyLayout` helper (§9)** that maps raw assembly bytes ⇄ typed fields (offset/type/bit), but the *naming and configuration* of fields stays in the adapter. | Field extraction from hostile bytes belongs inside the fuzz boundary; signal semantics (names, UNS channels, deadbands) are adapter business the crate must not learn. |
| **D-ENIP-12** | **Fragmented read/write is auto-driven inside the crate** (status `0x06` → continue at the next offset; writes chunked to the negotiated size), with a configurable `max_value_bytes` cap (default 1 MiB) bounding reassembly memory. | The caller asks for a tag and gets the whole value or a typed error. Wire-supplied sizes never drive unbounded allocation (§4). |
| **D-ENIP-13** | **v1 restricts routing to port numbers ≤ 14** (covers backplane port 1 + slot, the only routed path the adapter exposes). The extended-port encoding is implemented per spec but gated behind a conformance vector captured from real routed hardware before it is enabled. | The references disagree on extended-port byte order and we have no routed device to arbitrate; shipping an unverified encoding of a rarely-used path is how wire bugs are born. Declared limitation, not silent. |
| **D-ENIP-14** | **The crate ships NO embedded test target.** Session/connection state-machine tests run over in-memory `tokio::io::duplex` byte-stream fixtures — the session actor is generic over `AsyncRead + AsyncWrite`, so a fixture deterministically injects wrong-`sender_context`, stale, fragmented, and sequence-mismatch frames a real device cannot be scripted to send. Real device behavior is validated against the EXTERNAL cpppo (poll) and OpENer (push) containers in the adapter's integration suite (§12.5). | Keeps every device simulator external to match reality (user decision) while preserving deterministic adversarial testing via raw-byte fixtures: the duplex fixture is a byte pipe, not a peer implementation, so a decoder bug can never be masked by a matching encoder bug in an in-crate double. (The earlier `testserver` in-crate target idea was dropped for this reason — there is no `testserver` module or feature.) |
| **D-ENIP-16** | **ForwardOpen success replies are verified before use** — originator echo quad equality (T→O connection id, connection serial, vendor id, originator serial) plus, for class-1, an API range of [100 µs, 600 s]; failure ⇒ best-effort ForwardClose + typed error. | An unvalidated reply API of 0 previously livelocked the produce scheduler; an unverified echo can bind a connection to the wrong identity. The target-assigned O→T id is excluded because the request sends 0 and the choice is the target's. |
| **D-ENIP-17** | **A ForwardOpen reply cannot steer our class-1 traffic.** (a) The O→T Sockaddr Info item retargets the **port only**: the transmit address is always the target's own. A sockaddr naming `0.0.0.0` contributes its port; one naming the target's address is honoured as written; one naming any other address — foreign unicast, broadcast, multicast, loopback — has its address **refused** (warned, naming the address) and only its port kept. With no known target address a redirect is unresolvable and the open fails. (b) The T→O multicast group is joined **only** when the ForwardOpen requested `ConnType::Multicast` for T→O; a multicast T→O sockaddr answering any other request is a `ProtocolViolation` whose detail names the type that was requested (`"multicast T→O sockaddr on a point-to-point request"`, `"multicast T→O sockaddr on a null (reconfigure) request"`) — the adapter only ever requests P2P, but the crate API accepts either, and a violation must not misreport which one it refused. A requested-multicast connection whose reply carries a unicast or absent T→O sockaddr consumes unicast. Both paths keep the D-ENIP-16 teardown invariant (best-effort ForwardClose before the typed error). Strict by default, with no opt-out knob. | Honouring a concrete foreign address let any target aim our cyclic O→T stream at a third party — a reflection/amplification primitive driven entirely by an attacker-controlled reply — and a multicast offer subscribed our socket to an arbitrary group on a connection we asked to keep point-to-point. The address is the one field the originator already knows (it opened the TCP session); the port is the only field a target legitimately needs to move, which is why the split is address-refuse/port-honour rather than reject-the-reply — real targets that relocate the port keep working. No config knob ships: a strict default needs none, and if field interop ever demands honouring a foreign redirect, that is a `ClientOptions` opt-in to be argued on evidence, not a hedge built in advance. **The refusal is observable, not just logged:** it increments `refused_redirects` on the connection (`enip::IoStats`, 0 or 1 per connection), and the adapter surfaces it as the `refusedRedirects` measure (DESIGN §8.8) plus a one-shot `io-redirect-refused` warning event per ForwardOpen. That closes the one narrow silent failure mode the address-refusal leaves: a device that both *requires* the redirect to receive O→T **and** never enforces its own O→T inactivity watchdog keeps producing inputs while its outputs are dead, and the local `send_to` still succeeds — so `sendErrors` cannot catch it and the adapter would otherwise report the link healthy. |
| **D-ENIP-18** | **The class-3 inactivity keepalive is crate-owned and window-derived, with no adapter knob.** A class-3 ForwardOpen arms an inactivity watchdog on the target (`timeout_multiplier × O→T API`), so the crate keeps the connection off it: when no request has flowed for **¾ of the window** the session sends a connected `Get_Attribute_Single` of the Identity object (`0x01`, instance 1, attribute 4 = Revision). The window comes from the negotiated values — the reply's actual O→T API when it lies in [100 µs, 600 s], else the clamped requested RPI — and the requested pair is `ClientOptions.class3_rpi` / `class3_timeout_multiplier` (defaults 2 s / ×16, the values the crate previously hard-coded, so a caller that changes nothing emits a byte-identical ForwardOpen). An implausible reply API falls back; it never fails the open (§7.6). Any completed exchange, CIP-error replies included, counts as activity; `ClientStats.keepalives_sent` is the observable face. **No adapter config-schema key is added.** | Feeding the connection's own watchdog is a protocol obligation of the connection's owner, and the owner is this crate — an adapter that has to remember to poll fast enough is a defect waiting for the first paused instance or slow poll group (the adapter's only idle traffic is a `ListIdentity` encapsulation command, which never rides the connected path and so cannot feed the watchdog at any cadence). Deriving the window from the negotiated values rather than a constant means a target that shortens the interval is honoured instead of outlived. The values become options because they are what arms the watchdog and a field device may need them moved; they stay out of the adapter's schema because nothing about a correct default needs operator attention, and the adapter's `keepaliveProbeIntervalMs` is a different surface entirely (paused-state health reporting) that stays as it is. |
| **D-ENIP-19** | **Tag-enumeration cursors are full 32-bit symbol-instance ids, never masked, and the walk is bounded by the crate.** `list_tags(start_instance: u32, ..) -> (Vec<SymbolInfo>, Option<u32>)` carries the cursor at the same width as `SymbolInfo.instance_id`, and `Segment::Instance` widens to the 32-bit logical form (`0x26`, §6.2) so the request can address it. Three crate-side rules bound the walk regardless of the peer: the records of one page must be **strictly ascending** in instance id or the page is `ProtocolViolation { detail: "tag list page is not in ascending instance order" }`; a `0x06` page whose derived resume point does not advance past `start_instance` is `ProtocolViolation { detail: "tag list page did not advance" }`; and a last record at `u32::MAX` ends the enumeration rather than wrapping (§7.3). | The 16-bit cursor was not a capacity limit but a **liveness** bug: real Logix controllers exceed 65 535 symbol instances, and masking the resume point back into 16 bits sent a caller that pages to completion around the same pages forever — the adapter's hierarchical browse did exactly that, so the observable failure was a command handler that never returned. Widening alone would have left the loop reachable from a merely non-compliant peer, so the ordering the reply already promises is checked instead of trusted — **both** of the things that ordering buys, not just one: the *resume point* must move forward (or the walk revisits pages, the hang), and the page's *own records* must ascend (or every resume point derived from the last one — this crate's `last_id + 1` and any page size a caller cuts to on top of it — silently strands whatever sat behind it, the exact defect the truthful-`max` contract exists to kill, DESIGN D-EIP-29). Each costs one comparison per record and converts a hang or a silent skip into a typed error at the layer that can name the cause. The `0x26` form is the ODVA-defined third width of the same logical segment (the `Element` segment already emitted its `0x2A` analogue), so nothing new is invented on the wire — and because no container sim serves instances that high, it is pinned by hand-assembled golden vectors (§12.4) and cross-checked live against EthernetIPSharp, which parses the segment and answers at the CIP layer (DESIGN §11.7). |
| **D-ENIP-20** | **ForwardOpen arming is acknowledged, and output staging is confirmable.** `forward_open` completes only after the socket task has registered the connection **and** joined any multicast T→O group; a join failure is a typed `EnipError::Io` with the usual best-effort ForwardClose, and an opener whose future is cancelled before its acknowledgement has the connection unregistered rather than left producing. The handle gains `stage_output`, which carries the manager's verdict back — the same validation as `set_output`, then `Ok` only when the buffer is held for a live connection, `Err(Closed)` when the manager has shut down or the connection is gone. `set_output` keeps its signature and its unconfirmed semantics. Multicast group membership is **not** refcounted: a second connection joining a group its manager socket already holds fails fast and is refused. | The join result was discarded (`let _ = socket.join_multicast_v4(..)`), so a connection whose membership never happened was armed anyway and received nothing: the operator's only symptom was a delayed watchdog timeout naming `Timeout`, with the interface error that caused it thrown away at the point it was known. Making the join load-bearing means the verdict has to travel back, and once `Add` is acknowledged the return-before-registration gap closes with it — a datagram arriving the instant `forward_open` returns can no longer be counted as `unknown_connection`. The same reasoning applies one step further out: `SetOutput` was fire-and-forget, so a write aimed at a connection the task had already removed was reported as success, the crate-side link in the `sb/write` silent-success chain (DESIGN D-EIP-31). Alternatives rejected: refcounting shared groups (the adapter opens one `IoManager` per push session, so sharing never occurs in product use — a refcount would exist only to be tested, where the fail-fast refusal is itself the honest answer), and making `set_output` async (it would break every existing caller to confirm something most of them cannot act on). **Scope limit, stated:** multicast T→O is proven here only by crate tests (join failure, armed post-condition) — no sim in the bench matrix serves a real multicast T→O stream, so true multicast conformance remains real-hardware territory. |
| **D-ENIP-21** | **Encapsulation validation is complete, not partial — header *and* RegisterSession body.** (a) `options ≠ 0` is enforced, not just documented: inside a session the frame is discarded **before** correlation and counted on its own cause (`ClientStats.discarded_options`, warn-logged); at the RegisterSession handshake it is a refusal (`ProtocolViolation`). (b) The **RegisterSession reply is correlated** — it must echo the request's `sender_context` (`ECREGIST`), checked *first*, ahead of command/options/status/handle/version (§5.5). (c) A **non-zero CIP interface handle** in a `SendRRData`, `SendUnitData`, or Connection-Manager UCMM reply is a `ProtocolViolation` at all three decode sites (§5.2). (d) The **RegisterSession reply's 4-byte command-specific body is validated whole**, not just its leading word: `u16 protocol_version` must be 1, the `u16` session-options word must be **0**, and there must be **exactly** those four bytes — a body that ends before either word, and a body with trailing data after them, are both refusals (§5.5). | The header was matched on context, command and handle but never on `options`, and the one exchange with no correlation at all was the handshake that establishes the session: any RegisterSession-shaped frame already on the stream could be adopted as our session, and a peer stamping `options` could answer a request with a frame the spec says to drop. The interface handle was read and thrown away at three sites while §5.2 declares it 0 — a peer addressing another interface is not speaking the CIP encapsulation we asked for, so its payload is not a Message Router reply we may decode and nothing in it may bind a connection. The asymmetry between the two `options` dispositions is deliberate: mid-session the actor has a deadline and other frames may follow, so discard-and-keep-waiting is right; pre-actor exactly one frame is expected, so looping over discards buys nothing and adopting a session from a peer this broken is worse. The counter is its own field rather than folded into `stale_replies` because the two say different things about the peer (§10.2, never silent). The body was the same defect one field further in: reading the version word and stopping accepted a **two-byte** `01 00` reply — one in which the options word §5.5 requires is simply absent — and accepted any amount of trailing data after a well-formed one, so "the reply is the same four bytes we sent" was a documented claim nothing checked. The options word must be 0 because ODVA Vol 2 reserves it with no defined meaning: a target has nothing it may legitimately say there, so bits in it mean the peer is either negotiating an option we never offered or overlaying a different structure on the same four bytes — the header-level `options` refusal is this same rule one layer out, and clause (a)'s reasoning for refusing rather than discarding applies unchanged. **Variant split:** a body of the right *shape* whose version is not 1 is `Unsupported` — the peer is speaking a generation of the encapsulation layer this crate does not implement, which is exactly what encapsulation status `0x0069` says, so both routes to "wrong generation" read the same to a caller; a wrong-length body or a reserved field carrying bits is `ProtocolViolation`, because it is not a protocol we could support at some other version, it is a frame that does not conform. A reader can therefore tell "understood, cannot speak it" from "malformed" by the variant alone, and each refusal names its own field in `detail`. **Interop arbitration:** the context echo, the interface-handle refusals and the whole-body check are spec-correct but strict, so the live-sims gate (cpppo, OpENer, ab_server, EthernetIPSharp, stunnel-TLS ×2, OpENer-CIPSec, EST) is the false-positive check; the pre-approved concessions, to be taken only on evidence of a real peer failing, are accepting an all-zero context on RegisterSession with a one-time warn and/or demoting the interface-handle refusal to a counted warn. **No concession is taken: no fallback is implemented.** The body check was measured before it shipped: every EtherNet/IP peer in the bench — cpppo, libplctag's ab_server, EthernetIPSharp, OpENer and the OpENer CIPSecurity branch — answers RegisterSession with exactly `01 00 00 00`, and the two stunnel terminators are byte-transparent TLS in front of cpppo, so there is no observed peer whose body the rule would newly refuse. |
| **D-ENIP-22** | **Encapsulation status `0x0064` (`InvalidSessionHandle`) severs the session at the actor.** The caller that provoked it still gets `Err(Encap(InvalidSessionHandle))`; the actor then exits, so every pending and subsequent request completes `Err(Closed)` without stream I/O. The rule applies to **any** correlated reply, discovery commands included. Recovery is the owner's reconnect — the adapter's classification maps a session-poisoning `Encap` status to transient (DESIGN §10.1) — and the crate never re-registers in place. | The status is a statement about our *registration*, not about the command that provoked it: once the target has forgotten the handle, nothing later on that stream can succeed. Delivering the typed error and then carrying on merely deferred recovery to whatever arbitrary later failure happened next, and left a *live* actor speaking into a session the device had already torn down. It also fed the class-3 inactivity keepalive: `send_connected` touches the activity clock only after the transaction returns `Ok`, so while the poisoned frame was delivered as `Ok` the clock was refreshed by a dead session's reply and the probe cadence went on "keeping alive" a handle that no longer existed (§7.6). Severing at the actor fixes both with one rule, in the one place that owns the stream. In-crate re-registration was rejected as a non-goal: the adapter's reconnect ladder already classifies the status as transient and owns backoff, alarms and instance state — a second, silent recovery path inside the crate would race it. |

---

## 3. Workspace & crate layout

### 3.1 Repository becomes a Cargo workspace

Mirroring `core/cli/` (virtual workspace + `crates/`):

```text
ethernet-ip-adapter/
  Cargo.toml                 # [workspace] resolver=3, members = crates/*; workspace deps/lints
  crates/
    enip/                    # THE PROTOCOL CRATE (package `ec-enip`, lib name `enip`)
      Cargo.toml             # publish = false (git dep for now); no edgecommons dependency — ever
      src/…                  # §3.2
      fuzz/                  # cargo-fuzz targets + corpus (§12.3)
      tests/                 # golden vectors, roundtrips, mock-target integration (§12)
    ethernet-ip-adapter/     # the adapter binary crate (unchanged name; DESIGN.md §3)
      Cargo.toml             # deps: edgecommons (pinned rev), ec-enip = { path = "../enip" }
      src/…
```

Build artifacts land in the workspace `target/` at the repo root, so `Dockerfile` / `build.sh` /
`supervisor/` paths keep working with only the build-context adjustments listed in `DESIGN.md` §13.
CI runs `cargo test` / `cargo llvm-cov` **workspace-wide** — the protocol crate is inside the
coverage gate, not excluded from it.

### 3.2 Protocol crate modules (the layering)

```text
crates/enip/src/
  lib.rs           #![forbid(unsafe_code)]; crate docs; public re-exports (the API in §11)
  error.rs         EnipError / WireError / CipStatus-carrying variants (§10)
  wire.rs          WireReader / WireWriter — the ONLY way wire bytes are read (§4)
  encap/
    mod.rs         EncapHeader, commands, encapsulation status codes (§5)
    codec.rs       tokio_util Encoder/Decoder: 24-byte-header framing, length cap, NOP skip
  cpf.rs           Common Packet Format items: encode/decode, item-type registry (§5.4)
  cip/
    epath.rs       Segment enum + EPath builder + padded encoder + symbolic tag-path parser (§6.2)
    message.rs     MessageRequest encode / MessageReply decode (§6.1)
    status.rs      GeneralStatus TYPED enum + extended status (§6.4)
    types.rs       CipType codes, CipValue, checked value decode/encode (§6.3)
    services.rs    generic Get/Set_Attribute_Single, Get_Attribute_All (§7.5)
  cm.rs            Connection Manager: ForwardOpen/LargeForwardOpen/ForwardClose codecs,
                   NetworkConnectionParams bit packing, timing conversions (§8.2–§8.4)
  logix.rs         Read/Write Tag (+fragmented), Get Instance Attribute List, SymbolType (§7.2–§7.4)
  io.rs            class-1 runtime: IoManager (UDP socket task), IoConnection state,
                   frame codec, sequence windows, produce scheduler, watchdog (§8.5–§8.7)
  assembly.rs      AssemblyLayout: bounds-checked field extraction/insertion (§9)
  client/
    mod.rs         EipClient handle + ClientOptions (§11.2)
    session.rs     the session actor: writer, reader, correlation, deadlines, quarantine (§11.1)
    connected.rs   class-3 connected messaging (ForwardOpen'd explicit path) (§7.6)
  discovery.rs     ListIdentity / ListServices / ListInterfaces parsing (§5.3)
```

There is no `testserver` module or feature (D-ENIP-14): actor tests drive the session over
in-memory `tokio::io::duplex` fixtures, and real-device conformance is external (§12.5).

Layering rule (enforced by review + module visibility): `wire` ← `encap`/`cpf`/`cip` ←
`cm`/`logix`/`io`/`assembly` ← `client`/`discovery`. Nothing imports upward; `client` is the only
module that owns sockets besides `io`.

### 3.3 What the adapter consumes

The adapter's `eip/` backend (DESIGN.md §3) uses exactly this surface: `EipClient` (connect,
read/write tag, list tags, get/set attribute, identity, close), `IoManager`/`IoConnection`
(forward-open, output buffer, event stream, close), `AssemblyLayout`, `CipValue`/`CipType`,
`EnipError`, `TagAddress`. Everything else is `pub(crate)`.

---

## 4. Memory-safe decoding: the `WireReader` invariant

Every inbound buffer — TCP frame payloads, UDP datagrams, CIP reply bodies, tag-list entries — is
fully attacker/device-controlled. The crate's single decoding rule:

> **All reads of wire bytes go through `WireReader`, which checks remaining length before every
> read and returns `Err(WireError::Truncated)` — never panics, never indexes, never wraps.**

```rust
/// A checked little-endian cursor over one wire buffer. The ONLY decode primitive.
pub(crate) struct WireReader<'a> { buf: &'a [u8], pos: usize }

impl<'a> WireReader<'a> {
    pub fn remaining(&self) -> usize;
    pub fn u8(&mut self)  -> Result<u8,  WireError>;   // ..i8/u16/i16/u32/i32/u64/i64/f32/f64,
    pub fn u16(&mut self) -> Result<u16, WireError>;   // all little-endian (CIP byte order)
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError>; // n checked vs remaining
    pub fn skip(&mut self, n: usize) -> Result<(), WireError>;
    pub fn expect_end(&self) -> Result<(), WireError>; // trailing-garbage check where the spec is exact
}
```

Normative invariants (each has a dedicated test and a fuzz target proving it, §12):

1. **No panic on any input.** Decoders are total functions `&[u8] → Result<T, WireError>`.
   `WireError::Truncated { needed, remaining, context }` names the layer that failed.
2. **No unchecked arithmetic on wire-supplied numbers.** Length math uses `checked_mul`/
   `checked_add` (e.g. `extended_status_size * 2`, `element_count × type_size`); overflow is
   `WireError::Malformed`, not a wrap.
3. **Wire lengths never drive allocation before validation.** A count/length field is validated
   against `remaining()` **before** any `Vec` reservation; reassembly (fragmented reads, tag-list
   accumulation) is capped by `max_value_bytes` (D-ENIP-12).
4. **UTF-8 is always checked.** Tag/symbol names decode via `str::from_utf8` → invalid sequences
   are `WireError::Malformed` (with a lossy rendering in the error text for diagnostics only).
   *(This is the `from_utf8_unchecked` fix.)*
5. **Enums are total.** Unknown command codes, item types, type codes, status codes decode into
   explicit `Unknown(raw)` variants or typed errors — no `unreachable!`, no `panic!` on match.
6. **Truncation is checked before semantic validation** so a 5-byte "reply" is `Truncated`, not an
   index panic. *(This is the rseip `SendRRData` fix: interface-handle + timeout are read via the
   cursor, not `data[0..4]`.)*

Lints, pinned in `crates/enip/Cargo.toml` `[lints]`: `unsafe_code = "forbid"`,
`clippy::indexing_slicing = "deny"`, `clippy::arithmetic_side_effects = "deny"`,
`clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"` (test code may `allow` locally).
Encoding uses `WireWriter` (append-only `BytesMut` wrapper) — encoding of *our own* values may
assert internal invariants, but anything derived from caller input (tag names > 255 bytes, path
sizes) returns `Err`, not panic.

---

## 5. Encapsulation layer

### 5.1 The 24-byte encapsulation header

All multi-byte fields little-endian (network byte order applies **only** inside Sockaddr Info
items, §5.4):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | `command` | §5.2 codes |
| 2 | 2 | `length` | byte length of the data portion following the header (0–65511) |
| 4 | 4 | `session_handle` | 0 until RegisterSession; then the target-assigned handle, echoed on every request |
| 8 | 4 | `status` | 0 = success; §5.6 codes; **replies with status ≠ 0 carry no usable data** |
| 12 | 8 | `sender_context` | opaque to the target, echoed verbatim in the reply — our correlation key (§10.3) |
| 20 | 4 | `options` | always 0; a received packet with options ≠ 0 is discarded per spec |

The `options` rule is enforced, not merely documented (D-ENIP-21). Inside a session the actor drops
such a frame **before** it attempts correlation — the frame is malformed at the encapsulation layer,
so which request it claims to answer is not yet a meaningful question — counts it on its own cause
(`ClientStats.discarded_options`, never folded into `stale_replies`), logs it at warn, and keeps
waiting inside the request's absolute deadline. During the RegisterSession handshake the same value
is a **refusal** instead: see §5.5.

TCP framing (`encap/codec.rs`): read 24 bytes → validate `length ≤ 65511` → read `length` bytes →
one `EncapFrame`. The codec enforces the cap *before* buffering (a hostile `length` cannot cause
over-allocation), skips `NOP` (0x0000) frames, and treats a header that cannot arrive (EOF
mid-frame) as `EnipError::ConnectionLost`.

### 5.2 Commands

| Command | Code | Direction / transport | Purpose |
|---|---|---|---|
| `NOP` | `0x0000` | either, TCP | keepalive filler; receiver ignores (never replied) |
| `ListServices` | `0x0004` | req/reply, TCP or UDP | capability discovery (reports CIP encapsulation support) |
| `ListIdentity` | `0x0063` | req/reply, TCP or UDP broadcast | device discovery (§5.3) — serves the adapter's device-level `sb/browse` |
| `ListInterfaces` | `0x0064` | req/reply, TCP or UDP | optional interface discovery |
| `RegisterSession` | `0x0065` | req/reply, TCP | opens the session (§5.5) |
| `UnRegisterSession` | `0x0066` | request only, TCP | graceful close; **no reply defined** — send, then close the socket |
| `SendRRData` | `0x006F` | req/reply, TCP | carries unconnected CIP (UCMM); data = interface handle `u32=0` + timeout `u16=0` + CPF |
| `SendUnitData` | `0x0070` | send only (either direction), TCP | carries connected class-3 CIP; same interface-handle/timeout prefix + CPF |

`SendRRData`/`SendUnitData` reply decode reads the CIP interface handle and timeout through the
cursor, then hands the remainder to the CPF decoder — a `< 6`-byte data portion is
`WireError::Truncated` (invariant 6). The interface handle is **0 by Vol 2**, and a reply carrying
anything else is `ProtocolViolation` at each of the three decode sites — the `SendRRData` reply, the
connected `SendUnitData` reply, and the Connection-Manager UCMM reply the class-1 I/O layer opens
connections through (D-ENIP-21). A peer addressing another interface is not speaking the CIP
encapsulation we asked for, so its payload is not a Message Router reply we may decode, and nothing
in it may bind a connection. `ProtocolViolation` is non-transient in `is_transient()`: a peer that
mislabels its interface will keep doing so, so the failure surfaces rather than driving a reconnect
ladder.

### 5.3 ListIdentity reply (discovery)

Reply data = CPF with ≥ 1 item of type `0x000C` (Identity):

```text
u16  encapsulation protocol version (1)
16B  sockaddr info (§5.4 layout — network byte order)
u16  vendor id        u16 device type      u16 product code
u8   revision major   u8  revision minor
u16  status word      u32 serial number
SHORT_STRING product name (u8 length + bytes, no padding)
u8   state
```

`discovery.rs` exposes this as `DeviceIdentity` (typed, with vendor/device-type rendered through a
small known-values table plus `Unknown(raw)`).

### 5.4 Common Packet Format (CPF)

`u16 item_count`, then `item_count × { u16 type_id, u16 length, length bytes }`. Decoded
generically by `cpf.rs` with per-item bounds checks; consumers then assert the shape they need.

| Item | Type id | Payload |
|---|---|---|
| Null address | `0x0000` | empty — UCMM requests/replies |
| Identity response | `0x000C` | §5.3 |
| Connected address | `0x00A1` | `u32 connection_id` — class-3 |
| Connected data | `0x00B1` | class-3: `u16 sequence` + MR; class-1: §8.5 frame |
| Unconnected data | `0x00B2` | a MessageRouter request/reply |
| O→T sockaddr info | `0x8000` | 16 B `{i16 sin_family, u16 sin_port, u32 sin_addr, u8[8] zero}` — **big-endian** family/port/addr per spec (the one endianness exception; pinned by a conformance vector) |
| T→O sockaddr info | `0x8001` | same layout |
| Sequenced address | `0x8002` | `u32 connection_id` + `u32 encapsulation_sequence` — class-0/1 UDP |

Explicit replies must contain exactly the expected 2-item shape (address + data); anything else is
`WireError::Malformed` with the offending item id in context.

### 5.5 Session lifecycle

```text
TCP connect (endpoint, default port 44818)
  → RegisterSession { sender_context = "ECREGIST", data: u16 protocol_version = 1, u16 options = 0 }
  ← reply: same 4-byte data; session_handle in the HEADER (must be ≠ 0), status must be 0
  … SendRRData / SendUnitData requests, sender_context-correlated …
  → UnRegisterSession { session_handle } (no reply) → close socket
```

The reply is validated in this order, and every check is a refusal (D-ENIP-21):

1. **context echo** — the reply must carry back the request's `sender_context`. The handshake runs
   before the actor owns the stream, so the session-scoped monotonic context of §10.3 does not exist
   yet and a fixed 8-byte tag (`ECREGIST`) stands in for it. This check is **first**: a frame that is
   not even our reply must not be diagnosed by its other fields, and without the echo any
   RegisterSession-shaped frame already on the stream could be adopted as our session.
2. **command echo** — `RegisterSession`.
3. **options = 0** — §5.1. Deliberately asymmetric with the session actor, which discards such a
   frame and keeps waiting: pre-actor there is exactly one expected frame on the stream, so looping
   over discards during a handshake buys nothing against a peer this broken, and adopting a session
   from it would be worse.
4. **status ok** — a non-zero status is `EnipError::Encap(status)`.
5. **session handle ≠ 0**.
6. **protocol version = 1** (`Unsupported` otherwise — encap status `0x0069` also maps there).
7. **session options = 0** — the body's second word, reserved by Vol 2 and fixed at 0, the same rule
   check 3 applies to the header's `options`. Bits there are a `ProtocolViolation`.
8. **exactly four body bytes** — a body that ends before either word, or that carries anything after
   them, is a `ProtocolViolation`. Checks 6–8 together are the "same 4-byte data" contract above,
   validated whole rather than on its leading word (D-ENIP-21d); each refusal names the field that
   failed in its `detail`.

State machine in `client/session.rs`: `Connecting → Registered → Closing → Closed`. Requests during
`Closing/Closed` fail fast with `EnipError::Closed`.

### 5.6 Encapsulation status codes (typed `EncapStatus`)

`0x0000` Success · `0x0001` unsupported command · `0x0002` insufficient memory ·
`0x0003` incorrect data · `0x0064` invalid session handle · `0x0065` invalid length ·
`0x0069` unsupported protocol version · else `Unknown(u32)`. A non-zero status on a reply
completes the request with `EnipError::Encap(status)`.

**`0x0064` additionally severs the session, at the actor** (D-ENIP-22). The status is a statement
about our *registration*, not about the command that provoked it, so it applies to any correlated
reply — discovery commands included. The caller that provoked it still receives
`Err(Encap(InvalidSessionHandle))`; the actor then exits, its command receiver drops, and every
pending and subsequent request completes `Err(Closed)` without touching the stream. Recovery is the
session owner's: the adapter's reconnect classification maps a session-poisoning `Encap` status to
*transient* (DESIGN §10.1) and re-registers on a fresh stream. The crate never re-registers in
place, and the crate-side `EnipError::is_transient()` default leaves `Encap` non-transient except
for `InsufficientMemory` — the reconnect decision belongs to the owner that holds the backoff ladder
and the instance state (§10.1, §7.6).

---

## 6. CIP layer

### 6.1 Message Router request / reply

Request (`cip/message.rs`):

```text
u8  service code
u8  request path size (in 16-bit WORDS)
    padded EPATH (§6.2)
    service-specific data
```

Reply:

```text
u8  reply service (request service | 0x80)
u8  reserved (0)
u8  general status (§6.4)
u8  additional status size (in WORDS)
u16 × size   additional (extended) status words
    service-specific data (present per-service even on some non-zero statuses, e.g. 0x06)
```

Decode order (invariant-6-safe): ensure 4 bytes → read the four header bytes → checked-multiply
the extended size → ensure/take the extended words → the remainder is the service data. The reply
service must equal `request | 0x80` (checked in the client, `ProtocolViolation` otherwise). The
extended-status list is kept in full (`SmallVec<u16>`); the first word is the primary extended code.

### 6.2 EPATH encoding (padded — the form CIP messaging uses)

| Segment | First byte | Layout |
|---|---|---|
| Class, 8-bit | `0x20` | `0x20, u8` |
| Class, 16-bit | `0x21` | `0x21, 0x00(pad), u16le` |
| Instance, 8-bit | `0x24` | `0x24, u8` |
| Instance, 16-bit | `0x25` | `0x25, 0x00, u16le` |
| Instance, 32-bit | `0x26` | `0x26, 0x00, u32le` (browse cursors above `0xFFFF` — §7.3) |
| Attribute, 8-bit | `0x30` | `0x30, u8` |
| Attribute, 16-bit | `0x31` | `0x31, 0x00, u16le` |
| Member/element, 8-bit | `0x28` | `0x28, u8` |
| Member/element, 16-bit | `0x29` | `0x29, 0x00, u16le` |
| Member/element, 32-bit | `0x2A` | `0x2A, 0x00, u32le` |
| Connection point, 8-bit | `0x2C` | `0x2C, u8` (assembly connection points in I/O paths, §8.4) |
| Connection point, 16-bit | `0x2D` | `0x2D, 0x00, u16le` |
| ANSI extended symbolic | `0x91` | `0x91, u8 char_count, bytes, pad byte if odd` — Logix tag names |
| Port segment | `port ≤ 14`: `u8 (port \| 0x10 if link > 1 byte)`; optional `u8 link_size`; link bytes; pad to even | backplane routing: port 1, link = `[slot]` |

The builder always emits the smallest encoding; total path length must be even (the symbolic and
port pads guarantee it) and ≤ 255 words. **v1 rejects port numbers > 14 at the API** (D-ENIP-13).

`TagAddress::parse` (in `cip/epath.rs`) parses Logix symbolic paths into segments:
`"Program:Main.FillTimer.ACC"` → symbolic segments split on `.` (each ≤ 255 bytes, non-empty);
`"ZONE_TEMPS[3]"` → symbolic + element segment(s); multi-dim `[a,b]` → consecutive element
segments. Parse failures are typed (`PathError`), surfaced at adapter config validation.

### 6.3 CIP elementary data types (`CipType`, `CipValue`)

| Type | Code | Rust repr | Size |
|---|---|---|---|
| BOOL | `0xC1` | `bool` (wire: `u8`, 0=false, non-zero=true; write emits `0xFF`/`0x00`) | 1 |
| SINT | `0xC2` | `i8` | 1 |
| INT | `0xC3` | `i16` | 2 |
| DINT | `0xC4` | `i32` | 4 |
| LINT | `0xC5` | `i64` | 8 |
| USINT | `0xC6` | `u8` | 1 |
| UINT | `0xC7` | `u16` | 2 |
| UDINT | `0xC8` | `u32` | 4 |
| ULINT | `0xC9` | `u64` | 8 |
| REAL | `0xCA` | `f32` | 4 |
| LREAL | `0xCB` | `f64` | 8 |
| BYTE / WORD / DWORD / LWORD | `0xD1/0xD2/0xD3/0xD4` | bit-string aliases of u8/u16/u32/u64 | 1/2/4/8 |
| STRING | `0xD0` | **not decoded** (reported as unsupported) | — |
| Structure marker | `0x02A0` then `u16` template handle | **not decoded**; surfaced as `CipValue::Struct { handle, bytes_len }` | — |

`CipValue` is the crate's value type: one variant per supported scalar plus `Array(CipType,
Vec<CipValue>)` and the opaque `Struct` marker. Value decode is
`(CipType, &[u8]) → Result<CipValue>` with the element count derived from
`data_len / type_size` (a non-integral division is `Malformed`). The adapter owns JSON conversion.

### 6.4 General status (typed, not stringified)

`cip/status.rs` defines `GeneralStatus` as a real enum with `#[non_exhaustive]` and `Unknown(u8)`:

`0x00 Success · 0x01 ConnectionFailure · 0x02 ResourceUnavailable · 0x03 InvalidParameterValue ·
0x04 PathSegmentError · 0x05 PathDestinationUnknown · 0x06 PartialTransfer · 0x07 ConnectionLost ·
0x08 ServiceNotSupported · 0x09 InvalidAttributeValue · 0x0A AttributeListError ·
0x0B AlreadyInState · 0x0C ObjectStateConflict · 0x0D ObjectAlreadyExists ·
0x0E AttributeNotSettable · 0x0F PrivilegeViolation · 0x10 DeviceStateConflict ·
0x11 ReplyDataTooLarge · 0x13 NotEnoughData · 0x14 AttributeNotSupported · 0x15 TooMuchData ·
0x1E EmbeddedServiceError · 0x26 InvalidPathSize · 0xFF ExtendedError` (+ `Unknown(u8)`).

`CipStatus { general: GeneralStatus, extended: SmallVec<u16> }` with helpers the adapter's quality
mapping keys on: `is_ok()`, `has_more()` (== `PartialTransfer`), `is_tag_not_found()`
(`PathSegmentError`/`PathDestinationUnknown`), `is_routing_error()` (per Vol 1 3-5.5:
general 1 with extended `0x0204/0x0311/0x0312/0x0315`, or general 2/4), and Logix `0xFF`
extended decodes (`0x2104` offset beyond end, `0x2105` count beyond end, `0x2107` type mismatch).
`Display` renders `"0x04 (path segment error)"` — the `qualityRaw` string the adapter publishes.

---

## 7. Explicit messaging (poll)

### 7.1 Unconnected (UCMM) and routed requests

- **Direct (no route path)**: the MessageRouter request rides `SendRRData` CPF
  `[Null address, Unconnected data]` as-is. This is the cpppo/CompactLogix-direct path.
- **Routed (route path configured, e.g. backplane slot)**: the request is wrapped in
  **Unconnected_Send (0x52)** addressed to the Connection Manager (`0x20 0x06 0x24 0x01`):

```text
u8  priority/time_tick (default 0x03)      u8 timeout_ticks (default 0xFA)
u16 embedded message request size (bytes)
    the embedded MessageRouter request
u8  pad (only if embedded size is odd)
u8  route path size (words)                u8 reserved (0)
    the route path (port segment(s), padded)
```

The reply is the embedded service's reply (already unwrapped by the target). Routing errors are
distinguishable via `CipStatus::is_routing_error()` + `remaining_path_size`.

### 7.2 Logix symbolic tag services

| Service | Code | Request data (after the symbolic EPATH) | Success reply data |
|---|---|---|---|
| Read Tag | `0x4C` | `u16 element_count` | `u16 type code` (or `0x02A0,u16 handle`) + value bytes |
| Write Tag | `0x4D` | `u16 type code` (+handle) `u16 element_count` + value bytes | empty |
| Read Tag Fragmented | `0x52` | `u16 element_count, u32 byte_offset` | type code + value bytes at offset; status `0x06` ⇒ more |
| Write Tag Fragmented | `0x53` | `u16 type, u16 element_count, u32 byte_offset` + chunk | empty; status `0x06` ⇒ target expects more |
| Read-Modify-Write | `0x4E` | `u16 mask_size ∈ {1,2,4,8,12}` + OR-masks + AND-masks | empty |

**Auto-fragmentation (D-ENIP-12).** `read_tag` first issues `0x4C`; on `PartialTransfer` (or
`ReplyDataTooLarge`) it switches to `0x52`, accumulating `(offset += chunk_len)` until a final
status 0 — capped by `max_value_bytes`. `write_tag` computes the encoded size; if it exceeds the
session's usable request size (≈ 480 B unconnected; the connected size negotiated at ForwardOpen),
it chunks via `0x53` on element boundaries. The caller never sees fragmentation.

Note: `0x52`/`0x4E` service codes collide with Unconnected_Send/Forward_Close codes — CIP service
codes are scoped by the target object (Symbol vs Connection Manager); the crate keeps them in
separate modules (`logix.rs` vs `cm.rs`) so the constants never cross.

### 7.3 Tag enumeration — Get Instance Attribute List (0x55)

Request: EPATH `[0x20 0x6B (Symbol class), <instance segment> start_instance]`, data
`u16 attr_count = 2, u16 attr 1 (name), u16 attr 2 (type)`. The instance segment is the smallest
form that addresses the cursor — `0x24` / `0x25` / `0x26` by magnitude (§6.2). Program-scoped
enumeration prefixes the program's symbolic segment (`0x91 "Program:MainProgram"`) before the class
path.

Reply data = repeating, cursor-decoded records:

```text
u32 instance_id
u16 name_length      name_length bytes (checked UTF-8; ≤ remaining)
u16 symbol_type      (§7.4 word)
```

Status `0x06` ⇒ more instances exist: re-issue with `start_instance = last_id + 1`. A full enumeration
begins at `start_instance = 0`, the bottom of the instance space: instance ids are the device's to
assign, so starting anywhere above 0 skips whatever sits below the chosen start (and some servers —
EthernetIPSharp among them — serve the enumeration *only* from the class-level start instance 0). The
crate exposes one **page** per call —

```rust
list_tags(start_instance: u32, scope: &Scope) -> Result<(Vec<SymbolInfo>, Option<u32>)>
```

— and paging policy (page size to the console, cursors) stays in the adapter. A record that fails to
decode fails the page (`Malformed`), never a partial silent success.

**The cursor is a full `u32` and is never masked.** It is the same width as `SymbolInfo.instance_id`,
because a Logix controller routinely serves symbol instances above `0xFFFF`; narrowing the resume
point to 16 bits would send the walk back into pages it already served, forever. Addressing those
instances is what the 32-bit logical instance segment (`0x26`) exists for.

Three rules bound the walk on the crate side, so a caller that pages to completion sees every symbol
exactly once and terminates whatever the peer does:

* **Ordering guard.** The records of one page must be **strictly ascending** in instance id, checked
  in one pass over the decoded page before any cursor is derived from it. Every resume point is taken
  from the page's *last* record — `last_id + 1` here, and whatever a caller derives after cutting the
  page to its own page size — which is only a safe summary of the page if nothing behind that record
  was left unserved. A page `[10, 2, 3]` cut to one record returns instance 10 and resumes at 11:
  instances 2 and 3 are skipped silently and forever. A repeated instance id strands a record the
  same way. Neither is legal `0x55` output, so both are
  `ProtocolViolation { detail: "tag list page is not in ascending instance order" }` rather than data
  loss at the caller.
* **Advance guard.** A compliant `0x55` reply pages in ascending instance order, so a `0x06` page
  whose derived resume point (`last_id + 1`) does not advance past `start_instance` could only
  revisit itself. That is a broken or hostile peer, and it is
  `ProtocolViolation { detail: "tag list page did not advance" }` — not a loop the caller has to
  detect. (An empty `0x06` page has no resume point at all and simply ends the enumeration.)
* **End of the instance space.** A last record at `u32::MAX` has no representable resume point, so
  the next cursor is `None` and the enumeration ends rather than wrapping to the start.

All three are decode-side rules over already-decoded values; none is a timer input, so a hostile
field costs a browse walk and nothing else.

### 7.4 The symbol-type word

`bit 15` = structure flag; `bits 13–14` = array dims (0–3); atomic: `bits 0–7` = type code
(bool adds `bits 8–10` = bit position); structure: `bits 0–11` = template instance,
`> 0xEFF` ⇒ system-predefined. Exposed as typed `SymbolType` with `is_struct()/dims()/type_code()`
— the adapter uses it to mark browse results `supported: false` for structs/strings/multi-dim.

### 7.5 Generic CIP services

`Get_Attribute_Single 0x0E`, `Set_Attribute_Single 0x10`, `Get_Attribute_All 0x01` against any
`(class, instance, attribute)` EPATH, returning raw `Bytes` (typed decode is the caller's, since
attribute layouts are object-specific). This is the generic-CIP-device escape hatch and what
identity polling uses when ListIdentity is not appropriate (Identity object `0x01`).

### 7.6 Connected class-3 explicit messaging

`ForwardOpen` (§8.2) with `transport_class_trigger = 0xA3` (dir=server, trigger=application,
class 3), P2P, variable-length size 500 both directions, connection path
`[port?] 0x20 0x02 0x24 0x01` (Message Router). Requests then ride `SendUnitData` CPF
`[Connected address (o_t_connection_id), Connected data (u16 sequence + MR)]`; each request
increments the 16-bit sequence (skipping 0); the reply's sequence **must equal** the request's
(D-ENIP-5) and its connection id must be our T→O id. ForwardClose on shutdown.

**Inactivity keepalive (D-ENIP-18).** The open's requested packet interval and timeout-multiplier
code are `ClientOptions` fields — `class3_rpi` (default **2 s**, clamped into the §8.2 plausible band
[100 µs, 600 s] and sent as **both** the O→T and T→O RPI) and `class3_timeout_multiplier` (default
**×16**) — because together they arm the **target's** inactivity watchdog on the connection:
`multiplier × O→T API`. Left at the defaults the ForwardOpen is byte-identical to the pair the crate
previously hard-coded, and the window is 32 s.

The window the client keeps itself inside is derived from the negotiated values: the success reply's
**actual** O→T API when it lies within [100 µs, 600 s], otherwise the clamped requested RPI. This is
the deliberate asymmetry with class-1's reply-API validation (D-ENIP-16): there an implausible API
poisons the produce scheduler and the connection watchdog, so it is a hard `ProtocolViolation`; here
the only timer it feeds is our own keepalive, so an implausible value forfeits the refinement and
never fails the open.

When no request has flowed for **¾ of that window**, the session sends a NOP-level read on the
connected path — `Get_Attribute_Single` of the Identity object (class `0x01`, instance 1,
attribute 4 = Revision), the cheapest mandatory attribute every CIP device serves. The probe rides
the ordinary request path, so it is correlated, deadline-bounded and sequence-checked like any other
request, and it refreshes the same activity clock. **Activity is any completed exchange**, including
one whose MessageReply carries a non-OK CIP status: the reply proves traffic flowed both ways, which
is exactly what the target's watchdog measures. A request that timed out or broke the transport does
not count as activity — the keepalive may then fire though bytes did flow, which costs one tiny read.
`ClientStats.keepalives_sent` (from `SessionStats`) counts probes that completed an exchange, a CIP
error reply included.

**A dead session's reply feeds nothing.** The clock is touched only after the transaction returns
`Ok`, so a reply carrying encapsulation status `0x0064` — which severs the session at the actor
(§5.6, D-ENIP-22) — refreshes no activity and arms no further probe. The connection is not "kept
alive" against a handle the target has already disowned; the owner reconnects instead.

The keepalive task holds only a `Weak` reference to the client's inner state plus a `WeakSender` for
the session actor's command channel, so it keeps neither alive: it returns when the last `EipClient`
handle drops, and when a probe reports the session `Closed` or lost. Any other probe failure is
logged at debug and retried by the next due-time computation — the actor's consecutive-timeout ladder
(§10.4) stays the liveness authority. A sleep is additionally capped at 60 s so liveness is
re-checked at that cadence whatever the window size.

### 7.7 CIP Security posture reads (0x5D / 0x5E / 0x5F)

`cip/security.rs` adds *typed decoding* of the target's security object model on top of §7.5's
`Get_Attribute_Single` — no new wire capability, no feature gate. The decoders are total functions
over `WireReader` (§4): a truncated attribute, an over-long cipher-suite count, or an unknown scalar
value yields a typed `WireError` or an `Unknown(_)` variant, never a panic (fuzz target
`fuzz_security_attrs`).

- **CIP Security Object 0x5D** — `CipSecurityState` (attr 1: Factory Default / Configuration In
  Progress / Configured / …), `SecurityProfiles` bitmaps (attrs 2/3, WORD → named bits).
- **EtherNet/IP Security Object 0x5E** — object state (attr 1), capability flags (attr 2), the
  available / allowed **cipher-suite lists** (attrs 3/4: a USINT count + count × 2-byte IANA id, each
  mapped to its suite name), and the verify-client / send-chain / check-expiration booleans (attrs
  9/10/11).
- **Certificate Management Object 0x5F** — push/pull `CertificateCapabilities` (class attr 8), and the
  instance-1 `CertificateInstance` name / state / encoding (instance attrs 1/2/5).

`EipClient::read_security_posture` reads all three and returns a `SecurityPosture`, mapping any CIP
status (object/attribute unavailable) to "absent" so a generic CIP device reports an empty posture
rather than an error; only a connection-level failure propagates. Validated against the OpENer
`CIPSecurity` branch (§12.5) and duplex-fixture reads.

---

## 8. Implicit messaging (push / class-1 I/O)

### 8.1 Overview

The adapter is the **scanner/originator**: it ForwardOpens an I/O connection pair against a
target's assembly instances — **O→T** (originator-to-target: our cyclic output, or a heartbeat)
and **T→O** (target-to-originator: the input data the target produces at its RPI). Data flows over
**UDP port 2222** (`0x08AE`) as bare CPF frames (no encapsulation header). The TCP session
(§5.5) stays open: it owns the Connection Manager for open/close and is how the connection is
re-established.

### 8.2 ForwardOpen (0x54) / LargeForwardOpen (0x5B)

Addressed to the Connection Manager (`0x20 0x06 0x24 0x01`) via UCMM. Request data (36 bytes +
path; all LE):

| # | Field | Size |
|---|---|---|
| 1 | priority/time_tick | u8 |
| 2 | timeout_ticks | u8 |
| 3 | O→T connection id (0 — target assigns for P2P O→T) | u32 |
| 4 | T→O connection id (originator-chosen: `rand::random::<u32>() \| 1`, so it is non-zero and collides only by chance across originators) | u32 |
| 5 | connection serial number (unique per originator) | u16 |
| 6 | originator vendor id | u16 |
| 7 | originator serial number | u32 |
| 8 | connection timeout multiplier **code** (0→×4, 1→×8 … 7→×512; multiplier = `4 << code`) | u8 |
| 9 | reserved | u8 × 3 |
| 10 | O→T RPI (µs) | u32 |
| 11 | O→T network connection parameters (§8.3) | u16 (u32 in 0x5B) |
| 12 | T→O RPI (µs) | u32 |
| 13 | T→O network connection parameters | u16 (u32) |
| 14 | transport class/trigger: `direction << 7 \| trigger << 4 \| class` — class-1 I/O uses `0x01` (client, cyclic, class 1) | u8 |
| 15 | connection path size (words) | u8 |
| 16 | connection path (§8.4) | — |

Success reply: `u32 O→T id (target-assigned), u32 T→O id (echo), u16 serial, u16 vendor,
u32 orig serial, u32 O→T API (µs), u32 T→O API (µs), u8 app_reply_size (words), u8 reserved,
app bytes`. **The APIs (actual packet intervals) from the reply — not the requested RPIs — drive
the produce timer and the timeout watchdog.**

The reply CPF may carry Sockaddr Info items (§5.4), and **neither of them can steer our traffic**
(D-ENIP-17). The O→T sockaddr moves our transmit **port** only: we always transmit to the target's
own address, so a sockaddr naming `0.0.0.0` contributes its port, one naming the target's address is
honoured as written, and one naming any other address — foreign unicast, broadcast, multicast,
loopback — has its address refused (logged at `warn`, naming it) with only its port kept. A session
with no known target address cannot resolve a transmit endpoint at all, redirect or not. The T→O
sockaddr's multicast address is joined only when the ForwardOpen requested `ConnType::Multicast` for
T→O; a multicast T→O sockaddr answering any other request is a protocol violation naming the type
that was requested (`"multicast T→O sockaddr on a point-to-point request"` /
`"… on a null (reconfigure) request"`), and a requested-multicast connection whose reply names a
unicast address (or carries no T→O sockaddr) consumes unicast.

**Joining that group is part of arming the connection** (D-ENIP-20). The socket task performs the
`IP_ADD_MEMBERSHIP` join as it registers the connection, and a join failure refuses to arm it: the
ForwardOpen fails with the socket error (`EnipError::Io`) and the target-side connection is torn
down by the same best-effort ForwardClose as every other post-success failure. Without membership
the T→O stream never reaches the socket, so an armed-anyway connection would show the operator a
delayed watchdog timeout instead of the interface error that caused it. Group membership is **not**
refcounted across connections: a second connection asking the same manager socket to join a group it
already holds fails that join and is refused. The adapter runs one `IoManager` per push session, so
a shared group never arises in product use, and a fail-fast refusal is preferable to a refcount
whose only exercise would be a test.

The client verifies a success reply before arming anything: the echoed T→O connection id,
connection serial, vendor id, and originator serial must equal the request's
(`verify_forward_open_echo`), and for class-1 both reply APIs must lie within [100 µs, 600 s]
(`validate_reply_apis` — a zero or absurd API is a protocol violation, not a timer input). Class-3
verifies the echo only; its timing is not API-driven. The target-assigned O→T connection id is
deliberately outside the check: the request sends 0 and whatever the target picks is legitimate.

**Any failure after a successful ForwardOpen issues a best-effort ForwardClose** before the typed
error propagates. Past the target's success reply the target believes a connection is open and
produces into it until its own watchdog expires, so every remaining failure path tears it down: a
reply that fails echo verification, a reply whose APIs are out of range, an O→T transmit endpoint
that cannot be resolved (no known target address), a multicast T→O sockaddr on a connection that did
not request multicast T→O, a multicast group the socket could not join, and a manager task that has
already exited so the connection could never be serviced. The ForwardClose is best-effort throughout
— its encode, round trip, and reply status are all discarded, because the caller is already leaving
with a more specific error that must not be replaced.

Failure reply (non-zero status): `u16 serial, u16 vendor, u32 orig serial, u8
remaining_path_size, u8 reserved` — surfaced as `EnipError::ForwardOpenRejected { status,
remaining_path_size }` (typed; extended status `0x0100` duplicate connection, `0x0113` out of
connections, `0x0315` bad segment, etc., render via `CipStatus`).

`LargeForwardOpen (0x5B)` is byte-identical except the two NCP fields widen to u32; selected
automatically when either direction's size exceeds 505 bytes.

### 8.3 Network connection parameters bit packing

Standard (u16): `bits 0–8` connection size (bytes, **including** the class-1 sequence count and
the 32-bit header when present) · `bit 9` variable(1)/fixed(0) · `bits 10–11` priority (0 low,
1 high, 2 scheduled, 3 urgent) · `bits 13–14` connection type (0 null, 1 multicast, 2 P2P) ·
`bit 15` redundant owner. Large (u32): size `bits 0–15`, variable `bit 25`, priority
`bits 26–27`, type `bits 29–30`, redundant `bit 31`.

The crate computes sizes from the caller's *data* sizes: `on_wire = data + 2 (class-1 seq) +
4 (if 32-bit header)`; O→T heartbeat = data size 0 (seq only). Encoding and decoding of the
packed word live in `cm.rs` with exhaustive round-trip tests — this bit-packing is a
classic silent-corruption site.

### 8.4 The I/O connection path

`[port segment if routed] 0x20 0x04 (Assembly class) [0x24 config_instance]
0x2C output_instance (O→T connection point) 0x2C input_instance (T→O connection point)`
— 16-bit forms (`0x25/0x2D`) when an instance exceeds 255. The config instance (+ optional config
data appended as a data segment) is included when the target requires one (OpENer and most
adapters do); input-only connections still open the pair, with the O→T side sized 0 (heartbeat).

### 8.5 The class-1 UDP frame

Bare CPF on UDP :2222 — **no encapsulation header**:

```text
u16 item_count = 2
item 0x8002 (sequenced address): u32 connection_id, u32 encapsulation_sequence
item 0x00B1 (connected data), length N:
    u16 class-1 sequence count            (present: transport class 1)
    u32 run/idle header                   (present only when that direction's real-time
                                           format is "32-bit header"; bit 0: 1=Run 0=Idle,
                                           bits 1–31 reserved 0)
    application data (the assembly bytes)
```

**Order is sequence-then-header (D-ENIP-10).** Conventional formats: O→T = 32-bit header
(scanner signals run/idle), T→O = modeless (pure data). Both are configurable per direction
(`RealTimeFormat::{Modeless, Header32Bit, Heartbeat, ZeroLength}`).

### 8.6 Consume loop (validation gauntlet — every step counted)

**Registration is acknowledged, so routing has no start-up hole** (D-ENIP-20). `forward_open`
completes only after the socket task has inserted the connection into the routing table and joined
any multicast group, so a T→O datagram that arrives the instant it returns is routed rather than
counted as `unknown_connection`. The wait is causal, not timed: the task either services its command
queue or has exited, and both complete it. If the opener's future is cancelled between the command
and its acknowledgement, nobody owns the connection, so the task unregisters it — leaving any group —
instead of producing O→T into it for the life of the process.

One `IoManager` task owns the UDP socket. Per datagram: CPF decode (`WireReader`; runt/malformed →
`malformed_frames` counter, drop) → sequenced-address lookup by `connection_id` against live
connections (unknown → `unknown_connection` counter, drop) → strip class-1 sequence + optional
header per the connection's negotiated T→O format → **size check** against the negotiated T→O data
size (fixed-size mismatch → `size_mismatch` counter, drop) → **sequence acceptance**: accept iff
`(seq − last_accepted) as i16 > 0` (mod-65536 forward window; duplicates/stale → `stale_frames`
counter, drop; a forward jump > 1 additionally increments `sequence_gaps` by the gap) → feed the
watchdog → deliver `IoEvent::Data { data, run_mode, class1_seq, encap_seq, received_at }` to the
connection's queue.

**The per-connection event queue is bounded and latest-wins.** Its capacity (256) bounds `Data`
events; a sample arriving at capacity evicts the **oldest** queued `Data` event and increments
`overflowed_events` — telemetry prefers fresh data over backpressure, so a consumer that falls
behind reads the newest frames rather than an ever-staler backlog. The control events `Up` and
`Lost` are **never** evicted and always enqueue: a connection emits at most one of each, so the
queue is bounded by capacity + 2, and a terminal reason can never be lost behind a flood of samples.
The surviving events keep their relative order, and a push to a queue whose receiver has been
dropped is discarded without counting an overflow (nothing was evicted — there is nobody to deliver
to). `IoConnectionHandle::events()` hands out the consumer half (`IoEventReceiver`, with `recv` /
`try_recv` mirroring `mpsc::Receiver`'s shapes); the sender half lives with the manager task and
owns the connection's counters, so an eviction is counted where it happens.

**Socket errors are counted and classified, never swallowed.** Every `recv_from` failure increments
`recv_errors`. Per-datagram kinds (`ConnectionReset` — the Windows ICMP port-unreachable case —
`ConnectionRefused`, `ConnectionAborted`, `Interrupted`, `WouldBlock`) are survivable drops: they
concern one datagram, not the socket, so they reset the fatal streak and the loop continues. Three
consecutive errors of any other kind declare the socket dead: `IoEvent::Lost { reason: Io }` fans
out to **every** registered connection and the manager task exits. `Lost` is a control event, so a
backlog of samples cannot displace it; the event stream **ending** remains the authoritative
terminal signal — a consumer that sees `recv() == None` must treat the connection as gone whether or
not it drained the `Lost`.

**Watchdog (D-ENIP-8):** per connection, a deadline of `multiplier × T2O_API` refreshed on every
*accepted* frame; expiry ⇒ `IoEvent::Lost { reason: Timeout }`, connection removed, best-effort
ForwardClose over the TCP session. The first accepted frame after open emits `IoEvent::Up`.

### 8.7 Produce loop

Per connection, a schedule at the **O→T API** with `MissedTickBehavior::Skip` semantics (skipped
ticks increment `produce_overruns`): build frame (encap sequence `+1` every send; class-1 sequence
`+1` every send, skipping 0 on wrap), encode current output buffer + run/idle bit, `send_to` the
connection's transmit endpoint; `frames_produced` counts only frames actually sent. A failed send is
counted (`send_errors`) and classified like the receive side; three consecutive non-survivable send
failures declare that connection `Lost { reason: Io }`. Per-datagram send failures never contribute
to that streak — a dead target is the T→O watchdog's verdict to render, not the send path's. The
catch-up computation is arithmetic (O(1)), never a per-tick loop. The output buffer is set via
`IoConnectionHandle::set_output(bytes)` (validated against the negotiated O→T data size) and
`set_run(bool)`; a heartbeat connection sends the seq-only frame. Production never stops while the
connection is open (D-ENIP-9) — run/idle conveys intent.

### 8.8 ForwardClose (0x4E)

Via UCMM to the Connection Manager: `u8 priority/time_tick, u8 timeout_ticks, u16 serial,
u16 vendor, u32 orig serial, u8 path_size (words), u8 reserved, connection path` (same path as the
open — note the reserved byte after path size, absent in ForwardOpen). Sent on `close()`, on
drop of the last handle (best-effort, spawned), and after a watchdog timeout (the target may
already consider it dead; a failure reply is logged, not fatal). Removing a multicast T→O connection
additionally leaves its IGMP group. There is no membership refcount, and none is needed: a group is
held by exactly one connection per manager socket, because a second connection's join of a group the
socket already holds fails and that connection is refused at ForwardOpen (§8.2, D-ENIP-20).

---

## 9. Assembly layout mapping

Raw I/O is just bytes; the *adapter* configures named fields (DESIGN.md §4.6) and the *crate*
provides the checked extraction (D-ENIP-11):

```rust
pub struct AssemblyLayout { fields: Vec<FieldSpec>, data_size: usize }
pub struct FieldSpec {
    pub key: usize,            // caller-supplied index (the adapter maps it to a signal)
    pub offset: usize,         // byte offset into the assembly data
    pub ty: CipType,           // elementary types only
    pub bit: Option<u8>,       // for packed booleans: bit 0–7 within the byte at `offset`
    pub count: usize,          // 1 = scalar; N = contiguous array of N elements
}
```

- `AssemblyLayout::new` **validates at construction**: every field fits inside `data_size`
  (`offset + size × count ≤ data_size`, checked arithmetic), `bit` only with BOOL/BYTE-class
  types, no zero counts. Errors are typed — the adapter turns them into config-validation
  failures at startup, so runtime extraction cannot go out of bounds *by construction*.
- `decode(&self, data: &[u8]) → Result<Vec<(usize, CipValue)>>` re-checks `data.len() ==
  data_size` then extracts each field via `WireReader` — total, no panics (fuzzed, §12.3).
- `encode_into(&self, values, buf) → Result<()>` is the write-side inverse for the output
  assembly (used by the adapter's push-mode `sb/write`); unset fields keep their previous bytes.
- Overlapping fields are permitted (a status word and its individual bits); the layout is data,
  not a partition.

The crate never sees signal names, UNS channels, scaling, or deadbands — those are adapter
concerns applied to the `(key, CipValue)` pairs.

---

## 10. Error & failure model; correlation & timeouts

### 10.1 The error enum

```rust
#[non_exhaustive]
pub enum EnipError {
    Io(std::io::Error),                              // socket-level
    ConnectionLost { context: &'static str },        // EOF / broken framing mid-session
    Timeout { op: &'static str },                    // deadline elapsed (D-ENIP-6)
    Encap(EncapStatus),                              // non-zero encapsulation status
    Cip(CipStatus),                                  // non-zero CIP general status
    ForwardOpenRejected { status: CipStatus, remaining_path_size: Option<u8> },
    Malformed(WireError),                            // decode failure — hostile/broken peer
    ProtocolViolation { detail: &'static str },      // reply service/shape mismatch
    Unsupported { what: &'static str },              // e.g. struct value, port > 14
    Closed,                                          // session/connection already closed
    TooLarge { limit: usize },                       // max_value_bytes / request-size caps
}
```

`EnipError::is_transient()` gives the adapter's reconnect classification a protocol-informed
default: `Io/ConnectionLost/Timeout/Encap(insufficient memory)` and routing/resource CIP statuses
are transient; `Malformed/ProtocolViolation/Unsupported/TooLarge` are not (a peer that breaks the
protocol will keep breaking it — surface, don't hammer). Per-tag CIP errors (`PathSegmentError`
etc.) are *values* to the adapter (BAD samples), not session failures — the crate returns them as
`Err(Cip(..))` per call and the adapter decides (DESIGN.md §10.1).

### 10.2 Failure containment rules

- A malformed **reply to my request** fails that request only; the session survives unless framing
  itself is broken (unrecoverable stream position ⇒ `ConnectionLost`).
- A malformed **UDP datagram** never affects any connection (dropped + counted, §8.6).
- A socket-level UDP error is counted (`recv_errors`/`send_errors`); per-datagram errors never
  affect any connection; a dead socket loses **all** its connections with a typed `Lost{Io}`, never
  silently.
- Peer-driven counters (`stale_frames`, `malformed_frames`, `overflowed_events`,
  `refused_redirects`, `discarded_options`, …) are exposed on the handles (`stats()`), so the adapter can alarm on a
  noisy/hostile peer without the crate knowing what an alarm is. `refused_redirects` is 0 or 1 per
  connection and records that the ForwardOpen reply's O→T sockaddr named a foreign address, whose
  address half was refused and only its port honoured (D-ENIP-17) — the one disposition a healthy
  link would otherwise hide. `keepalives_sent` on `ClientStats` is the explicit-side equivalent for
  the class-3 keepalive (§7.6). `discarded_options` on `ClientStats` counts replies dropped for a
  non-zero encapsulation `options` field (§5.1, D-ENIP-21) — its own cause, kept out of
  `stale_replies` so the peer defect is diagnosable rather than hidden inside ordinary staleness.

### 10.3 Explicit correlation (D-ENIP-5)

`sender_context` carries a session-scoped monotonically increasing `u64` (LE in the 8-byte field).
The session task holds at most **one** outstanding request `{context, deadline, reply_tx}`. Reader
loop, per inbound frame:

1. **`options` gate** (§5.1, D-ENIP-21) — a frame with `options ≠ 0` is discarded and counted
   (`discarded_options`) with a warn, *before* correlation is attempted. The order is deliberate:
   such a frame is malformed at the encapsulation layer, so which request it claims to answer is not
   yet a meaningful question — a foreign-context frame with non-zero options counts as a discarded
   options frame, not as staleness.
2. **Correlation** — a reply completes the outstanding request iff its `sender_context`, its
   command, and (for session-scoped `SendRRData`/`SendUnitData`) its session handle all match;
   discovery replies (`ListIdentity`/`ListServices`/`ListInterfaces`) are exempt from the handle
   check (§5.2 — sessionless-capable; live targets answer with handle 0). Any non-matching frame is
   discarded and counted (`stale_replies`); a context-matched frame with a wrong command or handle
   is additionally logged at warn.
3. **Poison check** (§5.6, D-ENIP-22) — a correlated reply whose status is `InvalidSessionHandle`
   completes its caller with `Err(Encap(..))` and kills the actor.

Class-3 additionally matches the connected-data sequence count (hard `Err`-on-mismatch → drop +
count, never `debug_assert!`).

### 10.4 Timeouts & stale-reply quarantine (D-ENIP-6)

Every public call runs under a deadline taken from `ClientOptions.request_timeout` — one value per
client; the API exposes no per-call override. On expiry the request completes `Err(Timeout)` and the
session notes the timed-out context. Because TCP guarantees ordering, the session remains usable: a
later reply bearing the old context is dropped by §10.3. If **three consecutive** requests time out
(configurable), the session declares itself dead (`ConnectionLost`) — sustained silence means the
peer or path is gone, and the adapter's reconnect ladder takes over. There is no state in which a
late reply can complete a newer request: contexts never repeat (u64), and the map from context to
waiter is removed at timeout.

Deadlines bound the **write** side too: the deadline is computed at enqueue (queue wait counts), the
actor hand-off and the frame write run under `timeout_at`, and a write that cannot complete by the
deadline severs the session as `ConnectionLost` (a cancelled `write_all` may leave a partial frame —
framing is unrecoverable). A transaction dequeued past its deadline completes `Err(Timeout)` without
touching the stream and without counting toward the consecutive-timeout ladder; one whose caller has
gone is skipped.

**Two clocks, one authority.** The session actor is the authority on *which* failure an elapsed
deadline is: an ordinary per-request `Timeout`, the third consecutive strike (`ConnectionLost`), or a
write that stalled mid-frame and desynchronised the stream (`ConnectionLost`). Every other bound in
the path sits exactly at the deadline: the caller's hand-off into the actor's queue (which the actor
never sees, so a bare `Timeout` is the whole truth there), the dequeue triage, the write, and the
read. The caller's wait on the reply
channel is therefore not a second deadline but a *liveness backstop* against an actor that never
answers at all, and it is set at `deadline + REPLY_BACKSTOP_GRACE` (50 ms). Were the two timers on
the same instant, the caller's — registered first, and so fired first — would pre-empt the actor at
every deadline and collapse every failure class into a bare `Timeout`; the grace makes the actor's
verdict, not a tie, what the caller observes. The accepted consequence is that a request can
observably complete up to 50 ms past its deadline. Both caller-side bounds (the enqueue wait and the
reply backstop) increment `timeouts` when they fire — no timeout path is silent (§10.2). Fixed
constants: `UNREGISTER_WRITE_DEADLINE` = 500 ms, `CLOSE_HANDOFF_DEADLINE` = 2 s,
`REPLY_BACKSTOP_GRACE` = 50 ms.

Class-1 has its own liveness (§8.6 watchdog); UnRegisterSession/ForwardClose during shutdown are
best-effort with a short fixed deadline so shutdown never hangs.

---

## 11. Async model & public API

### 11.1 Task topology

- **One session task per `EipClient`** (`client/session.rs`): owns the `TcpStream` (via the
  `encap::codec` framed transport), an mpsc request channel, and the correlation state. Requests are
  `{encoded frame, deadline, oneshot reply}`. The task dies on `ConnectionLost`; pending and
  subsequent requests complete with `Err(Closed)`. **No global mutable state anywhere in the crate**;
  every handle is `Send + Sync` (`EipClient` is a cheap clone around the channel sender).
- **One keepalive task per connected-messaging client** (`client/keepalive.rs`, §7.6): drives the
  ¾-window class-3 probe. It holds only a `Weak` to the client's inner state and a `WeakSender` for
  the session channel, so it keeps neither alive and exits with the last client handle.
- **One `IoManager` task per bound UDP socket** (usually one per adapter process): owns the
  socket, the connection registry, the consume loop, and all produce timers (spawned per
  connection, aborted on close). `IoConnectionHandle` exposes `events` (a bounded latest-wins
  receiver, §8.6), `set_output`, `stage_output`, `set_run`, `stats`, `close`. Commands that can
  fail inside the task — registering a connection, and the confirmed form of output staging — carry
  a `oneshot` acknowledgement so the verdict reaches the caller (D-ENIP-20).
- **Graceful teardown**: `EipClient::close()` → UnRegisterSession → socket close;
  `IoConnectionHandle::close()` → ForwardClose (needs the `EipClient`) → produce timer aborted →
  registry removal. `Drop` is non-async: it aborts tasks and closes sockets (RAII), spawning
  best-effort ForwardClose/UnRegisterSession only if a runtime handle is available — the adapter's
  shutdown path calls the async closes explicitly (DESIGN.md §10.3).
- Nothing blocks a worker thread: all I/O is Tokio; the only computation is codec work on
  already-buffered bytes.

### 11.2 The public API (the surface `DESIGN.md` §3.4 consumes)

```rust
// ---- explicit (poll) ----
let client = EipClient::connect(
    "192.168.1.50:44818",
    ClientOptions {
        route: Some(RoutePath::backplane_slot(0)),   // None for cpppo / CompactLogix-direct
        connect_timeout: …, request_timeout: …,
        connected_messaging: false,                  // true ⇒ class-3 ForwardOpen (§7.6)
        class3_rpi: Duration::from_secs(2),          // requested class-3 RPI, both directions
        class3_timeout_multiplier: TimeoutMultiplier::X16,   // ⇒ a 32 s target watchdog, ¾-window keepalive
        max_value_bytes: 1 << 20,
        ..Default::default()
    },
).await?;

let tag = TagAddress::parse("ZONE_TEMPS")?;
let v: TagReadResult = client.read_tag(&tag, /*elements*/ 8).await?;
//    TagReadResult { value: CipValue, wire_type: CipType, fragmented: bool }
client.write_tag(&tag2, CipType::Real, &CipValue::Real(55.5)).await?;      // Ok = CIP-acked
let (symbols, next): (Vec<SymbolInfo>, Option<u32>) =
    client.list_tags(/*start_instance*/ 0u32, &Scope::Controller).await?;   // §7.3 u32 cursor
let raw = client.get_attribute_single(0x01, 1, 7).await?;                  // generic CIP
let ident = client.identity().await?;                                      // ListIdentity over the session
client.close().await;

// ---- implicit (push) ----
let io = IoManager::bind("0.0.0.0:2222").await?;
let conn = io.forward_open(&client, IoConnectionSpec {
    assembly: AssemblyPath { config: Some(151), output: 150, input: 100, route: None },
    t2o: DirectionSpec { rpi: Duration::from_millis(20), data_size: 32,
                         format: RealTimeFormat::Modeless, conn_type: ConnType::P2P,
                         priority: Priority::Scheduled },
    o2t: DirectionSpec { rpi: Duration::from_millis(20), data_size: 4,
                         format: RealTimeFormat::Header32Bit, .. },        // data_size 0 ⇒ heartbeat
    timeout_multiplier: TimeoutMultiplier::X16,
}).await?;    // Err(ForwardOpenRejected{..}) on refusal; Ok ⇒ the connection is ARMED (§8.6)

conn.set_output(&bytes)?;            // validated against negotiated O→T size; UNCONFIRMED
conn.stage_output(&bytes).await?;    // same validation, plus the manager's accept/refuse verdict
conn.set_run(true);
// `events()` is an IoEventReceiver: bounded + latest-wins on Data, Up/Lost never evicted (§8.6);
// `None` is the authoritative "connection is gone".
while let Some(ev) = conn.events().recv().await {
    match ev {
        IoEvent::Up { o2t_api, t2o_api } => …,
        IoEvent::Data { data, run_mode, class1_seq, received_at, .. } => …,
        IoEvent::Lost { reason } => …,               // Timeout | ClosedByPeer | Io
    }
}
conn.close(&client).await;
```

**Output staging comes in two forms** (D-ENIP-20). `set_output` is synchronous and *unconfirmed*:
its `Ok` says the command was queued for the socket task, and a connection the task has already
removed swallows it. `stage_output` runs the same size validation and then awaits the task's
verdict, so its `Ok` means the buffer is held for a live connection and will ride the next produced
frame; `Err(Closed)` names a manager that has shut down or a connection that is gone, and says
plainly that the value was never staged. Callers answering a write command use `stage_output`; the
fire-and-forget setter stays for callers with nothing to report to.

Everything is deadline-bounded — including writes, connect/close, shutdown, and the TLS handshake at
both `connect_tls` and the `connect_tls_over` stream-injection entry point — returns
`Result<_, EnipError>`, and is documented with rustdoc (`//!`/`///` per org convention, `cargo doc`
clean).

---

## 12. Testing, fuzzing & conformance vectors

The protocol crate sits **inside** the workspace 90% line-coverage gate (`cargo llvm-cov`
workspace-wide) — no `enip` file is excluded from the denominator. The pure codec, state machines,
and class-1 receive/produce logic reach the bar offline over `duplex` fixtures (§12.2). The crate's
live-socket **runtime** — the class-1 UDP `IoManager`/`manager_task`/`IoConnectionHandle` in `io.rs`,
`client/io_service.rs`, and the TCP connect in `client/mod.rs` — needs a real peer, so it is exercised
by the live OpENer/cpppo suites (§12.4) rather than offline; it stays **counted against the gate**
(not carved out), and the well-tested codec keeps the crate over the bar without excluding it. (The
adapter holds the same line: no product file of its own is excluded either — see DESIGN §12.2.)

### 12.1 Unit tests (per codec, no I/O)

Every encoder/decoder pair gets: round-trip (`decode(encode(x)) == x`) across representative and
boundary values; golden-vector equality (§12.4); and *truncation sweeps* — for each golden frame,
every prefix `frame[..n]` must decode to `Err(Truncated)`, never panic (a shared
`assert_no_panic_prefixes!` helper makes this one line per decoder). Bit-packing (NCP, symbol
type, transport trigger) gets exhaustive-domain tests. `CipStatus`/`EncapStatus` render/classify
tests pin the typed-enum contract.

### 12.2 State-machine tests (in-memory `duplex` byte-stream fixtures)

The session actor is generic over `AsyncRead + AsyncWrite`, so tests drive it over
`tokio::io::duplex` in-memory pipes (D-ENIP-14) and feed hand-scripted raw bytes onto the wire —
no socket, no peer implementation, fully deterministic: RegisterSession happy/rejected/garbage;
correlation — a delayed reply pushed onto the fixture *after* the caller timed out must be
quarantined (assert `stale_replies == 1` and the next request gets the *right* answer);
three-consecutive-timeouts ⇒ `ConnectionLost`; class-3 sequence mismatch dropped; fragmented read
spanning ≥ 3 chunks incl. the `max_value_bytes` cap; ForwardOpen success/reject. Class-1 receive
logic is driven the same way — crafted datagrams fed straight into the consume gauntlet / sequence
window (the codec and window rules are pure): Up on first frame, stale/dup/size-mismatch drops
with exact counter assertions, gap counting, watchdog Lost on producer stop, produce cadence +
heartbeat under `tokio::time::pause()`. Because the fixture injects raw bytes rather than replaying
the crate's own encoders, a decoder bug cannot be cancelled out by a matching encoder bug.

The **class-3 keepalive** (§7.6) rides the same fixtures under `start_paused` time
(`tests/class3_keepalive.rs`): the probe's exact `SendUnitData` / MessageRequest shape at the
¾ point, request traffic pushing the deadline out, the window derived from the reply's O→T API and
the fallback when that API is implausible, a CIP-error reply still counting as a completed probe,
and the task exiting when the last client handle drops or the session is closed — no socket, no
timing race. The **latest-wins event queue** (§8.6) is proven as a pure policy function
(`push_latest_wins`: oldest-`Data` eviction, control-event immunity, order preservation, receiver
gone) and through its real sender/receiver pair (the counted overflow, `Lost` surviving a flood,
terminal-after-drain, wakeup and cancel-safety), with the manager's `select!` glue driven end to end
over a loopback UDP pair.

**Tag-enumeration paging** (§7.3, D-ENIP-19) rides the same fixtures (`tests/tag_paging.rs`): a
scripted `0x55` reply whose record sits above `0xFFFF` yields a cursor above `0xFFFF` and the request
that carried it is asserted byte-exact as the 32-bit instance segment (`20 6B 26 00 00 00 01 00`);
a `0x06` page that resumes before where it started is the typed `ProtocolViolation`; an out-of-order
page (`[10, 2, 3]`, whose last record still derives an advancing cursor) and a page repeating an
instance id are the typed ordering `ProtocolViolation`, the second on a *final* page so the guard is
shown not to be gated on `0x06`; and a last record at `u32::MAX` ends the enumeration.

**Session hygiene** (§5.1/§5.2/§5.5/§5.6, D-ENIP-21/22) rides the same fixtures
(`tests/session_p2.rs`): a correlated `0x0064` reply delivers `Encap(InvalidSessionHandle)` and the
next request is `Closed` with nothing further reaching the peer; a reply that is otherwise perfectly
ours but carries `options ≠ 0` is never delivered and lands on `discarded_options`; the same frame
with a *foreign* context still lands on `discarded_options` and not on `stale_replies`, pinning the
gate ahead of correlation; a RegisterSession reply with a foreign context, and one with non-zero
header options, are each refused with no actor spawned (asserted by the peer's EOF); the same
handshake fixture drives the body rule across all five of its outcomes — an empty body, the
two-byte `01 00` body whose options word is missing, a body with the options word set, a body with
trailing bytes, and a well-formed body at protocol version 2 — each asserted on its own `detail` or
variant, against the conforming `01 00 00 00` body that still registers; and a non-zero
interface handle is refused at each of the three decode sites — `SendRRData`, `SendUnitData`, and
`ForwardOpenService::cm_ucmm`. The keepalive half of the poison rule is in
`tests/class3_keepalive.rs`, waiting causally on the peer's EOF rather than on a clock: a surviving
session would instead go on probing and trip the bound.

### 12.3 Fuzzing (the safety claim, made executable)

`crates/enip/fuzz/` (cargo-fuzz/libFuzzer, run on Linux/WSL/CI) with one target per hostile
surface — the invariant for all: **no panic, no OOM (allocation caps hold), decode is total**:

| Target | Surface |
|---|---|
| `fuzz_encap_frame` | TCP bytes → framed decoder (header + length games) |
| `fuzz_cpf` | CPF item soup |
| `fuzz_message_reply` | MR reply incl. extended-status size lies |
| `fuzz_forward_open_reply` | success/fail reply + sockaddr items |
| `fuzz_tag_list` | 0x55 record stream (name-length lies, bad UTF-8) |
| `fuzz_cip_value` | `(CipType, bytes)` value decode |
| `fuzz_io_frame` | UDP datagram → consume gauntlet (runt frames — the EIPScanner bug class) |
| `fuzz_assembly_decode` | `AssemblyLayout::decode` against arbitrary layouts + data |
| `fuzz_tag_path` | `TagAddress::parse` (caller-supplied strings) |
| `fuzz_discovery` | discovery reply decoders (§5.3): `DeviceIdentity::parse_reply` / `parse_item` (sockaddr item + SHORT_STRING product-name length games) and the `parse_list_services` / `parse_list_interfaces` CPF walkers |
| `fuzz_security_attrs` | CIP Security object attrs (0x5D/0x5E/0x5F): cipher-suite count lies, short strings, width-tolerant flags (§7.7) |

Structured fuzzing via `arbitrary` for round-trip targets (`encode(x)` then mutate). Corpus
seeded from the §12.4 vectors. Two CI cadences carry this: the `fuzz-smoke` job in
`.github/workflows/ci.yml` runs **every** target for a fixed short budget (`-max_total_time=30`)
over the checked-in corpus + regressions on each PR, and `.github/workflows/fuzz-weekly.yml` runs
every target at 600 s on a weekly schedule. Both enumerate the targets with `cargo fuzz list` — a
target joins its gate by existing — and both treat an empty list as an error rather than a pass.
Found crashes fail the run and are committed as regression inputs under
`fuzz/corpus/<target>/`, where `tests/fuzz_corpus.rs` then replays them on every platform.

### 12.4 Conformance vectors (provable wire-correctness)

`crates/enip/tests/vectors/` — annotated golden byte sequences, each a JSON manifest entry
`{ name, direction, layer, hex, decoded }` asserted **both ways** (encode produces exactly the
bytes; decode produces exactly the struct). Sources, in order of authority:

1. **Live captures against cpppo** (RegisterSession, Read/Write Tag req+reply, array read,
   error replies incl. 0x04/0x05, tag list) — captured once via a pcap of the existing probe,
   checked in as hex.
2. **Live captures against the push target** (§12.5): ForwardOpen req+reply, class-1 frames in
   both directions, ForwardClose.
3. **Hand-assembled from the ODVA layouts** in §5–§8 for paths with no live producer (extended
   status forms, LargeForwardOpen, sockaddr items, encap error statuses) — cross-checked against
   both reference implementations' encoders during authoring (study, not import). This is also
   where the **32-bit logical instance segment** (§6.2) is pinned, because no bench peer serves more
   than 65 535 symbol instances: `epath_instance_32bit` (`26 00 00 00 01 00`, the bare segment via
   `EPath::encode`) and `get_instance_attribute_list_request_32bit_instance`
   (`55 04 20 6B 26 00 00 00 01 00 02 00 01 00 02 00`, the whole §7.3 browse request at
   `start_instance = 0x0001_0000`). Both are assembled byte by byte from the segment-type-byte
   layout rather than generated from this crate's encoder, which would make them circular.

The vector suite is the regression net that lets us refactor codecs fearlessly; a vector may only
change with a spec citation in the commit.

### 12.5 Test peers: `duplex` fixtures (unit) + external containers (integration)

Unit/CI level: in-memory `tokio::io::duplex` byte-stream fixtures (D-ENIP-14, §12.2). The session
actor is generic over `AsyncRead + AsyncWrite`; a fixture is one end of a byte pipe onto which the
test writes hand-scripted frames — a happy reply, a stale reply after the deadline, a fragmented
reply, a wrong-`sender_context` reply, a sequence-mismatched class-1 datagram, or pure garbage.
Because the fixture carries raw bytes rather than replaying the crate's own encoders, a decoder bug
cannot be cancelled out by a matching encoder bug. No socket, no container, no in-crate peer
implementation — the crate ships no `testserver`.

System level: real-device conformance is validated against EXTERNAL containers in the adapter's
integration suite (DESIGN.md §11) — **cpppo** for poll (explicit messaging) and **OpENer** (the
ODVA-member OSS EtherNet/IP *adapter/target* stack) for push (class-1 implicit I/O), each an
independent implementation rather than our own code talking to itself. The crate's own CI does not
depend on containers.

---

*Cross-references: the adapter that consumes this crate — `DESIGN.md` (config §4, seam §3.3,
quality mapping §5.4, metrics §8, simulator/validation §11). This document owns everything on the
wire; that one owns everything on the bus.*
