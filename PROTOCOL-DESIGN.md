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
2. [Decisions register (D-ENIP-1…D-ENIP-14)](#2-decisions-register)
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

**Non-goals (v1).** UDT/structure *value* decoding (struct tags are detected and reported, not
decoded); Logix STRING values; CIP Multiple Service Packet batching; CIP Security/TLS
(EtherNet/IP here is plaintext); CIP Sync/Motion; acting as a full *target* (the crate ships a
minimal test-target for validation only, §12.5); DeviceNet/ControlNet adaptations of CIP.

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

---

## 2. Decisions register

| # | Decision | Rationale / alternatives |
|---|---|---|
| **D-ENIP-1** | **One protocol crate (`crates/enip`, package `ec-enip`), module-split internally — not separate `eip`/`cip` crates.** | The split rseip chose (core/eip/cip/client crates) buys nothing here: CIP without the EtherNet/IP adaptation has no second consumer (we do not target DeviceNet), and one crate gives one coverage denominator, one fuzz corpus tree, and no cross-crate churn. Module boundaries (§3) keep the layering reviewable; a future crate split along those module lines stays cheap if a second transport ever appears. |
| **D-ENIP-2** | **`#![forbid(unsafe_code)]` at the crate root — no exceptions, no `unsafe` islands.** | Nothing in this protocol needs `unsafe`: framing is length-prefixed byte handling, decode is cursor reads, UDP/TCP are Tokio. rseip's only `unsafe` (tag-list UTF-8) is exactly the bug class we are eliminating. `forbid` (not `deny`) so no module can opt back in. |
| **D-ENIP-3** | **All decoding goes through the checked `WireReader` cursor (§4); direct slice indexing of wire data is banned** (`clippy::indexing_slicing` + `clippy::arithmetic_side_effects` denied in decode modules). | Makes the no-panic invariant *reviewable*: any indexing or unchecked arithmetic on wire-derived lengths is a lint failure, not a code-review catch. |
| **D-ENIP-4** | **Decode by wire-declared type, not caller expectation:** `read_tag` returns the `CipValue` the reply's type code declares; the caller compares against its expectation. | A type mismatch becomes *data* (the adapter maps it to a BAD sample) instead of a decode error deep in a generic; kills the monomorphized `read_tag::<TagValue<T>>` dispatch pattern and its blind trust of the wire. |
| **D-ENIP-5** | **Explicit correlation is `sender_context`-based with one in-flight request per session**; a reply whose context does not match the outstanding request is discarded (counted, logged), never delivered. Connected class-3 replies must match the connected-data sequence count or be discarded — a hard check, not a `debug_assert!`. | Fixes rseip's worst defect (silent wrong-tag values in release builds). One-in-flight keeps the model simple and is sufficient at adapter poll rates; pipelining is a v2 option the correlation design already permits (§10.3). |
| **D-ENIP-6** | **Every request has a caller-supplied deadline enforced inside the session task**; on timeout the request completes `Err(Timeout)` and the session enters *stale-reply quarantine* (§10.4) rather than being torn down. | Isolated slowness must not cost a reconnect, but a late reply must never surface as an answer. Quarantine + context matching achieves both. |
| **D-ENIP-7** | **Class-1 receive validation is mandatory**: CPF shape, connection-id lookup, size-vs-negotiated check, and 16-bit sequence acceptance via the signed-window rule `(new − last) as i16 > 0`; stale/duplicate/mis-sized frames are dropped **and counted**, never delivered and never silent. | EIPScanner swallows all three checks. Counters make the drops observable (the adapter surfaces them as metrics). |
| **D-ENIP-8** | **I/O connection liveness is originator-monitored**: no valid T2O frame within `timeout_multiplier × T2O_API` ⇒ the connection is declared lost, a typed `Lost` event is emitted, and the connection is closed. Production continues at O2T API regardless of consumption. | The spec's inactivity watchdog, implemented on our side (EIPScanner's shape, made typed and non-silent). API values come from the ForwardOpen **reply** (actual PI), not the request. |
| **D-ENIP-9** | **The class-1 produce path always sends at the O2T API cadence** (data, or a heartbeat when the O2T size is 0), incrementing the encapsulation sequence every frame and the class-1 sequence count every produce. | The target runs the same watchdog against us; a paused/idle adapter that stops producing kills its own connection. Run/idle is signaled in the 32-bit header (§8.5), not by stopping. |
| **D-ENIP-10** | **Frame order for class-1 connected data is `[u16 class-1 sequence][u32 run/idle header, if the format includes it][data]`** — sequence first. | ODVA Vol 2: the run/idle header is *inserted between the sequence count and the data*. EIPScanner encodes this correctly on produce but decodes header-first on consume — a reference bug we pin here so nobody "fixes" our order to match it. |
| **D-ENIP-11** | **The crate exposes a bounds-checked `AssemblyLayout` helper (§9)** that maps raw assembly bytes ⇄ typed fields (offset/type/bit), but the *naming and configuration* of fields stays in the adapter. | Field extraction from hostile bytes belongs inside the fuzz boundary; signal semantics (names, UNS channels, deadbands) are adapter business the crate must not learn. |
| **D-ENIP-12** | **Fragmented read/write is auto-driven inside the crate** (status `0x06` → continue at the next offset; writes chunked to the negotiated size), with a configurable `max_value_bytes` cap (default 1 MiB) bounding reassembly memory. | The caller asks for a tag and gets the whole value or a typed error. Wire-supplied sizes never drive unbounded allocation (§4). |
| **D-ENIP-13** | **v1 restricts routing to port numbers ≤ 14** (covers backplane port 1 + slot, the only routed path the adapter exposes). The extended-port encoding is implemented per spec but gated behind a conformance vector captured from real routed hardware before it is enabled. | The references disagree on extended-port byte order and we have no routed device to arbitrate; shipping an unverified encoding of a rarely-used path is how wire bugs are born. Declared limitation, not silent. |
| **D-ENIP-14** | **The crate ships a minimal in-crate test target** (`testserver` feature: explicit-messaging responder + class-1 producer/consumer) used by unit/integration tests and by the adapter's push validation fallback. | The session/connection state machines need a live peer to test without hardware; owning a tiny target also gives CI a class-1 peer with no container dependency (§12.5). It is a test double, not a product. |

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
  testserver.rs    feature "testserver": mock explicit responder + class-1 target (§12.5)
```

Layering rule (enforced by review + module visibility): `wire` ← `encap`/`cpf`/`cip` ←
`cm`/`logix`/`io`/`assembly` ← `client`/`discovery`. Nothing imports upward; `client` is the only
module that owns sockets besides `io`; `testserver` may reach anything (it is a test double).

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

`SendRRData`/`SendUnitData` reply decode reads interface handle (must be 0) and timeout through the
cursor, then hands the remainder to the CPF decoder — a `< 6`-byte data portion is
`WireError::Truncated` (invariant 6).

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
  → RegisterSession { data: u16 protocol_version = 1, u16 options = 0 }
  ← reply: same 4-byte data; session_handle in the HEADER (must be ≠ 0), status must be 0
  … SendRRData / SendUnitData requests, sender_context-correlated …
  → UnRegisterSession { session_handle } (no reply) → close socket
```

State machine in `client/session.rs`: `Connecting → Registered → Closing → Closed`; the reply's
protocol version must be 1 (`Unsupported` otherwise — encap status `0x0069` also maps there).
Requests during `Closing/Closed` fail fast with `EnipError::Closed`.

### 5.6 Encapsulation status codes (typed `EncapStatus`)

`0x0000` Success · `0x0001` unsupported command · `0x0002` insufficient memory ·
`0x0003` incorrect data · `0x0064` invalid session handle · `0x0065` invalid length ·
`0x0069` unsupported protocol version · else `Unknown(u32)`. A non-zero status on a reply
completes the request with `EnipError::Encap(status)`; `0x0064` additionally poisons the session
(the handle is gone — reconnect).

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

Request: EPATH `[0x20 0x6B (Symbol class), 0x25 start_instance]`, data
`u16 attr_count = 2, u16 attr 1 (name), u16 attr 2 (type)`. Program-scoped enumeration prefixes
the program's symbolic segment (`0x91 "Program:MainProgram"`) before the class path.

Reply data = repeating, cursor-decoded records:

```text
u32 instance_id
u16 name_length      name_length bytes (checked UTF-8; ≤ remaining)
u16 symbol_type      (§7.4 word)
```

Status `0x06` ⇒ more instances exist: re-issue with `start_instance = last_id + 1`. The crate
exposes one **page** per call (`list_tags(start_instance) → (Vec<SymbolInfo>, Option<next>)`) —
paging policy (page size to the console, cursors) stays in the adapter. A record that fails to
decode fails the page (`Malformed`), never a partial silent success.

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
class 3), P2P, size 500/504 fixed, connection path `[port?] 0x20 0x02 0x24 0x01` (Message Router).
Requests then ride `SendUnitData` CPF `[Connected address (o_t_connection_id),
Connected data (u16 sequence + MR)]`; each request increments the 16-bit sequence (skipping 0);
the reply's sequence **must equal** the request's (D-ENIP-5) and its connection id must be our
T→O id. Class-3 connections idle-timeout on the target: the session sends a NOP-level keepalive
(a Get_Attribute_Single of Identity revision) if no request has flowed for ¾ of the inactivity
window. ForwardClose on shutdown.

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
| 4 | T→O connection id (originator-chosen, unique per live connection: `incarnation << 16 \| counter`) | u32 |
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
the produce timer and the timeout watchdog.** The reply CPF may carry Sockaddr Info items
(§5.4): an O→T sockaddr redirects our transmit endpoint (port, and address unless `0.0.0.0`); a
T→O sockaddr with a multicast address is the group to join for multicast consumption.

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

One `IoManager` task owns the UDP socket. Per datagram: CPF decode (`WireReader`; runt/malformed →
`malformed_frames` counter, drop) → sequenced-address lookup by `connection_id` against live
connections (unknown → `unknown_connection` counter, drop) → strip class-1 sequence + optional
header per the connection's negotiated T→O format → **size check** against the negotiated T→O data
size (fixed-size mismatch → `size_mismatch` counter, drop) → **sequence acceptance**: accept iff
`(seq − last_accepted) as i16 > 0` (mod-65536 forward window; duplicates/stale → `stale_frames`
counter, drop; a forward jump > 1 additionally increments `sequence_gaps` by the gap) → feed the
watchdog → deliver `IoEvent::Data { data, run_mode, class1_seq, encap_seq, received_at }` to the
connection's channel (bounded; overflow = `overflowed_events` counter + latest-wins, telemetry
prefers fresh data over backpressure).

**Watchdog (D-ENIP-8):** per connection, a deadline of `multiplier × T2O_API` refreshed on every
*accepted* frame; expiry ⇒ `IoEvent::Lost { reason: Timeout }`, connection removed, best-effort
ForwardClose over the TCP session. The first accepted frame after open emits `IoEvent::Up`.

### 8.7 Produce loop

Per connection, a `tokio::time::interval` at the **O→T API** with
`MissedTickBehavior::Skip` (skipped ticks increment `produce_overruns`): build frame
(encap sequence `+1` every send; class-1 sequence `+1` every send, skipping 0 on wrap), encode
current output buffer + run/idle bit, `send_to` the connection's transmit endpoint. The output
buffer is set via `IoConnectionHandle::set_output(bytes)` (validated against the negotiated O→T
data size) and `set_run(bool)`; a heartbeat connection sends the seq-only frame. Production never
stops while the connection is open (D-ENIP-9) — run/idle conveys intent.

### 8.8 ForwardClose (0x4E)

Via UCMM to the Connection Manager: `u8 priority/time_tick, u8 timeout_ticks, u16 serial,
u16 vendor, u32 orig serial, u8 path_size (words), u8 reserved, connection path` (same path as the
open — note the reserved byte after path size, absent in ForwardOpen). Sent on `close()`, on
drop of the last handle (best-effort, spawned), and after a watchdog timeout (the target may
already consider it dead; a failure reply is logged, not fatal). Multicast T→O additionally
leaves the IGMP group when the last connection using it closes.

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
- Peer-driven counters (`stale_frames`, `malformed_frames`, …) are exposed on the handles
  (`stats()`), so the adapter can alarm on a noisy/hostile peer without the crate knowing what an
  alarm is.

### 10.3 Explicit correlation (D-ENIP-5)

`sender_context` carries a session-scoped monotonically increasing `u64` (LE in the 8-byte field).
The session task holds at most **one** outstanding request `{context, deadline, reply_tx}`. Reader
loop, per inbound frame: match command + context → complete the request; context mismatch → the
frame is a **stale reply** (from a timed-out predecessor): increment `stale_replies`, log at debug,
drop. Class-3 additionally matches the connected-data sequence count (hard `Err`-on-mismatch →
drop + count, never `debug_assert!`).

### 10.4 Timeouts & stale-reply quarantine (D-ENIP-6)

Every public call runs under a deadline (`ClientOptions.request_timeout`, caller-overridable
per call). On expiry the caller gets `Err(Timeout)` immediately, and the session notes the
timed-out context. Because TCP guarantees ordering, the session remains usable: a later reply
bearing the old context is dropped by §10.3. If **three consecutive** requests time out
(configurable), the session declares itself dead (`ConnectionLost`) — sustained silence means the
peer or path is gone, and the adapter's reconnect ladder takes over. There is no state in which a
late reply can complete a newer request: contexts never repeat (u64), and the map from context to
waiter is removed at timeout.

Class-1 has its own liveness (§8.6 watchdog); UnRegisterSession/ForwardClose during shutdown are
best-effort with a short fixed deadline so shutdown never hangs.

---

## 11. Async model & public API

### 11.1 Task topology

- **One session task per `EipClient`** (`client/session.rs`): owns the `TcpStream` (via the
  `encap::codec` framed transport), an mpsc request channel, the correlation state, and the
  keepalive timer. Requests are `{encoded frame, deadline, oneshot reply}`. The task dies on
  `ConnectionLost`; pending and subsequent requests complete with `Err(Closed)`. **No global
  mutable state anywhere in the crate**; every handle is `Send + Sync` (`EipClient` is a cheap
  clone around the channel sender).
- **One `IoManager` task per bound UDP socket** (usually one per adapter process): owns the
  socket, the connection registry, the consume loop, and all produce timers (spawned per
  connection, aborted on close). `IoConnectionHandle` exposes `events` (bounded receiver),
  `set_output`, `set_run`, `stats`, `close`.
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
        max_value_bytes: 1 << 20,
        ..Default::default()
    },
).await?;

let tag = TagAddress::parse("ZONE_TEMPS")?;
let v: TagReadResult = client.read_tag(&tag, /*elements*/ 8).await?;
//    TagReadResult { value: CipValue, wire_type: CipType, fragmented: bool }
client.write_tag(&tag2, CipType::Real, &CipValue::Real(55.5)).await?;      // Ok = CIP-acked
let (symbols, next) = client.list_tags(start_instance, Scope::Controller).await?;
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
}).await?;                                            // Err(ForwardOpenRejected{..}) on refusal

conn.set_output(&bytes)?;            // validated against negotiated O→T size
conn.set_run(true);
while let Some(ev) = conn.events().recv().await {
    match ev {
        IoEvent::Up { o2t_api, t2o_api } => …,
        IoEvent::Data { data, run_mode, class1_seq, received_at, .. } => …,
        IoEvent::Lost { reason } => …,               // Timeout | ClosedByPeer | Io
    }
}
conn.close(&client).await;
```

Everything is deadline-bounded, returns `Result<_, EnipError>`, and is documented with rustdoc
(`//!`/`///` per org convention, `cargo doc` clean).

---

## 12. Testing, fuzzing & conformance vectors

The protocol crate sits **inside** the workspace 90% line-coverage gate (`cargo llvm-cov`
workspace-wide) — this design removes the old "raw client seam excluded from coverage" carve-out,
because the stack is now fully testable without hardware.

### 12.1 Unit tests (per codec, no I/O)

Every encoder/decoder pair gets: round-trip (`decode(encode(x)) == x`) across representative and
boundary values; golden-vector equality (§12.4); and *truncation sweeps* — for each golden frame,
every prefix `frame[..n]` must decode to `Err(Truncated)`, never panic (a shared
`assert_no_panic_prefixes!` helper makes this one line per decoder). Bit-packing (NCP, symbol
type, transport trigger) gets exhaustive-domain tests. `CipStatus`/`EncapStatus` render/classify
tests pin the typed-enum contract.

### 12.2 State-machine tests (mock peer over real sockets)

The `testserver` (D-ENIP-14) drives session/connection logic through real Tokio TCP/UDP:
RegisterSession happy/rejected/garbage; correlation — delayed reply released *after* the caller
timed out must be quarantined (assert `stale_replies == 1` and the next request gets the *right*
answer); three-consecutive-timeouts ⇒ `ConnectionLost`; class-3 sequence mismatch dropped;
fragmented read spanning ≥ 3 chunks incl. the `max_value_bytes` cap; ForwardOpen success/reject;
class-1: Up on first frame, stale/dup/size-mismatch drops with exact counter assertions, gap
counting, watchdog Lost on producer stop, produce cadence + heartbeat under
`tokio::time::pause()`.

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

Structured fuzzing via `arbitrary` for round-trip targets (`encode(x)` then mutate). Corpus
seeded from the §12.4 vectors. CI: every PR runs each target for a fixed short budget
(`-max_total_time=30` per target) over the checked-in corpus + regressions; found crashes are
committed as regression inputs. Longer runs are a periodic (weekly) job.

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
   both reference implementations' encoders during authoring (study, not import).

The vector suite is the regression net that lets us refactor codecs fearlessly; a vector may only
change with a spec citation in the commit.

### 12.5 The class-1 test peer

Unit/CI level: the in-crate `testserver` (D-ENIP-14) — a minimal target: accepts RegisterSession +
ForwardOpen, produces a configurable assembly at the agreed RPI over UDP, consumes our O→T,
supports scripted misbehavior (stop producing, wrong sizes, stale sequences, garbage) to drive
the §12.2 assertions. It reuses the crate's *encoders* but is careful to also carry raw-byte
scripted frames so decoder bugs can't cancel out encoder bugs.

System level: **OpENer** (the ODVA-member OSS EtherNet/IP *adapter/target* stack) in a container
as the independent conformance peer — the adapter-repo E2E plan (DESIGN.md §11) specifies it; the
crate's own CI does not depend on containers.

---

*Cross-references: the adapter that consumes this crate — `DESIGN.md` (config §4, seam §3.3,
quality mapping §5.4, metrics §8, simulator/validation §11). This document owns everything on the
wire; that one owns everything on the bus.*
