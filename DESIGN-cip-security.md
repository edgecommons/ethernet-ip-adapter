# CIP Security for ethernet-ip-adapter — design spike

**Status: SPIKE (decision document, 2026-07-19). Nothing here is implemented.** This document is
the output of the CIP Security design spike: a phased design (TLS on the explicit path; the
originator-side certificate/security-object model), a **definite answer on the validation
target**, and effort/risk/go-no-go per phase. It is written to be promotable into
`DESIGN.md`/`PROTOCOL-DESIGN.md` decisions if the phases are approved; until then it is internal
planning material and none of its content belongs in user-facing docs.

Grounding artifacts (all re-verified 2026-07-19, none from memory):

- `PROTOCOL-DESIGN.md` §5 (encapsulation/session), §11 (async model / `connect_over` seam), §1
  non-goals ("CIP Security/TLS — EtherNet/IP here is plaintext"); the live seam code
  `crates/enip/src/client/{mod.rs,session.rs}` (session actor generic over
  `AsyncRead + AsyncWrite`).
- `DESIGN.md` §4 (config), §7.1 (`sb/status`), §11 (external-target validation pattern), §14.5
  (the current "No CIP Security / TLS" limitation).
- `core/docs/CREDENTIALS.md` — the vault, `gg.credentials()`, `getTlsBundle(name) →
  {certPem, keyPem, caPem?}`, config `{"$secret": …}` refs, rotation change listeners.
- ODVA: *A Practical Guide for CIP Security Device Developers* (2017 ODVA conference paper —
  cipher-suite table, port 2221, commissioning model); *PUB00317 R22* ODVA mandatory-change list
  (Dec 2025 — the Vol 8 1.13 GCM requirement quoted verbatim in §2.4); PUB00319 At-a-Glance.
- `EIPStackGroup/OpENer` branches `CIPSecurity` / `CIPSecurity_develop` — file tree, the three
  security-object sources, the POSIX network handler, branch README, and commit history
  (inspected file-by-file; findings in §5.2).

**One correction surfaced up front (fidelity rule):** the spike brief listed the object classes
as "EtherNet/IP Security 0x5F, CIP Security 0x5D, Certificate Management 0x5E". The
authoritative assignments — verified against the OpENer branch sources, which encode the Vol 8
values — are:

| Object | Class | OpENer source |
|---|---|---|
| CIP Security Object | **0x5D** | `cipsecurity.h`: `kCipSecurityObjectClassCode = 0x5DU` |
| EtherNet/IP Security Object | **0x5E** | `ethernetipsecurity.h`: `kEIPSecurityObjectClassCode = 0x5EU` |
| Certificate Management Object | **0x5F** | `certificatemanagement.h`: `0x5FU` |

This document uses the corrected mapping throughout.

---

## Table of contents

1. [Overview & decision context](#1-overview--decision-context)
2. [CIP Security ground truth (what the spec actually requires)](#2-cip-security-ground-truth)
3. [Phase 1 design — TLS on the explicit (poll) path](#3-phase-1-design--tls-on-the-explicit-poll-path)
4. [Phase 2 design — originator cert & security-object model](#4-phase-2-design--originator-cert--security-object-model)
5. [Validation plan & THE TARGET ANSWER](#5-validation-plan--the-target-answer)
6. [Effort, risk & go/no-go per phase](#6-effort-risk--gono-go-per-phase)
7. [Docs impact](#7-docs-impact)

---

## 1. Overview & decision context

**What CIP Security is.** ODVA Volume 8 ("CIP Security") adds transport-layer security to
EtherNet/IP without changing the application protocol: the same encapsulation frames, CIP
services, and connection machinery ride inside **TLS 1.2+ for everything TCP** (encapsulation
session, UCMM, connected class-3) and **DTLS 1.2+ for the UDP class-0/1 implicit I/O path**.
Identity is mutual — X.509 certificates (or PSK, now discouraged; §2.4) on **both** ends, so the
adapter (the originator/scanner) presents a client certificate the device verifies, and verifies
the device's certificate in return. Three CIP objects manage security state on a device: the
**CIP Security Object (0x5D)** (overall state/profiles, commissioning services), the
**EtherNet/IP Security Object (0x5E)** (per-endpoint TLS/DTLS policy: cipher suites, cert paths,
trust anchors, verify-client, port policy), and the **Certificate Management Object (0x5F)**
(device cert inventory, Create_CSR, Verify_Certificate). Provisioning is either **push** (a
config tool writes certs/config into the device — every CIP Security device must support it) or
**pull** (the device enrolls itself against plant PKI via **EST, RFC 7030** — optional profile).

**The phasing decision (user-decided; this spike designs it, does not reopen it):**

- **Phase 1 — TLS on the EXPLICIT (poll) path.** Wrap the EtherNet/IP encapsulation TCP session
  in TLS (mutual X.509), pure-Rust via `rustls`, cert material sourced from the EdgeCommons
  credentials vault. This alone secures everything the adapter's poll mode does: RegisterSession,
  UCMM reads/writes, connected class-3, browse, identity.
- **Phase 2 — the originator-side certificate / security-object model.** Trusted-CA management,
  EST-based enrollment/rotation of the adapter's own client cert, and typed reads of the target's
  0x5D/0x5E/0x5F objects (our generic `get_attribute_single`/`get_attribute_all` already reach
  them) to honor the target's posture. NOT the device-side security-object surface — we are the
  originator, not a configurable target.
- **DTLS on the implicit (push) path — documented FUTURE, out of scope.** §3.6 records exactly
  where it would slot in and why it is hard. It is the pure-Rust-breaking part: `rustls` has no
  DTLS and no credible pure-Rust DTLS 1.2 server/client exists at the maturity this stack
  requires, and no OSS validation peer exists at all. Additionally, Vol 8 (PUB00317 CT23) has
  **deprecated** the halfway house — using a TLS session to ForwardOpen a *non-secure* class-0/1
  connection over UDP 2222 — so there is no legitimate "TLS explicit + plaintext push on a
  secured target" hybrid to build toward: secure push means DTLS, whole and entire, later.

**Why this phasing is right for this adapter.** Poll mode is the default and the
brownfield-realistic mode; explicit messaging is where writes (the security-sensitive operation)
happen; and TLS-on-TCP is the part of Vol 8 that maps 1:1 onto a seam we already built
(§3.1 — the session actor is transport-generic by design). Phase 2 is what turns "TLS works"
into "operable in a real plant PKI" (cert lifecycle instead of hand-provisioned files).

---

## 2. CIP Security ground truth

Facts the design leans on, each pinned to a source during this spike.

### 2.1 Ports — fixed, well-known; policy on the target

- **TCP 2221 = EtherNet/IP over TLS** (explicit). **UDP 2221 = EtherNet/IP over DTLS**
  (implicit). Plaintext stays on TCP 44818 / UDP 2222. The ODVA developers' guide uses port 2221
  throughout its debug examples (`openssl s_client -connect <host>:2221`,
  `nmap --script ssl-enum-ciphers -p 2221`), and specifies the originator convention: a secure
  connection is addressed by including the TLS port in the connection target ("`192.168.10.10`"
  = unsecure vs "`192.168.10.10:2221`" = secure).
- So the brief's "negotiates via the target's config, not a fixed alt-port" needed sharpening,
  and the accurate statement is: **the secure port is fixed (2221); what is negotiable is the
  target's port *policy*** — the EtherNet/IP Security Object (0x5E) decides whether the
  plaintext ports stay open at all, and a hardened device closes 44818 entirely. The
  *originator* (us) chooses security per connection simply by which port it dials and whether it
  speaks TLS on it. There is no STARTTLS-style in-band upgrade on 44818.
- Consequence for config (§3.3): `security.mode: "tls"` flips the adapter's default port for
  that instance from 44818 to **2221**; an explicit `endpoint: "host:port"` always wins.

### 2.2 What TLS carries

Everything the TCP session carries today, unchanged: the 24-byte encapsulation header framing
(PROTOCOL-DESIGN §5.1), RegisterSession/UnRegisterSession, SendRRData (UCMM +
Unconnected_Send routing), SendUnitData (connected class-3), ListIdentity-over-session. CIP
Security deliberately does not touch the application bytes — which is precisely why Phase 1 is
a transport swap, not a protocol change. (UDP *broadcast* ListIdentity discovery remains
plaintext in the ecosystem; a hardened device may not answer it.)

### 2.3 The object model (Phase 2's read surface)

Verified against the OpENer CIPSecurity branch sources (which implement the Vol 8 definitions):

- **CIP Security Object 0x5D** — attrs: 1 State, 2 Security Profiles, 3 Security Profiles
  Configured; services Begin_Config (0x4B), Kick_Timer (0x4C), End_Config (0x4D),
  Object_Cleanup (0x4E). One instance; the commissioning state machine.
- **EtherNet/IP Security Object 0x5E** — 16 instance attributes incl. 3 Available Cipher
  Suites / 4 Allowed Cipher Suites (lists of IANA suite IDs), 5 Pre-Shared Keys, 6 Active
  Device Certificates / 7 Trusted Authorities (paths to Certificate Management instances /
  File objects), 8 CRL path, 9–11 booleans (Verify Client Certificate, Send Certificate Chain,
  Check Expiration), 12 Trusted Identities, 13–16 pull-model config / DTLS timeout / UDP-only
  policy; services Begin_Config, Kick_Timer, Apply_Config, Abort_Config. Newer editions add
  Available/Allowed **Originator** Cipher Suites (attrs 17/18, Vol 8 1.15) and an I/O
  Authorization Policy attr 20 (1.18).
- **Certificate Management Object 0x5F** — instance attrs 1 Name, 2 State, 3 Device
  Certificate, 4 CA Certificate, 5 Certificate Encoding; class attrs 8 Capability Flags
  (push/pull), 9 Certificate List, 10 Encodings Flag; services **Create_CSR (0x4B)**,
  **Verify_Certificate (0x4C)**.

All are reachable with the shipped generic services (`get_attribute_single 0x0E`,
`get_attribute_all 0x01` — PROTOCOL-DESIGN §7.5). Phase 2 adds *typed decoding*, not new wire
capability.

### 2.4 Cipher suites — the single most decision-relevant fact of the spike

The original Vol 8 suite set (ODVA developers' guide, Table "Summary of Cipher Suites"):

```text
TLS_RSA_WITH_NULL_SHA256              TLS_ECDHE_ECDSA_WITH_NULL_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_PSK_WITH_NULL_SHA256        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
```

**Every one of these is CBC, NULL-encryption, static-RSA, or PSK — and `rustls` supports none
of them** (rustls is AEAD-only by architecture: no CBC, no NULL, no static-RSA key exchange,
no TLS-PSK, no DTLS). Had the spec stopped there, "pure-Rust Phase 1" would be dead on arrival.

It did not stop there. **ODVA PUB00317 (mandatory change list), Vol 8 edition 1.13:**

> "Require GCM-based cipher suites be supported and change RSA-based cipher from required to
> optional for CIP Security endpoints. (Table 3-5.4, Section 5-4.4.6 and 5-4.9)"
> "EtherNet/IP Security Object Allowed Cipher Suites attribute 4 shall only allow cipher suites
> that support confidentiality in the Factory Default state. PSK based cipher suites shall not
> be allowed by default."

Later editions (1.16) demote several previously-required suites to recommended, and 1.18 adds
Encrypt-then-MAC (RFC 7366) as mandatory *when* CBC is used. So:

- **Spec-current devices (Vol 8 ≥ 1.13, ~2021 onward) MUST support GCM suites** —
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B) and friends — which `rustls` speaks
  natively in TLS 1.2, plus the TLS 1.3 suites. **Pure-Rust Phase 1 interoperates with any
  spec-current CIP Security device.**
- **Legacy CIP Security firmware (2019–2021 era) may offer only the CBC/NULL/PSK list** — the
  OpENer branch's factory defaults are exactly the ECDHE-ECDSA **CBC** pair (§5.2), which
  `rustls` cannot negotiate. This is a *documented interop boundary*, with two escape hatches:
  (a) the device's Allowed Cipher Suites attr (0x5E attr 4) is configurable — a commissioning
  tool can enable GCM on most such devices; (b) if a real fleet ever demands CBC, a non-default
  `tls-openssl` backend feature is the fallback — a deliberate, user-approved divergence from
  pure Rust, not a silent one. We do **not** build (b) now.
- `rustls` covers the rest of what Phase 1 needs: TLS 1.2+1.3, client-certificate (mTLS) auth,
  custom `ServerCertVerifier` (needed for device certs that carry IP SANs or legacy CN-only
  names), `ServerName::IpAddress` (PLCs are dialed by IP), configurable cipher-suite list via
  its `CryptoProvider`, and `SSLKEYLOGFILE`-style key logging (`ClientConfig.key_log`) — which
  recovers the Wireshark-debuggability that the spec's NULL suites exist for, without ever
  offering NULL on the wire.

### 2.5 Commissioning / trust model (Phase 2 context)

Out of the box a device holds **default credentials** (vendor cert or self-signed); a
commissioning session over those provisions the operational credentials. All devices must
support the **push** model; the **pull** model (device-side EST against plant PKI) is an
optional profile (Vol 8 1.13 added the Pull Model Profile). For **us** — the originator — the
relevant lifecycle is our *own* client certificate: obtain it from the plant CA (EST
`/simpleenroll`), re-enroll before expiry (`/simplereenroll`), and trust the plant root(s) that
sign device certs. We consume EST as a *client of plant PKI*, we do not implement the
device-side pull-model profile.

---

## 3. Phase 1 design — TLS on the explicit (poll) path

### 3.1 Where TLS wraps — the seam, confirmed in code

The design bet made in PROTOCOL-DESIGN §11.1/D-ENIP-14 pays off unmodified. The session actor
and the connect path are already generic over the byte stream:

```rust
// crates/enip/src/client/mod.rs (today, verbatim signature)
pub async fn connect_over<S>(mut stream: S, opts: ClientOptions) -> Result<Self>
where S: AsyncRead + AsyncWrite + Unpin + Send + 'static { … }

// crates/enip/src/client/session.rs (today)
impl<S> SessionActor<S> where S: AsyncRead + AsyncWrite + Unpin { … }
```

`tokio_rustls::client::TlsStream<TcpStream>` satisfies `AsyncRead + AsyncWrite + Unpin + Send`,
so **the entire session machinery — framing codec, correlation, deadlines, stale-reply
quarantine, class-3 sequencing — runs over TLS with zero changes**. TLS sits *below* the
encapsulation codec and *above* TCP, exactly as Vol 8 layers it. The only additions are a
handshake step in the connect path and plumbing for the peer address (today `connect_over`
leaves `peer_addr: None`; irrelevant for poll, kept correct anyway):

```rust
// crates/enip — NEW, behind feature "tls" (dependency-budget decision D-ENIP-15, §3.5)
pub struct TlsOptions {
    /// Built by the CALLER (the adapter) — the crate never reads cert files or secrets.
    pub config: Arc<rustls::ClientConfig>,
    /// Verification/SNI name; typically ServerName::IpAddress(<endpoint ip>).
    pub server_name: rustls::pki_types::ServerName<'static>,
}

impl EipClient {
    /// TCP connect (default port 2221) → TLS handshake (inside connect_timeout) →
    /// RegisterSession → session actor. Everything after the handshake is the existing path.
    pub async fn connect_tls(addr: &str, opts: ClientOptions, tls: TlsOptions) -> Result<Self> {
        let tcp = /* existing bounded TCP connect, DEFAULT_TLS_PORT = 2221 */;
        let connector = tokio_rustls::TlsConnector::from(tls.config);
        let stream = timeout(remaining_connect_budget,
                             connector.connect(tls.server_name, tcp)).await??;
        let peer_addr = stream.get_ref().0.peer_addr().ok();
        let mut client = Self::connect_over(stream, opts).await?;
        client.peer_addr = peer_addr;
        Ok(client)
    }
}
```

Error mapping: handshake failures surface as a new typed
`EnipError::Tls { kind: TlsErrorKind, detail: String }`
(`HandshakeFailed`/`PeerUnverified`/`NoCipherOverlap`/`Io`), classified **non-transient by
default** for cert/verification failures (a bad cert will stay bad — surface loudly, back off at
the ceiling, mirroring the §10.1 `Malformed` posture) and transient for pre-handshake I/O.
`NoCipherOverlap` gets a dedicated rendering because it is the predictable legacy-CBC-device
failure (§2.4) and the error text must say so
(`"no common cipher suite — target may be pre-1.13 CIP Security (CBC-only); enable GCM suites on
the device or see docs"`).

Shutdown ordering: `close()` keeps its sequence (best-effort UnRegisterSession, then drop);
dropping the `TlsStream` sends `close_notify` best-effort. No change to the deadline-bounded
shutdown contract.

**Class-3 connected messaging and routing work unchanged** — they are bytes inside the same
stream. **Push mode (`mode: "push"`) with `security.mode: "tls"` is refused at config
validation** ("class-1 I/O requires DTLS, which is not supported; see limitations") — we
refuse rather than do the CT23-deprecated thing (TLS session opening plaintext I/O), and we do
not silently fall back to plaintext.

### 3.2 The `enip` ⇄ adapter split (isolation contract preserved)

The isolation contract (PROTOCOL-DESIGN §1) says the crate knows nothing about EdgeCommons — it
says nothing about TLS, which is protocol-level (Vol 8 *is* EtherNet/IP). The split:

| Concern | Where | Why |
|---|---|---|
| TLS transport: `connect_tls`, `TlsOptions`, handshake, `EnipError::Tls`, default port 2221 | **`crates/enip`**, feature `tls` (adds `tokio-rustls`; rustls re-exported) | Protocol-level; keeps the crate the complete EtherNet/IP story; testable/fuzzable in isolation |
| Building `rustls::ClientConfig`: parsing PEM (`rustls-pemfile`), root store, client cert/key, custom verifier (IP-SAN / no-verify mode), suite constraints, key-log wiring | **adapter** (`src/eip/tls.rs`, new) | Policy + material handling; the crate takes an opaque `Arc<ClientConfig>` and never sees key bytes' provenance |
| Sourcing cert material: vault (`gg.credentials().getTlsBundle`), `{"$secret": …}` refs, files; rotation listeners | **adapter** | EdgeCommons knowledge — exactly what the crate must never learn |
| Config schema (`connection.security`), `sb/status` security surface, metrics | **adapter** | Adapter behavior per DESIGN.md ownership split |

Dependency-budget note (PROTOCOL-DESIGN §1 requires a decision for additions): record
**D-ENIP-15: the `tls` cargo feature adds `tokio-rustls`/`rustls` (+`rustls-pki-types`) to
`crates/enip`; default features remain TLS-free; no C deps, builds on Windows/MSVC + Linux
unchanged** (rustls with the default `aws-lc-rs` provider builds natively on both; the `ring`
provider is the fallback knob if a build issue ever appears).

### 3.3 Adapter config surface (`connection.security`)

`connection` is the one deliberately-open object (DESIGN §4.2) — the `security` sub-block is
added as a *typed* island inside it (parsed strictly when present):

```jsonc
"connection": {
  "endpoint": "192.168.10.60",          // port defaults: 44818 plaintext / 2221 when tls
  "security": {
    "mode": "tls",                      // "plaintext" (default) | "tls"
    "client": {                          // the adapter's identity (mutual TLS)
      "certSecret": "ot-pki/eip-originator",  // vault TLS bundle: {certPem, keyPem[, caPem]}
      "certFile": "…", "keyFile": "…"        // OR files; secret wins if both; values may be {"$secret": …}
    },
    "ca": {                              // trust anchors for verifying the DEVICE
      "secret": "ot-pki/plant-root",     // vault secret (PEM, may contain several certs)
      "file": "…"                        // OR a PEM file
    },
    "verifyPeer": true,                  // false = accept any device cert (LOUD warning + event; for commissioning/debug)
    "serverName": "192.168.10.60",       // optional; default = endpoint host (IP → IP-SAN verification)
    "checkExpiration": true,             // mirror of the device-side 0x5E semantics; false tolerates RTC-less-device certs
    "cipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]   // optional constraint; default = rustls defaults
  }
}
```

Validation (fail-fast at startup, per the existing skip-bad-instance rule): `mode:"tls"`
requires a client cert+key source AND a CA source unless `verifyPeer:false` (CIP Security
devices require client certs by default — 0x5E attr 9 — so an identity-less TLS config is
almost certainly a misconfiguration; we warn loudly if only the CA is missing and
`verifyPeer:false`). `mode:"tls"` + `mode:"push"` instance ⇒ startup validation error (§3.1).
Secret resolution is lazy at connect time (the `$secret` contract — never into the logged config
snapshot); key material lives in zeroizing buffers per the vault's hygiene rules and is dropped
after the `ClientConfig` is built.

**Rotation (Phase 1 minimal):** a vault change listener on the referenced secrets marks the
instance's TLS config dirty; the next reconnect (natural, or operator `reconnect`) rebuilds
`ClientConfig`. Live re-handshake mid-session is not attempted (Phase 2 adds proactive
rotation, §4.3).

### 3.4 Observable surface

- **`sb/status`** (DESIGN §7.1) gains a `security` object on TLS instances:

```json
"security": { "mode": "tls", "tlsVersion": "1.3",
  "cipherSuite": "TLS13_AES_128_GCM_SHA256", "peerVerified": true,
  "clientCertNotAfter": "2027-03-01T00:00:00Z",
  "handshakeFailures": { "interval": 0, "total": 2 } }
```

  (`mode: "plaintext"` instances report `"security": { "mode": "plaintext" }` so consoles can
  render the posture column unconditionally.)
- **State keepalive**: `attributes.security: "tls" | "plaintext"` beside `connectionMode` —
  same single-source rule as `paused` (all surfaces derive from one place).
- **Metrics**: `EtherNetIpConnection` gains `tlsHandshakeFailuresTotal/Interval` and a
  `security` dimension value is **not** added (dimension churn not worth it; the gauge
  `sessionConnected` + status carry the posture). Handshake latency folds into the existing
  `connectLatencyMs`.
- **Events**: `device-connected` context gains `"security": "tls"`; a dedicated
  `tls-handshake-failed` Warning event fires on the *transition* into handshake-failing (not per
  retry), with the typed reason (incl. the `NoCipherOverlap` legacy hint).

### 3.5 Testing (inside the existing discipline)

- The session actor needs **no new tests** (transport-generic, proven over `duplex`).
- `connect_tls` unit tests drive a real rustls **server config on the other end of an in-memory
  duplex pair** (tokio-rustls acceptor): handshake ok / wrong CA / expired cert / no-overlap /
  client-cert-required-and-missing, then RegisterSession over the established stream. This does
  NOT violate D-ENIP-14 ("no embedded EtherNet/IP peer"): the fixture is a *TLS endpoint on a
  byte pipe*, not an EtherNet/IP implementation — the same class as the duplex fixture itself,
  and the crypto is rustls-vs-rustls only at the unit tier; independent-implementation TLS
  interop comes from the live target (§5.3, OpenSSL/mbedTLS on the other side).
- Adapter: config-validation tests per §3.3 row; `ClientConfig` builder tests over fixture PEMs
  (checked-in throwaway test certs generated by the harness, never real material); vault-ref
  resolution against the in-memory fake vault.
- Fuzzing: no new decoder surface (TLS records are rustls's problem; our decoders see the same
  plaintext bytes) — the existing fuzz targets remain the complete set.

### 3.6 Where DTLS (push) would slot in — FUTURE, recorded only

For completeness of the map, not for building now: the class-1 path would need (a) a DTLS 1.2
client bound to the `IoManager` UDP socket (per-connection DTLS sessions to `UDP 2221`),
(b) ForwardOpen carried over the TLS session with the paired DTLS endpoints
(0x5E DTLS timeout attr 14 governing), (c) the §8.6 consume gauntlet running on *decrypted*
datagrams — the gauntlet itself is transport-agnostic and would not change. The blockers are
unchanged by anything found in this spike: `rustls` has no DTLS; the only pure-Rust DTLS
(`webrtc-dtls`) is WebRTC-profile-shaped and not at this stack's assurance bar; the C routes
(openssl/mbedtls/wolfSSL bindings) break the zero-C-deps property; and there is **no OSS DTLS
EtherNet/IP peer at all** (§5.2), so it would ship unvalidatable. Revisit only with a lab
CIP-Security PLC on the bench and an explicit decision on the C-dependency trade.

---

## 4. Phase 2 design — originator cert & security-object model

Phase 2 = three separable capabilities that compose with Phase 1: **(a)** typed reads of the
target's security objects, **(b)** vault-native trust/cert lifecycle with proactive rotation,
**(c)** EST enrollment of the adapter's own certificate. They are deliberately independent —
each can land (or be held) alone; §6 prices them separately.

### 4.1 (a) Reading the target's 0x5D/0x5E/0x5F — typed posture

New `crates/enip/src/cip/security.rs` (no new deps, no feature gate — it is pure decoding over
the shipped generic services): typed structs + decoders for the §2.3 attribute set —
`CipSecurityState` (attr 0x5D/1: Factory Default / Configuration In Progress / Configured /
Incident), `SecurityProfiles` bitmap, `EipSecurityPosture` (active/allowed suite-ID lists
decoded to IANA names where known + `Unknown(u16)`, verify-client / expiration flags, pull-model
config presence), `CertMgmtInventory` (cert list, capability flags, per-instance state/encoding).
All decoding via `WireReader` (the §4 invariant — these are device-supplied bytes), fuzz target
`fuzz_security_attrs` added to the §12.3 table.

Adapter surface: `sb/status` `security` object (Phase 1, §3.4) gains a `target` sub-object when
the instance successfully reads the posture (read once per connect, refreshed on `reconnect`):

```json
"target": { "state": "Configured", "profiles": ["EtherNet/IP Confidentiality"],
            "allowedCipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "…"],
            "verifyClient": true, "pullModel": false }
```

Posture *honoring*: before dialing TLS the adapter can (optionally, `security.probe: true`)
read 0x5E over plaintext 44818 *if open* to pre-flight suite overlap and produce a precise
config-time diagnostic instead of a handshake failure; on a hardened device (44818 closed) the
handshake itself is the probe. A device whose state reads `Factory Default` with default
credentials gets a WARN in status (unprovisioned device being polled securely).
Devices *without* CIP Security answer these reads with CIP status 0x08/0x05 — surfaced as
`"target": null` + `targetSupportsCipSecurity: false`, never an error (same typed-refusal
pattern as browse).

### 4.2 (b) Trust & cert lifecycle in the vault

Straight application of `CREDENTIALS.md` machinery — no new vault features needed:

- **Trusted CAs**: one vault secret (PEM bundle, possibly several roots) per trust domain,
  referenced by `security.ca.secret`; central-synced from Secrets Manager where the plant PKI
  publishes roots, local-`put` otherwise. Rotation grace (`rotationGraceSecs`) already gives the
  old+new-root overlap window a CA rollover needs — the adapter builds its root store from *all
  live versions* of the CA secret during the grace window (the one genuinely new lifecycle
  behavior in (b)).
- **The adapter's cert**: `getTlsBundle` secret as in Phase 1; Phase 2 adds **proactive
  rotation**: a lifecycle task per TLS instance watches `clientCertNotAfter`, and at a
  configurable threshold (`security.client.renewBeforeDays`, default 30) either (i) fires a
  `certificate-expiring` Warning event (manual-provisioning deployments) or (ii) triggers EST
  re-enrollment (§4.3) when configured. After the secret rotates (centrally or via EST), the
  change listener rebuilds `ClientConfig` and schedules a graceful reconnect per instance —
  bounded, jittered, never all instances at once.

### 4.3 (c) EST enrollment/rotation of the originator cert

**Library vs new code — the spike's answer: thin owned client, ~400 LoC, over crates we already
trust.** RFC 7030's client surface is small: HTTPS + `GET /cacerts` (PKCS#7 cert-bag),
`POST /simpleenroll` / `/simplereenroll` (PKCS#10 CSR in base64-DER → PKCS#7 reply), optional
`/csrattrs`. The Rust ecosystem has exactly one EST crate (`est-ca`, v0.2 — young, CA/server-
oriented with a client bolted on); it is a useful *reference*, not a foundation the credentials
path should stand on. The owned client composes: `rcgen` (keypair + CSR), `reqwest`/`hyper` over
rustls (the Phase 1 TLS stack, with the bootstrap identity), RustCrypto `cms` + `x509-cert`
(PKCS#7 parse) — all maintained, no C. It lives in the **adapter** (`src/eip/est.rs`) — EST is
credential *provisioning*, not EtherNet/IP protocol, so it does not belong in `enip`; promotion
into the core credentials subsystem (a `gg.credentials()` EST source usable by every component)
is the natural follow-on and is flagged as a core-promotion candidate, not performed here (the
D-EIP-3 pattern).

Flow (per trust domain, one enrollment task):

```text
bootstrap identity (initial cert from config/vault — vendor, self-signed, or prior cert)
  → GET /cacerts            (pin/refresh the explicit trust anchors; compare against §4.2 store)
  → generate P-256 keypair + CSR (rcgen; key never leaves the process; zeroizing)
  → POST /simpleenroll      (mTLS with bootstrap identity; handle 202 retry-after polling)
  → verify returned cert chains to the trust anchors; vault.put() as a NEW VERSION of the
    client-cert secret (local-only secret; the vault's version grace covers in-flight sessions)
  → subsequent cycles: /simplereenroll with the CURRENT cert at renewBeforeDays (§4.2)
```

Config:

```jsonc
"security": { …,
  "est": { "server": "https://est.plant.example:8085/.well-known/est",
           "label": "eip",                       // optional EST label segment
           "bootstrap": { "certSecret": "ot-pki/bootstrap" },
           "renewBeforeDays": 30, "retryBackoffMins": 60 }
}
```

Failure posture: EST unreachable ⇒ keep using the current cert (offline-first, the vault rule),
`certificate-expiring`/`enrollment-failed` events + a `sync-staleness`-style metric; **never**
block polling on PKI availability; a cert that expires anyway produces the ordinary Phase 1
handshake failure with a cause the events have already been narrating for 30 days.

### 4.4 What Phase 2 explicitly does NOT do

No device-side security-object *writes* (no Begin_Config/Apply_Config commissioning of
targets — that is a config-tool role, out of adapter scope); no CRL/OCSP fetching (trust-store
rotation is the revocation story at this tier; noted as a future hardening); no PSK mode (spec
demotes it, rustls can't, and mutual X.509 is the design center); no pull-model *device profile*
(we are not a CIP Security target).

---

## 5. Validation plan & THE TARGET ANSWER

Per the org rule: phases are only *done* against a real peer, sims external, no
our-code-to-our-code conformance. This section is the spike's most important output.

### 5.1 The direct question: is there an OSS CIP-Security TLS target? — **No usable one exists today.**

**OpENer (EIPStackGroup/OpENer) — investigated file-by-file.** It has two long-lived branches,
`CIPSecurity` and `CIPSecurity_develop` (master/develop have zero CIP Security content). The
develop branch, last touched **December 2023** (stalled ~2.5 years), gated by CMake flag
`OPENER_CIP_SECURITY` + mbedTLS + the separate OpENer File Object project, contains:

- ✅ **The three security objects implemented as CIP objects**: `cipsecurity.c/h` (0x5D),
  `ethernetipsecurity.c/h` (0x5E, incl. the suite attributes with the Vol 8 defaults),
  `certificatemanagement.c/h` (0x5F), plus mbedTLS-derived cert/key/CSR utilities
  (`gen_key`, `cert_req`, `cert_write`) backing Create_CSR.
- ❌ **No TLS/DTLS transport.** The POSIX `networkhandler.c` on the branch is the plain
  TCP 44818 / UDP 2222 handler — no `mbedtls_ssl_*` calls, no port 2221, no secure-socket file
  anywhere in `ports/`. `ethernetipsecurity.c` carries TODOs and manages configuration state
  only. The encapsulation layer is never wrapped.
- Its 0x5E factory defaults allow only `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` /
  `…AES_256_CBC_SHA384` — even if its TLS existed, **rustls could not talk to its defaults**
  (§2.4).

**Verdict: OpENer's CIP Security branch is an object-model skeleton, not a TLS target. It
cannot be stood up as the TLS peer the way we stood up OpENer for class-1 I/O.** It *is*
valuable for Phase 2(a): built with `OPENER_CIP_SECURITY`, it serves real 0x5D/0x5E/0x5F
attribute reads on the wire.

**Everything else surveyed:** cpppo, libplctag `ab_server`, EthernetIPSharp, EIPScanner,
CIPster, pycomm3/pylogix — all plaintext-only; no CIP Security branches or issues. No OSS
EtherNet/IP-over-TLS test server, scanner, or shim exists anywhere we could find. Commercial
stacks (RTA, Pyramid, HMS) and the ODVA conformance tool are member/paid-only. Rockwell's
FactoryTalk Policy Manager is a free-with-account Windows config *tool*, not a target, and only
useful against real Rockwell hardware. **The org lab has no CIP-Security-capable PLC**
(`lab-5950x` is a Greengrass PC; the KEPServerEX VM does not terminate CIP Security).

### 5.2 The fallback that works — and the honest statement of what it proves

The saving structural fact (§2.2): EtherNet/IP-over-TLS is **byte-identical EtherNet/IP inside
a standard TLS tunnel on TCP 2221**. Therefore a *stock TLS terminator* in front of our
*existing, already-validated external targets* is a faithful Phase-1 peer at the exact layer
Phase 1 changes:

**Target A — `tls-proxy` (Phase 1 workhorse): stunnel (OpenSSL) fronting cpppo.**
A ~15-line `test-infra/tls-proxy/` container: stunnel in server mode on `:2221`, mutual TLS
required (`verify = 2`, our test CA), forwarding to `enip-sim:44818`. This validates, against an
**independent TLS implementation (OpenSSL)** carrying **independently-implemented EtherNet/IP
(cpppo)**: the TLS wrap of the full explicit surface (RegisterSession → reads/writes/errors →
UnRegisterSession), mutual X.509 (client-cert required and verified), vault-sourced material,
hostname/IP verification, suite negotiation — plus the negative matrix stunnel makes trivially
scriptable: wrong CA, expired cert, missing client cert and, decisively, a **CBC-only-suites
stunnel config** to prove the documented legacy failure mode fails *typed and loud*
(`NoCipherOverlap`, §3.1) rather than confusingly. Variants front `ab_server` (routed path over
TLS) for one smoke each. A `live_tls.rs` suite (self-skipping on a 2221 probe, the §11.3
pattern) covers all of it.

**Target B — OpENer `CIPSecurity_develop` build (Phase 2(a) peer):** the branch built with
`OPENER_CIP_SECURITY` + File Object + mbedTLS, fronted by the same stunnel. Serves genuine
0x5D/0x5E/0x5F Get_Attribute reads — the typed posture decoders (§4.1) get a real,
independent-implementation peer, over TLS. (Build-health risk priced in §6: the branch is
stalled and its CMake/File-Object integration may need patching in our Dockerfile — the
ab_server precedent, patches in the Dockerfile, never to `enip`.)

**Target C — EST server (Phase 2(c) peer): Cisco `libest`'s test server** in a container
(independent C implementation of RFC 7030), our test CA behind it; `testrfc7030.com` as an
optional external smoke. Validates /cacerts, /simpleenroll, /simplereenroll, 202-retry, and the
vault write-back path end to end.

**What this does NOT prove — stated plainly, per the fidelity contract:** none of A/B/C is a
*real CIP Security device*. Untouched by this plan: a certified Vol 8 TLS endpoint's actual
posture (port policy with 44818 closed, Vol-8-exact suite lists and renegotiation behavior,
`Send Certificate Chain`/`Verify Client Certificate` corner semantics), device-side EST
pull-model behavior, and CIP-Security push-model commissioning interplay. Closing that requires
a **lab CIP-Security PLC** (realistically: a CompactLogix 5380/ControlLogix 5580 v32+ or a
1756-EN4TR, commissioned with FactoryTalk Policy Manager — order-of-$2–8k hardware). Until one
is on the bench, real-device CIP Security conformance is a **declared lab-hardware validation
gap** — the same class, and the same §14.6/§12.4 bookkeeping, as backplane routing and
real-Logix browse today. This is an honest gap, not a blocker: Phase 1's changed layer *is*
fully exercised by Target A.

### 5.3 Recommended path & cost

**Recommend: build Target A with Phase 1 (~1–2 days, mostly compose/certs/suite scripting);
build Targets B+C with Phase 2 (~2–3 days combined incl. the OpENer-branch build fight); record
the lab-PLC row in §12.4/§14 as the declared gap; acquire the PLC only if/when CIP Security
becomes a shipping claim rather than a capability.** The E2E plan (§11.4) gains one step:
instance `filler-plc-tls` (poll, TLS via tls-proxy) publishing on the bus alongside the
plaintext instances, plus the failure drill (kill the proxy → BACKOFF + typed TLS error; wrong
cert → non-transient loud failure).

---

## 6. Effort, risk & go/no-go per phase

### 6.1 Effort (single senior implementer; days of focused work)

| Slice | Est. |
|---|---|
| **Phase 1** — enip `tls` feature (`connect_tls`, `TlsOptions`, `EnipError::Tls`, tests over duplex+rustls-acceptor) | 1.5–2 d |
| **Phase 1** — adapter: `connection.security` config+validation, vault sourcing, `ClientConfig` builder + custom verifier, `sb/status`/state/metrics/events surface, docs | 2–3 d |
| **Phase 1** — Target A (stunnel container, test CA/cert tooling, `live_tls.rs`, negative matrix, E2E step) | 1–2 d |
| **Phase 1 total** | **≈ 5–7 d** |
| **Phase 2(a)** — `cip/security.rs` typed decoders + fuzz target + `sb/status.target` + probe | 1.5–2 d |
| **Phase 2(b)** — CA-store lifecycle (multi-version root store), proactive-rotation task, reconnect choreography | 1.5–2 d |
| **Phase 2(c)** — owned EST client + vault write-back + enrollment task + config | 3–4 d |
| **Phase 2** — Targets B+C (OpENer-branch Dockerfile, libest container, live suites) | 2–3 d |
| **Phase 2 total** | **≈ 8–11 d** (variance dominated by the OpENer-branch build and EST edge cases) |

### 6.2 Risks

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| **Legacy CBC-only CIP Security devices can't handshake with rustls** (§2.4) | Medium in brownfield / High per-device | Typed `NoCipherOverlap` error with the exact remediation text; device-side Allowed-Suites reconfig is the spec-sanctioned fix; a non-default `tls-openssl` backend is the priced escape hatch (NOT built now; would need an explicit divergence decision) |
| **No real CIP Security device in validation** (§5.2) | Certain until a lab PLC exists / Medium | Declared gap in §14/§12.4 (established precedent); Target A fully covers the changed layer; PLC purchase is the closing move, listed as a go/no-go input below |
| OpENer CIPSecurity branch doesn't build cleanly (stalled Dec 2023, File-Object dependency) | Medium / Low (Phase 2(a) only) | Dockerfile-side patches (ab_server precedent); worst case 2(a) validates over plaintext 44818 against the branch (the object bytes are transport-independent) |
| EST ecosystem immaturity in Rust (one v0.2 crate) | Certain / Medium | Own thin client over rcgen+cms+x509-cert (§4.3); libest independent-implementation peer; EST is cleanly deferrable (2(c) is severable) |
| Cert-provisioning UX (bootstrap identity chicken-and-egg, plant-PKI variance) | Medium / Medium | Phase 1 works with hand-provisioned vault bundles (no EST needed); events narrate expiry 30 d out; docs get a dedicated provisioning how-to |
| rustls API churn (provider model) | Low / Low | Pin like every other dep; the surface used is stable core API |

### 6.3 Go/no-go recommendation

- **Phase 1 — GO.** The seam is confirmed ideal (a `TlsStream` drops into `connect_over`
  untouched), the spec's current cipher reality (GCM mandatory since Vol 8 1.13) makes
  pure-rustls interoperable with spec-current devices, the vault provides the material story
  wholesale, effort is ~a week, and Target A gives real independent-implementation validation
  of exactly the changed layer. The one honest asterisk — no certified device in the loop — is
  a declared, precedented gap, not a reason to hold the capability.
- **Phase 2 — SPLIT GO.** **GO on 2(a) posture reads and 2(b) lifecycle/rotation** (cheap,
  validatable, and they make Phase 1 operable). **CONDITIONAL GO on 2(c) EST**: build it behind
  config (off by default) with libest-container validation *if* the EST capability is wanted
  this cycle; otherwise defer 2(c) intact — it is severable, and nothing in 1/2(a)/2(b) depends
  on it. The condition to state to the user: 2(c) ships validated against an OSS EST server
  only; real plant-PKI enrollment joins the lab-hardware gap list.
- **DTLS / push — NO (unchanged).** Documented future (§3.6); revisit only with a lab PLC and
  an explicit C-dependency decision.
- **Lab-PLC purchase** — the single go/no-go input that upgrades every gap above from
  "sim-grade" to "device-proven"; recommended when CIP Security graduates from capability to
  claim.

---

## 7. Docs impact

**Internal (this repo — where roadmap/status language belongs):**

- `PROTOCOL-DESIGN.md`: §1 non-goals — replace "CIP Security/TLS (EtherNet/IP here is
  plaintext)" with: TLS on the explicit path is in scope behind the `tls` feature (new
  **D-ENIP-15**, the dependency decision §3.2); DTLS/implicit remains a non-goal with the §3.6
  future note. New §5.7 "TLS transport" (the `connect_tls` contract, port 2221, error taxonomy);
  §12 gains the rustls-acceptor fixture note and (Phase 2) the `fuzz_security_attrs` row.
- `DESIGN.md`: **replace §14.5 wholesale** (stale-content rule — do not leave "No CIP
  Security / TLS" beside the new truth) with the phased statement: explicit-path TLS supported
  (Phase 1 scope), push+TLS refused at validation, DTLS unsupported; new decisions
  **D-EIP-21** (TLS explicit / config surface / vault sourcing), **D-EIP-22** (security-object
  read surface), **D-EIP-23** (EST, if 2(c) goes); §4.2 `connection.security` table; §7.1
  `sb/status.security`; §8.2 the handshake-failure measures; §11 gains the `tls-proxy` (+
  OpENer-CIPSecurity, libest) target rows and `live_tls.rs`; §12.4/§14.6 gain the declared
  **lab CIP-Security-PLC gap** row.
- This file graduates into the repo (e.g. `DESIGN-cip-security.md` beside the other two) as the
  decision record for the phase gates.

**User-facing (`docs/`, present tense, zero roadmap language — write only what has SHIPPED at
each phase, stated as plain current fact):**

- After Phase 1: "The adapter connects to CIP-Security-capable devices over TLS (EtherNet/IP
  over TLS, TCP port 2221) with mutual X.509 authentication. Certificates and trusted CAs come
  from the EdgeCommons credentials vault or from files; `{"$secret": …}` references are
  supported. TLS applies to poll instances; class-1 implicit I/O (`mode: "push"`) uses plaintext
  UDP 2222, and a push instance configured with TLS is rejected at startup. Devices that offer
  only CBC-based cipher suites are not supported; enable GCM-based suites on the device."
  Plus the `security` block in `docs/reference/configuration.md`, the `security` object in
  `docs/reference/messaging-interface.md` (`sb/status`), the new measures in
  `docs/reference/metrics.md`, and a how-to: "Connect to a CIP Security device" (cert
  provisioning walk-through).
- After Phase 2: the posture fields, rotation behavior, and (if 2(c) ships) an EST enrollment
  how-to — same present-tense discipline.

---

*Spike sources beyond the repo: ODVA "A Practical Guide for CIP Security Device Developers"
(2017 conference paper; cipher table §2.4, port-2221 usage, commissioning model); ODVA PUB00317
R22 mandatory-change list (Dec 2025; Vol 8 1.13/1.15/1.16/1.17/1.18 entries quoted in §2.4/§2.3,
CT23 in §1); ODVA PUB00319 At-a-Glance; EIPStackGroup/OpENer branches `CIPSecurity{,_develop}`
(object sources, README, POSIX network handler, commit log — §5.2); rustls/tokio-rustls
capability set (§2.4); RFC 7030; Cisco libest; crates.io `est-ca` v0.2 (§4.3).*
