# Reference — Configuration

Every configuration option the adapter understands. For *why* these exist see
[explanation.md](../explanation.md); for tasks see the [how-to guides](../how-to-guides.md); for the
type system see [data-types.md](data-types.md). This page matches `config.schema.json`.

## Config source

The adapter reads one JSON document from `-c/--config`, defaulting by platform: `HOST` → `FILE`,
`GREENGRASS` → `GG_CONFIG`, `KUBERNETES` → `CONFIGMAP`. Adapter settings live under `component`; the
sibling sections (`tags`, `hierarchy`, `identity`, `topic`, `messaging`, `logging`, `metricEmission`,
`heartbeat`) are standard edgecommons sections owned by the library and are not redeclared here.

The adapter's own configuration is the object at **`component.global`** plus each entry of
**`component.instances[]`**. `component.token` sets the `{component}` UNS token (`ethernet-ip-adapter`).

UNS topics are `ecv1/{device}/{component}/{instance}/{class}[/channel]` — built and validated by the
library from the identity; there are no per-instance/per-signal topic templates.

## Top-level sections

| Section | Required | Purpose |
|---------|----------|---------|
| `component` | yes | Adapter global config + device instances (this document). |
| `tags` | recommended | Business metadata attached to every message's `tags`. |
| `hierarchy` | optional | UNS enterprise-hierarchy level names; last level is the device (thing). Absent ⇒ `["device"]`. |
| `identity` | optional | Values for every hierarchy level except the last (the resolved thing name). |
| `topic` | optional | `includeRoot` — insert the site level after `ecv1` on a multi-site broker. |
| `messaging` | HOST/KUBERNETES | MQTT broker connection (or `--transport MQTT <file>`). |
| `metricEmission` | optional | Routes `southbound_health` plus the `EtherNetIp*` metric families to `log`/`messaging`/`cloudwatch`/`prometheus`. `messaging` auto-routes to the UNS `metric` class. |
| `logging`, `heartbeat` | optional | Standard edgecommons sections. |

## `component.global`

The global object the adapter validates. Every field is optional; the built-in defaults apply when a
field is absent.

### `global.defaults`

Defaults applied to every device/group that does not override them. Precedence for a resolved value is
**signal ▸ group ▸ device.defaults ▸ global.defaults ▸ built-in**.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `pollIntervalMs` | integer ≥ 1 | `5000` | Poll cadence for any group that does not override it. |
| `publishMode` | `onChange` \| `always` | `onChange` | `onChange` publishes only samples that pass the deadband/change gate; `always` publishes every polled sample. |
| `batchMs` | integer ≥ 0 | `0` | Coalescing window: samples for one signal within the window ride one `SouthboundSignalUpdate.samples[]`. `0` = publish per poll cycle. |

### `global.timeouts`

Connection lifecycle timings.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `connectMs` | integer ≥ 1 | `5000` | Connect deadline (incl. host lookup + RegisterSession). |
| `requestTimeoutMs` | integer ≥ 1 | `2000` | Per-CIP-request deadline (read/write/browse). |
| `reconnectBackoffMinMs` | integer ≥ 1 | `1000` | The first reconnect window. Each attempt doubles it, up to the max. |
| `reconnectBackoffMaxMs` | integer ≥ 1 | `60000` | The reconnect ceiling. Backoff is jittered within the window so many adapters do not reconnect in lockstep. |

### `global.healthThresholds`

Thresholds feeding the `southbound_health` metric.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `staleSignalSecs` | integer ≥ 1 | `60` | A signal with no successful (GOOD) read for longer than this counts as stale. Suspended while an instance is paused. |
| `keepaliveProbeIntervalMs` | integer ≥ 1 | `60000` | Paused-state liveness-probe cadence: while paused, the adapter keeps `connected` truthful with a slow real CIP round-trip on this interval. |

### `global.metricsIntervalSecs`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `metricsIntervalSecs` | integer ≥ 1 | `60` | Operational-metrics emit cadence, seconds. Interval counters reset on each emit; totals never reset. |

## `component.instances[]` — one device

One entry == one PLC / CIP endpoint, with its own task and connection lifecycle. **Mode is exclusive:** a
`push` device requires `io` and must not declare `pollGroups`; any other device (poll — the default when
`mode` is absent) requires `pollGroups` and must not declare `io`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `id` | string (lower-kebab) | **required** | Unique device id. The `{instance}` token of this device's UNS topics and the `instance` metric dimension; must be a stable, valid UNS token. |
| `connection` | object | **required** | How to reach the device (below). |
| `adapter` | string | `ethernet-ip` | Protocol backend: `ethernet-ip` (CIP) or `sim` (in-process simulator). Published in `device.adapter`. |
| `mode` | `poll` \| `push` | `poll` | `poll` reads CIP tags on a schedule (requires `pollGroups`, forbids `io`); `push` consumes a class-1 implicit-I/O assembly (requires `io`, forbids `pollGroups`). |
| `defaults` | object | — | Per-device overrides of `global.defaults` (`pollIntervalMs`, `publishMode`, `batchMs`). |
| `pollGroups` | array | poll only | The device's poll groups; each read on its own cadence (below). |
| `io` | object | push only | The class-1 implicit-I/O connection + assembly layout (below). |
| `writes` | object | — | The write allow-list (below). |

### `connection`

How to reach the device. This object is deliberately **open** (`additionalProperties: true`) — different
targets need different keys; everything else in the schema is strict.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `endpoint` | string | **required** | `<host>` or `<host>:<port>` (default CIP port `44818`, or `2221` when `security.mode` is `tls`). Published in `device.endpoint`. |
| `slot` | integer 0–255 | — | ControlLogix CPU slot ⇒ backplane connection path (`1,<slot>`). Absent ⇒ no routing path (correct for cpppo / CompactLogix-direct). |
| `connected` | boolean | `false` | `true` ⇒ CIP connected messaging (ForwardOpen); `false` ⇒ unconnected explicit messaging. |
| `security` | object | — | TLS (CIP Security) on the explicit-messaging path (below). Absent ⇒ plaintext. |

#### `connection.security` (CIP Security / TLS)

Runs a poll instance's explicit-messaging session over **TLS** (EtherNet/IP over TLS, TCP port `2221`)
with mutual X.509 authentication. TLS applies to poll instances only; a push (`mode: push`) instance
configured with `security.mode: tls` is rejected at startup.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `mode` | `plaintext` \| `tls` | `plaintext` | `tls` wraps the session in mutual TLS on TCP `2221` (the default port when the endpoint has no explicit port). |
| `client` | object | — | The adapter's client identity for mutual TLS. Sourced by exactly one style (below). |
| `ca` | object | — | Trust anchors for verifying the device certificate. Sourced by exactly one style (below). |
| `verifyPeer` | boolean | `true` | `true` verifies the device certificate against the trust anchors; `false` accepts any device certificate (a commissioning/debug posture that raises a `tls-peer-unverified` event). |
| `serverName` | string | endpoint host | The verification / SNI name. An IP literal is verified against the device certificate's IP SAN. |
| `checkExpiration` | boolean | `true` | `false` tolerates an expired / not-yet-valid device certificate (for devices without a real-time clock). With `true`, an already-expired **client** certificate is refused at connect rather than attempted. |
| `cipherSuites` | string[] | GCM + TLS 1.3 | An optional cipher-suite allow-list (IANA / rustls names). Only GCM-based and TLS 1.3 suites are supported. |
| `client.renewBeforeDays` | integer | `30` | Fire a `cert-expiring` event this many days before the client certificate's `notAfter`. |
| `reloadIntervalSecs` | integer | `300` | How often (seconds) to re-read the vault for a rotated client certificate / trust store. A detected change reconnects so the new material takes effect without a restart. `0` disables the re-read (material is then reloaded only on a natural reconnect). |

Each credential — the client certificate, the client key, and the CA — is sourced by exactly **one**
style; mixing styles on one credential is a startup error.

| Credential | Vault ref (typed) | File path | Inline `$secret` content |
|------------|-------------------|-----------|--------------------------|
| Client identity | `client.certSecret` — a `{certPem, keyPem[, caPem]}` vault bundle (cert + key together) | `client.certFile` + `client.keyFile` | `client.cert` + `client.key`, each `{"$secret": "<name>"}` |
| CA trust anchors | `ca.secret` — a vault PEM secret | `ca.file` | `ca.cert` — `{"$secret": "<name>"}` |

The CA trust anchors form a **managed trust store** — a set of trusted roots, not just one. Two more
`ca` styles build the set:

| `ca` style | What it is |
|------------|------------|
| `ca.trustStore` | A vault secret holding a bundle of trusted CAs. The trust store is built from **all retained versions** of the secret, so during a CA rollover the old and new roots are trusted at the same time. |
| `ca.list` | An explicit array of `{"$secret": "<name>"}` refs, each a CA PEM, assembled into one trust store. |

An inline reference is `{"$secret": "<vault-name>"}` (the ecosystem-wide `$secret` convention): the
PEM content is resolved from the credentials vault at connect time and never lands in the logged
config. Add `"field": "<key>"` to read one JSON field of the secret (for example, a
`{certPem, keyPem}` bundle referenced field-by-field). Example:

```json
"security": {
  "mode": "tls",
  "client": {
    "cert": { "$secret": "tls/cip-client-cert" },
    "key":  { "$secret": "tls/cip-client-key" }
  },
  "ca": { "cert": { "$secret": "tls/plant-root" } }
}
```

`mode: tls` requires a client identity (any one style); with `verifyPeer: true` it also requires trust
anchors (any one `ca` style, or a `certSecret` bundle that carries `caPem`). Devices that offer only
CBC-based cipher suites are not supported — enable GCM-based suites on the device. See the how-to guide
"Connect to a CIP Security device."

##### `connection.security.est` (automatic enrollment / renewal)

The adapter obtains and renews its own client certificate automatically from an EST server
(Enrollment over Secure Transport, RFC 7030). The enrolled key and certificate are written into the
credentials vault, where the reload watcher (`reloadIntervalSecs`) picks them up and reconnects — so a
certificate lifecycle runs without operator intervention or a restart. EST is off unless
`est.enabled` is set.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `enabled` | boolean | `false` | Enable automatic EST enrollment/renewal for this instance. |
| `server` | string | — | The EST server base URL, e.g. `https://est.plant.example:8443/.well-known/est`. Must be `https://`. Required when `enabled`. |
| `label` | string | — | An optional EST label path segment, inserted before the operation (`.../est/<label>/simpleenroll`). |
| `trust` | object | connection `ca` | Trust anchors for verifying the EST server's TLS certificate (a `ca`-style block: `secret` / `file` / `cert` / `trustStore` / `list`). Defaults to the connection's `ca` trust store. |
| `auth` | object | reuse client cert | How the adapter authenticates to the EST server. `auth.bootstrap` — a client identity (`certSecret` / `certFile`+`keyFile` / `cert`+`key`) used for the initial enrollment; `auth.basic` — `{"$secret": "<name>"}` for a vault `{username, password}` secret sent as HTTP Basic. With neither, the current client certificate is reused (a mutual-TLS renewal). |
| `into` | object | derived from `client` | Where the enrolled material is written: `into.certSecret` (a `{certPem, keyPem}` bundle secret) or `into.cert` + `into.key` (a secret pair). Defaults to the `security.client` secret(s), so the reload watcher reloads it. |
| `subject` | string | `eip-originator` | The CSR subject CommonName. |
| `renewBeforeDays` | integer | `client.renewBeforeDays` or `30` | Renew the certificate this many days before its `notAfter`. |
| `retryBackoffMins` | integer | `60` | Minimum minutes between failed enrollment attempts. |
| `fetchCaCerts` | boolean | `false` | Fetch the EST server's CA bag (`GET /cacerts`) before enrolling, to confirm trust. |

The adapter enrolls (`simpleenroll`) when it has no usable certificate, and renews (`simplereenroll`)
within `renewBeforeDays` of expiry. An unreachable EST server never blocks polling — the current
certificate is kept and the attempt is retried. Enrollment outcomes are reported as `cert-enrolled` /
`cert-enroll-failed` events, the `estEnrollments` / `estFailures` metrics, and the `security.est`
object in `sb/status`.

### `pollGroups[]` (poll mode)

A set of signals read together on one cadence.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `id` | string | `group-<n>` | The `pollGroup` metric dimension. Defaults to `group-<n>` (1-based) when absent. |
| `pollIntervalMs` | integer ≥ 1 | device ▸ global ▸ `5000` | This group's poll cadence. |
| `publishMode` | `onChange` \| `always` | device ▸ global ▸ `onChange` | This group's publish gate. |
| `signals` | array (≥ 1) | **required** | The group's signals (below). |

### Signal (entries of `pollGroups[].signals`)

One CIP tag mapped to a data point.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `name` | string (lower-kebab) | **required** | Human label AND the `data` topic channel. Unique per device. |
| `tagPath` | string | **required** | The CIP tag path, verbatim/case-sensitive (`LINE_SPEED`, `Program:Main.FillPV`). It IS the stable `signal.id`. Unique per device. |
| `type` | enum | **required** | The CIP elementary type used to decode the tag (see [data-types](data-types.md)). |
| `arrayCount` | integer ≥ 1 | — | Present ⇒ a 1-D array read of that many elements; the value is a JSON array. |
| `scale` | number | — | Published value = `raw × scale + offset` (element-wise for arrays; numeric types only, not `bool`). |
| `offset` | number | — | See `scale`. |
| `deadband` | object | `{type:"none"}` | The change/deadband gate for `onChange` publishing (numeric types only; below). |

### `io` (push mode)

The class-1 implicit-I/O connection + assembly layout. The device produces its T→O assembly at the RPI;
the adapter consumes it and maps the configured byte-offset fields to signals. Field bounds are
validated against the assembly size at startup.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `rpiMs` | integer ≥ 1 | **required** | Requested T→O RPI (the device's produce cadence toward the adapter), ms. The negotiated API from the ForwardOpen reply is what actually runs. |
| `o2tRpiMs` | integer ≥ 1 | `rpiMs` | Requested O→T RPI (the adapter's produce cadence toward the device), ms. |
| `connectionType` | `p2p` \| `multicast` | `p2p` | T→O connection type. `multicast` consume joins the group from the ForwardOpen reply's sockaddr item; O→T is always point-to-point. |
| `priority` | `low` \| `high` \| `scheduled` \| `urgent` | `scheduled` | CIP connection priority, both directions. |
| `timeoutMultiplier` | 4 \| 8 \| 16 \| 32 \| 64 \| 128 \| 256 \| 512 | `16` | Inactivity watchdog = multiplier × T→O API. |
| `assemblies` | object | **required** | The assembly instance ids (below). |
| `input` | object | **required** | The T→O (input) direction — the device's data to the adapter (below). |
| `output` | object | — | The O→T (output) direction — the adapter's data to the device (below). Absent ⇒ a heartbeat O→T connection. |

#### `io.assemblies`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `input` | integer 0–65535 | **required** | T→O assembly instance (the device's inputs; the T→O connection point). Also the `a<inst>/…` prefix of input-field ids. |
| `output` | integer 0–65535 | **required** | O→T assembly instance (the adapter's outputs; the O→T connection point). Also the `a<inst>/…` prefix of output-field ids. |
| `config` | integer 0–65535 | — | Config assembly instance (connection path only; no data plane). Most targets require it. |

#### `io.input`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `sizeBytes` | integer ≥ 1 | **required** | Negotiated T→O data size in bytes (excl. sequence/header). A received frame that mismatches is dropped and counted, never partially decoded. |
| `realTimeFormat` | `modeless` \| `header32` | `modeless` | T→O framing. Conventional targets produce `modeless`; `header32` carries a run/idle header. |
| `sampleMs` | integer ≥ 0 | `0` | Publish-eligibility floor per field, ms: at most one sample per field per window (`0` = every accepted frame eligible). Deadband/publishMode apply after it. |
| `signals` | array (≥ 1) | **required** | The input-assembly field layout (see the field table below). |

#### `io.output`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `sizeBytes` | integer ≥ 0 | `0` | O→T data size in bytes. `0` ⇒ a heartbeat connection (no output data; `signals` must be absent). |
| `realTimeFormat` | `header32` \| `heartbeat` \| `modeless` | `header32` | O→T framing; `header32` carries the run/idle bit. |
| `run` | boolean | `true` | Initial run/idle state produced in the 32-bit header. |
| `signals` | array | — | Output-assembly fields (writable via `sb/write` when allow-listed). Same field shape as input signals, minus `deadband`. |

### Assembly-layout field (entries of `io.input.signals` / `io.output.signals`)

One byte-offset field within a push assembly (the push analog of a poll signal). The stable `signal.id`
is `a<assemblyInstance>/<offset>/<type>[.<bit>]`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `name` | string (lower-kebab) | **required** | Human label AND the `data` topic channel. Unique per device. |
| `offset` | integer ≥ 0 | **required** | Byte offset within the assembly data. Fields may overlap; every field must fit inside `sizeBytes`. |
| `type` | enum | **required** | The CIP elementary type used to decode/encode the field (see [data-types](data-types.md)). |
| `bit` | integer 0–7 | — | Bit extraction within the byte at `offset`. `bool` only, single element (no `arrayCount`). |
| `arrayCount` | integer ≥ 1 | — | Present ⇒ a contiguous array of that many elements; the value is a JSON array. |
| `scale` | number | — | Published value = `raw × scale + valueOffset` (element-wise for arrays; numeric types only, not `bool`). |
| `valueOffset` | number | — | The additive term of the value transform (named to avoid colliding with the byte `offset`). |
| `deadband` | object | `{type:"none"}` | Input-side fields only (numeric types); the change gate for `onChange` publishing. |

### `writes`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `allow` | array of string | `[]` | Stable `signal.id`s this device may write — a CIP tag path (poll) or an `a<assemblyInstance>/<offset>/<type>` output-field id (push). Anything not listed is refused. An empty list — the default — means the device is read-only. |

### `deadband` object

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `type` | `none` \| `absolute` \| `percent` | `none` | `none` republishes on any change; `absolute` requires `|new−old| ≥ value`; `percent` is relative to the previous value. Arrays: exceeded if ANY element exceeds. |
| `value` | number ≥ 0 | `0` | The threshold. |

## Identity & the UNS device tree

`hierarchy.levels` names the enterprise tree, deepest (the device) last; `identity` supplies every
level's value **except** the last (always the resolved thing name). The values become the envelope
`identity.hier`/`path`. With the default (`["device"]`) topics are
`ecv1/{thing}/ethernet-ip-adapter/{instance}/...`; `topic.includeRoot: true` prepends the first level
after `ecv1` on a multi-site broker.

```jsonc
"hierarchy": { "levels": ["site", "device"] },
"identity":  { "site": "factory-1" }
// -> identity.path = "factory-1/<thing>", topics device token = <thing>
```

## Precedence

`pollIntervalMs` / `publishMode` / `batchMs` resolve: **signal/group value ▸ device `defaults` ▸
`global.defaults` ▸ built-in**.

## Limitations

- **Value types** — CIP elementary scalars and 1-D arrays thereof (see [data-types](data-types.md)).
  Structures/UDTs, Logix `STRING`, and multi-dimensional arrays are rejected at config-parse time.
- **One mode per instance** — a device needing both poll and push telemetry is two instances.
- **TLS (CIP Security)** — poll (explicit-messaging) instances can run over TLS with mutual X.509
  (`connection.security`, above). Only GCM-based and TLS 1.3 cipher suites are supported; devices that
  offer only CBC-based suites are not. Class-1 implicit I/O (`mode: push`) runs over plaintext UDP
  `2222` — a push instance configured with TLS is rejected at startup.
- **Managed trust store and certificate rotation** — the CA trust anchors are a set of roots
  (`ca.trustStore` / `ca.list`), and a CA rollover's old and new roots are trusted together while both
  are live. The adapter re-reads the vault on the `reloadIntervalSecs` cadence and, when the client
  certificate or trust store rotates (for example via `ec-secrets`), reconnects so the new material
  takes effect without a restart. It monitors the client certificate's expiry: a `cert-expiring` event
  fires within `client.renewBeforeDays` of `notAfter`, a `cert-expired` event fires when it lapses, and
  an already-expired client certificate is refused at connect. Direct EST enrollment of the adapter's
  own certificate is not part of this adapter; provision the client certificate through the vault.
- **Security posture reporting** — on connect the adapter reads the target's CIP Security objects and
  reports the device's posture (state, security profiles, allowed/available cipher suites, client-cert
  and expiration policy, and a certificate summary) on `sb/status` under `security.target`, with
  `security.targetSupportsCipSecurity` indicating whether the device implements them. This is automatic
  and needs no configuration; a device without CIP Security simply reports
  `targetSupportsCipSecurity: false`. See the [messaging interface](messaging-interface.md) reference.
