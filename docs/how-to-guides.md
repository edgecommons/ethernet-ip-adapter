# How-to Guides

Recipes for specific tasks. Each assumes the adapter builds and runs (see the [tutorial](tutorial.md)).
For concepts see [explanation.md](explanation.md); for exhaustive options see [reference/](reference/).

---

## Configure a poll device (CIP tags + poll groups + deadband)

A poll device reads CIP tags on a schedule. EtherNet/IP tags are not wire-discoverable in general, so
you declare every signal. Group signals that share a cadence into a `pollGroup`; give the device an
allow-list only if it needs to be writable.

```jsonc
{
  "id": "filler-plc",
  "adapter": "ethernet-ip",
  "connection": { "endpoint": "10.0.0.50:44818" },
  "pollGroups": [
    { "id": "fast", "pollIntervalMs": 500, "signals": [
      { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real",
        "deadband": { "type": "absolute", "value": 0.5 } },
      { "name": "tank-level", "tagPath": "TANK_LEVEL", "type": "real", "scale": 0.1 }
    ] },
    { "id": "slow", "pollIntervalMs": 2000, "publishMode": "always", "signals": [
      { "name": "product-count", "tagPath": "PRODUCT_COUNT", "type": "dint" },
      { "name": "zone-temps",    "tagPath": "ZONE_TEMPS",    "type": "real", "arrayCount": 8 }
    ] }
  ]
}
```

- `tagPath` is the CIP tag path **verbatim and case-sensitive** (`LINE_SPEED`, `Program:Main.FillPV`) —
  it is the stable `signal.id`.
- `type` is the CIP elementary type used to decode the tag (see
  [data-types](reference/data-types.md)); `arrayCount` reads a 1-D array of that many elements.
- `scale`/`offset` apply engineering units (`value = raw × scale + offset`); `deadband` gates
  `onChange` publishing.
- For a ControlLogix chassis, set `connection.slot` to the CPU slot so the adapter routes across the
  backplane; omit it for CompactLogix-direct or cpppo.

Tune data freshness vs bus volume:

| You want… | Set |
|-----------|-----|
| Faster/slower polling | `pollGroups[].pollIntervalMs` |
| Publish only on real change | `publishMode: "onChange"` (default) + a `deadband` per signal |
| Publish every poll | `publishMode: "always"` |
| Drop sensor jitter | `deadband: { "type": "absolute", "value": 0.5 }` (or `percent`) |
| Fewer, larger messages | `defaults.batchMs > 0` (coalesce a signal's samples per window) |
| Lower per-signal request cost | fewer, larger poll groups at longer intervals |

---

## Configure a push device (class-1 I/O + assembly layout)

A push device consumes a class-1 implicit-I/O assembly. Set `mode: "push"`, declare the `io` block, and
**do not** declare `pollGroups`. You must know the device's assembly instance ids, sizes, and byte
layout — there is no discovery.

```jsonc
{
  "id": "palletizer-io",
  "adapter": "ethernet-ip",
  "mode": "push",
  "connection": { "endpoint": "10.0.0.60:44818" },
  "io": {
    "rpiMs": 100,
    "connectionType": "p2p",
    "priority": "scheduled",
    "timeoutMultiplier": 16,
    "assemblies": { "config": 151, "output": 150, "input": 100 },
    "input": {
      "sizeBytes": 32,
      "realTimeFormat": "modeless",
      "sampleMs": 500,
      "signals": [
        { "name": "din-word",   "offset": 0,  "type": "udint" },
        { "name": "motor-run",  "offset": 0,  "type": "bool", "bit": 0 },
        { "name": "line-speed", "offset": 4,  "type": "real",
          "deadband": { "type": "absolute", "value": 0.5 } },
        { "name": "zone-temps", "offset": 16, "type": "real", "arrayCount": 4 }
      ]
    },
    "output": {
      "sizeBytes": 32,
      "realTimeFormat": "header32",
      "run": true,
      "signals": [
        { "name": "dout-word",     "offset": 0, "type": "udint" },
        { "name": "fill-setpoint", "offset": 4, "type": "real" }
      ]
    }
  },
  "writes": { "allow": ["a150/4/real"] }
}
```

- `assemblies.input`/`output` are the T→O / O→T connection points; `config` is included in the
  connection path (most targets require it).
- `rpiMs` is the requested produce cadence; the negotiated API from the ForwardOpen reply is what
  actually runs. `o2tRpiMs` defaults to `rpiMs`.
- Each `input.signals` field is a byte `offset` + `type` (+ `bit` for a single boolean, `arrayCount` for
  an array). Fields may overlap (a status word and its bits share `offset`), and every field must fit
  inside `sizeBytes`, which is checked at startup.
- `sampleMs` is a per-field publish floor for fast RPIs — at most one sample per field per window before
  deadband/publish-mode apply. `0` makes every accepted frame eligible.
- An absent `output` block (or `output.sizeBytes: 0`) makes a heartbeat O→T connection with no output
  data.

---

## Allow-list a writable signal and write it

Writes are refused unless the signal's stable `signal.id` is in the device's `writes.allow` list, which
is **empty by default** (read-only). Add the ids you want writable:

```jsonc
// poll device — allow-list CIP tag paths
"writes": { "allow": ["FILL_SETPOINT", "MOTOR_RUN"] }

// push device — allow-list OUTPUT field ids (a<outputAssembly>/<offset>/<type>)
"writes": { "allow": ["a150/4/real"] }
```

Then write through the command inbox (`ecv1/{device}/ethernet-ip-adapter/cmd/sb/write`):

```
publish   ecv1/<device>/ethernet-ip-adapter/cmd/sb/write
          { "header": { "name": "sb/write", "reply_to": "app/r", "correlation_id": "7" },
            "body": { "instance": "filler-plc", "writes": [ { "name": "fill-setpoint", "value": 42.5 } ] } }
subscribe app/r   → { "ok": true, "result": { "id": "filler-plc", "written": 1, "results": [ … ] } }
```

- Address a signal by `name` (a configured signal) or explicitly by ref — poll:
  `{ "tagPath", "type", "arrayCount"? }`; push: `{ "assembly", "offset", "type", "bit"? }`. Only push
  **output** fields are writable; an input-field ref is reported `ok:false` (`input field`).
- A poll write is CIP-acked (`ok:true` = the device accepted it). A push write returns
  `applied: "next-frame"` — it rides the next cyclic O→T frame (implicit I/O has no per-write ack).
- If *every* entry is refused by the allow-list, the whole command returns a `WRITE_NOT_ALLOWED` error;
  a mix reports refusals per-entry. Every entry emits a `write-audit` event.

---

## Pause and resume an instance

Take a device out of active polling/publishing during maintenance without dropping its connection:

```
publish   ecv1/<device>/ethernet-ip-adapter/cmd/sb/pause
          { "header": { "name": "sb/pause", ... }, "body": { "instance": "filler-plc" } }
   → { "ok": true, "result": { "id": "filler-plc", "paused": true, "changed": true } }

publish   ecv1/<device>/ethernet-ip-adapter/cmd/sb/resume
          { "header": { "name": "sb/resume", ... }, "body": { "instance": "filler-plc" } }
   → { "ok": true, "result": { "id": "filler-plc", "paused": false, "changed": false } }   // was already resumed
```

While paused, the instance reports `state: "PAUSED"` (with `connected` still truthful), stale-signal
health is suspended, a slow liveness probe keeps `connected` honest, and `repoll` is refused. Both verbs
are idempotent — `changed` tells you whether the call moved the state. Pause is in-memory and resets to
running on restart.

---

## Browse a device's tags

`sb/browse` lists what a device exposes. On a **poll** instance it calls the CIP tag-list service and
returns a page of tags, each flagged `configured` (is it in your config) and `supported` (is its CIP
type decodable):

```
publish   ecv1/<device>/ethernet-ip-adapter/cmd/sb/browse
          { "header": { "name": "sb/browse", ... }, "body": { "instance": "filler-plc", "max": 200 } }
   → { "ok": true, "result": { "id": "filler-plc", "tags": [
         { "name": "LINE_SPEED", "type": "REAL", "configured": true,  "supported": true },
         { "name": "RECIPE",     "type": "SSTRING", "configured": false, "supported": false } ],
       "cursor": "…" } }
```

Pass the returned `cursor` back to page. The tag-list service is a Logix-family capability; a generic CIP
device (e.g. a plain I/O adapter) answers `BROWSE_UNSUPPORTED`. On a **push** instance `sb/browse`
returns the configured assembly layout (input + output fields) with no device round-trip.

---

## Bridge several devices from one adapter

Add an entry per device under `component.instances[]` — each gets its own task, connection, and mode, so
one device being down doesn't disturb the others:

```jsonc
"instances": [
  { "id": "filler-plc",   "adapter": "ethernet-ip", "connection": { "endpoint": "10.0.0.50:44818" }, "pollGroups": [ ... ] },
  { "id": "palletizer-io","adapter": "ethernet-ip", "mode": "push", "connection": { "endpoint": "10.0.0.60:44818" }, "io": { ... } }
]
```

With more than one device, commands must carry `instance` in the body; with exactly one it may be
omitted.

---

## Connect to a CIP Security device

Run a poll instance's explicit-messaging session over TLS (EtherNet/IP over TLS, TCP port `2221`) with
mutual X.509 authentication. Add a `security` block to the device's `connection`.

**With certificates from the credentials vault** (a `credentials` section is configured, so
`gg.credentials()` is available):

```jsonc
{
  "id": "filler-plc",
  "adapter": "ethernet-ip",
  "connection": {
    "endpoint": "10.0.0.60",              // no port ⇒ the TLS default 2221
    "security": {
      "mode": "tls",
      "client": { "certSecret": "ot-pki/eip-originator" },  // a {certPem,keyPem[,caPem]} vault bundle
      "ca":     { "secret":     "ot-pki/plant-root" },       // CA PEM (one or more roots)
      "verifyPeer": true
    }
  },
  "pollGroups": [ /* … */ ]
}
```

**With certificates from files** (no vault):

```jsonc
"security": {
  "mode": "tls",
  "client": { "certFile": "/etc/eip/originator.pem", "keyFile": "/etc/eip/originator.key" },
  "ca":     { "file":     "/etc/eip/plant-root.pem" }
}
```

**With inline `$secret` references** (the ecosystem `$secret` convention — each PEM resolved from the
vault at connect time, and never written into the logged config):

```jsonc
"security": {
  "mode": "tls",
  "client": {
    "cert": { "$secret": "tls/cip-client-cert" },
    "key":  { "$secret": "tls/cip-client-key" }
  },
  "ca": { "cert": { "$secret": "tls/plant-root" } }
}
```

Notes:

- Each credential (client cert/key, CA) is sourced by exactly **one** style — a typed vault ref
  (`certSecret`/`ca.secret`), files (`certFile`/`keyFile`/`ca.file`), or an inline `{"$secret": …}`
  (`client.cert`+`client.key`/`ca.cert`). Mixing styles on one credential is a startup error.
- `mode: tls` requires a client identity; with `verifyPeer: true` it also requires trust anchors
  (any `ca` style, or a `certSecret` bundle carrying `caPem`).
- The device is dialed by IP by default, so its certificate must carry the endpoint IP as a
  Subject Alternative Name. Set `serverName` to override the verified name.
- Only GCM-based and TLS 1.3 cipher suites are supported. A device that offers only CBC-based suites
  fails with a "no cipher overlap" error — enable GCM-based suites on the device.
- TLS applies to poll instances. A push (`mode: push`) instance configured with TLS is rejected at
  startup (class-1 implicit I/O runs over plaintext UDP `2222`).
- `sb/status` returns a `security` object (`mode`, `tlsVersion`, `cipherSuite`, `peerVerified`,
  `peer`, `clientCertNotAfter`, `clientCertSerial`, `clientCertExpiryDays`, `trustStore`,
  `handshakeFailures`, `certReloads`); a `tls-handshake-failed` event fires on a handshake failure.
  Certificate rotation and expiry are covered in "Rotate certificates and manage the trust store" below.
- On connect the adapter reads the target's CIP Security objects and reports the device's posture
  under `security.target` (state, security profiles, allowed/available cipher suites, client-cert and
  expiration policy, certificate summary), with `security.targetSupportsCipSecurity` telling you
  whether the device implements them. This works on plaintext instances too — a device without CIP
  Security reports `targetSupportsCipSecurity: false`.

For `verifyPeer: false` (commissioning/debug, accepts any device certificate), the adapter connects
without verifying the device and raises a `tls-peer-unverified` event.

---

## Rotate certificates and manage the trust store

The CA trust anchors are a **managed trust store** — a set of trusted roots, not a single CA — and the
adapter reloads its own client certificate and the trust store from the vault while it runs, so a
rotation takes effect without a restart.

**Trust a set of CA roots.** Point `ca.trustStore` at a vault secret holding a bundle of CA PEMs; the
trust store is built from **all retained versions** of that secret, so during a CA rollover the old and
new roots are trusted at the same time:

```jsonc
"security": {
  "mode": "tls",
  "client": { "certSecret": "ot-pki/eip-originator" },
  "ca":     { "trustStore": "ot-pki/plant-trust-store" }
}
```

Or list several independently-rotated roots explicitly:

```jsonc
"ca": { "list": [ { "$secret": "ot-pki/root-a" }, { "$secret": "ot-pki/root-b" } ] }
```

**Rotate without a restart.** The adapter re-reads the vault every `reloadIntervalSecs` (default 300).
When you write a new client certificate or CA into the vault (for example with `ec-secrets`), the
adapter detects the change, emits `cert-rotated`, increments the `certReloads` metric, and reconnects so
the next handshake presents the new certificate:

```jsonc
"security": {
  "mode": "tls",
  "client": { "certSecret": "ot-pki/eip-originator", "renewBeforeDays": 30 },
  "ca":     { "trustStore": "ot-pki/plant-trust-store" },
  "reloadIntervalSecs": 300
}
```

**Watch for expiry.** The adapter monitors its own client certificate: a `cert-expiring` event fires
within `client.renewBeforeDays` (default 30) of `notAfter`, a `cert-expired` event fires when it lapses,
and an already-expired certificate is refused at connect (with `checkExpiration: true`). `sb/status`
reports `security.clientCertExpiryDays` and `security.trustStore` (the anchor count and each root's
subject/`notAfter`), and the `certExpiryDays` metric is a gauge of the days remaining.

---

## Enroll and renew certificates automatically with EST

The adapter obtains and renews its own client certificate from an EST server (Enrollment over Secure
Transport, RFC 7030), so the certificate lifecycle runs without operator intervention. Add an `est`
block to `connection.security`:

```jsonc
"security": {
  "mode": "tls",
  "client": { "certSecret": "ot-pki/eip-originator" },
  "ca":     { "secret": "ot-pki/plant-root" },
  "est": {
    "enabled": true,
    "server": "https://est.plant.example:8443/.well-known/est",
    "label": "eip",
    "trust":  { "secret": "ot-pki/est-root" },            // verifies the EST server (defaults to the connection ca)
    "auth":   { "bootstrap": { "certSecret": "ot-pki/eip-bootstrap" } },
    "into":   { "certSecret": "ot-pki/eip-originator" },  // writes the enrolled cert where the client reads it
    "renewBeforeDays": 30,
    "fetchCaCerts": true
  }
}
```

The adapter enrolls when it has no usable certificate (`POST /simpleenroll`) and renews within
`renewBeforeDays` of expiry (`POST /simplereenroll`), authenticating with the bootstrap identity, an
HTTP Basic credential (`auth.basic`), or — for a renewal — the current client certificate. It writes the
enrolled key and certificate into the vault destination (`into`, defaulting to the `client` secret), and
the reload watcher then applies it and reconnects — the same path as a manual rotation above.

An unreachable EST server never blocks polling: the current certificate is kept and the attempt is
retried after `retryBackoffMins`. Enrollment reports through the `cert-enrolled` / `cert-enroll-failed`
events, the `estEnrollments` / `estFailures` metrics, and `sb/status` `security.est` (`enabled`,
`lastEnroll`, `nextRenew`, `enrollments`, `failures`).

---

## Deploy to a platform

**HOST** (standalone process/container, MQTT transport):

```bash
cargo run -p ethernet-ip-adapter -- \
  --platform HOST --transport MQTT ./messaging.json -c FILE ./config.json -t my-thing
```

Or containerized with the bundled `compose.yaml` (`docker compose up --build`), which starts an EMQX
broker and the adapter, and can also start the cpppo (`enip-sim`) and OpENer (`enip-io-sim`) targets.

**Greengrass** — package per `gdk-config.json`/`recipe.yaml`; config comes from the deployment
(`--platform GREENGRASS -c GG_CONFIG`), messaging is Greengrass IPC (`--transport IPC`). The
Greengrass build uses the `greengrass` feature (Linux only).

**Kubernetes** — build the image and apply `k8s/`; config is a mounted ConfigMap (`-c CONFIGMAP`),
identity resolves from the Downward API, and the broker/device are reached by in-cluster Service DNS.
With `--platform auto` the library detects the platform and needs no CLI args.

---

## Observe health and status

- **Metric** `southbound_health` (`connectionState`, `paused`, `readErrors`, `writeErrors`,
  `staleSignals`, `reconnects`, latencies) — with `metricEmission.target: messaging` it auto-publishes
  on the UNS `metric` class; `log`/`cloudwatch`/`prometheus` also work.
- **Operational metrics** `EtherNetIpConnection`, `EtherNetIpInventory`, `EtherNetIpPoll`,
  `EtherNetIpPublish`, `EtherNetIpCommand`, and (push only) `EtherNetIpIo`. Use `EtherNetIpPoll` for poll
  health, `EtherNetIpIo` for class-1 frame health (`framesConsumed`, `staleFramesDropped`,
  `sequenceGaps`), `EtherNetIpConnection` for link/reconnect pressure, and `EtherNetIpCommand` for
  control-plane volume. See [reference/metrics.md](reference/metrics.md).
- **State keepalive** — `ecv1/{device}/ethernet-ip-adapter/state` every ~5 s; the RUNNING keepalive
  carries an `instances[]` array with each device's live `connected` flag and `connectionMode`.
- **Events** — `evt/{info|critical}/device-connected|device-unreachable` (a stateful link alarm),
  `evt/{warning|info}/adapter-paused|adapter-resumed`, `evt/{info|warning}/write-audit`, and — for
  TLS instances — `evt/warning/tls-handshake-failed` and `evt/warning/tls-peer-unverified`.
- **Security posture** — `sb/status` returns a `security` object per instance, and the `state`
  keepalive carries `attributes.security` (`"tls"`|`"plaintext"`).
- **Status verb** `sb/status` → connection state, paused, a counter snapshot (and an `io` block on push).
  **Signals verb** `sb/signals` → the resolved signal list with addresses and writable flags.
