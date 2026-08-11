# Reference — Messaging Interface & CLI

Every topic and message the adapter publishes or accepts, and the CLI flags. Addressing follows the
**Unified Namespace (UNS)**: `ecv1/{device}/{component}/{instance}/{class}[/channel]`. For the
data/control plane model see [explanation.md](../explanation.md); for client recipes, the
[how-to guides](../how-to-guides.md).

- `{device}` — the resolved Thing name (the last `hierarchy` level).
- `{component}` — the component UNS token, `ethernet-ip-adapter`.
- `{instance}` — a device instance id (`filler-plc`, …) for `data` and for the per-device `evt`
  events; the `state` keepalive, `metric`, and the component-wide `config-applied` event are
  component-scope. `cmd` accepts both scopes: component-scope
  (`…/ethernet-ip-adapter/cmd/{verb}`) and instance-addressed
  (`…/ethernet-ip-adapter/{instance}/cmd/{verb}`).

## Envelope

All messages use the EdgeCommons JSON envelope: `{header, identity, tags, body}`. The library stamps the
top-level **`identity`** (`{hier, path, component, instance}`) on every message built from config. `tags`
is arbitrary business metadata. Request/reply carries `header.reply_to` + `header.correlation_id`; the
reply is published to `reply_to` with the same `correlation_id`.

```jsonc
"identity": {
  "hier": [ { "level": "site", "value": "factory-1" }, { "level": "device", "value": "my-thing" } ],
  "path": "factory-1/my-thing", "component": "ethernet-ip-adapter", "instance": "filler-plc"
}
```

## Topics

| Class | Message | Direction | Topic | Reply |
|-------|---------|-----------|-------|-------|
| `data` | `SouthboundSignalUpdate` | adapter → bus | `ecv1/{device}/ethernet-ip-adapter/{instance}/data/{signal}` | — |
| `evt` | `evt` | adapter → bus | `ecv1/{device}/ethernet-ip-adapter[/{instance}]/evt/{severity}/{type}` | — |
| `cmd` | the nine verbs (below) | bus → adapter | `ecv1/{device}/ethernet-ip-adapter[/{instance}]/cmd/{verb}` | `{ok,result}` |
| `metric` | `southbound_health`, `EtherNetIpConnection`, `EtherNetIpInventory`, `EtherNetIpPoll`, `EtherNetIpPublish`, `EtherNetIpCommand`, `EtherNetIpIo` | adapter → bus (auto) | `ecv1/{device}/ethernet-ip-adapter/metric/{metricName}` | — |
| `state` | keepalive | adapter → bus (auto) | `ecv1/{device}/ethernet-ip-adapter/state` | — |

Fleet consumers subscribe the UNS wildcards — telemetry `ecv1/+/+/+/data/#`; events `ecv1/+/+/+/evt/#`;
metrics `ecv1/+/+/+/metric/#`; state `ecv1/+/+/+/state`. `state`/`metric`/`cfg`/`log` are library-owned
**reserved** classes; the adapter only ever mints `data`/`evt` topics via the `data()`/`events()`
facades and `cmd` replies via the command inbox — never a hand-assembled topic string.

## The command inbox

The read/write/control surface is served through the library's **command inbox**, which subscribes
both command scopes: the component scope `ecv1/{device}/ethernet-ip-adapter/cmd/#` and the instance
scope `ecv1/{device}/ethernet-ip-adapter/{instance}/cmd/#`. A request's **verb** is the topic channel
after `cmd/` and must equal `header.name`. Built-in verbs (`ping`, `reload-config`,
`get-configuration`, `describe`) ship with every component; the adapter adds the nine `sb/*`/`reconnect`/
`repoll` verbs below. `reload-config` re-reads the active config source and applies it as the
instance-level transaction described in [configuration — Applying changes](configuration.md#applying-changes),
answering `{"reloaded": true}` or a `RELOAD_FAILED` error when the candidate is rejected.

**Instance routing.** Every verb below declares the `instance` scope — the value `describe` reports
in `commands[].scope` — and the addressing resolves in this order: an instance-scoped topic names the
device with its `{instance}` token; a component-scoped topic names it with the **`instance`** field in
the request body; a body `instance` that disagrees with the topic's token is refused with `BAD_ARGS`
before the verb runs; a request that names no instance addresses the sole **running** device (with
≥ 2 of them it is `BAD_ARGS`, and while none is running — the brief window in which a configuration
change restarts every instance — it is `DEVICE_UNAVAILABLE`); and an addressed instance that names no
running device is `NO_SUCH_INSTANCE`. The reply body is `{"ok": true, "result": <verb result>}` on
success, or `{"ok": false, "error": {"code", "message"}}` on failure.

When every configured device runs push mode, `describe` reports `repoll` as `unsupported` (the verb
applies to poll instances); a `repoll` request is still answered with its per-instance refusal.

### The nine verbs

| Verb | Scope | Modes | Body | Result (on `ok:true`) |
|------|-------|-------|------|-----------------------|
| `sb/status` | `instance` | poll, push | `{instance?}` | `{id, mode, connected, state, paused, endpoint, adapter, metrics, security, identity, dialect, io?}` |
| `sb/read` | `instance` | poll, push | `{instance?, signals:[ref…]}` | `{id, reads:[…]}` |
| `sb/write` | `instance` | poll, push | `{instance?, writes:[{ref…, value}]}` (or a single `{ref…, value}`) | `{id, written, results:[…]}` |
| `sb/signals` | `instance` | poll, push | `{instance?}` | `{id, mode, signals:[…]}` |
| `sb/browse` | `instance` | poll, push | `{instance?, cursor?, max?}` or `{instance?, ref, depth?, maxRefs?}` | `{id, tags:[…], cursor?}` (paged) or `{id, mode:"hierarchical", root, refCount, depth, truncated}` |
| `sb/pause` | `instance` | poll, push | `{instance?}` | `{id, paused:true, changed}` |
| `sb/resume` | `instance` | poll, push | `{instance?}` | `{id, paused:false, changed}` |
| `reconnect` | `instance` | poll, push | `{instance?}` | `{id, connected:true}` |
| `repoll` | `instance` | poll only | `{instance?}` | `{id, polled:<groups>}` |

### Error codes

Returned as `{"ok": false, "error": {"code", "message"}}`.

| Code | When |
|------|------|
| `BAD_ARGS` | Malformed body; a request that addresses no instance with ≥ 2 devices running; a body `instance` that disagrees with the topic's instance token; `repoll` on a push instance; mixing the paged and hierarchical `sb/browse` argument families, `depth`/`maxRefs` without `ref`, an unknown browse `ref`, a push `sb/browse` `cursor` that is not one a previous page returned, or an explicit poll signal-ref whose `arrayCount` is outside 1–65535 (the whole command is refused; nothing is read or written). |
| `PAUSED` | `repoll` on a paused instance — resume first. |
| `NO_SUCH_INSTANCE` | The addressed instance names no running device. |
| `WRITE_NOT_ALLOWED` | Every `sb/write` entry was refused by the allow-list. |
| `WRITE_FAILED` | A write reached the device but the device rejected it (per-entry failures are also reported inline). |
| `READ_FAILED` | A live `sb/read` (poll) failed at the link. |
| `DEVICE_UNAVAILABLE` | The device task could not be reached (e.g. `repoll` mid-outage), or the request named no instance while none is running (a configuration change restarting every instance). |
| `RECONNECT_FAILED` | `reconnect`'s single bounded attempt did not connect. |
| `BROWSE_UNSUPPORTED` | The device refuses the CIP tag-list service at the start of the walk, so it has no tag list to browse (poll browse). |
| `BROWSE_FAILED` | A mid-browse link failure; a device that serves a first page and then refuses to resume from the cursor it issued; a poll `sb/browse` `cursor` that is not one a previous page returned; a device whose page repeats or reorders symbol instances; or a device whose paging does not terminate — a cursor that repeats or moves backwards, a cursor that is not a number, or a hierarchical walk that runs past 1024 pages. |

## Signal references

A signal-ref in `sb/read`/`sb/write` is either **friendly** (`{"name": "<configured signal>"}`) or
**explicit**:

- **poll:** `{"tagPath", "type", "arrayCount"?}` — an arbitrary CIP tag. `arrayCount` is an integer from
  1 to 65535; any other value refuses the whole command with `BAD_ARGS`.
- **push read:** `{"assembly", "offset", "type", "bit"?}` matching a declared **input** field.
- **push write:** an **output** field, by `name` or `{"assembly", "offset", "type", "bit"?}`. An input
  field is reported per-entry as `input field`; an unknown ref as `unresolved ref`.

## Data plane

### `SouthboundSignalUpdate` (adapter → bus, `data` class)

Published through the library's `data()` facade — the adapter never hand-builds a topic or body. Topic
`ecv1/{device}/ethernet-ip-adapter/{instance}/data/{signal}`, where `{signal}` is the sanitized signal
`name`. The stable `signal.id` and protocol-native `signal.address` stay in the body (consumers key on
those, not the topic channel).

```jsonc
// poll signal
"body": {
  "device": { "adapter": "ethernet-ip", "instance": "filler-plc", "endpoint": "10.0.0.50:44818" },
  "signal": {
    "id": "TANK_LEVEL",
    "name": "tank-level",
    "address": { "tagPath": "TANK_LEVEL", "type": "real" }
  },
  "samples": [ { "value": 12.5, "quality": "GOOD", "qualityRaw": "0x00", "serverTs": "2026-07-19T01:48:00Z" } ]
}

// push field (class-1 input assembly 100, byte offset 4)
"body": {
  "device": { "adapter": "ethernet-ip", "instance": "palletizer-io", "endpoint": "10.0.0.60:44818" },
  "signal": {
    "id": "a100/4/real",
    "name": "line-speed",
    "address": { "assembly": 100, "offset": 4, "type": "real" }
  },
  "samples": [ { "value": 30.2, "quality": "GOOD", "serverTs": "2026-07-19T01:48:00Z" } ]
}
```

Published when a polled/consumed value changes (`publishMode: onChange`, gated by the signal's
`deadband`) or every sample (`always`). A non-GOOD sample always publishes. One message carries one
signal's `samples` (one, or many when `batchMs > 0`). `sourceTs` is never emitted (EtherNet/IP carries
no device timestamp); `serverTs` is the adapter's read/receive time, ISO-8601 UTC. Per the southbound
four-slot timestamp model, `serverTs` is the capture time — stamped at read completion (poll) or
class-1 frame receipt (push), so a `batchMs` flush carries each sample's capture-time stamp — and
`receivedTs` is not emitted (a direct-client adapter's receipt and capture coincide).

### `sb/read` (command, request/reply)

```jsonc
// request body
"body": { "instance": "filler-plc", "signals": [ { "name": "tank-level" }, { "tagPath": "PRODUCT_COUNT", "type": "dint" } ] }
// reply result
{ "id": "filler-plc", "reads": [
  { "signal": { "id": "TANK_LEVEL", "address": { "tagPath": "TANK_LEVEL", "type": "real" } },
    "value": 12.5, "quality": "GOOD", "qualityRaw": "0x00", "serverTs": "…" } ] }
```

Poll reads are live (a real read serialized on the device task, and it works while paused); push reads
serve the last consumed input snapshot. An unresolvable ref returns a `BAD` entry with `qualityRaw:
"UNRESOLVED_REF"`; a poll ref with no data, `"NO_DATA"`; a push field with no frame yet, `"NO_FRAME"`.

### `sb/write` (command)

```jsonc
"body": { "instance": "filler-plc", "writes": [ { "name": "fill-setpoint", "value": 42.5 } ] }
// poll result:  { "id": "filler-plc", "written": 1, "results": [ { "signal": "FILL_SETPOINT", "value": 42.5, "ok": true } ] }
// push result:  { "id": "palletizer-io", "written": 1, "results": [ { "signal": "a150/4/real", "value": 42.5, "ok": true, "applied": "next-frame" } ] }
```

A single `{ref…, value}` object (no `writes` array) is also accepted. The allow-list check runs **before
any device I/O**. A poll write is CIP-acked; a push write reports `applied: "next-frame"` (staged into
the O→T buffer). A push write that cannot be staged reports `ok: false` with the reason, and the reason
distinguishes a class-1 connection that was **lost** — naming the loss (inactivity watchdog timeout,
peer close, socket error) — from one that was **closed**, from a session that is closing or could not
confirm the staging in time. A push write is bounded by `timeouts.requestTimeoutMs` end to end, and a
refusal is final: a value reported `ok: false` is never staged afterwards, and never rides out inside
a later write to another field of the same output assembly. Entries without a `value`, an unresolvable
ref, an input-side push field, or a device rejection are reported per-entry `{"ok": false, "error": …}`.
Every entry emits a `write-audit` event.

## Control plane

- **`sb/status`** → `{ id, mode, connected, state ("ONLINE"|"BACKOFF"|"PAUSED"|…), paused, endpoint,
  adapter, metrics: { read:{interval,total}, write:{interval,total}, readErrors:{interval,total} },
  security: {…}, identity: {…}|null, dialect: {…} }`. A push instance also carries
  `io: { o2tApiMs, t2oApiMs, run, peerRun,
  framesConsumed, staleDropped, sequenceGaps, sendErrors, recvErrors, sourceMismatchDatagrams,
  refusedRedirects }` — `sendErrors` counts O→T datagrams that failed to send, `recvErrors` counts
  receive failures on the class-1 socket, `sourceMismatchDatagrams` counts inbound datagrams that
  carried a live connection's id but came from an address other than that connection's device (they
  are dropped without delivering a sample and without refreshing the watchdog), and
  `refusedRedirects` counts connections whose device asked for its outputs at a foreign address (the
  adapter refuses the address and keeps the device's own), each as an `{interval, total}` pair like
  the other `io` counters.
- **`security`** — the connection's security posture. A plaintext instance reports
  `{ mode: "plaintext" }`; a TLS instance reports `{ mode: "tls", tlsVersion, cipherSuite, peerVerified,
  peer, clientCertNotAfter, clientCertSerial, clientCertExpiryDays,
  trustStore: { count, anchors: [{ subject, notAfter }] },
  handshakeFailures: {interval,total}, certReloads: {interval,total} }` — the negotiated fields are
  present once the session is up. `trustStore` summarizes the managed set of trusted CA roots (a CA
  rollover shows both the old and new roots while both are live); `clientCertExpiryDays` is the whole
  days until the adapter's own certificate expires (negative when expired); `certReloads` counts client
  cert / trust-store rotations picked up from the vault without a restart. The `state` keepalive carries
  the same posture as `attributes.security` (`"tls"`|`"plaintext"`).

  When automatic enrollment is enabled, `security` also carries an **`est`** object with the EST
  lifecycle state: `{ enabled, server, lastEnroll, nextRenew, lastError, enrollments, failures }`.
  `nextRenew` is the certificate's `notAfter` minus the renew window; `enrollments` / `failures` count
  successful and failed enrollment attempts.

  While a session is up, `security` also carries **`targetSupportsCipSecurity`** (boolean) and, when
  the device implements the CIP Security objects, a **`target`** object with the device's decoded
  posture: `{ state, profiles: [...], allowedCipherSuites: [...], availableCipherSuites: [...],
  verifyClient, sendCertificateChain, checkExpiration, pullModel, certificate: { pushSupported,
  pullSupported, name, state, encoding } }`. The adapter reads the target's CIP Security (0x5D),
  EtherNet/IP Security (0x5E), and Certificate Management (0x5F) objects on connect (both plaintext and
  TLS instances). A device that does not implement these objects reports
  `targetSupportsCipSecurity: false` and no `target`.
- **`identity`** — what the device says it is. The adapter reads the CIP Identity Object (class `0x01`,
  instance 1) once when a session is established, and answers from that reading:
  `{ vendorId, vendorName, deviceType, deviceTypeName, productCode, revision, serialNumber,
  productName }`. `revision` is `"<major>.<minor>"`; `serialNumber` is a hex string such as
  `"0x1234ABCD"`; `vendorName` and `deviceTypeName` are `null` for codes the adapter has no registered
  name for, and the numeric field beside each is the authority. `identity` is `null` while the session
  is down and for a device that refuses the read — refusing is allowed and costs nothing else, the
  instance connects and polls exactly as it would otherwise.

  The identity is informational. It is what the device asserts about itself, nothing verifies it, and
  the adapter's behavior never depends on it: what a device supports is settled by the answers it gives
  to real requests, not by its nameplate.
- **`dialect`** — what the adapter has learned about this device's CIP dialect from operations that
  have already run: `{ tagListService: "supported"|"unsupported"|"unknown" }`. It reads `supported`
  once the device has answered a tag-list browse, `unsupported` once the device has refused that
  service (`BROWSE_UNSUPPORTED`), and `unknown` until a browse has settled it. A browse that fails at
  the link (`BROWSE_FAILED`) teaches nothing and leaves the value unchanged. The adapter does not probe
  for capabilities when it connects.
- **`sb/signals`** → the resolved config view, no device I/O. Poll: `{ id, mode:"poll", signals:[{ name,
  id, address, pollGroup, pollIntervalMs, publishMode, writable, deadband, observedType? }] }`.
  `observedType` is the CIP type the device declared on that signal's last reply (`"REAL"`,
  `"DWORD"`, …) — the representation it is actually served in, beside the `address.type` the
  configuration asked for. It is absent for a signal that has not been read yet. Push: `{ id,
  mode:"push", signals:[{ name, id, address, direction ("input"|"output"), publishMode, writable,
  deadband? }] }`.
- **`sb/browse`** → poll: `{ id, tags:[{ name, type, configured, supported, arrayDim? }], cursor? }`.
  `arrayDim` is the tag's array **dimensionality** — `1` for a one-dimensional array, `2` or `3` for a
  multi-dimensional one, absent for a scalar. `supported` reports whether the tag can be configured as a
  signal and decoded, which depends on both its type and its shape: multi-dimensional tags, structures,
  and strings are `false`; scalars and one-dimensional arrays of the elementary types are `true`.
  Push: `{ id, tags:[{ name, id, type, direction, configured:true, supported:true }], cursor? }` (the
  configured layout, no round-trip). Both modes page the same way: a request without a cursor starts at
  the beginning of the inventory, `max` bounds the page, `cursor` appears only while entries remain, and
  passing it back verbatim continues from where the page stopped — so a walk that follows cursors to
  their absence sees every entry exactly once. The cursor
  is opaque; a value the adapter did not issue is an error (`BROWSE_FAILED` on poll, `BAD_ARGS` on
  push), not a restart from the beginning.
  **Hierarchical form:** a body with `ref` selects the tree mode over the same inventory —
  `{ instance?, ref, depth? (clamped 1..4), maxRefs? (clamped 1..1000) }` →
  `{ id, mode:"hierarchical", root:{ nodeId, name, nodeClass, dataType, refs:[{ referenceType:
  "contains", target:{ nodeId, name, nodeClass, dataType, … } }] }, refCount, depth, truncated }`.
  `ref:"root"` answers the device node whose refs are the inventory; a tag or field id answers that
  leaf. Mixing `ref`/`depth`/`maxRefs` with `cursor`/`max`, using `depth`/`maxRefs` without `ref`,
  or naming an unknown `ref` is `BAD_ARGS`.
- **`sb/pause`** / **`sb/resume`** → `{ id, paused, changed }` — idempotent; `changed` is whether the
  call moved the state.
- **`reconnect`** → drops and re-establishes the link (one bounded attempt); `{ id, connected:true }` or
  a `RECONNECT_FAILED` error.
- **`repoll`** (poll only) → forces one immediate poll cycle; `{ id, polled:<groups> }`. Refused on push
  (`BAD_ARGS`) and while paused (`PAUSED`).

## Events (`evt` class)

Published through the library's `events()` facade: severity **derives** the channel `evt/{severity}/
{type}`, so the topic and the body can never disagree.

```jsonc
"body": {
  "severity": "critical", "type": "device-unreachable", "message": "lost the link to 10.0.0.50:44818",
  "timestamp": "2026-07-19T01:48:00Z", "context": { "instance": "filler-plc" }, "alarm": true, "active": true
}
```

| Channel | Severity | When |
|---------|----------|------|
| `evt/info/device-connected` | Info | The link came up. Clears the `device-unreachable` alarm. When the device answered the Identity Object read, `context.identity` carries the same nameplate object `sb/status` reports; when it did not, the key is absent. |
| `evt/critical/device-unreachable` | Critical | The link was lost — a stateful alarm (`alarm:true, active:true` on loss; cleared on reconnect via the same channel). A configuration change that removes the instance also clears it, so a device the configuration no longer runs leaves no latched alarm. |
| `evt/warning/adapter-paused` | Warning | `sb/pause` moved the instance to paused. `context.by` carries the requester identity path. |
| `evt/info/adapter-resumed` | Info | `sb/resume` moved the instance back to running. |
| `evt/info/write-audit` | Info | An `sb/write` entry succeeded. `context` carries `{instance, signalId, ok, value}`. |
| `evt/warning/write-audit` | Warning | An `sb/write` entry failed or was refused. `context` adds `error`. |
| `evt/warning/io-redirect-refused` | Warning | A push instance's device answered the class-1 connection request by pointing the outbound (O→T) stream at a foreign address. The adapter refuses that address and keeps sending to the device's own, honouring only the port the device named. A device that requires the redirect does not receive the adapter's outputs, so check its socket configuration. Fired once per connection; `context` carries `{refusedRedirects}`. |
| `evt/warning/tls-handshake-failed` | Warning | A TLS instance's handshake failed (bad certificate, no cipher overlap, protocol mismatch) — fired on the transition into failing. `context` carries `{instance, security:"tls"}`. |
| `evt/warning/tls-peer-unverified` | Warning | A TLS instance connected with `verifyPeer:false` (the device certificate was not verified). |
| `evt/info/cert-rotated` | Info | The adapter's client certificate or trust store rotated in the vault; the adapter reconnected to apply it. `context` carries `{instance, security:"tls", serial, notAfter}`. |
| `evt/warning/cert-expiring` | Warning | The adapter's client certificate is within `renewBeforeDays` of expiry. `context` carries `{instance, security:"tls", daysRemaining, notAfter}`. |
| `evt/warning/cert-expired` | Warning | The adapter's client certificate has expired; TLS connects fail until it is rotated. `context` carries `{instance, security:"tls", notAfter}`. |
| `evt/info/config-applied` | Info | A configuration change was applied. **Component-scope** (no `{instance}` topic token) — it describes the whole transaction. `context` carries `{started, stopped, kept, skipped, restartAll}`. |

On a TLS instance, `device-connected` carries `context.security: "tls"`.

`config-applied`'s context lists the instance ids the change `started`, `stopped`, and `kept`, plus
`skipped` — the `[id, reason]` pairs for every instance the change passed over, whether its entry was
malformed or it could not be started — and
`restartAll`, true when the change was outside `component.instances[]` and therefore restarted every
instance:

```jsonc
"context": {
  "started": ["palletizer-io"], "stopped": ["packer-plc"], "kept": ["filler-plc"],
  "skipped": [ ["mixer-plc", "unknown field `pollGroup`"] ], "restartAll": false
}
```

An instance the change restarts appears in both `stopped` and `started`. See
[configuration — Applying changes](configuration.md#applying-changes).

A fleet consumer subscribing `ecv1/+/+/+/evt/critical/#` sees only alarm-grade events without per-adapter
knowledge of the channel shape.

## Metrics (`metric` class, reserved — automatic)

The metric subsystem publishes health and operational metrics on the reserved `metric` class
(`ecv1/{device}/ethernet-ip-adapter/metric/{metricName}`); the component never addresses that topic
itself. For every metric's dimensions, measures, units, and diagnostic purpose, see
[Reference — Metrics](metrics.md).

## State keepalive (`state` class, reserved — automatic)

The library's heartbeat publishes the `state` keepalive every ~5 s. The RUNNING keepalive carries an
**`instances`** array: one entry per configured device, so a fleet consumer sees every device's
condition under the one component without a separate UNS instance per device.

```jsonc
"body": {
  "status": "RUNNING", "uptimeSecs": 3600,
  "instances": [
    { "instance": "filler-plc", "connected": true, "state": "ONLINE", "detail": "10.0.0.50:44818",
      "attributes": { "adapter": "ethernet-ip", "mode": "poll", "connectionMode": "unconnected",
                      "paused": false, "security": "plaintext" } },
    { "instance": "packer-plc", "connected": true, "state": "PAUSED", "detail": "10.0.0.51:44818",
      "attributes": { "adapter": "ethernet-ip", "mode": "poll", "connectionMode": "unconnected",
                      "paused": true, "security": "plaintext" } }
  ]
}
```

- `connected` — the normalized live-liveness flag every console reads (always present).
- `state` — the device's condition, the same token `sb/status` returns: `CONNECTING` (first connect,
  nothing has failed yet), `ONLINE` (session up and producing), `BACKOFF` (the link failed and is
  being retried), `PAUSED` (`sb/pause` is latched and the session is up, so the instance is
  deliberately quiet rather than stale). A link break while paused reports `BACKOFF` with
  `attributes.paused: true`, so `connected` and `state` always tell the truth together.
- `detail` — the connection endpoint.
- `attributes.connectionMode` — `connected` (CIP connected messaging), `unconnected`, or `class1-io`
  (a push instance's cyclic I/O connection).
- `attributes.paused` / `attributes.security` — the pause flag and the TLS posture
  (`"tls"`|`"plaintext"`), from the same per-instance state the `sb/status` reply reads.

## Edge-console panels

The adapter registers three descriptor panels (surfaced by the built-in `describe`), each
`scope: "instance"`:

| Panel | Order | Widgets | Verbs |
|-------|-------|---------|-------|
| `overview` | 10 | summary (orientation rows), command summary (`sb/status`/`sb/pause`/`sb/resume`/`reconnect`) | `sb/status`, `sb/pause`, `sb/resume`, `reconnect` |
| `signals` | 20 | signal grid (`signalsVerb`/`subscriptionsVerb` → `sb/signals`, `readVerb` → `sb/read`) | `sb/signals`, `sb/read`, `sb/write`, `repoll` |
| `diagnostics` | 30 | tree browser (hierarchical `sb/browse` from `rootRef:"root"`, `readVerb` → `sb/read`), key/value list | `sb/browse`, `sb/status` |

Command-backed widgets repeat `scope: "instance"` at widget level. No widget advertises a
`writeVerb`; writes go through `cmd/sb/write` behind the allow-list.

## CLI

| Flag | Values | Notes |
|------|--------|-------|
| `--platform` | `GREENGRASS` \| `HOST` \| `KUBERNETES` \| `auto` | Default `auto`. |
| `--transport` | `MQTT [path]` \| `IPC` | HOST/K8s use MQTT (the path is the messaging config); IPC is Greengrass-only. |
| `-c/--config` | `FILE <path>` \| `ENV` \| `GG_CONFIG` \| `CONFIGMAP` \| … | Default from the platform. |
| `-t/--thing` | `<name>` | IoT Thing name; the `{device}` token of every UNS topic. |
