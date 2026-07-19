# Reference — Messaging Interface & CLI

Every topic and message the adapter publishes or accepts, and the CLI flags. Addressing follows the
**Unified Namespace (UNS)**: `ecv1/{device}/{component}/{instance}/{class}[/channel]`. For the
data/control plane model see [explanation.md](../explanation.md); for client recipes, the
[how-to guides](../how-to-guides.md).

- `{device}` — the resolved Thing name (the last `hierarchy` level).
- `{component}` — the component UNS token, `ethernet-ip-adapter`.
- `{instance}` — a device instance id (`filler-plc`, …) for `data`/`evt`; the shared command inbox, the
  `state` keepalive, and `metric` are component-scope.

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
| `evt` | `evt` | adapter → bus | `ecv1/{device}/ethernet-ip-adapter/{instance}/evt/{severity}/{type}` | — |
| `cmd` | the nine verbs (below) | bus → adapter | `ecv1/{device}/ethernet-ip-adapter/cmd/{verb}` | `{ok,result}` |
| `metric` | `southbound_health`, `EtherNetIpConnection`, `EtherNetIpInventory`, `EtherNetIpPoll`, `EtherNetIpPublish`, `EtherNetIpCommand`, `EtherNetIpIo` | adapter → bus (auto) | `ecv1/{device}/ethernet-ip-adapter/metric/{metricName}` | — |
| `state` | keepalive | adapter → bus (auto) | `ecv1/{device}/ethernet-ip-adapter/state` | — |

Fleet consumers subscribe the UNS wildcards — telemetry `ecv1/+/+/+/data/#`; events `ecv1/+/+/+/evt/#`;
metrics `ecv1/+/+/+/metric/#`; state `ecv1/+/+/+/state`. `state`/`metric`/`cfg`/`log` are library-owned
**reserved** classes; the adapter only ever mints `data`/`evt` topics via the `data()`/`events()`
facades and `cmd` replies via the command inbox — never a hand-assembled topic string.

## The command inbox

The read/write/control surface is served through the library's **command inbox** — a single
component-scope subscription `ecv1/{device}/ethernet-ip-adapter/cmd/#`. A request's **verb** is the topic
channel after `cmd/` and must equal `header.name`. Built-in verbs (`ping`, `reload-config`,
`get-configuration`, `describe`) ship with every component; the adapter adds the nine `sb/*`/`reconnect`/
`repoll` verbs below.

A multi-instance adapter selects the target device with an **`instance`** field in the request body
(optional when only one device is configured). The reply body is `{"ok": true, "result": <verb result>}`
on success, or `{"ok": false, "error": {"code", "message"}}` on failure.

### The nine verbs

| Verb | Modes | Body | Result (on `ok:true`) |
|------|-------|------|-----------------------|
| `sb/status` | poll, push | `{instance?}` | `{id, mode, connected, state, paused, endpoint, adapter, metrics, security, io?}` |
| `sb/read` | poll, push | `{instance?, signals:[ref…]}` | `{id, reads:[…]}` |
| `sb/write` | poll, push | `{instance?, writes:[{ref…, value}]}` (or a single `{ref…, value}`) | `{id, written, results:[…]}` |
| `sb/signals` | poll, push | `{instance?}` | `{id, mode, signals:[…]}` |
| `sb/browse` | poll, push | `{instance?, cursor?, max?}` | `{id, tags:[…], cursor?}` |
| `sb/pause` | poll, push | `{instance?}` | `{id, paused:true, changed}` |
| `sb/resume` | poll, push | `{instance?}` | `{id, paused:false, changed}` |
| `reconnect` | poll, push | `{instance?}` | `{id, connected:true}` |
| `repoll` | poll only | `{instance?}` | `{id, polled:<groups>}` |

### Error codes

Returned as `{"ok": false, "error": {"code", "message"}}`.

| Code | When |
|------|------|
| `BAD_ARGS` | Malformed body; `instance` required with ≥ 2 devices; `repoll` on a push instance or a paused instance. |
| `NO_SUCH_INSTANCE` | `instance` names no configured device. |
| `WRITE_NOT_ALLOWED` | Every `sb/write` entry was refused by the allow-list. |
| `WRITE_FAILED` | A write reached the device but the device rejected it (per-entry failures are also reported inline). |
| `READ_FAILED` | A live `sb/read` (poll) failed at the link. |
| `DEVICE_UNAVAILABLE` | The device task could not be reached (e.g. `repoll` mid-outage). |
| `RECONNECT_FAILED` | `reconnect`'s single bounded attempt did not connect. |
| `BROWSE_UNSUPPORTED` | The device has no CIP tag-list service (poll browse). |
| `BROWSE_FAILED` | A mid-browse link failure. |

## Signal references

A signal-ref in `sb/read`/`sb/write` is either **friendly** (`{"name": "<configured signal>"}`) or
**explicit**:

- **poll:** `{"tagPath", "type", "arrayCount"?}` — an arbitrary CIP tag.
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
no device timestamp); `serverTs` is the adapter's read/receive time, ISO-8601 UTC.

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
the O→T buffer). Entries without a `value`, an unresolvable ref, an input-side push field, or a device
rejection are reported per-entry `{"ok": false, "error": …}`. Every entry emits a `write-audit` event.

## Control plane

- **`sb/status`** → `{ id, mode, connected, state ("ONLINE"|"BACKOFF"|"PAUSED"|…), paused, endpoint,
  adapter, metrics: { read:{interval,total}, write:{interval,total}, readErrors:{interval,total} },
  security: {…} }`. A push instance also carries `io: { o2tApiMs, t2oApiMs, run, peerRun,
  framesConsumed, staleDropped, sequenceGaps }`.
- **`security`** — the connection's TLS posture. A plaintext instance reports `{ mode: "plaintext" }`.
  A TLS instance reports `{ mode: "tls", tlsVersion, cipherSuite, peerVerified, peer,
  clientCertNotAfter, handshakeFailures: {interval,total} }` — the negotiated fields are present once
  the session is up. The `state` keepalive carries the same posture as `attributes.security`
  (`"tls"`|`"plaintext"`).
- **`sb/signals`** → the resolved config view, no device I/O. Poll: `{ id, mode:"poll", signals:[{ name,
  id, address, pollGroup, pollIntervalMs, publishMode, writable, deadband }] }`. Push: `{ id,
  mode:"push", signals:[{ name, id, address, direction ("input"|"output"), publishMode, writable,
  deadband? }] }`.
- **`sb/browse`** → poll: `{ id, tags:[{ name, type, configured, supported, arrayDim? }], cursor? }` —
  page with the returned `cursor`. Push: `{ id, tags:[{ name, id, type, direction, configured:true,
  supported:true }] }` (the configured layout, no round-trip).
- **`sb/pause`** / **`sb/resume`** → `{ id, paused, changed }` — idempotent; `changed` is whether the
  call moved the state.
- **`reconnect`** → drops and re-establishes the link (one bounded attempt); `{ id, connected:true }` or
  a `RECONNECT_FAILED` error.
- **`repoll`** (poll only) → forces one immediate poll cycle; `{ id, polled:<groups> }`. Refused on push
  or while paused (`BAD_ARGS`).

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
| `evt/info/device-connected` | Info | The link came up. Clears the `device-unreachable` alarm. |
| `evt/critical/device-unreachable` | Critical | The link was lost — a stateful alarm (`alarm:true, active:true` on loss; cleared on reconnect via the same channel). |
| `evt/warning/adapter-paused` | Warning | `sb/pause` moved the instance to paused. `context.by` carries the requester identity path. |
| `evt/info/adapter-resumed` | Info | `sb/resume` moved the instance back to running. |
| `evt/info/write-audit` | Info | An `sb/write` entry succeeded. `context` carries `{instance, signalId, ok, value}`. |
| `evt/warning/write-audit` | Warning | An `sb/write` entry failed or was refused. `context` adds `error`. |
| `evt/warning/tls-handshake-failed` | Warning | A TLS instance's handshake failed (bad certificate, no cipher overlap, protocol mismatch) — fired on the transition into failing. `context` carries `{instance, security:"tls"}`. |
| `evt/warning/tls-peer-unverified` | Warning | A TLS instance connected with `verifyPeer:false` (the device certificate was not verified). |

On a TLS instance, `device-connected` carries `context.security: "tls"`.

A fleet consumer subscribing `ecv1/+/+/+/evt/critical/#` sees only alarm-grade events without per-adapter
knowledge of the channel shape.

## Metrics (`metric` class, reserved — automatic)

The metric subsystem publishes health and operational metrics on the reserved `metric` class
(`ecv1/{device}/ethernet-ip-adapter/metric/{metricName}`); the component never addresses that topic
itself. For every metric's dimensions, measures, units, and diagnostic purpose, see
[Reference — Metrics](metrics.md).

## State keepalive (`state` class, reserved — automatic)

The library's heartbeat publishes the `state` keepalive every ~5 s. The RUNNING keepalive carries an
**`instances`** array: one entry per configured device, so a fleet consumer sees every device's up/down
state under the one component without a separate UNS instance per device.

```jsonc
"body": {
  "status": "RUNNING", "uptimeSecs": 3600,
  "instances": [
    { "instance": "filler-plc", "connected": true, "detail": "10.0.0.50:44818",
      "attributes": { "connectionMode": "unconnected" } }
  ]
}
```

- `connected` — the normalized live-liveness flag every console reads (always present).
- `detail` — the connection endpoint.
- `attributes.connectionMode` — `connected` (CIP connected messaging) or `unconnected`.

## Edge-console panels

The adapter registers three descriptor panels (surfaced by the built-in `describe`), each
`scope: "instance"`:

| Panel | Order | Widgets | Verbs |
|-------|-------|---------|-------|
| `overview` | 10 | summary (`connected`/`state`/`paused`/`endpoint`), command summary | `sb/status`, `sb/pause`, `sb/resume`, `reconnect` |
| `signals` | 20 | signal grid | `sb/signals`, `sb/read`, `sb/write`, `repoll` |
| `diagnostics` | 30 | tree browser, key/value list | `sb/browse`, `sb/status` |

## CLI

| Flag | Values | Notes |
|------|--------|-------|
| `--platform` | `GREENGRASS` \| `HOST` \| `KUBERNETES` \| `auto` | Default `auto`. |
| `--transport` | `MQTT [path]` \| `IPC` | HOST/K8s use MQTT (the path is the messaging config); IPC is Greengrass-only. |
| `-c/--config` | `FILE <path>` \| `ENV` \| `GG_CONFIG` \| `CONFIGMAP` \| … | Default from the platform. |
| `-t/--thing` | `<name>` | IoT Thing name; the `{device}` token of every UNS topic. |
