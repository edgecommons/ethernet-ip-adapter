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
  `evt/{warning|info}/adapter-paused|adapter-resumed`, and `evt/{info|warning}/write-audit`.
- **Status verb** `sb/status` → connection state, paused, a counter snapshot (and an `io` block on push).
  **Signals verb** `sb/signals` → the resolved signal list with addresses and writable flags.
