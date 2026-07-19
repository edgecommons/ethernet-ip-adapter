# Sample Configurations

Complete, copy-paste-ready configurations for the EtherNet/IP adapter
(`com.mbreissi.edgecommons.EthernetIpAdapter`) — one **poll** device and one **push** (class-1 I/O)
device — explained key by key, with what each option does at runtime.

For the exhaustive option list see [reference/configuration.md](reference/configuration.md); for the
type system see [reference/data-types.md](reference/data-types.md); for tasks see
[how-to-guides.md](how-to-guides.md); for the message envelopes see
[reference/messaging-interface.md](reference/messaging-interface.md); for the model see
[explanation.md](explanation.md).

The adapter loads **one JSON document** from `-c/--config`. The adapter's own settings are `component`
(`component.global` + `component.instances[]`); the top level may also carry the standard edgecommons
sections `tags`, `hierarchy`, `identity`, `topic`, `messaging`, `metricEmission`, `logging`, and
`heartbeat`. Timing values resolve **signal/group ▸ device `defaults` ▸ `global.defaults` ▸ built-in**.

All topics follow the **Unified Namespace**: `ecv1/{device}/{component}/{instance}/{class}[/channel]`,
built and validated by the library from `hierarchy`/`identity` (there are no per-instance or per-signal
topic templates). Telemetry rides the `data` class, events `evt`, the command surface the `cmd` inbox;
the library owns `state`/`metric`/`cfg`/`log` automatically.

---

## 1. A poll device (explicit-messaging CIP tags)

One instance, `filler-plc`, reads CIP tags on two cadences and allows two writable tags. This is the
worked `test-configs/config.json` / `config-cpppo.json` (the two differ only in `adapter`/`endpoint`).

```jsonc
{
  "hierarchy": { "levels": ["site", "device"] },
  "identity": { "site": "factory-1" },
  "heartbeat": { "enabled": true, "intervalSecs": 5, "measures": { "cpu": true, "memory": true }, "destination": "local" },
  "metricEmission": { "target": "log", "namespace": "edgecommons" },
  "tags": { "site": "factory-1" },
  "component": {
    "token": "ethernet-ip-adapter",
    "global": {
      "defaults": { "pollIntervalMs": 1000, "publishMode": "onChange", "batchMs": 0 },
      "timeouts": { "connectMs": 5000, "requestTimeoutMs": 2000, "reconnectBackoffMinMs": 1000, "reconnectBackoffMaxMs": 60000 },
      "healthThresholds": { "staleSignalSecs": 60, "keepaliveProbeIntervalMs": 60000 },
      "metricsIntervalSecs": 60
    },
    "instances": [
      {
        "id": "filler-plc",
        "adapter": "ethernet-ip",
        "connection": { "endpoint": "10.0.0.50:44818", "connected": false },
        "pollGroups": [
          { "id": "fast", "pollIntervalMs": 500, "signals": [
            { "name": "line-speed", "tagPath": "LINE_SPEED", "type": "real",
              "deadband": { "type": "absolute", "value": 0.5 } },
            { "name": "fill-temp",  "tagPath": "FILL_TEMP",  "type": "real",
              "deadband": { "type": "percent", "value": 1.0 } },
            { "name": "tank-level", "tagPath": "TANK_LEVEL", "type": "real", "scale": 0.1, "offset": 0.0 }
          ] },
          { "id": "slow", "pollIntervalMs": 2000, "publishMode": "always", "signals": [
            { "name": "product-count", "tagPath": "PRODUCT_COUNT", "type": "dint" },
            { "name": "zone-temps",    "tagPath": "ZONE_TEMPS",    "type": "real", "arrayCount": 8 },
            { "name": "motor-run",     "tagPath": "MOTOR_RUN",     "type": "dint" },
            { "name": "fill-setpoint", "tagPath": "FILL_SETPOINT", "type": "real" }
          ] }
        ],
        "writes": { "allow": ["FILL_SETPOINT", "MOTOR_RUN"] }
      }
    ]
  }
}
```

### What each option does at runtime

| Option | Effect |
|--------|--------|
| `hierarchy` / `identity` | Place the device in the UNS enterprise tree (envelope `identity`); the last hierarchy level is the resolved thing name = the topic `{device}`. |
| `metricEmission.target: log` | Routes `southbound_health` + the `EtherNetIp*` families to a rotating log file. `messaging` auto-routes to the UNS `metric` class; `cloudwatch`/`prometheus` also work. |
| `component.token` | The `{component}` UNS token — `ethernet-ip-adapter`. |
| `global.defaults` | Fallback `pollIntervalMs`/`publishMode`/`batchMs` for any group that omits them. |
| `global.timeouts` | Connect/request deadlines and the exponential, jittered, capped reconnect backoff window. |
| `global.healthThresholds` | `staleSignalSecs` feeds the `staleSignals` health measure; `keepaliveProbeIntervalMs` is the paused-state liveness-probe cadence. |
| `instances[].id` | Stable device id — the `{instance}` topic token, `device.instance`, the `instance` metric dimension, and the `[filler-plc]` log prefix. |
| `adapter: "ethernet-ip"` | The CIP explicit-messaging backend. `sim` selects the hardware-free in-process simulator. |
| `connection.endpoint` | `<host>:<port>` (default port `44818`). Published in `device.endpoint`. |
| `connection.connected: false` | Unconnected explicit messaging. `true` opens a ForwardOpen-backed connected (class-3) session; `connectionMode` becomes `connected`. |
| `connection.slot` (not shown) | The ControlLogix CPU slot for backplane routing; omit for CompactLogix-direct / cpppo. |
| `pollGroups[].pollIntervalMs` | Per-group cadence — `fast` every 500 ms, `slow` every 2 s, each on its own schedule. |
| `pollGroups[].publishMode` | `slow` uses `always` (every poll publishes — right for counters); `fast` inherits `onChange`. |
| signal `tagPath` | The CIP tag path, verbatim — the stable `signal.id`. |
| signal `type` | The CIP elementary type used to decode (see [data-types](reference/data-types.md)). |
| signal `arrayCount` | `zone-temps` reads a 1-D array of 8 `real`s → a JSON array. |
| signal `scale` / `offset` | `tank-level` publishes `raw × 0.1` (a scaled integer becomes a float). |
| signal `deadband` | `line-speed` republishes only when it moves ≥ 0.5; `fill-temp` only on ≥ 1 % change. |
| `writes.allow` | Only `FILL_SETPOINT` and `MOTOR_RUN` are writable (by `signal.id` = tag path); everything else is read-only. |

### How the groups behave

Each poll group runs on its own cadence. The `fast` group reads `LINE_SPEED`/`FILL_TEMP`/`TANK_LEVEL`
every 500 ms; under `onChange`, `line-speed` and `fill-temp` republish only past their deadbands, so a
steady line does not flood the bus. The `slow` group reads its four signals every 2 s and publishes
every poll (`always`) — right for the monotonic `product-count` counter and a steady "still alive" feed.
One CIP request is issued per signal per cycle; the `EtherNetIpInventory.requestsPerCycle` metric makes
that cost visible.

### UNS data-plane topics

With thing name `my-thing`, `hierarchy = [site, device]`, and instance `filler-plc`:

| Signal | Resolved topic |
|--------|----------------|
| `line-speed` | `ecv1/my-thing/ethernet-ip-adapter/filler-plc/data/line-speed` |
| `zone-temps` | `ecv1/my-thing/ethernet-ip-adapter/filler-plc/data/zone-temps` |

The enterprise location rides the top-level `identity` (`identity.path = "factory-1/my-thing"`), not the
topic. A `SouthboundSignalUpdate` body for `tank-level`:

```jsonc
"body": {
  "device": { "adapter": "ethernet-ip", "instance": "filler-plc", "endpoint": "10.0.0.50:44818" },
  "signal": { "id": "TANK_LEVEL", "name": "tank-level", "address": { "tagPath": "TANK_LEVEL", "type": "real" } },
  "samples": [ { "value": 12.5, "quality": "GOOD", "qualityRaw": "0x00", "serverTs": "2026-07-19T01:48:00Z" } ]
}
```

---

## 2. A push device (class-1 implicit I/O)

One instance, `palletizer-io`, consumes a class-1 assembly the device produces every 100 ms and can
stage two output fields. This is the worked `test-configs/config-push.json` (top-level sections
identical to example 1 and omitted here).

```jsonc
{
  "component": {
    "token": "ethernet-ip-adapter",
    "global": { "defaults": { "pollIntervalMs": 1000, "publishMode": "onChange", "batchMs": 0 },
      "timeouts": { "connectMs": 5000, "requestTimeoutMs": 2000, "reconnectBackoffMinMs": 1000, "reconnectBackoffMaxMs": 60000 },
      "healthThresholds": { "staleSignalSecs": 60, "keepaliveProbeIntervalMs": 60000 }, "metricsIntervalSecs": 60 },
    "instances": [
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
              { "name": "din-word",      "offset": 0,  "type": "udint" },
              { "name": "motor-run",     "offset": 0,  "type": "bool", "bit": 0 },
              { "name": "fault",         "offset": 0,  "type": "bool", "bit": 1, "deadband": { "type": "none" } },
              { "name": "line-speed",    "offset": 4,  "type": "real", "deadband": { "type": "absolute", "value": 0.5 } },
              { "name": "fill-temp",     "offset": 8,  "type": "real", "deadband": { "type": "percent", "value": 1.0 } },
              { "name": "product-count", "offset": 12, "type": "dint" },
              { "name": "zone-temps",    "offset": 16, "type": "real", "arrayCount": 4 }
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
        "writes": { "allow": ["a150/0/udint", "a150/4/real"] }
      }
    ]
  }
}
```

### What each option does at runtime

| Option | Effect |
|--------|--------|
| `mode: "push"` | Selects class-1 implicit I/O — the device requires `io` and forbids `pollGroups`. |
| `io.rpiMs` | Requested T→O produce cadence (100 ms). The negotiated API from the ForwardOpen reply is what actually runs; `o2tRpiMs` defaults to this. |
| `io.connectionType: "p2p"` | Point-to-point T→O consume. `multicast` joins the group from the ForwardOpen reply's sockaddr item. |
| `io.priority` / `timeoutMultiplier` | CIP connection priority (`scheduled`) and the inactivity watchdog (16 × T→O API). |
| `io.assemblies` | `input 100` (T→O), `output 150` (O→T), `config 151` (connection path only). The input/output instance ids are the `a<inst>/…` prefix of field ids. |
| `input.sizeBytes` | The negotiated T→O size; a frame of a different size is dropped and counted (`sizeMismatchDropped`), never partially decoded. |
| `input.realTimeFormat: "modeless"` | Conventional T→O framing (no run/idle header). |
| `input.sampleMs: 500` | Per-field publish floor: at most one sample per field per 500 ms even though frames arrive every 100 ms; the deadband/publishMode gate runs after it. |
| input field `offset` / `type` / `bit` | Where and how each field decodes. `din-word` (a `udint` at byte 0) overlaps `motor-run`/`fault` (bits 0/1 of the same byte). |
| input field `arrayCount` | `zone-temps` is 4 contiguous `real`s at byte 16 → a JSON array. |
| input field `deadband` | Same change gate as poll signals; `fault` uses `none` (any change publishes). |
| `output.sizeBytes` / `realTimeFormat: "header32"` / `run` | The O→T assembly is 32 bytes with a 32-bit run/idle header, produced in run state. An absent `output` (or `sizeBytes: 0`) makes a heartbeat connection. |
| output field `offset` / `type` | The layout the adapter writes into the O→T buffer. |
| `writes.allow` | Only the two output fields `a150/0/udint` and `a150/4/real` (by `signal.id`) are writable; input fields are never writable. |

### How it behaves

On startup the adapter opens the class-1 connection (ForwardOpen using the config assembly `151` in the
path) and begins consuming the T→O frames the device produces every ~100 ms. Each accepted frame is
decoded field-by-field and published as `SouthboundSignalUpdate` on the `data` class — throttled to one
per field per `sampleMs`, then gated by each field's deadband/publishMode. Frame health is on the
`EtherNetIpIo` metric (`framesConsumed`, `staleFramesDropped`, `sequenceGaps`, …) and in the push
`sb/status` `io` block. A push field body:

```jsonc
"body": {
  "device": { "adapter": "ethernet-ip", "instance": "palletizer-io", "endpoint": "10.0.0.60:44818" },
  "signal": { "id": "a100/4/real", "name": "line-speed", "address": { "assembly": 100, "offset": 4, "type": "real" } },
  "samples": [ { "value": 30.2, "quality": "GOOD", "serverTs": "2026-07-19T01:48:00Z" } ]
}
```

An `sb/write` to `fill-setpoint` (allow-listed as `a150/4/real`) is staged into the O→T buffer and rides
the next cyclic frame — the reply reports `applied: "next-frame"` (implicit I/O has no per-write CIP
acknowledgement).

---

## 3. Deploying the same config across platforms

The `component` block is identical across platforms; only the config source, transport, identity, and
metric target differ (see the [how-to guides](how-to-guides.md#deploy-to-a-platform)):

- **HOST** — `--platform HOST --transport MQTT ./messaging.json -c FILE ./config.json -t my-thing`, or
  the bundled `compose.yaml`.
- **Greengrass** — `--platform GREENGRASS -c GG_CONFIG --transport IPC`; the config is the recipe's
  `ComponentConfig` and messaging is Greengrass IPC.
- **Kubernetes** — `-c CONFIGMAP`; config from a mounted ConfigMap, identity from the Downward API,
  broker/device by in-cluster Service DNS. `--platform auto` needs no CLI args.
