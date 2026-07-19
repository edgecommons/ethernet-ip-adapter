# Tutorial — From zero to live values

By the end you'll have the adapter polling an EtherNet/IP simulator and publishing value changes onto
MQTT, and you'll have read, written, and controlled a signal from a client. Then you'll see the same
adapter consume a **class-1 implicit I/O** (push) stream. No hardware required.

## 1. Prerequisites

- A Rust toolchain (stable) and Docker.
- A local MQTT broker on `localhost:1883` (`docker run -d -p 1883:1883 emqx/emqx`).
- The repo cloned, with the `edgecommons` library available (the workspace `.cargo/config.toml` path
  override points the `edgecommons` dep at a sibling checkout for local development).

Two config sources drive the run: a **messaging config** (`--transport MQTT <file>`, the broker to
publish on) and the **component config** (`-c FILE <file>`, the device map). Both live under
`crates/ethernet-ip-adapter/test-configs/`.

## 2. Run the adapter against the in-process simulator

The default `config.json` uses the built-in `sim` backend (`adapter: "sim"`) — one device, `filler-plc`,
with a `fast` and a `slow` poll group. No external simulator is needed. From the workspace root:

```bash
cargo run -p ethernet-ip-adapter -- \
  --platform HOST --transport MQTT ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
  -c FILE ./crates/ethernet-ip-adapter/test-configs/config.json \
  -t my-thing
```

You should see it connect, define its metric families, and start polling. `-t my-thing` is the device
(Thing) name — the `{device}` token of every UNS topic.

## 3. Watch values flow

Subscribe to the UNS data class (any MQTT client) — one wildcard covers the whole fleet:

```bash
mosquitto_sub -t 'ecv1/+/+/+/data/#' -v
```

You'll see `SouthboundSignalUpdate` messages on
`ecv1/my-thing/ethernet-ip-adapter/filler-plc/data/{signal}` for the changing signals (`line-speed`,
`fill-temp`, `tank-level`, `product-count`, `zone-temps`, …), each with a `value`, a normalized
`quality`, the CIP `address` (`{tagPath, type}`), and the top-level `identity`. Also try
`ecv1/+/+/+/state` for the keepalive and `ecv1/+/+/+/metric/#` for `southbound_health` plus the
`EtherNetIpConnection`, `EtherNetIpInventory`, `EtherNetIpPoll`, `EtherNetIpPublish`, and
`EtherNetIpCommand` operational metric families.

## 4. Read a signal on demand

Read/write/control go through the library **command inbox**
(`ecv1/{device}/ethernet-ip-adapter/cmd/{verb}`): set `header.name` to the verb and `reply_to` to a
topic you subscribe. With an EdgeCommons client this is one `request()` call; raw MQTT:

```
publish   ecv1/my-thing/ethernet-ip-adapter/cmd/sb/read
          {"header":{"name":"sb/read","reply_to":"app/r","correlation_id":"1"},
           "body":{"signals":[{"name":"tank-level"}]}}
subscribe app/r   →  { "ok": true, "result": { "id": "filler-plc", "reads": [
                        { "signal": { "id": "TANK_LEVEL", ... }, "value": 12.5, "quality": "GOOD", ... } ] } }
```

`tank-level` has `scale: 0.1`, so a raw `125` reads back `12.5`.

## 5. Write a signal

`FILL_SETPOINT` and `MOTOR_RUN` are the two entries in the device's `writes.allow` list — everything
else is refused before any device I/O:

```
publish   ecv1/my-thing/ethernet-ip-adapter/cmd/sb/write
          {"header":{"name":"sb/write","reply_to":"app/r","correlation_id":"2"},
           "body":{"writes":[{"name":"fill-setpoint","value":42.5}]}}
subscribe app/r   →  { "ok": true, "result": { "id": "filler-plc", "written": 1,
                        "results": [ { "signal": "FILL_SETPOINT", "value": 42.5, "ok": true } ] } }
```

Read it back to confirm. Each write also emits an `evt/info/write-audit` (or `evt/warning/write-audit`
on failure) audit event on the `evt` class.

## 6. Pause and resume the instance

Pause stops polling/publishing for one device while keeping its connection truthful with a slow liveness
probe — useful during maintenance so you don't get a wall of `BAD` samples:

```
publish   ecv1/my-thing/ethernet-ip-adapter/cmd/sb/pause    {"header":{"name":"sb/pause",...},"body":{}}
          →  { "ok": true, "result": { "id": "filler-plc", "paused": true, "changed": true } }
publish   ecv1/my-thing/ethernet-ip-adapter/cmd/sb/resume   {"header":{"name":"sb/resume",...},"body":{}}
          →  { "ok": true, "result": { "id": "filler-plc", "paused": false, "changed": true } }
```

## 7. Poll a real EtherNet/IP simulator (cpppo)

To poll a real CIP endpoint instead of the in-process sim, use `config-cpppo.json` (`adapter:
"ethernet-ip"`), which points its `endpoint` at a [cpppo](https://github.com/pjkundert/cpppo) tag
server. The bundled compose file brings up cpppo with the same tag layout:

```bash
docker compose up -d emqx enip-sim         # broker + cpppo tag server on :44818
cargo run -p ethernet-ip-adapter -- \
  --platform HOST --transport MQTT ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
  -c FILE ./crates/ethernet-ip-adapter/test-configs/config-cpppo.json -t my-thing
```

Now the `line-speed`/`tank-level`/`zone-temps` samples come off the wire, decoded from real CIP replies.
Try `sb/browse` — cpppo answers the tag-list service, so you get the device's tag inventory back.

## 8. Consume a class-1 I/O (push) stream (OpENer)

Push mode is the other half of the adapter. `config-push.json` (`mode: "push"`) consumes a class-1
implicit-I/O assembly the device produces at the RPI and maps its byte-offset fields to signals. The
compose file builds an [OpENer](https://github.com/EIPStackGroup/OpENer) sample I/O adapter serving the
demo assemblies (input `100`, output `150`, config `151`):

```bash
docker compose up -d emqx enip-io-sim
cargo run -p ethernet-ip-adapter -- \
  --platform HOST --transport MQTT ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
  -c FILE ./crates/ethernet-ip-adapter/test-configs/config-opener.json -t my-thing
```

The adapter opens the class-1 connection (ForwardOpen), consumes the cyclic T→O frames, decodes the
configured input fields, and publishes them as `SouthboundSignalUpdate` on the same `data` class. An
`sb/write` to an allow-listed **output** field is staged into the O→T buffer and rides the next cyclic
frame (`applied: "next-frame"`).

> The class-1 return path uses bidirectional UDP `:2222`. On a Linux Docker host keep the sim and the
> adapter on the same compose network. On Docker Desktop for Windows the WSL2 UDP NAT breaks the class-1
> return path — run the class-1 leg on a Linux host or natively.

Next: the [how-to guides](how-to-guides.md) for building your own device map, allow-listing writes, and
deploying; the [reference](reference/) for every option, verb, metric, and type; the
[explanation](explanation.md) for the poll-vs-push model.
