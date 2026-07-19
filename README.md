# EtherNet/IP Adapter

`com.mbreissi.edgecommons.EthernetIpAdapter` is the **Rust reference southbound EtherNet/IP adapter**
for the EdgeCommons ecosystem. It connects to EtherNet/IP devices — Allen-Bradley
ControlLogix/CompactLogix PLCs and generic CIP endpoints — and bridges their data onto the Unified
Namespace as normalized `SouthboundSignalUpdate` messages, so a consumer can chart an EtherNet/IP signal
next to a Modbus register or an OPC UA node without knowing the protocol.

It is built on the `edgecommons` Rust library and an owned pure-Rust EtherNet/IP + CIP stack (the `enip`
crate), and runs on all three platforms — Greengrass v2, HOST (standalone process/container), and
Kubernetes.

## Two modes, equal citizens

Each configured device runs in one of EtherNet/IP's two native data models:

- **Poll** (default) — scheduled **explicit-messaging** reads of CIP tags, grouped by cadence into
  `pollGroups[]`. This is the model for ControlLogix/CompactLogix tags.
- **Push** — **class-1 implicit I/O**: the device produces an assembly at the RPI and the adapter maps
  its byte-offset fields to signals (`io` block). This is the model for remote-I/O adapters and drives.

Either mode publishes value changes on the `data` class, emits `southbound_health` plus operational
metrics, and serves a command surface: nine `sb/*`/`reconnect`/`repoll` verbs including on-demand read,
allow-listed write, tag browse, and per-instance pause/resume. Writes are **allow-listed and empty by
default** — every device is read-only until you list the signal ids it may write, and the allow-list is
checked before any device I/O.

## Quick start

Run against the built-in hardware-free simulator (no PLC needed), publishing to a local MQTT broker:

```bash
docker run -d -p 1883:1883 emqx/emqx            # a local broker
cargo run -p ethernet-ip-adapter -- \
  --platform HOST --transport MQTT ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
  -c FILE ./crates/ethernet-ip-adapter/test-configs/config.json \
  -t my-thing
```

Watch the values flow (one wildcard covers the fleet):

```bash
mosquitto_sub -t 'ecv1/+/+/+/data/#' -v
```

The bundled `compose.yaml` also brings up a [cpppo](https://github.com/pjkundert/cpppo) tag server (live
poll target) and an [OpENer](https://github.com/EIPStackGroup/OpENer) I/O adapter (live class-1 push
target) — see the [tutorial](docs/tutorial.md).

## CLI

| Flag | Values |
|------|--------|
| `--platform` | `GREENGRASS` \| `HOST` \| `KUBERNETES` \| `auto` (default) |
| `--transport` | `MQTT [messaging.json]` \| `IPC` (Greengrass-only) |
| `-c/--config` | `FILE <path>` \| `GG_CONFIG` \| `CONFIGMAP` \| … (default by platform) |
| `-t/--thing` | IoT Thing name — the `{device}` token of every UNS topic |

## Documentation

Full docs live under [`docs/`](docs/) (synced to
[docs.edgecommons.mbreissi.com](https://docs.edgecommons.mbreissi.com)):

| Doc | For |
|-----|-----|
| [Tutorial](docs/tutorial.md) | Bring the adapter up against a simulator, end to end. |
| [How-to guides](docs/how-to-guides.md) | Configure poll/push devices, allow-list writes, pause, browse, deploy. |
| [Explanation](docs/explanation.md) | Poll vs push, the signal model, secure-by-default writes, the connection lifecycle. |
| [Sample configurations](docs/sample-configurations.md) | Annotated complete poll and push configs. |
| [Reference — Configuration](docs/reference/configuration.md) | Every config key, type, and default. |
| [Reference — Messaging](docs/reference/messaging-interface.md) | Topics, the `SouthboundSignalUpdate` body, the nine verbs, error codes. |
| [Reference — Metrics](docs/reference/metrics.md) | Every metric family, measure, and dimension. |
| [Reference — Data Types](docs/reference/data-types.md) | The CIP types, arrays, scaling, and quality. |

## Capabilities and limits

- **Value types:** CIP elementary scalars (`bool`, `sint`/`usint`/`int`/`uint`/`dint`/`udint`/`lint`/
  `ulint`, `real`, `lreal`) and 1-D arrays thereof. Structures/UDTs, Logix `STRING`, and
  multi-dimensional arrays are not supported.
- **Poll** uses CIP explicit messaging (one request per signal per cycle); **push** uses class-1
  implicit I/O.
- **Security:** EtherNet/IP here is plaintext (TCP `44818`, class-1 UDP `2222`); there is no CIP
  Security / TLS. Deploy on an isolated OT network segment.

## License

Business Source License 1.1 (BSL 1.1) — see [LICENSE](LICENSE). You may use, copy, modify, and self-host
the Licensed Work free of charge for development, testing, staging, evaluation, academic research, and
personal/non-commercial use; production use in a commercial product or service requires a separate
commercial license. Each released version converts to the Mozilla Public License 2.0 on its fourth
anniversary. See the license file for the exact terms.
