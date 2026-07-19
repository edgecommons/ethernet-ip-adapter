# EtherNet/IP Adapter — Documentation

`com.mbreissi.edgecommons.EthernetIpAdapter` connects to EtherNet/IP devices — Allen-Bradley
ControlLogix/CompactLogix PLCs and generic CIP endpoints — and bridges their data onto a message bus.
Each device runs in one of two modes: **poll** (scheduled explicit-messaging reads of CIP tags) or
**push** (class-1 implicit I/O, where the device produces an assembly at a fixed interval and the
adapter maps its byte-offset fields to signals). Either way it republishes value changes as structured
`SouthboundSignalUpdate` messages and serves on-demand reads, allow-listed writes, browse, and control.
Built on the `edgecommons` Rust library and the owned `enip` EtherNet/IP + CIP stack, it runs wherever
you deploy it — a Greengrass v2 component, a standalone process/container, or a Kubernetes pod. It is
the **Rust reference** southbound adapter.

| Doc | Start here when you want to… |
|-----|------------------------------|
| **[Tutorial](tutorial.md)** | learn by doing — bring the adapter up against a simulator, end to end |
| **[How-to guides](how-to-guides.md)** | accomplish a task — poll a device, consume class-1 I/O, write a signal, pause an instance, deploy |
| **[Reference](reference/)** | look up an exact option, topic, payload, verb, metric, or type |
| **[Explanation](explanation.md)** | understand how it works and why — poll vs push, the signal model, allow-listed writes |
| **[Sample configurations](sample-configurations.md)** | copy a complete, annotated poll and push config |

## Quick routing

- **"I'm new here."** → [Tutorial](tutorial.md).
- **"What config option does X?"** → [Reference — Configuration](reference/configuration.md).
- **"How is a CIP tag or assembly field turned into a value?"** → [Reference — Data Types](reference/data-types.md).
- **"What message on which topic?"** → [Reference — Messaging Interface](reference/messaging-interface.md).
- **"What does this metric mean?"** → [Reference — Metrics](reference/metrics.md).
- **"Poll or push — which do I use?"** → [Explanation](explanation.md).

## Audience

These docs are for **integrators and operators** — people who deploy the adapter and write clients that
consume or command it. They do not cover modifying the adapter's own source. The canonical docs site is
[docs.edgecommons.mbreissi.com](https://docs.edgecommons.mbreissi.com).
