# Explanation — How the EtherNet/IP adapter works, and why

This page is the mental model. For exact options see [reference/](reference/); for tasks, the
[how-to guides](how-to-guides.md).

## The southbound contract

The adapter is a *consumer* of the cross-language **southbound contract** (the same one the Modbus and
OPC UA reference adapters implement): it publishes a normalized `SouthboundSignalUpdate` envelope,
exposes a read/write/control command surface, and emits `southbound_health` plus protocol-specific
operational metrics. The cloud sees the same shape regardless of protocol — only `device.adapter`, the
opaque `signal.address`, and the metric family names differ. This adapter is the **EtherNet/IP**
reference, and it fronts EtherNet/IP's two data models as equal citizens: explicit-messaging **poll**
and class-1 implicit-I/O **push**.

## The Unified Namespace (UNS)

Addressing follows the UNS: every topic is `ecv1/{device}/{component}/{instance}/{class}[/channel]`,
built and validated by the library — never a hand-assembled string. Telemetry rides the `data` class
(`ecv1/{device}/ethernet-ip-adapter/{instance}/data/{signal}`); discrete events ride `evt`; the
on-demand command surface rides the library's `cmd` inbox; and the library owns `state` (a keepalive
whose RUNNING body also carries each configured device's live connectivity in an `instances[]` array),
`metric`, `cfg`, and `log` automatically. Every message carries a top-level **`identity`** element
(`{hier, path, component, instance}`) placing the reading in the enterprise tree — routing and
partitioning never parse the body or the topic. A fleet consumer needs one wildcard per class
(`ecv1/+/+/+/data/#`, `…/evt/#`, `…/metric/#`, `…/state`), not per-adapter topic templates.

## One device per instance, one mode per instance

Each `component.instances[]` entry is **one device** — one PLC or CIP endpoint — with its own task,
connection lifecycle, and one of the two modes. A `poll` device declares `pollGroups[]` and no `io`; a
`push` device declares `io` and no `pollGroups[]`. The two are mutually exclusive per instance: a device
you want to both poll and consume class-1 I/O from is two instances that happen to target the same
device. Instances are independent — a device going offline takes only its own signals to `BAD`; the
others keep streaming.

## Explicit poll vs implicit class-1 I/O

EtherNet/IP carries two fundamentally different data models, and the adapter models each in its own way.

### Poll — explicit messaging

Explicit messaging is request/response: the adapter opens a CIP session and **reads** each configured
tag on a schedule. This is the model for ControlLogix/CompactLogix tags. You group signals into
`pollGroups[]`, each with its own cadence (`pollIntervalMs`), and the adapter reads each group's tags,
decides what changed, and publishes. "Change" is decided client-side: with `publishMode: onChange` (the
default) a signal publishes only when its value moves past its `deadband`; with `always` it publishes
every poll. One CIP request is issued per signal per cycle — the `EtherNetIpInventory.requestsPerCycle`
metric makes that cost visible, and the answer to a large tag count is fewer, larger poll groups at
longer intervals (or push mode, which has no per-signal request cost). The connection can be
**unconnected** explicit messaging (the default) or CIP **connected** messaging (`connection.connected:
true`, a ForwardOpen-backed class-3 session).

### Push — class-1 implicit I/O

Class-1 implicit I/O is the protocol's native **cyclic** model, used by remote-I/O adapters and drives.
The adapter opens a class-1 connection (ForwardOpen) and the device **produces** its input (T→O)
assembly at the negotiated RPI — a fixed-size block of bytes arriving every few milliseconds. There is
no per-tag request; there is one byte buffer. You describe that buffer's layout in `io.input.signals`:
each field is a byte `offset`, a CIP `type`, and (for a bit) a `bit` number, and the adapter slices the
value out of every accepted frame. The optional output (O→T) assembly carries values the adapter
produces **toward** the device; its fields are what `sb/write` can stage. Because frames can arrive
faster than anyone wants published, an input-side `sampleMs` floor throttles publish-eligibility per
field before the deadband/publish-mode gate runs.

The consequence worth internalizing: **push discovers nothing by itself.** A class-1 assembly is an
opaque byte block; the field map lives entirely in your config. Get the offset, type, and size right and
the values are correct; get them wrong and you get plausible garbage. (`sb/browse` on a push instance
returns the *configured* layout, not a wire-discovered one.)

## The signal model

Every signal, in both modes, carries three identifiers, and they do different jobs:

- **`signal.name`** — your human label, and the sanitized `data`-class channel token (`.../data/<name>`).
- **`signal.id`** — the stable canonical key a consumer keys on. In poll mode it is the CIP **tag path**
  verbatim (`LINE_SPEED`, `Program:Main.FillPV`). In push mode it is `a<assembly>/<offset>/<type>[.<bit>]`
  (e.g. `a100/4/real`, `a100/0/bool.1`) — the assembly instance, byte offset, and type.
- **`signal.address`** — the protocol-native handle used to round-trip reads/writes: for poll,
  `{tagPath, type, arrayCount?, slot?}`; for push, `{assembly, offset, type, bit?, arrayCount?, slot?}`.

Keeping `id`/`address` in the body (not derived from the topic channel) means a consumer keys on stable
identity regardless of how the topic was minted.

### Quality

Every sample carries a normalized `quality` (`GOOD`/`BAD`/`UNCERTAIN`) plus `qualityRaw` (the native
detail). This is structural, not adapter discipline: the library's `data()` facade **requires** a
quality on every sample it constructs. A read whose wire type does not match the configured type is
`BAD` with a `DECODE type mismatch` `qualityRaw`. A value that goes non-finite after `scale`/`offset` is
`UNCERTAIN` with `NON_FINITE_AFTER_SCALE`. A failed poll read publishes `BAD` rather than silently
persisting a stale value — a failure is information, and silence is indistinguishable from "not
changing", so non-GOOD samples always publish regardless of deadband.

## Why writes are allow-listed and secure-by-default

The write surface is a hard-coded allow-list, `writes.allow[]`, and it is **empty by default**, making
every device read-only until you say otherwise. `allow` lists the stable `signal.id`s a device may write
— a CIP tag path (poll) or an `a<assembly>/<offset>/<type>` output-field id (push). The allow-list check
happens **before any device I/O**: an entry that is not on the list never becomes a device write, no
matter what a command asks for. An adapter that writes whatever it is told to is a control-system
vulnerability; an empty list is the correct posture for anything touching a control system, and you opt
in one signal at a time. Every `sb/write` entry — success, failure, or refusal — emits a `write-audit`
event.

Write confirmation is honest about what each mode can promise. A **poll** write is a CIP
write-with-acknowledgement: `ok:true` means the device accepted it. A **push** write has no per-write CIP
confirmation — implicit I/O has no acknowledgement channel — so `ok:true` means the value was staged into
the O→T buffer and rides the next cyclic frame, reported as `applied: "next-frame"`.

## The connection lifecycle and per-instance pause

Each instance's task runs connect → serve → reconnect. On startup it connects (host lookup +
RegisterSession within `connectMs`); on a link loss it retries with **exponential, jittered, capped**
backoff (`reconnectBackoffMinMs` doubling to `reconnectBackoffMaxMs`) so a plant full of adapters does
not reconnect in lockstep when a PLC reboots. A link up/down transition drives a stateful `evt` alarm
(`device-unreachable` raised on loss, cleared on reconnect) and flips the `southbound_health`
`connectionState` gauge. While the link is down the adapter still services the command inbox — control
verbs answer, I/O verbs report the device unavailable.

**Pause** (`sb/pause`) is an operator control distinct from a connection drop. It stops a device's
polling/publishing (or, for push, suppresses publishing) while keeping the connection alive and truthful
with a slow real CIP round-trip every `keepaliveProbeIntervalMs`. A paused instance reports `state:
"PAUSED"` while `connected` stays truthful, stale-signal health is suspended, and `repoll` is refused
until you resume. Pause is in-memory and does not survive a restart. `sb/resume` reverses it. Both are
idempotent — the reply's `changed` tells you whether the call actually changed state.

## Two planes

- **Data plane** — high-rate, fire-and-forget telemetry: `SouthboundSignalUpdate` out on the `data`
  class (through the library's `data()` facade); discrete events out on the `evt` class (through
  `events()`) — a `device-connected`/`device-unreachable` connection alarm pair, an
  `adapter-paused`/`adapter-resumed` pair, and a per-write `write-audit`. Severity **derives** the
  channel, so the topic and the body can never disagree.
- **Control plane** — low-rate request/reply through the `cmd` inbox: the nine `sb/*`/`reconnect`/`repoll`
  verbs.

Keeping them separate means a consumer can fire a control verb without perturbing the telemetry stream.
The command inbox is a single component-scope subscription (`ecv1/{device}/ethernet-ip-adapter/cmd/#`);
a multi-instance adapter selects the target device with an `instance` field in the request body
(optional when only one device is configured).

Metrics deliberately stay low-cardinality. `southbound_health` answers the common binary question, while
the richer `EtherNetIp*` families describe connection, inventory, poll, publish, command, and class-1
I/O behavior. Their dimensions are bounded values like `instance`, `pollGroup`, `publishMode`, `verb`,
`result`, and `connectionMode`; signal names, tag paths, endpoints, and raw error text belong in
data/events/logs/command replies, not in metric dimensions.

## A note on security

EtherNet/IP here is **plaintext** — CIP over TCP `44818` and class-1 UDP `2222`, with no CIP Security /
TLS. There is deliberately no credential/cert handling in the protocol layer; secure it at the
**network** layer by deploying on an isolated OT segment (a dedicated VLAN, firewalled device subnet).
Combined with the empty-by-default write allow-list, the adapter's default posture is read-only on an
isolated network.
