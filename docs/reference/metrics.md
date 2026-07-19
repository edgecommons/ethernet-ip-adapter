# Reference — Metrics

The adapter emits health and operational metrics through the EdgeCommons metric service. With
`metricEmission.target: messaging`, metrics publish on the reserved UNS `metric` class:

```text
ecv1/{device}/ethernet-ip-adapter/metric/{metricName}
```

The adapter never writes reserved `metric` topics directly. It defines metrics through the metric
service, so the same names, measures, units, and dimensions are used by the `messaging`, `log`,
`cloudwatch`, and `prometheus` targets. The emit cadence is `global.metricsIntervalSecs` (default 60 s).

## Counter pairs, gauges, and dimensions

Every **counter** is a measure pair: `<name>Total` (monotonic since component start) and
`<name>Interval` (since the previous emit of that family — **reset on emit**). **Gauges** and latency
measures are single measures. Each measure listed below as a counter therefore appears on the wire as
both `…Total` and `…Interval`.

Dimensions are intentionally low-cardinality and CloudWatch-friendly: `instance`, `connectionMode`
(`connected`|`unconnected`), `pollGroup`, `publishMode` (`onChange`|`always`), `verb` (the nine command
verbs), and `result` (`success`|`error`), plus runtime-injected component dimensions. Signal names, tag
paths, endpoints, assembly ids, and raw error text are **not** metric dimensions — they stay in data,
events, logs, and command replies.

The six `EtherNetIp*` families are the adapter's operational metrics; `southbound_health` is the shared
cross-adapter health metric. A poll device emits `EtherNetIpConnection`/`Inventory`/`Poll`/`Publish`/
`Command`; a push device emits `EtherNetIpConnection`/`Publish`/`Command`/`Io`.

## `southbound_health`

The shared per-instance health metric. Dimensions: `instance`. All single measures (gauges/counters, no
Total/Interval pair).

| Measure | Unit | Meaning |
|---|---|---|
| `connectionState` | Count | `1` connected, `0` down. Drives simple health alarms. |
| `paused` | Count | `1` when the instance is paused, else `0`. |
| `pollLatencyMs` | Milliseconds | Most recent poll-cycle latency. |
| `publishLatencyMs` | Milliseconds | Most recent publish latency. |
| `readErrors` | Count | Read errors observed in the interval. |
| `writeErrors` | Count | Write errors observed in the interval. |
| `staleSignals` | Count | Signals with no GOOD read within `staleSignalSecs` (suspended while paused). |
| `reconnects` | Count | Reconnects in the interval. |

## `EtherNetIpConnection`

Connection lifecycle and liveness. Dimensions: `instance`, `connectionMode`.

| Measure | Unit | Kind | Meaning |
|---|---|---|---|
| `sessionConnected` | Count | gauge | `1` connected, `0` down. |
| `connectAttempts` | Count | counter | Initial/reconnect connect attempts. |
| `connectFailures` | Count | counter | Failed connect attempts. |
| `connectionDrops` | Count | counter | Live links marked down. |
| `reconnects` | Count | counter | Reconnects performed. |
| `connectLatencyMs` | Milliseconds | gauge | Connect latency. |
| `connectedDurationMs` | Milliseconds | gauge | Time spent connected since the previous emission. |

## `EtherNetIpInventory`

Static poll inventory (poll mode). Config-derived gauges. Dimensions: `instance`, `pollGroup`.

| Measure | Unit | Meaning |
|---|---|---|
| `configuredSignals` | Count | Signals configured in the group. |
| `arraySignals` | Count | Array signals in the group. |
| `writableSignals` | Count | Allow-listed writable signals in the group. |
| `configuredPollIntervalMs` | Milliseconds | The group's resolved poll interval. |
| `requestsPerCycle` | Count | CIP requests issued per poll cycle (one per signal). |

## `EtherNetIpPoll`

Polling work and sample production (poll mode). Dimensions: `instance`, `pollGroup`, `result`
(`success`|`error`).

| Measure | Unit | Kind | Meaning |
|---|---|---|---|
| `pollCycles` | Count | counter | Poll cycles run. |
| `pollDurationMs` | Milliseconds | gauge | Accumulated poll work time. |
| `tagReads` | Count | counter | CIP tag reads issued. |
| `tagReadErrors` | Count | counter | Failed tag reads. |
| `samplesGood` | Count | counter | GOOD samples produced. |
| `samplesBad` | Count | counter | BAD samples produced. |
| `samplesUncertain` | Count | counter | UNCERTAIN samples produced. |
| `samplesChanged` | Count | counter | Samples that passed the change/deadband gate. |
| `samplesSuppressed` | Count | counter | Samples suppressed by `onChange`/deadband. |
| `pollOverruns` | Count | counter | Cycles whose work exceeded the interval. |

## `EtherNetIpPublish`

Data-message publication. Dimensions: `instance`, `publishMode`.

| Measure | Unit | Kind | Meaning |
|---|---|---|---|
| `dataMessagesPublished` | Count | counter | `SouthboundSignalUpdate` messages published. |
| `samplesPublished` | Count | counter | Samples included in published messages. |
| `publishFailures` | Count | counter | Data publish failures. |
| `batchFlushes` | Count | counter | Buffered signal batches flushed. |
| `batchSize` | Count | gauge | Samples per flushed/published batch. |
| `publishLatencyMs` | Milliseconds | gauge | Accumulated publish latency. |

## `EtherNetIpCommand`

Command-plane activity. Dimensions: `instance`, `verb`, `result` (`success`|`error`).

| Measure | Unit | Kind | Meaning |
|---|---|---|---|
| `commandRequests` | Count | counter | Command handler invocations. |
| `commandErrors` | Count | counter | Handlers that returned a coded error. |
| `commandLatencyMs` | Milliseconds | gauge | Accumulated command latency. |
| `readSignals` | Count | counter | Signals returned by `sb/read`. |
| `writeSignals` | Count | counter | Write entries supplied to `sb/write`. |
| `writeFailures` | Count | counter | Write entries reported failed. |
| `browsedTags` | Count | counter | Tags returned by `sb/browse`. |
| `pauseRequests` | Count | counter | `sb/pause` requests. |
| `resumeRequests` | Count | counter | `sb/resume` requests. |
| `reconnectRequests` | Count | counter | `reconnect` requests. |
| `repollRequests` | Count | counter | `repoll` requests. |

## `EtherNetIpIo`

Class-1 implicit-I/O health (push mode only). Dimensions: `instance`.

| Measure | Unit | Kind | Meaning |
|---|---|---|---|
| `ioConnectionState` | Count | gauge | `1` when the class-1 connection is established, else `0`. |
| `forwardOpens` | Count | counter | ForwardOpen requests. |
| `forwardOpenFailures` | Count | counter | Failed ForwardOpens. |
| `framesConsumed` | Count | counter | Accepted T→O frames. |
| `framesProduced` | Count | counter | O→T frames produced. |
| `staleFramesDropped` | Count | counter | Frames dropped as stale. |
| `sequenceGaps` | Count | counter | Missing frames inferred from sequence jumps. |
| `sizeMismatchDropped` | Count | counter | Frames dropped for wrong size. |
| `malformedFrames` | Count | counter | Malformed frames. |
| `ioTimeouts` | Count | counter | Class-1 inactivity/timeout events. |
| `produceOverruns` | Count | counter | O→T produce overruns. |
| `interFrameMs` | Milliseconds | gauge | Most recent T→O inter-arrival time. |
| `runMode` | Count | gauge | The peer's run/idle bit (`1` run, `0` idle). |
