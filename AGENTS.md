# ethernet-ip-adapter — component notes

EdgeCommons **southbound protocol adapter** (Rust). Full name
`com.mbreissi.edgecommons.EthernetIpAdapter`; repo/crate/bin `ethernet-ip-adapter`; UNS component
token `ethernet-ip-adapter` (via the `component.token` config override). Depends on the
`edgecommons` Rust library. Read the org umbrella `../AGENTS.md` first (platform matrix, validation
infra, local-dev sibling override).

## What it is

The Rust reference **EtherNet/IP** adapter — CIP explicit messaging over TCP and class-1 implicit
I/O over UDP (Allen-Bradley ControlLogix / CompactLogix and generic CIP devices). It reads
config-declared signals on scheduled poll groups (`mode: poll`, CIP explicit messaging —
structurally the closest sibling is the Python `modbus-adapter`) **and** consumes class-1 implicit
I/O (`mode: push`) at the negotiated RPI, per instance; both paths normalize every reading to a
`SouthboundSignalUpdate` with quality and publish on the `data` class via the library's `data()`
facade. It serves confirmed, allow-listed writes and the `sb/*` command family, and reports
per-instance connectivity.
Runs HOST / GREENGRASS / KUBERNETES via edgecommons (no platform branching).

One component instance (`component.instances[]` entry) = **one device** (one PLC / CIP endpoint),
each with its own task, session, and connection lifecycle.

## Authoritative design

**`DESIGN.md` is the design-fidelity contract** (v2.0). Build to it, re-read it before implementing,
and surface deviations up front — do not simplify silently. `CLI-DOGFOODING.md` records where the
`edgecommons` CLI / generated base fell short (internal dev note, not synced to the docs site).

## Key design choices (see DESIGN.md for rationale)

- **Protocol stack = the OWNED pure-Rust `crates/enip` crate** (package `ec-enip`, lib `enip`;
  `PROTOCOL-DESIGN.md`) — async/Tokio, `#![forbid(unsafe_code)]`, zero C deps, builds natively on
  Windows/MSVC and Linux. No external protocol library. It knows nothing about EdgeCommons; the
  adapter consumes it only through the `src/device.rs` seam (D-EIP-1/17). Both update models exist:
  `mode: "poll"` (scheduled explicit-messaging polling, the default) and `mode: "push"` (class-1
  implicit I/O), per instance (D-EIP-2).
- **Config lives entirely under `component.*`** (canonical-schema rule, no top-level block, no schema
  sync). `component.global` (defaults/timeouts/healthThresholds/metricsIntervalSecs) +
  `component.instances[]` (device → poll groups → signals). `#[serde(deny_unknown_fields)]`
  everywhere **except** `connection` (deliberately open). Precedence: signal ▸ group ▸
  device.defaults ▸ global.defaults ▸ built-in.
- **Signals are declared explicitly** in poll groups (Modbus-style, not OPC UA regex matching);
  `sb/browse` is on-demand CIP tag discovery. `signal.id` = the configured `tagPath` verbatim;
  the `data` topic channel = the config `name` (lower-kebab).
- **Supported value types**: CIP elementary scalars + 1-D arrays thereof. `string`/UDT/multi-dim are
  rejected at config validation (D-EIP-16).
- **Writes are allow-listed, secure-by-default**: empty `writes.allow[]` ⇒ all writes refused,
  matched on the stable `signal.id` (D-EIP-5).
- **`sb/pause`/`sb/resume` are a deliberate southbound-contract extension** (D-EIP-3), a candidate
  for core promotion — this repo does NOT edit core `SOUTHBOUND.md`.
- **Every verb declares its command scope** (D-EIP-26): all nine register at
  `CommandScope::Instance`, so the library owns addressing — the topic's instance token, a body
  `instance`, and the `BAD_ARGS` refusal when the two conflict — and hands the handler the resolved
  instance. The adapter keeps only what needs its own configuration: the sole-device default and
  `NO_SUCH_INSTANCE`. Never re-add topic parsing or a `body.instance` read.
- **One state model, two surfaces** (D-SC-7, §9.2): `connectivity_of` derives the
  `CONNECTING`/`ONLINE`/`BACKOFF`/`PAUSED` token and the `paused` attribute from the same `Health`
  object that answers `sb/status`, and the `state` keepalive's `instances[]` publishes it — a paused
  instance is never indistinguishable from a stale one.
- **The seam** (`src/device.rs`): `DeviceBackend`/`DeviceSession` traits know protocols and never
  import the UNS/topics/envelopes/metrics. The in-process `SimBackend`/`SimSession` (`src/sim.rs`)
  models the cpppo tag layout so `cargo run` and the unit tests need no PLC or network.

## Template & conventions (mirror `../modbus-adapter` / `../telemetry-processor`)

- `main.rs` = `EdgeCommonsBuilder::new(NAME).args(env::args_os()).build().await?` → `App::new`/`run`.
- Config: own subtree under `component.global`/`component.instances[]`; standard edgecommons sibling
  sections; `#[serde(rename_all="camelCase")]`; skip-bad-instance, fail-only-if-zero-valid.
- Three deploy artifacts kept in sync on the names: `recipe.yaml` (+ `build.sh`, `gdk-config.json`),
  `Dockerfile` + `k8s/`, `test-configs/`. The Greengrass **component** name stays PascalCase
  (`…EthernetIpAdapter`); the crate/bin/artifact and the UNS token are kebab (`ethernet-ip-adapter`).
- CI: one caller → `edgecommons/.github/.github/workflows/component-ci.yml@main` (`language: RUST`,
  `secrets: inherit`) + in-repo 90% gate (`cargo llvm-cov --fail-under-lines 90`), **workspace-wide**
  — the owned `crates/enip` protocol crate is inside the coverage gate, not carved out (D-EIP-17).
  The sim-gated live suites, the fuzz harness workspace, and the `#[cfg(test)]` test doubles are the
  only coverage exclusions; no product file is carved out (DESIGN §12.2). Every in-repo job that
  resolves dependencies runs `--locked` (D-EIP-30): `Cargo.lock` must be regenerated with the
  sibling `[patch]` override disabled, because a lock written while it is active loses the git
  `source` line for `edgecommons` and cannot build a clean clone.
- Docs: Diátaxis `.md`, no frontmatter, synced to the site — current behavior only, present tense.

## Registry

Add to `../registry/components.json` as `category: "adapter"`, status `experimental`, once published
under `edgecommons/ethernet-ip-adapter`.
