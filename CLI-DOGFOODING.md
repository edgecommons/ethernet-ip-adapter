# CLI dogfooding log — building `ethernet-ip-adapter` from the `edgecommons` CLI

A persistent, running record of **where the `edgecommons` CLI fell short** and **where the
generated base was lacking** for a real, parity-level southbound adapter. Kept so the CLI and the
`rust/protocol-adapter` template can be improved. Internal dev note — **not** synced to the docs
site (it lives at the repo root, outside `docs/`).

- CLI version dogfooded: `edgecommons 0.3.0` (built from `core/` at `main` `91d93d8`).
- Scaffold command:
  ```bash
  edgecommons component new \
    -n com.mbreissi.edgecommons.EthernetIpAdapter \
    -l RUST -k protocol-adapter \
    -d "Rust reference southbound EtherNet/IP adapter …" \
    -a "EdgeCommons" --dep-source registry -p . --yes
  ```
- Outcome: 17 files generated, exit 0, one expected warning (`EC4005`, no publish bucket).

## What the generated base got RIGHT (the head start is real)

The `rust/protocol-adapter` archetype is a genuinely good starting point, and most of it is kept:

- Clean **`DeviceSession` / `DeviceBackend` seam** (`src/device.rs`) with an enforced boundary rule
  ("a backend knows protocols, not the UNS/topics/metrics"). This is exactly the seam the rseip
  backend drops into.
- Correct **one-task-per-instance** supervisor (`src/app.rs`): connect → poll → publish → reconnect
  with **exponential, full-jittered, capped backoff**; permanent-vs-transient error split.
- **`SouthboundSignalUpdate` via the `data()` facade** (never hand-built topics/bodies); quality on
  every sample; a failed read published as `BAD`, not dropped.
- **`InstanceConnectivityProvider`** feeding both the `state` keepalive and the `status` verb from
  one source; **allow-listed writes**, read-only by default.
- Stateful `evt` alarms (`device-connected` / `device-unreachable`) on the events facade.
- All three **platform packs** emitted: `recipe.yaml` + `gdk-config.json` + `build.sh` (Greengrass),
  `compose.yaml` + `supervisor/` + `Dockerfile` (HOST), `Dockerfile` + `k8s/` (Kubernetes), plus a
  `config.schema.json` and passing template tests.

## Where the CLI fell short

1. **Crate/bin name is mangled, with no override.** `-n com.mbreissi.edgecommons.EthernetIpAdapter`
   produced crate + `[[bin]]` name **`ethernetipadapter`** — dots stripped, lowercased, **no
   separator**. The ecosystem's repos/UNS tokens are kebab (`modbus-adapter`, `opcua-adapter`), so
   the readable form is `ethernet-ip-adapter`. There is no `--crate-name` / `--bin-name` flag; the
   crate/bin name is derived from the reverse-DNS name with no way to get the kebab form the rest of
   the ecosystem uses. Fixed manually (crate/bin → `ethernet-ip-adapter`, updating Dockerfile,
   `recipe.yaml`, `build.sh`, `supervisor/`, `compose.yaml`).
2. **Output directory is the PascalCase short name, not the kebab repo name.** `-p .` produced
   `./EthernetIpAdapter`, not `./ethernet-ip-adapter`. No `--dir` / `--repo-name`. Renamed manually.
3. **Neither `--dep-source` matches the sibling-adapter convention.** Sibling Rust components
   (`file-replicator`, `telemetry-processor`) pin the core lib by **git `rev`** in `Cargo.toml`
   **and** carry a gitignored `.cargo/config.toml` `[patch]` path override for local dev. The CLI
   offers only: `registry` → a git **tag** (`rust-lib/v0.3.0`, which lags `main` and misses the very
   facades the template uses), or `local` → an **absolute path baked into `Cargo.toml`** (not
   shippable). Had to hand-edit the dep to `rev = "91d93d8…"` **and** hand-write
   `.cargo/config.toml`. A `--dep-source pinned-rev` (rev + emitted `.cargo` override) would match
   what the ecosystem actually ships.
4. **`gdk-config.json` can't publish as generated** (`EC4005`) unless `-b/--bucket` is passed —
   fine, but the warning is the only signal, and the field is silently left empty.

## Where the generated base was LACKING (gap to a parity adapter)

The template is a *minimal* archetype, not a parity-level reference. To match `modbus-adapter` /
`opcua-adapter`, the following had to be added from scratch:

5. **Metrics are nowhere near parity.** The base emits **one** metric, `southbound_health`, with 5
   measures — and those diverge from the canonical `SOUTHBOUND.md` §5 set (it omits `publishLatencyMs`
   and `staleSignals`, and adds `signalsPublished`/`reconnects`). The reference adapters emit **5–6
   metric families with dozens of measures** as `(total, interval)` counter pairs
   (`…Connection`, `…Inventory`, `…Poll`, `…Publish`, `…Command`). Built the full family set.
6. **Command surface is a stub.** The base registers only **`sb/write`**. The southbound `sb/*`
   family (`sb/status`, `sb/read`, `sb/signals`, `sb/browse`, `reconnect`/`repoll`) and the
   user-required **`sb/pause` / `sb/resume`** are absent. Built them all. (`sb/pause`/`sb/resume` is
   a **deliberate extension** — see DESIGN.md §Commands; neither reference adapter has it.)
7. **No `docs/` Diátaxis set.** The base ships a single `README.md`. The ecosystem requires
   `docs/{tutorial,how-to-guides,explanation,sample-configurations}.md` +
   `docs/reference/{configuration,messaging-interface,metrics,data-types}.md` that sync to the docs
   site. Authored from scratch.
8. **No CI.** No `.github/workflows/ci.yml` calling the org reusable `component-ci.yml`, and no
   `cargo llvm-cov --fail-under-lines 90` coverage job. Added.
9. **No integration-test layout.** Only inline unit tests. Sibling adapters carry `tests/*.rs`
   (simulator-gated, self-skipping). Added a simulator-gated live suite.
10. **No `AGENTS.md` / `CLAUDE.md` / `DESIGN.md` / `LICENSE`.** Sibling repos carry all four
    (Apache-2.0). Added.
11. **No edge-console panels.** Sibling adapters register `inbox.register_panel(...)`
    (overview / signals / diagnostics) surfaced by the built-in `describe`. The base registers none.
    Added.
12. **No `Cargo.lock`.** The template intentionally omits it; a binary component should commit one.
    Committed after first build.

## Build result of the untouched base (against current `main`)

With the dep reconciled to `rev = 91d93d8` + the `.cargo` path override, the **untouched generated
base compiled clean and all 10 template tests passed** on native Windows (standalone feature):

```
Finished `dev` profile … in 45.77s          # cargo build
test result: ok. 10 passed; 0 failed         # cargo test
```

So the archetype itself is sound against current `main` — the gaps above are of **scope/parity**
(one metric, one command, no docs/CI/tests), not correctness. Had the CLI's `--dep-source registry`
tag (`rust-lib/v0.3.0`) been used unchanged, the risk is the tag lagging the facades the template
calls; pinning `rev = main` avoided it (see shortfall #3).
