# ethernet-ip-adapter — component notes (Claude Code)

EdgeCommons **southbound protocol adapter** (Rust). Full name
`com.mbreissi.edgecommons.EthernetIpAdapter`; repo/crate/bin `ethernet-ip-adapter`; UNS component
token `ethernet-ip-adapter` (via the `component.token` config override). Depends on the
`edgecommons` Rust library. Read the org umbrella `../CLAUDE.md` first (platform matrix, validation
infra, local-dev sibling override).

The full component guidance — what it is, the authoritative `DESIGN.md` contract, key design choices,
template/CI/docs conventions, and the registry entry — lives in `AGENTS.md` and is shared with every
agent tool. It is imported here in full:

@AGENTS.md

## Claude-Code-specific setup (additive to AGENTS.md)

- **Build against the sibling library.** `.cargo/config.toml` (gitignored) patches the `edgecommons`
  git dep to the local `../edgecommons/core/libs/rust` checkout, so a plain `cargo build` /
  `cargo test` uses your working copy. CI keeps the pinned `rev` in `Cargo.toml`. Do NOT edit
  `.cargo/config.toml` or the `edgecommons` pin as part of feature work.
- **The `greengrass` feature is Linux-only** (the IPC SDK). Ordinary `cargo build` / `cargo test` /
  `cargo clippy` use the default `standalone` feature and run on Windows. The owned `crates/enip`
  protocol crate is pure Rust and builds natively on Windows/MSVC — no C toolchain needed.
- **This is a Cargo workspace** (D-EIP-17): `crates/enip` (the `ec-enip` protocol library) +
  `crates/ethernet-ip-adapter` (this binary). Use `--workspace` for builds/tests and
  `-p ethernet-ip-adapter` to run the binary.
- **Run the sim locally** (from the workspace root):
  ```bash
  cargo run -p ethernet-ip-adapter -- --platform HOST --transport MQTT \
    ./crates/ethernet-ip-adapter/test-configs/standalone-messaging.json \
    -c FILE ./crates/ethernet-ip-adapter/test-configs/config.json -t my-thing
  ```
- **Coverage gate**: 90% line, **workspace-wide**, Linux-authoritative (Windows undercounts Rust
  statements). The protocol crate is inside the gate (D-EIP-17); only live-hardware suites
  (sim-gated) are excluded.
- Always unsubscribe / handle SIGTERM before exit (RAII on the `EdgeCommons` runtime handles it) so a
  run does not leak subscriptions and trip the shared-connection quota.
