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
  `cargo clippy` use the default `standalone` feature and run on Windows. `rseip` is pure Rust and
  builds natively on Windows/MSVC — no C toolchain needed.
- **Run the sim locally:**
  ```bash
  cargo run -- --platform HOST --transport MQTT ./test-configs/standalone-messaging.json \
    -c FILE ./test-configs/config.json -t my-thing
  ```
- **Coverage gate**: 90% line, Linux-authoritative (Windows undercounts Rust statements). Exclude
  only `src/eip/client.rs` (the raw rseip call seam) and `tests/live_cpppo.rs` (sim-gated).
- Always unsubscribe / handle SIGTERM before exit (RAII on the `EdgeCommons` runtime handles it) so a
  run does not leak subscriptions and trip the shared-connection quota.
