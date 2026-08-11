#!/usr/bin/env bash
#
# Custom GDK build for a Rust Greengrass component.
#
# `gdk component build` invokes this (see gdk-config.json -> custom_build_command).
# The GDK contract for a custom build system is that this script must place:
#   - the recipe   in  greengrass-build/recipes/
#   - the artifact in  greengrass-build/artifacts/<ComponentName>/<ComponentVersion>/
# (GDK creates those folders before calling us.)
#
# The on-device artifact is built with the `greengrass` feature (Greengrass IPC),
# which is Linux-only (the SDK is a C-FFI crate needing libclang). Build on a Linux
# host, or set EDGECOMMONS_TARGET to a Linux triple you have a toolchain for, e.g.:
#   EDGECOMMONS_TARGET=x86_64-unknown-linux-gnu ./build.sh
#
# Environment: EDGECOMMONS_FEATURES, EDGECOMMONS_TARGET, CARGO_TARGET_DIR, and EDGECOMMONS_UNLOCKED
# (drops the default `--locked`; see the D-EIP-30 note below — the result is not a release artifact).
set -euo pipefail

COMPONENT_NAME="com.mbreissi.edgecommons.EthernetIpAdapter"
# Read the version from gdk-config.json so build.sh and the recipe never drift.
# (For the GDK custom build system, use a concrete version in gdk-config.json rather
# than NEXT_PATCH, so the staged artifact path matches what `gdk` expects.)
COMPONENT_VERSION="$(python3 -c 'import json; c = json.load(open("gdk-config.json"))["component"]; print(next(iter(c.values()))["version"])')"
BIN_NAME="ethernet-ip-adapter"

# Greengrass-mode features for the device build. Add edgecommons features here as
# needed, e.g. "greengrass,cloudwatch" for the direct CloudWatch metric target.
FEATURES="${EDGECOMMONS_FEATURES:-greengrass}"
TARGET="${EDGECOMMONS_TARGET:-}"

# Honor CARGO_TARGET_DIR if the caller set one (else cargo's default ./target).
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

# `-p ethernet-ip-adapter` selects the adapter crate in the workspace (D-EIP-17); without it the
# per-package feature flags are not valid at the virtual-workspace root. The binary lands in the
# shared workspace target/ regardless.
CARGO_ARGS=(build --release -p ethernet-ip-adapter --no-default-features --features "${FEATURES}")
if [[ -n "${TARGET}" ]]; then
  CARGO_ARGS+=(--target "${TARGET}")
  BIN_DIR="${TARGET_DIR}/${TARGET}/release"
else
  BIN_DIR="${TARGET_DIR}/release"
fi

# The Greengrass artifact is a shipped artifact, so it resolves against the committed Cargo.lock and
# `--locked` is the default (D-EIP-30) — a release build must use the dependency graph CI verified,
# not whatever a re-resolve happens to pick.
#
# The opt-out exists because, unlike CI and the container build, this script also runs in developer
# checkouts where the gitignored sibling `[patch]` override (`.cargo/config.toml`, pointing the
# `edgecommons` dep at a local path) may be active. A `[patch]` participates in resolution, so with
# it active the committed lock does not match and `--locked` hard-fails — and cargo discovers
# `.cargo/config.toml` by walking UPWARD, so a parent checkout's override reaches this tree even
# when this tree has none of its own.
if [[ "${EDGECOMMONS_UNLOCKED:-0}" == "0" ]]; then
  CARGO_ARGS+=(--locked)
  LOCKED=1
else
  LOCKED=0
  echo "WARNING: EDGECOMMONS_UNLOCKED is set — building WITHOUT --locked." >&2
  echo "WARNING: dependencies are resolved fresh, so this binary may be built against uncommitted" >&2
  echo "WARNING: (locally patched) dependencies. It is a development build, NOT a release artifact." >&2
fi

echo "Building ${BIN_NAME} (release, features=${FEATURES})${TARGET:+ for ${TARGET}}..."
if ! cargo "${CARGO_ARGS[@]}"; then
  if [[ "${LOCKED}" == "1" ]]; then
    cat >&2 <<'EOF'

error: the release build failed with --locked (D-EIP-30).

If cargo reported that the lock file needs to be updated, the most likely cause is a sibling
`[patch]` override in a `.cargo/config.toml` at or ABOVE this directory: it redirects the
`edgecommons` dependency to a local path, which changes resolution, which the committed
Cargo.lock does not describe.

Two ways forward:
  * Build a release artifact from a clean tree — no `.cargo/config.toml` override in this
    directory or any parent (moving this repo's own copy aside is not enough).
  * Build with the override on purpose, accepting that the result is NOT a release artifact:
        EDGECOMMONS_UNLOCKED=1 ./build.sh

Do not "fix" this by committing the regenerated Cargo.lock: a lock written while the override is
active loses the `source = "git+…"` line for `edgecommons` and cannot build a clean clone.
EOF
  fi
  exit 1
fi

# Resolve the binary path (Windows host builds produce a .exe).
BIN_PATH="${BIN_DIR}/${BIN_NAME}"
[[ -f "${BIN_PATH}" ]] || BIN_PATH="${BIN_DIR}/${BIN_NAME}.exe"
if [[ ! -f "${BIN_PATH}" ]]; then
  echo "error: built binary not found in ${BIN_DIR}" >&2
  exit 1
fi

ARTIFACT_DIR="greengrass-build/artifacts/${COMPONENT_NAME}/${COMPONENT_VERSION}"
RECIPE_DIR="greengrass-build/recipes"
mkdir -p "${ARTIFACT_DIR}" "${RECIPE_DIR}"

cp "${BIN_PATH}" "${ARTIFACT_DIR}/${BIN_NAME}"
chmod +x "${ARTIFACT_DIR}/${BIN_NAME}" || true
cp recipe.yaml "${RECIPE_DIR}/recipe.yaml"

echo "Staged artifact -> ${ARTIFACT_DIR}/${BIN_NAME}"
echo "Staged recipe   -> ${RECIPE_DIR}/recipe.yaml"
