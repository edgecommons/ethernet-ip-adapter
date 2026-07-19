# Container image for a edgecommons Rust component, for the KUBERNETES (and HOST/Docker) platform.
# Requires the edgecommons crate resolvable (cargo git dep on the private repo, or crates.io);
# see docs/platform/DESIGN-packaging.md §13.
#
# Multi-stage: stage 1 compiles the standalone release binary against the edgecommons crate;
# stage 2 is a slim glibc runtime that carries only the binary, run as a non-root user.
#
# Build (the cargo git dep needs network + git auth to fetch the private edgecommons repo —
# pass a GITHUB_TOKEN or mount an SSH agent):
#   docker build -t <image> .
# Then push to your registry (or `kind load docker-image <image>` for a local cluster) and set
# `image:` in k8s/deployment.yaml.

# ---- stage 1: build -------------------------------------------------------------------------
# The build toolchain must be recent enough for the committed Cargo.lock: the resolved transitive
# dependency tree (e.g. time 0.3.x, icu 2.x via the edgecommons crate) requires rustc >= 1.88.
FROM rust:1.88-slim AS build

# Resolve the private edgecommons git dependency using the system git (honours GITHUB_TOKEN / SSH).
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# git is needed for cargo to fetch the git dependency.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the workspace manifest + lockfile and every member crate, then build the adapter binary from
# the workspace root (D-EIP-17). `-p` selects the binary; the `enip` protocol crate builds with it
# once the S3 dependency lands.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p ethernet-ip-adapter

# ---- stage 2: runtime -----------------------------------------------------------------------
# debian:bookworm-slim has glibc (the binary is glibc-linked) and is small.
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/ethernet-ip-adapter /usr/local/bin/component

# Run as a non-root, unprivileged user (matches the Deployment's runAsNonRoot securityContext).
USER 65532:65532

# No default args: with --platform auto the library auto-detects KUBERNETES (or HOST) and
# defaults its config source / transport / identity accordingly. Override via the Deployment's
# args: if you need an explicit platform/transport/config-source.
ENTRYPOINT ["/usr/local/bin/component"]
