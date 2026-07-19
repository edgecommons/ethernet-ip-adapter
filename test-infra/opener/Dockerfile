# OpENer — the class-1 implicit-I/O **target** for the push live tests (DESIGN §11.5).
#
# OpENer (EIPStackGroup/OpENer) is the ODVA-member OSS EtherNet/IP *adapter/target* stack. There is
# no official published image, so this ~build-two-stage Dockerfile compiles the POSIX sample
# application from source and runs it. The sample serves the standard demo assemblies the §4.6 /
# test-configs/config-opener.json push config targets:
#
#   input  (T→O, produced by OpENer, consumed by us)  assembly 100 (0x64), 32 bytes
#   output (O→T, produced by us, consumed by OpENer)  assembly 150 (0x96), 32 bytes
#   config (used in the class-1 ForwardOpen path)     assembly 151 (0x97), 10 bytes
#
# (These are OpENer's `sample_application` defaults — DEMO_APP_*_ASSEMBLY_NUM in
# source/src/ports/POSIX/sample_application/sampleapplication.c. Pin/adjust config-opener.json to
# whatever this build reports if a future OpENer changes them.)
#
# Build + run standalone:
#   docker build -t opener-sim test-infra/opener
#   docker run --rm --network host opener-sim            # Linux docker: host net → clean UDP :2222
#   # (Docker-Desktop-on-Windows note: class-1 T→O return packets do not survive the WSL2 UDP NAT;
#   #  run OpENer with host networking on a Linux docker host, or natively, for the push live test.)
#
# The single argument to the OpENer binary is the network interface whose IPv4 the stack binds
# (default `eth0`); override via the compose `command:` or `docker run ... opener-sim <iface>`.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential cmake ca-certificates libcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Pin to a tag for reproducibility; OpENer's assembly layout is stable across recent releases.
RUN git clone --depth 1 https://github.com/EIPStackGroup/OpENer.git
WORKDIR /src/OpENer/build
# Build the POSIX port (the CIP stack + the sample I/O-adapter application). CMake source tree is
# under source/; the sample app is compiled in by default for the POSIX platform.
RUN cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DOpENer_PLATFORM=POSIX \
        -DOpENer_TESTS=OFF \
        -DOpENer_INSTALL_AS_LIB=OFF \
        ../source \
    && cmake --build . -j"$(nproc)"
# The sample executable lands under the POSIX port tree; normalize its location.
RUN set -eux; \
    bin="$(find /src/OpENer/build -type f -name OpENer -perm -u+x | head -n1)"; \
    test -n "$bin"; \
    cp "$bin" /src/OpENer/build/OpENer-bin

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ca-certificates libcap2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/OpENer/build/OpENer-bin /usr/local/bin/OpENer
# Encapsulation TCP/UDP 44818 + class-1 implicit I/O UDP 2222.
EXPOSE 44818/tcp 44818/udp 2222/udp
# `eth0` is the default container interface; the compose/CLI can pass another.
ENTRYPOINT ["/usr/local/bin/OpENer"]
CMD ["eth0"]
