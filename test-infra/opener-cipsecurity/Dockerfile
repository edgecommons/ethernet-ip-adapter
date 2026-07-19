# OpENer **CIPSecurity branch** — the CIP Security **object-model** target for the Phase 2a posture
# reads (DESIGN-cip-security.md §4.1/§5.2). This is a DIFFERENT build from test-infra/opener/ (the
# plaintext class-1 push target): it builds the `EIPStackGroup/OpENer` `CIPSecurity` branch with the
# `OPENER_CIP_SECURITY` CMake option, which compiles + registers the three CIP Security objects:
#
#   CIP Security Object            class 0x5D   (state, security profiles)
#   EtherNet/IP Security Object    class 0x5E   (cipher-suite lists, verify-client / cert flags)
#   Certificate Management Object  class 0x5F   (push/pull capability, cert instance)
#
# The branch implements the objects as CIP objects served over the ORDINARY plaintext encapsulation
# session on TCP 44818 — it does NOT implement the TLS/DTLS transport (that half of Vol 8 is stubbed,
# spike §5.2). So this container is the independent-implementation peer for the Phase-2a *posture
# decoders* (0x5D/0x5E/0x5F Get_Attribute_Single), reached over plaintext 44818. `crates/enip/tests/
# live_cip_security.rs` (self-skipping on a :44818 probe) drives the real `enip::read_security_posture`
# against it and asserts the decoded objects.
#
# The security sources are pure CIP object state machines (no mbedTLS include — the crypto/transport
# half is not on this branch), so `OPENER_CIP_SECURITY` builds with the same toolchain as the plaintext
# sample app; no extra crypto library is needed.
#
# Build + run standalone (Linux docker host; class-1 UDP is irrelevant here — posture reads are TCP):
#   docker build -t opener-cipsec test-infra/opener-cipsecurity
#   docker run --rm -p 44822:44818 opener-cipsec eth0
# Then, from the repo root:
#   cargo test -p ec-enip --test live_cip_security -- --nocapture

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential cmake ca-certificates libcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# The CIPSecurity branch carries the three security-object sources (cipsecurity.c / ethernetipsecurity.c
# / certificatemanagement.c). Pin to the branch head; the object attribute layout is stable.
RUN git clone --depth 1 --branch CIPSecurity https://github.com/EIPStackGroup/OpENer.git
# Dockerfile-side patches (the ab_server precedent — never patch `enip`) to satisfy the Certificate
# Management object's (0x5F) dependency on the SEPARATE EIPStackGroup/OpENerFileObject project (spike
# §5.2 — the branch's `certificatemanagement.c` does `#include "OpENerFileObject/cipfile.h"`):
#   1. Vendor OpENerFileObject under `source/src/cip/` so the relative include resolves and it shares
#      the main CIP library archive (`libCIP.a`) with `cipstringi.c` it calls — otherwise the File
#      Object and the international-string module land in different archives and static-link ordering
#      leaves `CipStringI*` unresolved.
#   2. Add `cipfile.c` to the main CIP source list + its dir to the CIP include path.
#   3. Provide a fallback for `FILE_OBJECT_EDS_FILE_LOCATION` (the integrator-supplied EDS path macro,
#      used only by the EDS/Icon helper the security path never invokes).
RUN git clone --depth 1 https://github.com/EIPStackGroup/OpENerFileObject.git \
        /src/OpENer/source/src/cip/OpENerFileObject
# The Certificate Management init (0x5F) creates File Object instances, so the File Object CLASS must
# be registered first — cipcommon.c guards `CipFileInit()` on `CIP_FILE_OBJECT`, which the CIP-Security
# option does not define. Enable it alongside OPENER_CIP_SECURITY (else CipFileCreateInstance derefs a
# null class → segfault at startup).
RUN sed -i 's#add_definitions(-DOPENER_CIP_SECURITY)#add_definitions(-DOPENER_CIP_SECURITY)\n  add_definitions(-DCIP_FILE_OBJECT)#' \
        /src/OpENer/source/CMakeLists.txt
RUN sed -i \
        -e 's#cipqos.c ciptypes.c)#cipqos.c ciptypes.c OpENerFileObject/cipfile.c)#' \
        -e '/^set( CIP_SRC/i include_directories(${CMAKE_CURRENT_SOURCE_DIR}/OpENerFileObject)' \
        /src/OpENer/source/src/cip/CMakeLists.txt
RUN sed -i '/#define OPENER_CIPFILE_H_/a #ifndef FILE_OBJECT_EDS_FILE_LOCATION\n#define FILE_OBJECT_EDS_FILE_LOCATION "/opt/opener/eds.bin"\n#endif' \
        /src/OpENer/source/src/cip/OpENerFileObject/cipfile.h
#   4. The CIP Security library (0x5F Certificate Management) and the main CIP library (File Object +
#      international-string helpers) reference each other, so a single-pass static link leaves symbols
#      unresolved whichever archive comes first. Bracket the two in a GNU-ld `--start-group` so the
#      linker rescans them until closure.
RUN printf '\nif(OPENER_CIP_SECURITY)\n  target_link_libraries( OpENer -Wl,--start-group CIP CIP_SECURITY -Wl,--end-group )\nendif()\n' \
        >> /src/OpENer/source/src/ports/POSIX/CMakeLists.txt
WORKDIR /src/OpENer/build
# Build the POSIX sample app WITH the CIP Security objects (-DOPENER_CIP_SECURITY=ON registers 0x5D/
# 0x5E/0x5F at CipStackInit — source/src/cip/cipcommon.c).
RUN cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DOpENer_PLATFORM=POSIX \
        -DOpENer_TESTS=OFF \
        -DOpENer_INSTALL_AS_LIB=OFF \
        -DOPENER_CIP_SECURITY=ON \
        ../source \
    && cmake --build . -j"$(nproc)"
RUN set -eux; \
    bin="$(find /src/OpENer/build -type f -name OpENer -perm -u+x | head -n1)"; \
    test -n "$bin"; \
    cp "$bin" /src/OpENer/build/OpENer-bin

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ca-certificates libcap2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/OpENer/build/OpENer-bin /usr/local/bin/OpENer
# The File Object EDS/Icon helper fopens FILE_OBJECT_EDS_FILE_LOCATION at init; provide a stub so the
# open succeeds (the posture reads never touch its contents).
RUN mkdir -p /opt/opener && head -c 64 /dev/urandom > /opt/opener/eds.bin
# Encapsulation TCP/UDP 44818 (the posture reads ride the plaintext explicit session here).
EXPOSE 44818/tcp 44818/udp
ENTRYPOINT ["/usr/local/bin/OpENer"]
CMD ["eth0"]
