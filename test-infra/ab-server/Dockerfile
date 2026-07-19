# ab_server — a second, INDEPENDENT Logix explicit-messaging **target** for the poll live tests
# (DESIGN §11.6). `ab_server` is the CIP PLC simulator that ships inside libplctag
# (github.com/libplctag/libplctag, `src/tools/ab_server`, MPL-2.0) and is the CI reference server the
# libplctag project tests its own client against — an implementation entirely independent of both
# `enip` and cpppo, so it is a genuine second conformance peer for the explicit-messaging poll paths
# (RegisterSession, Read/Write Named Tag `0x4C`/`0x4D`, fragmented `0x52`/`0x53`), reached through a
# real Unconnected_Send (`0x52`) route wrapper — the CompactLogix/ControlLogix backplane path that
# cpppo (direct, no backplane) never exercises.
#
#   input/output tags (Read/Write Named Tag)   LINE_SPEED / PRODUCT_COUNT / ZONE_TEMPS / ... (below)
#
# **Browse note (verified in source + full git history, DESIGN §11.6):** this ab_server does NOT serve
# the Logix tag-LIST service (Get Instance Attribute List `0x55` on the Symbol class `0x6B`). Its CIP
# dispatcher (`cip.c`, `cip_dispatch_request`) handles only Read/Write/Multi; `0x55` falls through to
# `CIP_ERR_UNSUPPORTED` (`0x08`) and the `CIP_LIST_TAGS` bytes are commented out. So — contrary to a
# common assumption — ab_server does NOT close the `sb/browse` gap. The independent browse (`0x55`)
# conformance peer is EthernetIPSharp (test-infra/ethernetip-sharp, §11.7); the real-Logix path stays
# §12.4. What ab_server DOES uniquely add here is the Unconnected_Send-routed read/write path.
#
# Build + run standalone:
#   docker build -t ab-server-sim test-infra/ab-server
#   docker run --rm -p 44820:44818 ab-server-sim        # host :44820 to coexist with cpppo/OpENer
#
# ab_server binds 0.0.0.0:44818 inside the container. It is a bare TCP/CIP target (no UDP class-1),
# so ordinary port publishing works on any docker host (unlike OpENer's class-1 UDP return path).
# The single build stage compiles just the ab_server tool + the one libplctag header it pulls
# (`utils/random_utils.h`) — its own `utils.c` provides the `random_u64` symbol, so no other library
# translation unit is linked.

FROM gcc:13-bookworm AS build
RUN git clone --depth 1 --branch v2.7.0 https://github.com/libplctag/libplctag.git /libplctag
WORKDIR /libplctag
# --- Two minimal spec-conformance patches to ab_server's ENCAPSULATION layer (eip.c) ---------------
# ab_server as shipped is more restrictive than the EtherNet/IP encapsulation spec (Vol 2 §2-4) in two
# ways that reject any spec-correct client which stamps a Sender Context — `enip` does (as do most real
# clients), and cpppo/OpENer both accept it, so these are ab_server limitations, NOT `enip` bugs:
#   1. RegisterSession rejects a non-zero Sender Context. The spec does not require it to be zero (the
#      field is opaque, echoed back); real Logix controllers accept any value. Neutralize the check.
#   2. ab_server echoes `plc->sender_context` — a field it NEVER assigns — so every reply carries
#      context 0 instead of the request's context. A real device echoes the *request's* Sender Context
#      verbatim (Vol 2 §2-3.3), which `enip` (and pycomm3, and libplctag over multiple in-flight)
#      relies on to correlate replies. Echo `header.sender_context` instead.
# Both patches make ab_server MORE spec-compliant; its CIP read/write/error logic is untouched, so it
# remains a fully independent conformance peer. (DESIGN §11.6 records this.)
RUN sed -i \
      -e 's/if(header->sender_context != (uint64_t)0) {/if(0) { \/* enip patch: Sender Context need not be zero (spec: opaque, echoed) *\//' \
      -e 's/slice_set_uin64_le(output, 12, plc->sender_context)/slice_set_uin64_le(output, 12, header.sender_context) \/* enip patch: echo the request Sender Context *\//g' \
      src/tools/ab_server/eip.c \
    && grep -q 'header.sender_context) /\* enip patch' src/tools/ab_server/eip.c \
    && test "$(grep -c 'enip patch' src/tools/ab_server/eip.c)" = "3"
# Compile the self-contained POSIX C sources of the ab_server tool. `-I src` satisfies the single
# `#include <utils/random_utils.h>`; ab_server's own utils.c defines the referenced symbols.
RUN gcc -O2 -I src -o /usr/local/bin/ab_server src/tools/ab_server/*.c -lm -lpthread

FROM debian:bookworm-slim
COPY --from=build /usr/local/bin/ab_server /usr/local/bin/ab_server
EXPOSE 44818/tcp
# ControlLogix mode + the backplane path (1,0) so clients reach the "CPU" through a real
# Unconnected_Send route wrapper. The §11.1 bottling-line tag layout (ab_server needs an explicit
# array size on every CIP tag, so scalars are `[1]`): REALs, a DINT, the REAL[8] array, a writable
# setpoint, and a STRING (Logix STRING structure) for tag-set parity with cpppo.
ENTRYPOINT ["/usr/local/bin/ab_server", "--plc=ControlLogix", "--path=1,0"]
CMD ["--tag=LINE_SPEED:REAL[1]", \
     "--tag=FILL_TEMP:REAL[1]", \
     "--tag=TANK_LEVEL:REAL[1]", \
     "--tag=PRODUCT_COUNT:DINT[1]", \
     "--tag=FILL_SETPOINT:REAL[1]", \
     "--tag=ZONE_TEMPS:REAL[8]", \
     "--tag=MOTOR_RUN:DINT[1]", \
     "--tag=RECIPE:STRING[1]"]
