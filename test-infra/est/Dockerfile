# EST (RFC 7030) test server for CIP Security Phase 2c live validation (DESIGN-cip-security.md §5.2
# Target C). Builds `globalsign/est`'s reference `estserver` — an independent (Go) RFC 7030
# implementation with a mock CA — and serves /.well-known/est/{cacerts,simpleenroll,simplereenroll}
# on :8443 over TLS with the generated test PKI (run gen-certs.sh first) (test-infra/est/certs + config.json).
#
# NOTE: this is a NON-PRODUCTION test server (its own -help says so). It is a genuine, independent EST
# peer for the self-skipping `live_est` test — not a real CIP Security device (that remains the
# declared lab-hardware gap, DESIGN.md §14.6).
FROM golang:1.23-bookworm AS build
# The repo's go.mod pins a newer toolchain; let Go fetch it.
ENV GOTOOLCHAIN=auto
RUN git clone --depth 1 https://github.com/globalsign/est.git /src
WORKDIR /src/cmd/estserver
RUN go build -o /estserver .

FROM debian:bookworm-slim
RUN useradd -r -s /usr/sbin/nologin est
COPY --from=build /estserver /usr/local/bin/estserver
COPY certs/ca.pem certs/ca.key certs/server-chain.pem certs/server.key /est/
COPY config.json /est/config.json
RUN chown -R est:est /est
USER est
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/estserver", "-config", "/est/config.json"]
