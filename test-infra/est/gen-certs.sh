#!/usr/bin/env bash
# Generate the EST test PKI (mirrors ../enip-tls/gen-certs.sh): a root CA, an EST-server leaf (with
# SANs for how the server is dialed — 127.0.0.1 for the host live test, est-server for in-compose), and
# a bootstrap client identity the adapter authenticates with. All ECDSA P-256, all signed by the CA.
# Committed so the live_est self-skipping test and the estserver container agree on trust; NEVER real.
set -euo pipefail
# Disable Git-Bash-on-Windows (MSYS) POSIX->Windows path mangling of the `/CN=…` subject args, the
# way ../enip-tls/gen-certs.sh does. The other Windows idiom — writing the subject as `//CN=…` — is
# NOT portable: MSYS collapses the leading `//` to `/`, but a Linux OpenSSL reads it literally,
# reports `Skipping unknown subject name attribute "/CN"` and mints certificates with an EMPTY
# subject. This PKI is generated on the Linux runner too (the CI live-sims job builds
# test-infra/est with these certs baked into the image), so it has to be right on both.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")"
# certs/ is a gitignored runtime artifact, so it does not exist in a fresh clone or CI checkout.
mkdir -p certs
cd certs
gen() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

gen ca.key
openssl req -x509 -new -key ca.key -subj "/CN=EdgeCommons EST Test Root CA" -days 3650 -out ca.pem

gen server.key
openssl req -new -key server.key -subj "/CN=est-server" -out server.csr
cat > server.ext <<EXT
subjectAltName = DNS:localhost, DNS:est-server, IP:127.0.0.1
EXT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile server.ext -out server.pem
cat server.pem ca.pem > server-chain.pem

gen client.key
openssl req -new -key client.key -subj "/CN=eip-bootstrap" -out client.csr
# The extension file is not decoration: `openssl x509 -req` without one mints an X.509 **v1**
# certificate, and rustls rejects a v1 client identity outright (`UnsupportedCertVersion`), so the
# adapter cannot even build its EST client config with it. Same clientAuth EKU the sibling
# ../enip-tls/gen-certs.sh gives its originator cert.
cat > client.ext <<EXT
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile client.ext -out client.pem

rm -f *.csr *.ext *.srl
echo "generated: $(ls)"
