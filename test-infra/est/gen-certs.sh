#!/usr/bin/env bash
# Generate the EST test PKI (mirrors ../enip-tls/gen-certs.sh): a root CA, an EST-server leaf (with
# SANs for how the server is dialed — 127.0.0.1 for the host live test, est-server for in-compose), and
# a bootstrap client identity the adapter authenticates with. All ECDSA P-256, all signed by the CA.
# Committed so the live_est self-skipping test and the estserver container agree on trust; NEVER real.
set -euo pipefail
cd "$(dirname "$0")/certs"
gen() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

gen ca.key
openssl req -x509 -new -key ca.key -subj "//CN=EdgeCommons EST Test Root CA" -days 3650 -out ca.pem

gen server.key
openssl req -new -key server.key -subj "//CN=est-server" -out server.csr
cat > server.ext <<EXT
subjectAltName = DNS:localhost, DNS:est-server, IP:127.0.0.1
EXT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile server.ext -out server.pem
cat server.pem ca.pem > server-chain.pem

gen client.key
openssl req -new -key client.key -subj "//CN=eip-bootstrap" -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -out client.pem

rm -f *.csr *.ext *.srl
echo "generated: $(ls)"
