#!/usr/bin/env bash
# Generate a throwaway CIP Security test PKI for the stunnel TLS terminator + the live_tls.rs suite
# (DESIGN-cip-security.md §5.2). Everything here is DISPOSABLE test material — it is gitignored and
# must NEVER be reused for anything real.
#
#   ./gen-certs.sh          # writes ca / server / client cert+key into ./certs
#
# The set:
#   ca.pem  ca.key         a self-signed test root
#   server.pem server.key  the "device" leaf, SAN = IP:127.0.0.1, DNS:localhost, DNS:enip-sim
#   client.pem client.key  the adapter's originator (mutual-TLS) cert
#   other-ca.pem           a SECOND unrelated root, for the "wrong CA is rejected" negative test
set -euo pipefail
# Disable Git-Bash-on-Windows (MSYS) POSIX->Windows path mangling of the `/CN=…` subject args.
# Harmless on Linux/macOS (an unknown env var).
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")"
mkdir -p certs
cd certs

DAYS=3650

# Ext files on disk (portable — Windows-native openssl cannot read a /dev/fd process substitution).
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:enip-sim,DNS:enip-tls\nextendedKeyUsage=serverAuth\n' > server.ext
printf 'extendedKeyUsage=clientAuth\n' > client.ext

# --- test root CA ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days "$DAYS" \
  -subj "/CN=EdgeCommons EtherNet-IP TLS Test CA"

# --- an unrelated root (for the wrong-CA negative test) ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout other-ca.key -out other-ca.pem -days "$DAYS" \
  -subj "/CN=EdgeCommons Unrelated Test CA"

# --- server (device) leaf with an IP SAN (PLCs are dialed by IP) ---
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=enip-tls-device"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem \
  -days "$DAYS" -extfile server.ext

# --- client (originator) leaf ---
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=eip-originator"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem \
  -days "$DAYS" -extfile client.ext

# --- a ROTATED originator leaf (Phase 2b): a fresh cert signed by the SAME CA, so the stunnel peer
#     (verify=2, CAfile=ca.pem) still accepts it. Distinct key + serial ⇒ the rotation is observable. ---
openssl req -newkey rsa:2048 -nodes -keyout client2.key -out client2.csr -subj "/CN=eip-originator-rotated"
openssl x509 -req -in client2.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client2.pem \
  -days "$DAYS" -extfile client.ext

# --- a NEAR-EXPIRY originator leaf (Phase 2b): valid, but only 20 days from notAfter, so the
#     cert-expiry monitor fires `cert-expiring` at the default 30-day threshold. ---
openssl req -newkey rsa:2048 -nodes -keyout client-expiring.key -out client-expiring.csr \
  -subj "/CN=eip-originator-expiring"
openssl x509 -req -in client-expiring.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client-expiring.pem -days 20 -extfile client.ext

# --- a managed TRUST STORE bundle (Phase 2b): the plant root PLUS a second (rollover) root, both
#     trusted at once — the ca.trustStore / rollover-grace shape. ---
cat ca.pem other-ca.pem > trust-store.pem

rm -f server.csr client.csr client2.csr client-expiring.csr server.ext client.ext ca.srl other-ca.key
echo "wrote test PKI into $(pwd):"
ls -1 *.pem *.key
