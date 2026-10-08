#!/usr/bin/env bash
# Sign the Issuing CA CSR with the Root CA. Run ON root-ca (offline).
# Produces the Issuing CA cert and the CA chain. Transfer both back to sub-ca.
#   usage: sign-sub.sh <path-to-sub.csr>
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
R=pki/root
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"
CSR="${1:?usage: sign-sub.sh <sub.csr>}"

echo "[*] Root is signing the Issuing CA (3 years, pathlen:0)..."
openssl ca -config "$R/root.cnf" -batch $PASS_IN -extensions v3_intermediate_ca \
  -days 1095 -notext -md sha384 -in "$CSR" -out "$R/certs/sub.crt"

cat "$R/certs/sub.crt" "$R/certs/root.crt" > "$R/certs/ca-chain.crt"

echo "[*] Verifying the chain..."
openssl verify -CAfile "$R/certs/root.crt" "$R/certs/sub.crt"
echo "[+] Issuing CA cert: $R/certs/sub.crt"
echo "[+] CA chain:        $R/certs/ca-chain.crt"
echo "    Copy sub.crt and ca-chain.crt back to sub-ca under pki/sub/certs/."
