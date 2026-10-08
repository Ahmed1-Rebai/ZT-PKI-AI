#!/usr/bin/env bash
# Initialize the Issuing CA: directory layout, encrypted P-384 key, and a CSR
# to be signed by the Root CA (see sign-sub.sh). Run ON sub-ca.
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
PASS_OUT="${PKI_PASS:+-pass env:PKI_PASS}"
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"

mkdir -p "$S"/{certs,newcerts,private,csr,crl}
chmod 700 "$S/private"
[ -f "$S/index.txt" ] || : > "$S/index.txt"
[ -f "$S/serial" ]    || echo 2000 > "$S/serial"
[ -f "$S/crlnumber" ] || echo 2000 > "$S/crlnumber"

if [ -f "$S/private/sub.key" ]; then
  echo "Issuing CA key already exists — refusing to overwrite." >&2
  exit 1
fi

echo "[*] Generating Issuing CA key (ECDSA P-384, AES-256 encrypted)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -aes-256-cbc $PASS_OUT -out "$S/private/sub.key"
chmod 400 "$S/private/sub.key"

echo "[*] Creating Issuing CA CSR..."
openssl req -config "$S/sub.cnf" -new -sha384 \
  -key "$S/private/sub.key" $PASS_IN -out "$S/csr/sub.csr"

echo "[+] CSR ready: $S/csr/sub.csr"
echo "    Transfer it to the Root CA and run: pki/scripts/sign-sub.sh pki/sub/csr/sub.csr"
