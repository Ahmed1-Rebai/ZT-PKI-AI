#!/usr/bin/env bash
# Initialize the offline Root CA: directory layout, encrypted P-384 key,
# self-signed root certificate. Run ON root-ca (offline). Idempotent-ish:
# refuses to overwrite an existing root key.
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
R=pki/root
# Optional: set PKI_PASS to run non-interactively (lab). Default is interactive.
PASS_OUT="${PKI_PASS:+-pass env:PKI_PASS}"
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"

mkdir -p "$R"/{certs,newcerts,private,crl}
chmod 700 "$R/private"
[ -f "$R/index.txt" ] || : > "$R/index.txt"
[ -f "$R/serial" ]    || echo 1000 > "$R/serial"
[ -f "$R/crlnumber" ] || echo 1000 > "$R/crlnumber"

if [ -f "$R/private/root.key" ]; then
  echo "Root key already exists at $R/private/root.key — refusing to overwrite." >&2
  exit 1
fi

echo "[*] Generating Root CA key (ECDSA P-384, AES-256 encrypted)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -aes-256-cbc $PASS_OUT -out "$R/private/root.key"
chmod 400 "$R/private/root.key"

echo "[*] Self-signing the Root certificate (10 years)..."
openssl req -config "$R/root.cnf" -new -x509 -days 3650 -sha384 \
  -extensions v3_root_ca -key "$R/private/root.key" $PASS_IN \
  -out "$R/certs/root.crt"

openssl x509 -in "$R/certs/root.crt" -noout -subject -issuer -dates
echo "[+] Root CA ready: $R/certs/root.crt"
