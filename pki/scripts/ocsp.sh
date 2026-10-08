#!/usr/bin/env bash
# Run the OCSP responder for the Issuing CA on :2560. Run ON sub-ca.
# Requires an OCSP signer cert (ocsp_cert profile). Foreground; use systemd in prod.
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"

# Create the OCSP signer if missing.
if [ ! -f "$S/certs/ocsp.crt" ]; then
  echo "[*] Creating OCSP signer cert..."
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$S/private/ocsp.key"
  chmod 400 "$S/private/ocsp.key"
  openssl req -config "$S/sub.cnf" -new -key "$S/private/ocsp.key" \
    -subj "/C=TN/O=ZT-Lab/CN=ocsp.lab.local" -out "$S/csr/ocsp.csr"
  openssl ca -config "$S/sub.cnf" -batch $PASS_IN -extensions ocsp_cert -days 90 \
    -notext -md sha256 -in "$S/csr/ocsp.csr" -out "$S/certs/ocsp.crt"
fi

echo "[*] OCSP responder on 0.0.0.0:2560 (Ctrl-C to stop)..."
exec openssl ocsp -port 2560 -text \
  -index "$S/index.txt" -CA "$S/certs/ca-chain.crt" \
  -rkey "$S/private/ocsp.key" -rsigner "$S/certs/ocsp.crt"
