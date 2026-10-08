#!/usr/bin/env bash
# (Re)generate the Issuing CA CRL (run hourly via cron + on every revocation).
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
mkdir -p "$S/crl"

openssl ca -config "$S/sub.cnf" -gencrl -out "$S/crl/sub.crl"
openssl crl -in "$S/crl/sub.crl" -outform PEM -out "$S/crl/sub.pem"
echo "[+] CRL: $S/crl/sub.pem"
openssl crl -in "$S/crl/sub.pem" -noout -lastupdate -nextupdate
