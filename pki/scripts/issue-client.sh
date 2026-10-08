#!/usr/bin/env bash
# Issue a short-lived client certificate (user or machine) from the Issuing CA.
#   usage: issue-client.sh <user> [days] [device-id]
# The device id is recorded in the inventory so the PDP can bind cert<->device.
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
USER="${1:?user required}"; DAYS="${2:-7}"
DEV="${3:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo dev-$RANDOM)}"
CN="${USER}@lab.local"

key="$S/private/${USER}.key"; csr="$S/csr/${USER}.csr"; crt="$S/certs/${USER}.crt"
echo "[*] Key (P-256) for $CN..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key"
chmod 400 "$key"

openssl req -config "$S/sub.cnf" -new -key "$key" -subj "/C=TN/O=ZT-Lab/CN=${CN}" -out "$csr"

echo "[*] Signing (clientAuth, $DAYS days)..."
openssl ca -config "$S/sub.cnf" -batch -extensions client_cert -days "$DAYS" \
  -notext -md sha256 -in "$csr" -out "$crt"

serial=$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)
echo "${USER},${DEV},${serial},$(date -u +%FT%TZ)" >> "$S/inventory.csv"
echo "[+] Issued: $crt  (serial $serial, device $DEV)"
