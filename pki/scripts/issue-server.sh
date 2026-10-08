#!/usr/bin/env bash
# Issue a server (or server+client) certificate from the Issuing CA.
#   usage: issue-server.sh <CN> <DNS[,DNS...][,IP:addr...]> [ext] [days]
#   ext defaults to server_cert; use server_client_cert for PDP/proxy/ai (mTLS).
# Example:
#   issue-server.sh vpn-gw.lab.local vpn-gw.lab.local,IP:192.168.100.1 server_cert 365
#   issue-server.sh pdp.lab.local    pdp.lab.local,IP:10.10.99.10 server_client_cert 365
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
CN="${1:?CN required}"; SANS="${2:?SAN list required}"; EXT="${3:-server_cert}"; DAYS="${4:-365}"

# Build the SAN string for -addext (DNS.* / IP.*). Accept "name" or "IP:addr".
san=""
IFS=',' read -ra parts <<< "$SANS"
for p in "${parts[@]}"; do
  if [[ "$p" == IP:* ]]; then san+="${san:+,}IP:${p#IP:}"; else san+="${san:+,}DNS:${p}"; fi
done

key="$S/private/${CN}.key"; csr="$S/csr/${CN}.csr"; crt="$S/certs/${CN}.crt"
echo "[*] Key (P-256) for $CN..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key"
chmod 400 "$key"

echo "[*] CSR with SAN=$san ..."
openssl req -config "$S/sub.cnf" -new -key "$key" -subj "/C=TN/O=ZT-Lab/CN=${CN}" \
  -addext "subjectAltName=${san}" -out "$csr"

echo "[*] Signing ($EXT, $DAYS days)..."
openssl ca -config "$S/sub.cnf" -batch -extensions "$EXT" -days "$DAYS" \
  -notext -md sha256 -in "$csr" -out "$crt"

openssl x509 -in "$crt" -noout -subject -ext subjectAltName,extendedKeyUsage
echo "[+] Issued: $crt"
