#!/usr/bin/env bash
# Renew a leaf certificate before expiry (keeps the same key).
#   usage: renew.sh <existing-cert> [days]
# Re-issues using the same CN/SAN; old cert should then be revoked if needed.
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"
CRT="${1:?cert path required}"; DAYS="${2:-365}"

CN=$(openssl x509 -in "$CRT" -noout -subject -nameopt multiline | awk -F' = ' '/commonName/{print $2}')
# Leaf keys live in pki/sub/private/<name>.key (same basename as the cert file).
name=$(basename "${CRT%.crt}"); key="$S/private/${name}.key"
[ -f "$key" ] || { echo "key $key not found" >&2; exit 1; }

# Detect EKU to pick the extension profile.
eku=$(openssl x509 -in "$CRT" -noout -ext extendedKeyUsage 2>/dev/null | tr -d ' ')
if   echo "$eku" | grep -q 'ServerAuthentication.*ClientAuthentication'; then EXT=server_client_cert
elif echo "$eku" | grep -q 'ServerAuthentication'; then EXT=server_cert
else EXT=client_cert; fi

csr="$S/csr/${name}.renew.csr"
openssl req -config "$S/sub.cnf" -new -key "$key" -subj "/C=TN/O=ZT-Lab/CN=${CN}" -out "$csr"
openssl ca -config "$S/sub.cnf" -batch $PASS_IN -extensions "$EXT" -days "$DAYS" \
  -notext -md sha256 -in "$csr" -out "$CRT"
echo "[+] Renewed $CN ($EXT, $DAYS days)"
