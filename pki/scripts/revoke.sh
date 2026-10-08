#!/usr/bin/env bash
# Revoke a certificate and regenerate the CRL.
#   usage: revoke.sh <path-to-cert> [reason]
# reason: keyCompromise|cessationOfOperation|superseded|affiliationChanged|unspecified
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"
CRT="${1:?cert path required}"; REASON="${2:-unspecified}"

echo "[*] Revoking $CRT (reason: $REASON)..."
openssl ca -config "$S/sub.cnf" $PASS_IN -revoke "$CRT" -crl_reason "$REASON"

bash "$(dirname "$0")/gencrl.sh"
echo "[+] Revoked and CRL regenerated. Serial:"
openssl x509 -in "$CRT" -noout -serial
