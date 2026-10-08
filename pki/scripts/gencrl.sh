#!/usr/bin/env bash
# (Re)generate the Issuing CA CRL (run hourly via cron + on every revocation).
set -euo pipefail
BASE="${PKI_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$BASE"
S=pki/sub
PASS_IN="${PKI_PASS:+-passin env:PKI_PASS}"
mkdir -p "$S/crl"

openssl ca -config "$S/sub.cnf" $PASS_IN -gencrl -out "$S/crl/sub.crl"
openssl crl -in "$S/crl/sub.crl" -outform PEM -out "$S/crl/sub.pem"

# Publish the DER CRL to the HTTP web root (served at http://10.10.99.5/crl/sub.crl)
# so the crlDistributionPoints URI in the leaf certs resolves. Set CRL_PUBLISH to
# override; skipped silently if the dir does not exist.
PUB="${CRL_PUBLISH:-/home/vagrant/crlpub/crl}"
if [ -d "$PUB" ]; then cp -f "$S/crl/sub.crl" "$PUB/sub.crl" && echo "[+] published -> $PUB/sub.crl"; fi

echo "[+] CRL: $S/crl/sub.pem"
openssl crl -in "$S/crl/sub.pem" -noout -lastupdate -nextupdate
