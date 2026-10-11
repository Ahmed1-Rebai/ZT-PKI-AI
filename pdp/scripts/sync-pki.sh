#!/usr/bin/env bash
# Stage M3 runtime material from the Issuing CA VM.  This deliberately writes
# only ignored local files; it never exports the CA private key.
#
# Before first use, on sub-ca issue the gateway's *client* identity:
#   PKI_BASE=/home/vagrant PKI_PASS=... pki/scripts/issue-server.sh \
#     gw-client.lab.local gw-client.lab.local server_client_cert 90
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO/infra"
SUBCA=/home/vagrant/pki/sub
OUT="$REPO/pdp/certs"
mkdir -p "$OUT" "$REPO/pdp/ssh"

fetch() {
  local remote="$1" local="$2"
  if ! (cd "$INFRA" && vagrant ssh sub-ca -c "cat '$remote'" > "$local") || [[ ! -s "$local" ]]; then
    rm -f "$local"
    echo "Missing $remote on sub-ca" >&2
    return 1
  fi
}

fetch "$SUBCA/certs/ca-chain.crt" "$OUT/ca-chain.crt"
fetch "$SUBCA/certs/pdp.lab.local.crt" "$OUT/pdp.crt"
fetch "$SUBCA/private/pdp.lab.local.key" "$OUT/pdp.key"
fetch "$SUBCA/certs/gw-client.lab.local.crt" "$OUT/gw-client.crt"
fetch "$SUBCA/private/gw-client.lab.local.key" "$OUT/gw-client.key"
chmod 600 "$OUT"/*.key

if [[ ! -f "$REPO/pdp/ssh/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$REPO/pdp/ssh/id_ed25519" -C ztpdp@zt-pdp
fi
chmod 600 "$REPO/pdp/ssh/id_ed25519"
echo "[+] M3 certs and restricted gateway key staged under pdp/ (git-ignored)"
