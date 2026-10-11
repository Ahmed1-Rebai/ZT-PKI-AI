#!/usr/bin/env bash
# Stage the DMZ proxy's mTLS material from the Issuing CA VM (sub-ca) into a
# git-ignored local directory that the `proxy` Ansible role picks up.
#   usage: apps/proxy/sync-pki.sh
# Requires sub-ca up (`cd infra && vagrant up sub-ca`).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO/infra"
SUBCA=/home/vagrant/pki/sub
OUT="$REPO/apps/proxy/pki"

mkdir -p "$OUT"

fetch() {  # fetch <vm> <remote-path> <local-path>
  local vm="$1" path="$2" out="$3"
  # Fetch to a temp file: a failed fetch must never destroy the staged copy.
  if vagrant ssh "$vm" -c "cat '$path'" 2>/dev/null > "$out.tmp" && [ -s "$out.tmp" ]; then
    mv -f "$out.tmp" "$out"
    return 0
  fi
  rm -f "$out.tmp"
  echo "    missing: $path (on $vm) — kept existing $(basename "$out")" >&2
  return 1
}

cd "$INFRA"
echo "[*] Proxy mTLS material (from sub-ca) ..."
fetch sub-ca "$SUBCA/certs/ca-chain.crt"              "$OUT/ca-chain.crt"
fetch sub-ca "$SUBCA/certs/proxy.lab.local.crt"       "$OUT/proxy.lab.local.crt"
fetch sub-ca "$SUBCA/private/proxy.lab.local.key"     "$OUT/proxy.lab.local.key"
chmod 600 "$OUT/proxy.lab.local.key"

# nginx validates the CRL for EVERY cert in the client chain (CRL_CHECK_ALL),
# so the bundle must contain both the Issuing CA and Root CA CRLs. The Root CRL
# is generated on the offline root-ca and published to sub-ca (pki/root/crl).
fetch sub-ca "$SUBCA/crl/sub.pem"                 "$OUT/.sub-crl.pem"
fetch sub-ca "/home/vagrant/pki/root/crl/root.pem" "$OUT/.root-crl.pem"
cat "$OUT/.root-crl.pem" "$OUT/.sub-crl.pem" > "$OUT/crl.pem"
rm -f "$OUT/.sub-crl.pem" "$OUT/.root-crl.pem"
echo "[+] bundled $(grep -c 'BEGIN X509 CRL' "$OUT/crl.pem") CRLs into crl.pem"
echo "[+] staged under apps/proxy/pki"
