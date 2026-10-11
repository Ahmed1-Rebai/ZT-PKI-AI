#!/usr/bin/env bash
# Stage the PKI material the gateway and client need, from the Issuing CA VM
# (sub-ca) into git-ignored local directories that the Ansible roles pick up.
#   usage: vpn/scripts/sync-pki.sh [user]
# Run from anywhere; it locates the repo root itself. Requires the VMs to be up
# (`cd infra && vagrant up sub-ca zt-gw`) and Vagrant on PATH.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO/infra"
USER="${1:-alice}"
SUBCA=/home/vagrant/pki/sub
GW_PKI="$REPO/vpn/server/pki"
CL_PKI="$REPO/vpn/client/pki"

mkdir -p "$GW_PKI" "$CL_PKI"

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

echo "[*] CA chain + gateway certs (from sub-ca) ..."
fetch sub-ca "$SUBCA/certs/ca-chain.crt"          "$GW_PKI/ca-chain.crt"
fetch sub-ca "$SUBCA/certs/vpn-gw.lab.local.crt"  "$GW_PKI/vpn-gw.crt"
fetch sub-ca "$SUBCA/private/vpn-gw.lab.local.key" "$GW_PKI/vpn-gw.key"
fetch sub-ca "$SUBCA/crl/sub.pem"        "$GW_PKI/crl.pem"
chmod 600 "$GW_PKI/vpn-gw.key"

echo "[*] Client material for '$USER' (from sub-ca) ..."
cp -f "$GW_PKI/ca-chain.crt" "$CL_PKI/ca-chain.crt"
fetch sub-ca "$SUBCA/certs/${USER}.crt"   "$CL_PKI/${USER}.crt"
fetch sub-ca "$SUBCA/private/${USER}.key" "$CL_PKI/${USER}.key"
chmod 600 "$CL_PKI/${USER}.key"

echo "[*] tls-crypt key ..."
if [ -s "$REPO/vpn/server/ta.key" ]; then
  echo "    using existing vpn/server/ta.key"
elif vagrant ssh zt-gw -c "sudo cat /etc/openvpn/server/ta.key" 2>/dev/null > "$REPO/vpn/server/ta.key" \
     && [ -s "$REPO/vpn/server/ta.key" ]; then
  echo "    fetched from zt-gw"
else
  rm -f "$REPO/vpn/server/ta.key"
  echo "    not available yet — provision zt-gw, then re-run to fetch it"
fi

echo "[+] staged under vpn/server/pki and vpn/client/pki"
