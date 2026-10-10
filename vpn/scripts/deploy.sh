#!/usr/bin/env bash
# One-shot M2 deployment: bring the VMs up in the right order, stage the PKI,
# provision the gateway (OpenVPN + nftables + hooks), build the client profile
# and provision the client. Idempotent — safe to re-run.
#
# Order matters: the gateway role deploys certs staged from sub-ca, the client
# role needs the rendered profile, and ta.key is generated on the gateway.
#
#   usage: vpn/scripts/deploy.sh [user]   (default: alice)
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO/infra"
USER="${1:-alice}"
cd "$INFRA"

echo "=== 1/6  bring up sub-ca (Issuing CA) ==="
vagrant up sub-ca

echo "=== 2/6  stage PKI material from sub-ca ==="
"$REPO/vpn/scripts/sync-pki.sh" "$USER"

echo "=== 3/6  bring up zt-gw + provision gateway (OpenVPN + nftables + hooks) ==="
vagrant up zt-gw
vagrant provision zt-gw

echo "=== 4/6  fetch ta.key from zt-gw ==="
"$REPO/vpn/scripts/sync-pki.sh" "$USER"

echo "=== 5/6  build $USER.ovpn ==="
"$REPO/vpn/scripts/make-client.sh" "$USER" 192.168.100.1 "$REPO/vpn/client"

echo "=== 6/6  bring up client-lin + provision profile ==="
vagrant up client-lin
vagrant provision client-lin

echo
echo "[+] done. Verify with:  make -C infra vpn-check"
