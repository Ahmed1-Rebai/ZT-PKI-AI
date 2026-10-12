#!/usr/bin/env bash
# Regenerate the Issuing CA CRL and deploy it to the gateway and the proxy.
# The CRL is valid for a short time only: once it expires, OpenVPN and nginx
# refuse every certificate. Run before a demo or test session.
#   usage (from the host):  bash pki/scripts/refresh-crl.sh
# Needs sub-ca, zt-gw and web-proxy up. PKI_PASS overrides the lab passphrase.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LABPASS="${PKI_PASS:-ZtLabCA-2026}"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 120 vagrant ssh "$vm" -c "$*" 2>/dev/null; }

echo "[*] generating a new CRL on sub-ca"
vs sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/gencrl.sh" | tail -3

echo "[*] staging it for the gateway and the proxy"
bash "$REPO/vpn/scripts/sync-pki.sh" alice >/dev/null
bash "$REPO/apps/proxy/sync-pki.sh" >/dev/null

# OpenVPN re-reads crl-verify on each connection; nginx needs a reload.
echo "[*] deploying"
vs zt-gw "sudo tee /etc/openvpn/server/crl.pem >/dev/null" < "$REPO/vpn/server/pki/crl.pem"
PROXY_CRL=$(vs web-proxy "sudo grep -rhoP 'ssl_crl\s+\K[^;]+' /etc/nginx | head -1")
vs web-proxy "sudo tee $PROXY_CRL >/dev/null && sudo nginx -t 2>/dev/null && sudo systemctl reload nginx" < "$REPO/apps/proxy/pki/crl.pem"

echo "[+] deployed CRLs expire:"
echo "    gateway : $(vs zt-gw "sudo openssl crl -in /etc/openvpn/server/crl.pem -noout -nextupdate")"
echo "    proxy   : $(vs web-proxy "sudo awk '/BEGIN X509 CRL/{n++} n==2' $PROXY_CRL | openssl crl -noout -nextupdate") (Issuing CA)"
echo "    proxy   : $(vs web-proxy "sudo openssl crl -in $PROXY_CRL -noout -nextupdate") (Root CA)"
