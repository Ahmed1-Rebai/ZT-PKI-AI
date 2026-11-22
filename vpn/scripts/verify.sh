#!/usr/bin/env bash
# VPN + gateway verification (M2 controls, in the enforced M3+ mode): exercises
# the controls against the lab and prints PASS/FAIL for each. Non-destructive where possible; the revoked-cert
# check re-issues alice's certificate afterwards.
#
#   usage: vpn/scripts/verify.sh            (safe checks only)
#          vpn/scripts/verify.sh --full     (also S3 revoked + S10 fail-closed)
#
# Preconditions: `make vpn` has run; sub-ca / zt-gw / client-lin are up and
# provisioned. Run from the repo root or via `make -C infra vpn-check`.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO/infra"
LABPASS="${PKI_PASS:-ZtLabCA-2026}"
FULL="${1:-}"
PASS=0; FAIL=0
ok() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
ko() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
gssh() { ( cd "$INFRA" && vagrant ssh "$1" -c "$2" 2>/dev/null ); }
cd "$INFRA"

echo "== [1] Gateway services & firewall =="
gssh zt-gw 'systemctl is-active --quiet openvpn-server@server' && ok "OpenVPN server active" || ko "OpenVPN server active"
gssh zt-gw "ss -lun | grep -q ':1194'" && ok "UDP/1194 listening" || ko "UDP/1194 listening"
gssh zt-gw 'sudo nft list chain inet zt_input input 2>/dev/null | grep -q "policy drop"' && ok "input chain deny-by-default" || ko "input chain deny-by-default"
gssh zt-gw 'sudo nft list chain inet zt forward 2>/dev/null | grep -q "policy drop"' && ok "forward chain deny-by-default" || ko "forward chain deny-by-default"
gssh zt-gw 'sudo grep -q "^PDP_ENFORCE=1" /etc/openvpn/zt/hook.env' && ok "hook mode = enforced, fail-closed (PDP_ENFORCE=1)" || ko "hook mode = enforced (PDP_ENFORCE=1)"

echo "== [2] Valid client connects (S-valid) =="
gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1'
gssh client-lin 'sudo openvpn --config /etc/openvpn/client/alice.conf --daemon ztcheck'
sleep 8
VPNIP="$(gssh client-lin "ip -4 addr show tun0 2>/dev/null | awk '/inet /{print \$2}'")"
if [ -n "$VPNIP" ]; then ok "tunnel up, fixed IP = $VPNIP"; else ko "tunnel up (no tun0 address)"; fi
# The only subnet-wide rule allowed is the posture channel to the PDP API.
gssh zt-gw 'sudo nft list chain inet zt forward | grep "10.8.0.0/24" | grep -vq "ip daddr 10.10.99.10 tcp dport 8443 accept"' \
  && ko "forward chain leaks the VPN subnet" || ok "forward chain isolates the VPN subnet (only the posture channel)"

echo "== [3] S1 — no client certificate =="
gssh client-lin 'sudo cp /etc/openvpn/client/alice.conf /tmp/alice.ro && sudo chmod 644 /tmp/alice.ro; set -e
  awk "/<ca>/{f=1} f{print} /<\/ca>/{f=0}" /tmp/alice.ro > /tmp/nocert.conf
  echo client >> /tmp/nocert.conf; echo dev tun >> /tmp/nocert.conf
  echo "proto udp" >> /tmp/nocert.conf; echo "remote 192.168.100.1 1194" >> /tmp/nocert.conf
  echo "remote-cert-tls server" >> /tmp/nocert.conf; echo "tls-version-min 1.3" >> /tmp/nocert.conf
  awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro >> /tmp/nocert.conf'
gssh client-lin 'sudo timeout 15 openvpn --config /tmp/nocert.conf --connect-retry-max 1 >/tmp/nocert.log 2>&1'; rc=$?
[ "$rc" -ne 0 ] && ok "handshake refused without a cert" || ko "handshake refused without a cert (rc=$rc)"

echo "== [4] S2 — certificate from a rogue CA =="
gssh client-lin 'set -e; D=/tmp/rogue; rm -rf $D; mkdir -p $D; cd $D
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj "/CN=Rogue CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=eve@lab.local" -keyout cli.key -out cli.csr 2>/dev/null
  openssl x509 -req -in cli.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
    -extfile <(printf "extendedKeyUsage=clientAuth") -out cli.crt 2>/dev/null
  { echo client; echo "dev tun"; echo "proto udp"; echo "remote 192.168.100.1 1194";
    echo "remote-cert-tls server"; echo "tls-version-min 1.3";
    echo "<ca>"; cat ca.crt; echo "</ca>";
    echo "<cert>"; cat cli.crt; echo "</cert>";
    echo "<key>"; cat cli.key; echo "</key>";
    awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro; } > $D/eve.conf'
gssh client-lin 'sudo timeout 15 openvpn --config /tmp/rogue/eve.conf --connect-retry-max 1 >/tmp/rogue.log 2>&1'; rc=$?
[ "$rc" -ne 0 ] && ok "rogue-CA cert refused" || ko "rogue-CA cert refused (rc=$rc)"

if [ "$FULL" = "--full" ]; then
  echo "== [5] S3 — revoked certificate (refusal < 60 s) =="
  t0=$(date +%s)
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/revoke.sh pki/sub/certs/alice.crt keyCompromise >/dev/null 2>&1 && bash pki/scripts/gencrl.sh >/dev/null 2>&1 && echo revoked"
  "$REPO/vpn/scripts/sync-pki.sh" alice >/dev/null 2>&1
  ( cd "$INFRA" && vagrant provision zt-gw >/dev/null 2>&1 )
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1'
  gssh client-lin 'sudo openvpn --config /etc/openvpn/client/alice.conf --daemon ztcheck2'
  sleep 8
  gssh client-lin 'ip link show tun0 >/dev/null 2>&1' && ko "revoked cert still connects" || ok "revoked cert refused ($(( $(date +%s)-t0 ))s)"
  # restore a valid alice
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/issue-client.sh alice 7 laptop-01 >/dev/null 2>&1 && bash pki/scripts/gencrl.sh >/dev/null 2>&1 && sudo systemctl restart zt-ocsp.service >/dev/null 2>&1"
  "$REPO/vpn/scripts/sync-pki.sh" alice >/dev/null 2>&1
  "$REPO/vpn/scripts/make-client.sh" alice 192.168.100.1 "$REPO/vpn/client" >/dev/null 2>&1
  ( cd "$INFRA" && vagrant provision zt-gw >/dev/null 2>&1 && vagrant provision client-lin >/dev/null 2>&1 )
  echo "  (alice re-issued and redeployed)"

  echo "== [6] S10 — PDP down => fail-closed =="
  gssh zt-pdp "sudo docker stop zt-pdp-pdp-1" >/dev/null 2>&1
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo openvpn --config /etc/openvpn/client/alice.conf --daemon ztcheck3'
  sleep 8
  gssh client-lin 'ip link show tun0 >/dev/null 2>&1' && ko "PDP down still allowed access" || ok "PDP down => connection refused (fail-closed)"
  gssh zt-pdp "sudo docker start zt-pdp-pdp-1" >/dev/null 2>&1
  echo "  (PDP restarted)"
fi

# Back to the managed tunnel (the checks above ran their own openvpn processes).
gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo systemctl restart openvpn-client@alice; true' >/dev/null 2>&1
echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
