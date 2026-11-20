#!/usr/bin/env bash
# Switch the lab between the four configurations compared in docs/09 §6.
#   A  perimeter      : VPN + PKI, VPN pool may reach every zone (classic VPN)
#   B  static ZT      : A's tunnel + permanent per-role rules from data.json
#   C  dynamic PDP    : PDP decides on connect, TTL rules, posture (no AI)
#   D  full           : C + AI anomaly engine in the loop (normal lab state)
# usage (from the host):  bash tests/abcd/set-config.sh A|B|C|D
# In A/B the PDP is stopped (fully out of the loop). Everything A adds is
# tagged "zt-abcd"; every switch starts from empty dynamic sets.
set -euo pipefail
CFG="${1:?usage: set-config.sh A|B|C|D}"; CFG="${CFG^^}"
[[ "$CFG" =~ ^[ABCD]$ ]] || { echo "config must be A, B, C or D" >&2; exit 64; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 120 vagrant ssh "$vm" -c "$*" 2>/dev/null; }

# B: permanent per-role elements derived from the PDP's own directory, as two
# single-line nft commands (multi-line input does not survive the SSH layer).
WEB=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["users"]; print(", ".join(u["vpn_ip"] for u in d.values()))' "$REPO/pdp/policies/data.json")
SSH=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["users"]; print(", ".join(u["vpn_ip"] for u in d.values() if u["role"]=="admin"))' "$REPO/pdp/policies/data.json")
ENFORCE=0; [[ "$CFG" == C || "$CFG" == D ]] && ENFORCE=1

echo "[*] PDP container (A/B: stopped, so its renewal loop cannot add rules)"
if [[ "$CFG" == A || "$CFG" == B ]]; then
  vs zt-pdp "sudo docker stop zt-pdp-pdp-1 >/dev/null"
else
  vs zt-pdp "sudo docker start zt-pdp-pdp-1 >/dev/null; for i in \$(seq 1 30); do sudo docker exec zt-pdp-pdp-1 true 2>/dev/null && break; sleep 1; done"
fi

echo "[*] gateway -> config $CFG (PDP_ENFORCE=$ENFORCE)"
# Restart OpenVPN first: its disconnect hooks then run before the new rules exist.
vs zt-gw "sudo sed -i 's/^PDP_ENFORCE=.*/PDP_ENFORCE=$ENFORCE/' /etc/openvpn/zt/hook.env; sudo systemctl restart openvpn-server@server; sleep 2"
vs zt-gw "for h in \$(sudo nft -a list chain inet zt forward | awk '/zt-abcd/{print \$NF}'); do sudo nft delete rule inet zt forward handle \$h; done
          for s in allow_web allow_ssh quarantine; do sudo nft flush set inet zt \$s; done"
case "$CFG" in
  A) vs zt-gw "sudo nft insert rule inet zt forward ip saddr 10.8.0.0/24 ip daddr 10.10.0.0/16 accept comment zt-abcd-perimeter" ;;
  B) vs zt-gw "sudo nft add element inet zt allow_web { $WEB }"
     [[ -n "$SSH" ]] && vs zt-gw "sudo nft add element inet zt allow_ssh { $SSH }" ;;
esac

# Servers outside the client's role have no route back to the VPN pool (least
# routing). A classic perimeter VPN routes the pool everywhere, so A adds those
# return routes and every other config removes them again.
echo "[*] return routes to the VPN pool (A only)"
for hv in db:10.10.30.1 sub-ca:10.10.99.1 siem:10.10.99.1; do
  if [[ "$CFG" == A ]]; then vs "${hv%%:*}" "sudo ip route replace 10.8.0.0/24 via ${hv##*:}"
  else vs "${hv%%:*}" "sudo ip route del 10.8.0.0/24 via ${hv##*:} 2>/dev/null; true"; fi
done

echo "[*] AI engine on the sensor"
if [[ "$CFG" == D ]]; then vs zt-sensor "sudo systemctl start zt-ai"; else vs zt-sensor "sudo systemctl stop zt-ai"; fi

echo "[*] reconnecting alice under config $CFG"
vs client-lin "sudo systemctl restart openvpn-client@alice; for i in \$(seq 1 50); do ip -br addr show tun0 2>/dev/null | grep -q 10.8.0 && break; sleep 0.3; done"
sleep 3

echo "[*] active configuration"
vs zt-gw "echo \"  PDP_ENFORCE : \$(sudo grep -oP '^PDP_ENFORCE=\K.*' /etc/openvpn/zt/hook.env)\"
          echo \"  zt-abcd     : \$(sudo nft list chain inet zt forward | grep -c zt-abcd) rule(s)\"
          for s in allow_web allow_ssh; do  # nft wraps long element lists: join lines first
            echo \"  \$s   : \$(sudo nft list set inet zt \$s | tr -s '\n\t' ' ' | grep -oE 'elements = \{[^}]*\}' || echo empty)\"; done"
echo "  zt-ai       : $(vs zt-sensor 'systemctl is-active zt-ai' || true)"
echo "  PDP         : $(vs zt-pdp "sudo docker inspect -f '{{.State.Status}}' zt-pdp-pdp-1" || true)"
echo "  alice tunnel: $(vs client-lin 'ip -br addr show tun0 2>/dev/null | awk "{print \$3}"' || echo down)"
echo "[+] lab is now in configuration $CFG"
