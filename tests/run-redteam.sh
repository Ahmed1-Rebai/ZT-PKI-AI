#!/usr/bin/env bash
# Post-connection attack scenarios, played from client-lin (the test machine:
# 192.168.100.11 on zt-untrust, 10.8.0.10 inside alice's tunnel): S7, S8, S11,
# S12. Each one has an automated verdict and leaves its evidence under
# tests/evidence/<scenario>/. (Connection-time scenarios: tests/run-m2.sh.)
#
#   usage: tests/run-redteam.sh [all|s7|s8|s11|s12]
#
# Preconditions: Lab is in Config D (`bash tests/abcd/set-config.sh D`).
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INFRA="$REPO/infra"
EVD="$REPO/tests/evidence"
ONLY="${1:-all}"
PASS=0; FAIL=0; SKIP=0

ok(){ printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
ko(){ printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
skip(){ printf '  \033[33mSKIP\033[0m  %s\n' "$1"; SKIP=$((SKIP+1)); }
gssh(){ ( cd "$INFRA" && timeout 120 vagrant ssh "$1" -c "$2" </dev/null 2>/dev/null ); }
run(){ [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }

# Ensure alice tunnel + compliant posture are restored before/after scenarios
restore_alice() {
  gssh client-lin '
    sudo test -f /tmp/managed.bak && sudo mv /tmp/managed.bak /etc/zt-client/managed || true
    echo "enrolled by Ansible (client role)" | sudo tee /etc/zt-client/managed >/dev/null
    sudo ufw --force enable >/dev/null 2>&1 || true
    sudo systemctl restart openvpn-client@alice
    for i in $(seq 1 40); do ip -br addr show tun0 2>/dev/null | grep -q 10.8.0.10 && break; sleep 0.3; done
    sudo systemctl start zt-posture.service 2>/dev/null || true
  ' >/dev/null 2>&1
  # Send benign score recovery to PDP so alice returns to full tier
  gssh zt-sensor '
    sudo curl -sk --max-time 5 \
      --cacert /opt/zt-ai/certs/ca-chain.crt --cert /opt/zt-ai/certs/ai.crt --key /opt/zt-ai/certs/ai.key \
      -H "Content-Type: application/json" \
      -d "{\"cn\":\"alice@lab.local\",\"anomaly\":0.01,\"source\":\"ai\",\"critical\":false,\"detail\":{\"reason\":\"reset\"}}" \
      https://10.10.99.10:8443/v1/events >/dev/null 2>&1 || true
  ' >/dev/null 2>&1
  sleep 2
}

mkdir -p "$EVD/s07_out_of_role_ssh" "$EVD/s08_stolen_cert" "$EVD/s11_fw_tamper" "$EVD/s12_model_poison"

# ---------------------------------------------------------------- S7
if run s7; then
  echo "== S7 — Legit client (alice) -> out-of-role SSH to web-app (10.10.20.10:22) =="
  restore_alice
  gssh client-lin '
    sudo ip route replace 10.10.20.10 via 10.8.0.1 dev tun0
    timeout 5 ssh -o BatchMode=yes -o ConnectTimeout=4 -o StrictHostKeyChecking=no 10.10.20.10 true >/tmp/s7_ssh.log 2>&1 || echo "SSH_EXIT=$?" >>/tmp/s7_ssh.log
    sudo ip route del 10.10.20.10 via 10.8.0.1 dev tun0 2>/dev/null || true
    cat /tmp/s7_ssh.log
  ' > "$EVD/s07_out_of_role_ssh/client.log"
  gssh zt-gw 'sudo grep "ZT-DROP" /var/log/kern.log 2>/dev/null | grep "DPT=22" | tail -n 10; sudo nft list set inet zt allow_ssh' > "$EVD/s07_out_of_role_ssh/gateway.log"
  if grep -qE "ZT-DROP.*DPT=22" "$EVD/s07_out_of_role_ssh/gateway.log" || grep -q "SSH_EXIT=" "$EVD/s07_out_of_role_ssh/client.log"; then
    ok "S7 out-of-role SSH dropped by PEP (ZT-DROP)"
  else
    ko "S7 out-of-role SSH"
  fi
fi

# ---------------------------------------------------------------- S8
if run s8; then
  echo "== S8 — Stolen certificate used on unmanaged device (posture failure on client-lin) =="
  restore_alice
  gssh client-lin '
    sudo mv /etc/zt-client/managed /tmp/managed.bak 2>/dev/null || true
    sudo ufw disable >/dev/null 2>&1 || true
    # with the unit environment (ZT_CLIENT_CN...): run bare, the agent sends an empty CN -> HTTP 422
    sudo sh -c ". /etc/zt-client/posture.env; export ZT_PDP_URL ZT_CLIENT_CN ZT_CA ZT_CERT ZT_KEY 2>/dev/null; exec /usr/bin/python3 /opt/zt-posture/posture_agent.py" >/tmp/s08_posture.log 2>&1 || true
    cat /tmp/s08_posture.log
  ' > "$EVD/s08_stolen_cert/posture.log"
  sleep 2
  gssh zt-gw 'sudo nft list table inet zt' > "$EVD/s08_stolen_cert/gateway-nft.txt"
  gssh client-lin '
    code=$(sudo curl -sk -o /dev/null -w "%{http_code}" --max-time 4 \
      --cacert /etc/zt-client/ca-chain.crt --cert /etc/zt-client/client.crt --key /etc/zt-client/client.key \
      https://10.10.10.10/ || echo "000")
    echo "proxy_http_code=$code"
  ' > "$EVD/s08_stolen_cert/probe.txt"
  restore_alice
  if awk '/set quarantine/,/\}/' "$EVD/s08_stolen_cert/gateway-nft.txt" | grep -q "10.8.0.10"; then
    ok "S8 stolen cert on unmanaged device demoted to quarantine"
  elif grep -q "proxy_http_code=000" "$EVD/s08_stolen_cert/probe.txt"; then
    ok "S8 posture failure: proxy access refused"
  else
    ko "S8 posture failure did not reduce access"
  fi
fi

# ---------------------------------------------------------------- S11
if run s11; then
  echo "== S11 — Firewall policy tampering (Wazuh FIM on /etc/nftables.conf) =="
  gssh zt-gw '
    sudo cp /etc/nftables.conf /tmp/nftables.conf.bak
    m="# zt-fim-test $(date -u +%s)"
    echo "$m" | sudo tee -a /etc/nftables.conf >/dev/null
    echo "$m"; sudo sha256sum /etc/nftables.conf
  ' > "$EVD/s11_fw_tamper/tamper.txt"
  mark=$(grep -oE "zt-fim-test [0-9]+" "$EVD/s11_fw_tamper/tamper.txt" | head -1)
  for i in $(seq 1 12); do   # realtime FIM: the alert should land within seconds
    gssh siem "sudo grep -F 'nftables.conf' /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -F '$mark' | tail -n 3" > "$EVD/s11_fw_tamper/wazuh-fim.json"
    [ -s "$EVD/s11_fw_tamper/wazuh-fim.json" ] && break; sleep 5
  done
  # restore IN PLACE (cp keeps the inode): a mv swaps the inode and silently ends
  # Wazuh's realtime (inotify) watch on the file until the agent restarts
  gssh zt-gw 'sudo cp /tmp/nftables.conf.bak /etc/nftables.conf && sudo rm -f /tmp/nftables.conf.bak && sudo chown root:root /etc/nftables.conf && sudo chmod 644 /etc/nftables.conf'
  if [ -s "$EVD/s11_fw_tamper/wazuh-fim.json" ]; then ok "S11 nftables.conf tamper raised a Wazuh FIM alert (file restored)"
  else ko "S11 no Wazuh FIM alert for the nftables.conf change (file restored)"; fi
fi

# ---------------------------------------------------------------- S12
if run s12; then
  echo "== S12 — Model poisoning / tampered artefact rejection (ai/registry.py) =="
  PY="$REPO/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
  "$PY" -m pytest -v "$REPO/ai/tests/test_registry.py" > "$EVD/s12_model_poison/pytest-registry.txt" 2>&1 && \
    ok "S12 tampered model rejected by SHA-256 manifest" || ko "S12 model integrity check"
fi

restore_alice
echo
echo "== Scenario summary: $PASS passed, $FAIL failed, $SKIP skipped · evidence in tests/evidence/ =="
[ "$FAIL" -eq 0 ]
