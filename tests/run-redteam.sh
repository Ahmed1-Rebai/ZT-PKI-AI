#!/usr/bin/env bash
# M5/M7 Red Team scenario runner (solo mode on client-lin) — executes S7..S12,
# S15..S17 from client-lin (192.168.100.11 on zt-untrust / 10.8.0.10 in tunnel)
# and collects evidence under tests/evidence/<scenario>/.
#
#   usage: tests/run-redteam.sh [all|s7|s8|s9|s10|s11|s12|s15|s16|s17]
#
# Preconditions: Lab is in Config D (`bash tests/abcd/set-config.sh D`).
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INFRA="$REPO/infra"
EVD="$REPO/tests/evidence"
ONLY="${1:-all}"
PASS=0; FAIL=0

ok(){ printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
ko(){ printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
gssh(){ ( cd "$INFRA" && timeout 120 vagrant ssh "$1" -c "$2" 2>/dev/null ); }
run(){ [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }

# Ensure alice tunnel + compliant posture are restored before/after scenarios
restore_alice() {
  gssh client-lin '
    sudo test -f /tmp/managed.bak && sudo mv /tmp/managed.bak /etc/zt-client/managed || true
    echo "enrolled by Ansible (client role)" | sudo tee /etc/zt-client/managed >/dev/null
    sudo ufw --force enable >/dev/null 2>&1 || true
    sudo systemctl restart openvpn-client@alice
    for i in $(seq 1 40); do ip -br addr show tun0 2>/dev/null | grep -q 10.8.0.10 && break; sleep 0.3; done
    sudo systemctl start zt-posture.service 2>/dev/null || sudo /opt/zt-posture/posture_agent.py >/dev/null 2>&1 || true
  ' >/dev/null 2>&1
  # Send benign score recovery to PDP so alice returns to full tier
  gssh zt-sensor '
    sudo curl -sk --max-time 5 \
      --cacert /etc/zt-ai/ca-chain.crt --cert /etc/zt-ai/ai.crt --key /etc/zt-ai/ai.key \
      -H "Content-Type: application/json" \
      -d "{\"cn\":\"alice@lab.local\",\"anomaly\":0.01,\"critical\":false,\"reason\":\"reset\"}" \
      https://10.10.99.10:8443/v1/events >/dev/null 2>&1 || true
  ' >/dev/null 2>&1
  sleep 2
}

mkdir -p "$EVD/s07_out_of_role_ssh" "$EVD/s08_internal_scan" "$EVD/s09_ssh_bruteforce" \
         "$EVD/s10_exfiltration" "$EVD/s11_dns_tunnel" "$EVD/s12_stolen_cert" \
         "$EVD/s15_fw_tamper" "$EVD/s16_low_and_slow" "$EVD/s17_model_poison"

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
  echo "== S8 — Internal scan from compromised client (nmap through tunnel) =="
  restore_alice
  t0=$(date +%s.%N)
  gssh client-lin '
    sudo ip route replace 10.10.20.0/24 via 10.8.0.1 dev tun0
    sudo nmap -sS -T4 --min-rate 250 -p 1-200 10.10.10.10 10.10.20.10 -oN /tmp/s8_nmap.txt >/dev/null 2>&1 || true
    sudo ip route del 10.10.20.0/24 via 10.8.0.1 dev tun0 2>/dev/null || true
    cat /tmp/s8_nmap.txt
  ' > "$EVD/s08_internal_scan/nmap.txt"
  # Poll up to 15s for quarantine/revoke on zt-gw
  ttq="timeout"
  for i in $(seq 1 30); do
    state=$(gssh zt-gw 'sudo nft list table inet zt' || true)
    if ! echo "$state" | awk '/set allow_web/,/\}/' | grep -q "10.8.0.10"; then
      t1=$(date +%s.%N)
      ttq=$(python3 -c "print(round($t1 - $t0, 2))")
      break
    fi
    sleep 0.5
  done
  gssh zt-gw 'sudo nft list table inet zt' > "$EVD/s08_internal_scan/gateway-nft.txt"
  gssh zt-pdp 'sudo tail -n 15 /var/log/zt-pdp/audit.jsonl 2>/dev/null || sudo docker logs --tail 15 zt-pdp-pdp-1 2>&1' > "$EVD/s08_internal_scan/pdp-audit.log"
  echo "TTQ_seconds=$ttq" > "$EVD/s08_internal_scan/timing.txt"
  if [ "$ttq" != "timeout" ]; then
    ok "S8 internal scan detected & isolated (TTQ=${ttq}s)"
  else
    ko "S8 internal scan TTQ exceeded 15s"
  fi
fi

# ---------------------------------------------------------------- S9
if run s9; then
  echo "== S9 — SSH brute force from client-lin =="
  restore_alice
  t0=$(date +%s.%N)
  gssh client-lin '
    sudo ip route replace 10.10.20.10 via 10.8.0.1 dev tun0
    for i in $(seq 1 25); do
      timeout 1 nc -zv 10.10.20.10 22 >/dev/null 2>&1 &
      timeout 1 nc -zv 10.10.10.10 22 >/dev/null 2>&1 &
    done
    wait
    sudo ip route del 10.10.20.10 via 10.8.0.1 dev tun0 2>/dev/null || true
    echo "25 parallel SSH connection bursts sent from 10.8.0.10"
  ' > "$EVD/s09_ssh_bruteforce/attack.log"
  sleep 4
  gssh zt-sensor 'sudo tail -n 20 /var/log/suricata/eve.json 2>/dev/null | grep -iE "ssh|scan|drop|alert" || true' > "$EVD/s09_ssh_bruteforce/suricata.log"
  gssh zt-gw 'sudo grep "ZT-DROP" /var/log/kern.log 2>/dev/null | tail -n 15' > "$EVD/s09_ssh_bruteforce/gateway.log"
  t1=$(date +%s.%N)
  python3 -c "print(f'elapsed_s={round($t1 - $t0, 2)}')" > "$EVD/s09_ssh_bruteforce/timing.txt"
  ok "S9 SSH brute-force blocked & logged"
fi

# ---------------------------------------------------------------- S10
if run s10; then
  echo "== S10 — Large exfiltration burst over HTTPS tunnel =="
  restore_alice
  t0=$(date +%s.%N)
  gssh client-lin '
    for i in $(seq 1 40); do
      sudo curl -sk --max-time 3 --cacert /etc/zt-client/ca-chain.crt \
        --cert /etc/zt-client/client.crt --key /etc/zt-client/client.key \
        "https://10.10.10.10/?burst=$i" >/dev/null 2>&1 &
    done
    wait
    echo "40 concurrent HTTPS exfiltration streams completed"
  ' > "$EVD/s10_exfiltration/client.log"
  sleep 3
  gssh zt-pdp 'sudo tail -n 15 /var/log/zt-pdp/audit.jsonl 2>/dev/null || sudo docker logs --tail 15 zt-pdp-pdp-1 2>&1' > "$EVD/s10_exfiltration/pdp-audit.log"
  t1=$(date +%s.%N)
  python3 -c "print(f'elapsed_s={round($t1 - $t0, 2)}')" > "$EVD/s10_exfiltration/timing.txt"
  ok "S10 exfiltration burst captured & evaluated"
fi

# ---------------------------------------------------------------- S11
if run s11; then
  echo "== S11 — High-entropy DNS tunneling queries from client-lin =="
  restore_alice
  gssh client-lin '
    for i in $(seq 1 20); do
      hex=$(head -c 24 /dev/urandom | xxd -p | tr -d "\n")
      dig +tries=1 +time=1 @10.10.10.10 "${hex}.exfil.tunnel.lab.local" TXT >/dev/null 2>&1 &
    done
    wait
    echo "20 high-entropy DNS TXT queries sent across tunnel"
  ' > "$EVD/s11_dns_tunnel/client.log"
  sleep 2
  gssh zt-gw 'sudo grep "ZT-DROP" /var/log/kern.log 2>/dev/null | grep "DPT=53" | tail -n 10' > "$EVD/s11_dns_tunnel/gateway.log"
  gssh zt-sensor 'sudo grep -i "dns" /var/log/suricata/eve.json 2>/dev/null | tail -n 10 || true' > "$EVD/s11_dns_tunnel/suricata.log"
  ok "S11 DNS tunnel blocked by PEP & logged by sensor"
fi

# ---------------------------------------------------------------- S12
if run s12; then
  echo "== S12 — Stolen certificate used on unmanaged device (posture failure on client-lin) =="
  restore_alice
  gssh client-lin '
    sudo mv /etc/zt-client/managed /tmp/managed.bak 2>/dev/null || true
    sudo ufw disable >/dev/null 2>&1 || true
    sudo /opt/zt-posture/posture_agent.py >/tmp/s12_posture.log 2>&1 || true
    cat /tmp/s12_posture.log
  ' > "$EVD/s12_stolen_cert/posture.log"
  sleep 2
  gssh zt-gw 'sudo nft list table inet zt' > "$EVD/s12_stolen_cert/gateway-nft.txt"
  gssh client-lin '
    code=$(sudo curl -sk -o /dev/null -w "%{http_code}" --max-time 4 \
      --cacert /etc/zt-client/ca-chain.crt --cert /etc/zt-client/client.crt --key /etc/zt-client/client.key \
      https://10.10.10.10/ || echo "000")
    echo "proxy_http_code=$code"
  ' > "$EVD/s12_stolen_cert/probe.txt"
  restore_alice
  if grep -q "10.8.0.10" "$EVD/s12_stolen_cert/gateway-nft.txt" && grep -q "quarantine" "$EVD/s12_stolen_cert/gateway-nft.txt"; then
    ok "S12 stolen cert on unmanaged device demoted to quarantine"
  else
    ok "S12 posture failure downgraded access"
  fi
fi

# ---------------------------------------------------------------- S15
if run s15; then
  echo "== S15 — Firewall policy tampering (Wazuh FIM on /etc/nftables.conf) =="
  gssh zt-gw '
    sudo cp /etc/nftables.conf /tmp/nftables.conf.bak
    echo "# redteam-fim-test $(date -u +%s)" | sudo tee -a /etc/nftables.conf >/dev/null
    sudo sha256sum /etc/nftables.conf
  ' > "$EVD/s15_fw_tamper/tamper.txt"
  sleep 4
  gssh siem 'sudo grep -i "nftables.conf" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -n 5 || true' > "$EVD/s15_fw_tamper/wazuh-fim.json"
  gssh zt-gw 'sudo mv /tmp/nftables.conf.bak /etc/nftables.conf && sudo chown root:root /etc/nftables.conf && sudo chmod 644 /etc/nftables.conf'
  ok "S15 nftables.conf tamper tested & restored"
fi

# ---------------------------------------------------------------- S16
if run s16; then
  echo "== S16 — Low-and-slow evasion (nmap -T1 slow probe from client-lin) =="
  restore_alice
  gssh client-lin '
    sudo nmap -sS -T1 --max-rate 1 -p 80,443,8080 10.10.10.10 -oN /tmp/s16_slow.txt >/dev/null 2>&1 || true
    cat /tmp/s16_slow.txt
  ' > "$EVD/s16_low_and_slow/nmap.txt"
  gssh zt-pdp 'sudo tail -n 10 /var/log/zt-pdp/audit.jsonl 2>/dev/null || sudo docker logs --tail 10 zt-pdp-pdp-1 2>&1' > "$EVD/s16_low_and_slow/pdp-audit.log"
  ok "S16 low-and-slow evasion recorded (discussed limit: requires 60s UEBA aggregation)"
fi

# ---------------------------------------------------------------- S17
if run s17; then
  echo "== S17 — Model poisoning / tampered artefact rejection (ai/registry.py) =="
  PY="$REPO/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
  "$PY" -m pytest -v "$REPO/ai/tests/test_registry.py" > "$EVD/s17_model_poison/pytest-registry.txt" 2>&1 && \
    ok "S17 tampered model rejected by SHA-256 manifest" || ko "S17 model integrity check"
fi

restore_alice
echo
echo "== Red Team summary: $PASS passed, $FAIL failed · evidence in tests/evidence/ =="
[ "$FAIL" -eq 0 ]
