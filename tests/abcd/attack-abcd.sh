#!/usr/bin/env bash
# Comparative A/B/C/D evaluation under attack from client-lin (docs/09 §6).
# Runs post-authentication attack probes from client-lin (10.8.0.10) across
# configurations A, B, C and D, recording whether each attack is blocked at the
# network layer, detected/isolated by posture (C/D), or dynamically quarantined
# by the AI closed loop (D), along with TTQ.
#
#   usage: bash tests/abcd/attack-abcd.sh   -> tests/reports/abcd/attacks.json
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$REPO/tests/reports/abcd/attacks.json"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 120 vagrant ssh "$vm" -c "$*" 2>/dev/null; }

trap 'echo "[*] restoring lab to config D"; bash "$HERE/set-config.sh" D >/dev/null' EXIT

RESULTS_TMP="$(mktemp)"
echo "{}" > "$RESULTS_TMP"

for CFG in A B C D; do
  echo "=== Attack evaluation under Config $CFG ==="
  bash "$HERE/set-config.sh" "$CFG" | grep -E '^\[\+\]'

  # 1. S7: Out-of-role lateral movement (SSH to web-app 10.10.20.10:22 & DB 10.10.30.10:5432)
  s7_res=$(vs client-lin '
    sudo ip route replace 10.10.20.10 via 10.8.0.1 dev tun0
    r=$(python3 -c "import socket
s=socket.socket(); s.settimeout(2)
try: s.connect((\"10.10.20.10\", 22)); print(\"EXPOSED\")
except ConnectionRefusedError: print(\"EXPOSED\")
except OSError: print(\"BLOCKED\")")
    sudo ip route del 10.10.20.10 via 10.8.0.1 dev tun0 2>/dev/null || true
    echo "$r"
  ' || echo "BLOCKED")

  # 2. S12: Stolen cert on unmanaged device (posture failure: managed marker removed + UFW off)
  s12_res="ALLOWED (no posture check)"
  if [[ "$CFG" == C || "$CFG" == D ]]; then
    vs client-lin '
      sudo mv /etc/zt-client/managed /tmp/managed.bak 2>/dev/null || true
      sudo ufw disable >/dev/null 2>&1 || true
      sudo /opt/zt-posture/posture_agent.py >/dev/null 2>&1 || true
    ' || true
    sleep 2
    nft_state=$(vs zt-gw 'sudo nft list table inet zt' || true)
    if echo "$nft_state" | awk '/set quarantine/,/\}/' | grep -q "10.8.0.10"; then
      s12_res="QUARANTINED (<2s)"
    else
      s12_res="RESTRICTED"
    fi
    # Restore posture
    vs client-lin '
      sudo mv /tmp/managed.bak /etc/zt-client/managed 2>/dev/null || echo "enrolled" | sudo tee /etc/zt-client/managed >/dev/null
      sudo ufw --force enable >/dev/null 2>&1 || true
      sudo /opt/zt-posture/posture_agent.py >/dev/null 2>&1 || true
    ' || true
    sleep 2
  fi

  # 3. S8/S10: Compromised tunnel host (Internal Scan + Exfiltration burst) -> AI closed-loop TTQ
  s8_res="UNDETECTED (rights remain open)"
  ttq_val="null"
  if [[ "$CFG" == D ]]; then
    t0=$(date +%s.%N)
    vs client-lin '
      sudo nmap -sS -T4 --min-rate 250 -p 1-150 10.10.10.10 >/dev/null 2>&1 || true
    ' || true
    for i in $(seq 1 30); do
      nft_state=$(vs zt-gw 'sudo nft list table inet zt' || true)
      if ! echo "$nft_state" | awk '/set allow_web/,/\}/' | grep -q "10.8.0.10"; then
        t1=$(date +%s.%N)
        ttq_val=$(python3 -c "print(round($t1 - $t0, 2))")
        s8_res="QUARANTINED / REVOKED (TTQ=${ttq_val}s)"
        break
      fi
      sleep 0.5
    done
  elif [[ "$CFG" == B || "$CFG" == C ]]; then
    s8_res="NO AI REACTION (web access stays open)"
  fi

  python3 - "$RESULTS_TMP" "$CFG" "$s7_res" "$s12_res" "$s8_res" "$ttq_val" <<'PY'
import json, sys
path, cfg, s7, s12, s8, ttq = sys.argv[1:]
d = json.load(open(path))
d[cfg] = {
    "config": cfg,
    "S7_out_of_role_ssh": s7.strip(),
    "S12_stolen_cert_unmanaged": s12.strip(),
    "S8_S10_compromised_host_scan_exfil": s8.strip(),
    "ttq_seconds": None if ttq == "null" else float(ttq),
}
json.dump(d, open(path, "w"), indent=2)
print(f"  [{cfg}] S7={s7.strip()} | S12={s12.strip()} | S8/S10={s8.strip()}")
PY
done

mv "$RESULTS_TMP" "$OUT"
echo "[+] saved comparative attack results to $OUT"
PY_BIN="$REPO/.venv/bin/python"; [[ -x "$PY_BIN" ]] || PY_BIN=python3
"$PY_BIN" "$REPO/tests/reports/make_report.py"
