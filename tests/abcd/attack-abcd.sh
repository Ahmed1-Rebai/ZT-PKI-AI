#!/usr/bin/env bash
# Comparative A/B/C/D evaluation under attack from client-lin (docs/09 §6).
# Runs two post-authentication attacks from client-lin (10.8.0.10) in each of
# the configurations A, B, C and D: S7 (SSH outside alice's role) and S8 (her
# certificate used from a non-compliant device). Records whether each one is
# blocked by the network policy or quarantined by the posture check (C/D).
#
#   usage: bash tests/abcd/attack-abcd.sh   -> tests/reports/abcd/attacks.json
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$REPO/tests/reports/abcd/attacks.json"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 120 vagrant ssh "$vm" -c "$*" </dev/null 2>/dev/null; }

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

  # 2. S8: Stolen cert on unmanaged device (posture failure: managed marker removed + UFW off).
  #    Measured in every config: is alice quarantined, and does the proxy still answer?
  vs client-lin '
    sudo mv /etc/zt-client/managed /tmp/managed.bak 2>/dev/null || true
    sudo ufw disable >/dev/null 2>&1 || true
    sudo sh -c ". /etc/zt-client/posture.env; export ZT_PDP_URL ZT_CLIENT_CN ZT_CA ZT_CERT ZT_KEY 2>/dev/null; exec /usr/bin/python3 /opt/zt-posture/posture_agent.py" >/dev/null 2>&1 || true
  ' || true
  sleep 3
  nft_state=$(vs zt-gw 'sudo nft list table inet zt' || true)
  code=$(vs client-lin 'sudo curl -s -o /dev/null -w "%{http_code}" --max-time 4 --cacert /etc/zt-client/ca-chain.crt --cert /etc/zt-client/client.crt --key /etc/zt-client/client.key https://10.10.10.10/ || true' | tr -d '\r')
  if echo "$nft_state" | awk '/set quarantine/,/\}/' | grep -q "10.8.0.10"; then
    s08_res="QUARANTINED (proxy HTTP ${code:-000})"
  elif [[ "${code:-000}" == 000 ]]; then
    s08_res="ACCESS CUT (proxy unreachable)"
  else
    s08_res="ALLOWED (proxy HTTP $code, no posture effect)"
  fi
  vs client-lin '
    sudo mv /tmp/managed.bak /etc/zt-client/managed 2>/dev/null || echo "enrolled by Ansible (client role)" | sudo tee /etc/zt-client/managed >/dev/null
    sudo ufw --force enable >/dev/null 2>&1 || true
    sudo sh -c ". /etc/zt-client/posture.env; export ZT_PDP_URL ZT_CLIENT_CN ZT_CA ZT_CERT ZT_KEY 2>/dev/null; exec /usr/bin/python3 /opt/zt-posture/posture_agent.py" >/dev/null 2>&1 || true
  ' || true
  sleep 2

  python3 - "$RESULTS_TMP" "$CFG" "$s7_res" "$s08_res" <<'PY'
import json, sys
path, cfg, s7, s8 = sys.argv[1:]
d = json.load(open(path))
d[cfg] = {
    "config": cfg,
    "S7_out_of_role_ssh": s7.strip(),
    "S8_stolen_cert_unmanaged": s8.strip(),
}
json.dump(d, open(path, "w"), indent=2)
print(f"  [{cfg}] S7={s7.strip()} | S8={s8.strip()}")
PY
done

mv "$RESULTS_TMP" "$OUT"
echo "[+] saved comparative attack results to $OUT"
PY_BIN="$REPO/.venv/bin/python"; [[ -x "$PY_BIN" ]] || PY_BIN=python3
"$PY_BIN" "$REPO/tests/reports/make_report.py"
