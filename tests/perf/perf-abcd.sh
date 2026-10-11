#!/usr/bin/env bash
# Zero Trust overhead on the SAME forwarded path (client tunnel -> web-app)
# under each configuration of docs/09 §6, plus D without the traffic mirror to
# isolate the cost of feeding the sensor. Complements perf.sh (plain/tunnel).
# Leaves the lab in config D with the mirror on.
# usage (from the host):  bash tests/perf/perf-abcd.sh   -> tests/reports/perf-abcd.json
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/tests/reports"; mkdir -p "$OUT"
SW="$REPO/tests/abcd/set-config.sh"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 180 vagrant ssh "$vm" -c "$*" 2>/dev/null; }
mirror() {  # mirror on|off — the tc filters live on the zone NICs, not in the unit
  if [[ "$1" == on ]]; then vs zt-gw "sudo systemctl restart zt-mirror"
  else vs zt-gw ". /etc/default/zt-mirror; for i in \$SRC_IFACES; do sudo tc qdisc del dev \$i ingress 2>/dev/null; sudo tc qdisc del dev \$i root 2>/dev/null; done; true"; fi
}

echo "[*] temporary zt-perf rule + iperf3 server on web-app"
vs zt-gw "sudo nft insert rule inet zt forward ip saddr 10.8.0.10 ip daddr 10.10.20.10 tcp dport 5201 accept comment \\\"zt-perf\\\""
vs web-app "pgrep -x iperf3 >/dev/null || iperf3 -s -D"
cleanup() {
  mirror on
  vs zt-gw "for h in \$(sudo nft -a list chain inet zt forward | awk '/zt-perf/{print \$NF}'); do sudo nft delete rule inet zt forward handle \$h; done"
  vs web-app "pkill -x iperf3 || true"
  bash "$SW" D >/dev/null
  echo "[*] lab back in config D, mirror on, zt-perf rule removed"
}
trap cleanup EXIT

measure() {  # measure <label> -> "label mbps cpu"
  vs zt-gw "nohup sh -c 'sleep 3; mpstat 1 8 > /tmp/zt-perf-cpu.txt' >/dev/null 2>&1 &"
  local r=() i
  for i in 1 2 3; do
    r+=("$(vs client-lin "iperf3 -c 10.10.20.10 -t 10 -P 4 -J" | python3 -c 'import sys,json; print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6,1))')")
  done
  local med cpu
  med=$(printf '%s\n' "${r[@]}" | sort -n | sed -n 2p)
  cpu=$(vs zt-gw "awk '/Average/{print 100-\$NF}' /tmp/zt-perf-cpu.txt")
  echo "$1 $med $cpu"
}

RES=()
for c in A B C D; do
  echo "[*] config $c (mirror on)"; bash "$SW" "$c" >/dev/null; RES+=("$(measure "$c")")
done
echo "[*] config D, mirror off"; mirror off; RES+=("$(measure D_no_mirror)")

python3 - "$OUT" "${RES[@]}" <<'PY'
import json, sys, time
out, rows = sys.argv[1], [r.split() for r in sys.argv[2:]]
tp = {k: float(v) for k, v, _ in rows}; cpu = {k: float(c) for k, _, c in rows}
base = tp["A"]
r = {"measured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
     "path": "client-lin tun0 -> zt-gw (nftables) -> web-app 10.10.20.10:5201",
     "throughput_mbps": tp, "gateway_cpu_pct": cpu,
     "overhead_pct_vs_A": {k: round(100 * (1 - v / base), 1) for k, v in tp.items() if k != "A"},
     "method": "iperf3 TCP -P4 -t10, median of 3 per config; mirror = tc mirred of the zone NICs to the sensor"}
json.dump(r, open(f"{out}/perf-abcd.json", "w"), indent=2)
print(json.dumps(r, indent=2))
PY
