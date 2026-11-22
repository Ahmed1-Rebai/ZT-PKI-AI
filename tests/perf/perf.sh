#!/usr/bin/env bash
# Performance overhead of the Zero Trust data path (docs/09 §5, ENF2, H4).
# Run from the host:  bash tests/perf/perf.sh
#
#   A plain   : client-lin -> zt-gw 192.168.100.1     (no tunnel, no ZT)
#   B tunnel  : client-lin -> zt-gw 10.8.0.1 (tun0)  (OpenVPN only)
#   C full ZT : client-lin -> tunnel -> nftables -> web-app 10.10.20.10
#
# iperf3 (TCP, 4 streams, 10 s, 3 runs -> median), ping RTT, OpenVPN connect
# time, PDP decision latency, gateway CPU during the full-ZT run.
# Test instrumentation: iperf3 is blocked by the deny-by-default policy, so
# temporary rules tagged "zt-perf" are inserted and removed at the end.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/tests/reports"; mkdir -p "$OUT"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 180 vagrant ssh "$vm" -c "$*" </dev/null 2>/dev/null; }

echo "[*] installing iperf3 / sysstat"
vs client-lin "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3 >/dev/null"
vs zt-gw      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3 sysstat >/dev/null"
vs web-app    "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3 >/dev/null"

echo "[*] temporary zt-perf rules + iperf3 servers"
vs zt-gw "sudo nft insert rule inet zt_input input ip saddr { 192.168.100.11, 10.8.0.10 } tcp dport 5201 accept comment \\\"zt-perf\\\";
          sudo nft insert rule inet zt forward ip saddr 10.8.0.10 ip daddr 10.10.20.10 tcp dport 5201 accept comment \\\"zt-perf\\\";
          pgrep -x iperf3 >/dev/null || iperf3 -s -D"
vs web-app "pgrep -x iperf3 >/dev/null || iperf3 -s -D"

cleanup() {
  echo "[*] removing zt-perf rules"
  vs zt-gw "for c in zt_input:input zt:forward; do t=\${c%%:*}; ch=\${c##*:};
              for h in \$(sudo nft -a list chain inet \$t \$ch | awk '/zt-perf/{print \$NF}'); do sudo nft delete rule inet \$t \$ch handle \$h; done; done;
            pkill -x iperf3 || true; sudo nft -a list ruleset | grep -c zt-perf || true" | tail -1 | sed 's/^/    zt-perf rules left: /'
  vs web-app "pkill -x iperf3 || true"
}
trap cleanup EXIT

run_iperf() {  # run_iperf <target> -> median Mbit/s over 3 runs
  local t="$1" r=() i
  for i in 1 2 3; do
    r+=("$(vs client-lin "iperf3 -c $t -t 10 -P 4 -J" | python3 -c 'import sys,json; print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]/1e6,1))')")
  done
  printf '%s\n' "${r[@]}" | sort -n | sed -n 2p
}
rtt() { vs client-lin "ping -q -c 40 -i 0.25 $1" | awk -F/ '/rtt/{print $5}'; }

echo "[*] A plain"; A=$(run_iperf 192.168.100.1); A_RTT=$(rtt 192.168.100.1)
echo "[*] B tunnel"; B=$(run_iperf 10.8.0.1); B_RTT=$(rtt 10.8.0.1)
echo "[*] C full ZT (+ gateway CPU)"
vs zt-gw "nohup sh -c 'sleep 3; mpstat 1 8 > /tmp/zt-perf-cpu.txt' >/dev/null 2>&1 &"
C=$(run_iperf 10.10.20.10)
GW_CPU=$(vs zt-gw "awk '/Average/{print 100-\$NF}' /tmp/zt-perf-cpu.txt")

echo "[*] OpenVPN connect time (reconnect alice)"
CONNECT=$(vs client-lin "s=\$(date +%s.%N); sudo systemctl restart openvpn-client@alice;
  for i in \$(seq 1 60); do ip -br addr show tun0 2>/dev/null | grep -q 10.8.0 && break; sleep 0.2; done;
  echo \"\$(date +%s.%N) - \$s\" | bc")

echo "[*] PDP decision latency (authenticate, from the gateway, 20 calls)"
PDP_MS=$(vs zt-gw "for i in \$(seq 1 20); do sudo curl -s -o /dev/null -w '%{time_total}\n' --cacert /etc/openvpn/hooks/ca-chain.crt \
  --cert /etc/openvpn/hooks/gw-client.crt --key /etc/openvpn/hooks/gw-client.key -H 'Content-Type: application/json' \
  -d '{\"cn\":\"alice@lab.local\",\"serial\":\"2015\",\"src_ip\":\"perf\"}' https://10.10.99.10:8443/v1/authenticate; done" \
  | sort -n | awk '{a[NR]=$1} END{printf "%.1f", a[int(NR/2)+1]*1000}')

python3 - "$A" "$B" "$C" "$A_RTT" "$B_RTT" "$GW_CPU" "$CONNECT" "$PDP_MS" "$OUT" <<'PY'
import json, sys, time
A, B, C, ar, br, cpu, conn, pdp, out = sys.argv[1:]
f = lambda x: float(x) if x else None
A, B, C, ar, br, cpu, conn, pdp = map(f, (A, B, C, ar, br, cpu, conn, pdp))
ov = lambda base, x: round(100 * (1 - x / base), 1) if base and x else None
r = {"measured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
     "throughput_mbps": {"A_plain": A, "B_tunnel": B, "C_full_zt": C},
     "overhead_pct_vs_plain": {"B_tunnel": ov(A, B), "C_full_zt": ov(A, C)},
     "rtt_ms": {"A_plain": ar, "B_tunnel": br},
     "gateway_cpu_pct_during_C": cpu, "openvpn_connect_s": conn, "pdp_authenticate_median_ms": pdp,
     "targets": {"throughput_overhead_pct": 15, "access_decision_ms": 500},
     "method": "iperf3 TCP -P4 -t10, median of 3; ping 40x; VirtualBox 7.1 virtio; temporary zt-perf rules removed after"}
json.dump(r, open(f"{out}/perf.json", "w"), indent=2)
print(json.dumps(r, indent=2))
PY
