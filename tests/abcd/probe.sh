#!/usr/bin/env bash
# Reachability matrix for the current A/B/C/D configuration (docs/09 §6).
# From alice's tunnel, try each lab service once (one TCP connect / one HTTPS
# request — no scanning) and record whether the gateway let it through.
# The client only has routes to the hosts its role needs; a client with root
# can add more, so the probe adds temporary /32 routes via the tunnel: the
# gateway (PEP) is then the only control under test. Routes are removed after.
# usage (from the host):  bash tests/abcd/probe.sh A|B|C|D   -> tests/reports/abcd/<cfg>.json
set -euo pipefail
CFG="${1:?usage: probe.sh A|B|C|D}"; CFG="${CFG^^}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/tests/reports/abcd"; mkdir -p "$OUT"
cd "$REPO/infra"
vs() { local vm="$1"; shift; timeout 120 vagrant ssh "$vm" -c "$*" 2>/dev/null; }

# name|host|port|expected for alice (employee) under Zero Trust
TARGETS="proxy_https_mtls|10.10.10.10|443|allow
app_direct_8080|10.10.20.10|8080|deny
app_ssh_admin_only|10.10.20.10|22|deny
db_5432|10.10.30.10|5432|deny
pki_subca_ssh|10.10.99.5|22|deny
siem_dashboard|10.10.99.20|443|deny
pdp_posture_channel|10.10.99.10|8443|allow"

RAW=$(vs client-lin "
  added=''
  for h in 10.10.30.10 10.10.99.5 10.10.99.20; do
    ip route show \$h | grep -q tun0 || { sudo ip route add \$h via 10.8.0.1 dev tun0 && added=\"\$added \$h\"; }
  done
  echo '$TARGETS' | while IFS='|' read -r n h p e; do
    if [ \"\$n\" = proxy_https_mtls ]; then
      code=\$(sudo curl -s -o /dev/null -w '%{http_code}' --max-time 4 --cacert /etc/zt-client/ca-chain.crt \
              --cert /etc/zt-client/client.crt --key /etc/zt-client/client.key https://10.10.10.10/ || true)
      case \"\$code\" in 2*|3*|4*) r=open;; *) r=blocked;; esac
    else
      r=\$(python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(3)
try: s.connect((sys.argv[1],int(sys.argv[2]))); print(\"open\")
except ConnectionRefusedError: print(\"open\")   # reached the host, port closed
except OSError: print(\"blocked\")' \$h \$p); code=-
    fi
    echo \"\$n|\$h|\$p|\$e|\$r|\$code\"
  done
  for h in \$added; do sudo ip route del \$h via 10.8.0.1 dev tun0; done
")
TTL=$(vs zt-gw "sudo nft list set inet zt allow_web | tr -s '\n\t' ' ' | grep -oE '10\.8\.0\.10( timeout [0-9a-z]+)?( expires [0-9a-z]+)?' | head -1" || true)

python3 - "$CFG" "$OUT" "$TTL" <<PY
import json, sys, time
cfg, out, ttl = sys.argv[1:]
rows = []
for line in """$RAW""".strip().splitlines():
    n, h, p, exp, got, code = line.split("|")
    rows.append({"target": n, "dst": f"{h}:{p}", "zt_expected": exp, "result": got,
                 "http_code": None if code == "-" else code,
                 "violation": (exp == "deny" and got == "open") or (exp == "allow" and got != "open")})
r = {"config": cfg, "measured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
     "alice_allow_web": ttl or None, "rights_expire": "expires" in (ttl or ""),
     "reachable": sum(x["result"] == "open" for x in rows),
     "violations": sum(x["violation"] for x in rows), "targets": rows}
json.dump(r, open(f"{out}/{cfg}.json", "w"), indent=2)
print(f"  config {cfg}: {r['reachable']}/{len(rows)} reachable, {r['violations']} ZT violation(s), alice right: {ttl or 'none'}")
for x in rows:
    print(f"    {x['target']:<22} {x['dst']:<18} {x['result']:<8} (ZT: {x['zt_expected']}){'  <-- violation' if x['violation'] else ''}")
PY
