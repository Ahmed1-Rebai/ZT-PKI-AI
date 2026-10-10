#!/usr/bin/env bash
# Build a self-contained OpenVPN client profile from staged PKI material.
#   usage: make-client.sh <user> [gw-host] [out-dir]
# Reads (all git-ignored, staged by vpn/scripts/sync-pki.sh):
#   vpn/client/pki/{ca-chain.crt,<user>.crt,<user>.key}
#   vpn/server/ta.key
# Writes <out-dir>/<user>.ovpn  (default: vpn/client/)
set -euo pipefail
BASE="${ZT_BASE:-$(cd "$(dirname "$0")/../.." && pwd)}"
USER="${1:?usage: make-client.sh <user> [gw-host] [out-dir]}"
GW="${2:-192.168.100.1}"
OUTDIR="${3:-$BASE/vpn/client}"

CA="$BASE/vpn/client/pki/ca-chain.crt"
CRT="$BASE/vpn/client/pki/${USER}.crt"
KEY="$BASE/vpn/client/pki/${USER}.key"
TA="$BASE/vpn/server/ta.key"
TPL="$BASE/vpn/client/client.ovpn.template"
OUT="$OUTDIR/${USER}.ovpn"

for f in "$CA" "$CRT" "$KEY" "$TA" "$TPL"; do
  [ -f "$f" ] || { echo "missing: $f (run vpn/scripts/sync-pki.sh first)" >&2; exit 1; }
done

mkdir -p "$OUTDIR"
python3 - "$TPL" "$OUT" "$GW" "$CA" "$CRT" "$KEY" "$TA" <<'PY'
import sys
tpl, out, gw, ca, crt, key, ta = sys.argv[1:]
with open(tpl) as f:
    text = f.read()
def read(p):
    with open(p) as f:
        return f.read().strip()
text = (text.replace("__GW_HOST__", gw)
            .replace("__CA_CHAIN__", read(ca))
            .replace("__CLIENT_CERT__", read(crt))
            .replace("__CLIENT_KEY__", read(key))
            .replace("__TLS_CRYPT__", read(ta)))
with open(out, "w") as f:
    f.write(text)
PY
chmod 600 "$OUT"
echo "[+] wrote $OUT (gw=$GW)"
