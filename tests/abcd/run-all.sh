#!/usr/bin/env bash
# Benign part of the A/B/C/D comparison (docs/09 §6): switch to each config,
# record the reachability matrix, then return the lab to D (normal state).
# The attack columns (S8–S11, S16 detection/TTQ per config) are added during
# the joint Red Team session with the same switcher.
# usage (from the host):  bash tests/abcd/run-all.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
trap 'echo "[*] returning the lab to config D"; bash "$HERE/set-config.sh" D >/dev/null' EXIT
for c in A B C D; do
  echo "=== config $c ==="
  bash "$HERE/set-config.sh" "$c" | grep -E '^\[\+\]'
  [[ "$c" == C || "$c" == D ]] && sleep 5   # let the PDP grant alice's TTL right
  bash "$HERE/probe.sh" "$c"
done
trap - EXIT
PY="$HERE/../../.venv/bin/python"; [[ -x "$PY" ]] || PY=python3   # .venv has matplotlib (charts)
"$PY" "$HERE/../reports/make_report.py"
