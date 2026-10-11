#!/usr/bin/env python3
"""Build the Phase 10 results tables and charts from the measured JSON files.

Inputs (tests/reports/):  perf.json, perf-abcd.json, abcd/{A,B,C,D}.json
Outputs:                  results.md (tables), charts/*.png (if matplotlib)
Missing inputs are skipped, so this can run before every measurement exists.
usage:  .venv/bin/python tests/reports/make_report.py
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHARTS = HERE / "charts"
CONFIGS = {"A": "Perimeter VPN", "B": "Static ZT", "C": "Dynamic PDP", "D": "PDP + AI (full)"}


def load(name: str):
    p = HERE / name
    return json.loads(p.read_text()) if p.exists() else None


def perf_section(perf, pabcd) -> list[str]:
    out = ["## Performance (ENF2, H4)", ""]
    if perf:
        t, r = perf["throughput_mbps"], perf["rtt_ms"]
        out += ["| Path | Throughput (Mbit/s) | RTT (ms) |", "|---|---:|---:|",
                f"| Plain (client → gateway, no tunnel) | {t['A_plain']} | {r['A_plain']} |",
                f"| OpenVPN tunnel (client → gateway) | {t['B_tunnel']} | {r['B_tunnel']} |",
                f"| Full ZT path (tunnel → nftables → web-app) | {t['C_full_zt']} | – |", "",
                "| Metric | Measured | Target | Status |", "|---|---:|---:|---|",
                f"| PDP decision (authenticate, median) | {perf['pdp_authenticate_median_ms']} ms | ≤ 500 ms | "
                f"{'met' if perf['pdp_authenticate_median_ms'] <= 500 else 'NOT met'} |",
                f"| OpenVPN connect (handshake + hooks + PDP) | {perf['openvpn_connect_s']:.2f} s | – | – |",
                f"| Gateway CPU during full-ZT run | {perf['gateway_cpu_pct_during_C']} % | – | – |", ""]
    if pabcd:
        tp, cpu, ov = pabcd["throughput_mbps"], pabcd["gateway_cpu_pct"], pabcd["overhead_pct_vs_A"]
        out += [f"Same forwarded path in every configuration ({pabcd['path']}):", "",
                "| Configuration | Throughput (Mbit/s) | Overhead vs A | Gateway CPU |", "|---|---:|---:|---:|"]
        for k, v in tp.items():
            name = CONFIGS.get(k, "D without traffic mirror" if k == "D_no_mirror" else k)
            if k == "A":
                cell = "baseline"
            elif k == "D_no_mirror":  # reference point: what the sensor feed costs D
                cell = f"mirror costs D {round(100 * (1 - tp['D'] / v), 1)} %"
            else:
                cell = f"{ov[k]} %"
            out.append(f"| {k} – {name} | {v} | {cell} | {cpu[k]} % |")
        worst = max(v for k, v in ov.items() if k != "D_no_mirror")
        out += ["", f"Target: ZT overhead ≤ 15 %. Worst configuration: {worst} % → "
                f"**{'met' if worst <= 15 else 'NOT met'}**.", ""]
    return out


def abcd_section(rows) -> list[str]:
    if not rows:
        return []
    targets = [t["target"] for t in rows[0]["targets"]]
    head = "| Target | ZT expects | " + " | ".join(f"{r['config']} – {CONFIGS[r['config']]}" for r in rows) + " |"
    out = ["## A/B/C/D comparison — exposed surface (benign probe)", "",
           "One TCP connect / HTTPS request per service from alice's tunnel (employee role). "
           "`open` = the gateway let it through.", "", head, "|---|---|" + "---|" * len(rows)]
    for i, t in enumerate(targets):
        exp = rows[0]["targets"][i]["zt_expected"]
        cells = []
        for r in rows:
            x = r["targets"][i]
            cells.append(f"**{x['result']}** ⚠" if x["violation"] else x["result"])
        out.append(f"| `{t}` ({rows[0]['targets'][i]['dst']}) | {exp} | " + " | ".join(cells) + " |")
    out += ["| **Reachable services** | | " + " | ".join(f"{r['reachable']}/{len(targets)}" for r in rows) + " |",
            "| **ZT violations** | | " + " | ".join(str(r["violations"]) for r in rows) + " |",
            "| **Rights expire (TTL)** | | " + " | ".join("yes" if r["rights_expire"] else "no (permanent)" for r in rows) + " |",
            "", "Detection / TTQ columns per configuration (S8–S11, S16) are filled in the joint Red Team session.", ""]
    return out


def charts(perf, pabcd, rows) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return ["_(charts skipped: matplotlib not installed)_", ""]
    CHARTS.mkdir(exist_ok=True)
    made = []
    if perf:
        t = perf["throughput_mbps"]
        fig, ax = plt.subplots(figsize=(6, 3.5))
        labels, vals = ["Plain", "Tunnel", "Full ZT path"], [t["A_plain"], t["B_tunnel"], t["C_full_zt"]]
        ax.bar(labels, vals, color=["#7a8a99", "#3b7dd8", "#d8613b"]); ax.set_yscale("log")
        ax.set_ylabel("Mbit/s (log)"); ax.set_title("Throughput by data path")
        for i, v in enumerate(vals): ax.text(i, v, f"{v:g}", ha="center", va="bottom")
        fig.tight_layout(); fig.savefig(CHARTS / "throughput-paths.png", dpi=150); plt.close(fig)
        made.append("throughput-paths.png")
    if pabcd:
        tp = pabcd["throughput_mbps"]
        fig, ax = plt.subplots(figsize=(6.5, 3.5))
        ax.bar(list(tp), list(tp.values()), color="#3b7dd8"); ax.set_ylabel("Mbit/s")
        ax.set_title("Forwarded throughput per configuration")
        for i, v in enumerate(tp.values()): ax.text(i, v, f"{v:g}", ha="center", va="bottom")
        fig.tight_layout(); fig.savefig(CHARTS / "throughput-abcd.png", dpi=150); plt.close(fig)
        made.append("throughput-abcd.png")
    if rows:
        fig, ax = plt.subplots(figsize=(6, 3.5))
        ax.bar([r["config"] for r in rows], [r["reachable"] for r in rows], color="#5a9e5a", label="reachable")
        ax.bar([r["config"] for r in rows], [r["violations"] for r in rows], color="#d8413b", label="ZT violations")
        ax.set_ylabel("services"); ax.set_title("Exposed surface from an employee tunnel"); ax.legend()
        fig.tight_layout(); fig.savefig(CHARTS / "surface-abcd.png", dpi=150); plt.close(fig)
        made.append("surface-abcd.png")
    return ["## Charts", ""] + [f"![{m}](charts/{m})" for m in made] + [""]


def main() -> None:
    perf, pabcd = load("perf.json"), load("perf-abcd.json")
    rows = [r for c in CONFIGS if (r := load(f"abcd/{c}.json"))]
    md = ["# Phase 10 — measured results", "",
          "Generated by `tests/reports/make_report.py` from the JSON files in this directory. "
          "Analysis: [perf.md](perf.md).", ""]
    md += perf_section(perf, pabcd) + abcd_section(rows) + charts(perf, pabcd, rows)
    (HERE / "results.md").write_text("\n".join(md))
    print(f"[+] wrote {HERE / 'results.md'}")


if __name__ == "__main__":
    main()
