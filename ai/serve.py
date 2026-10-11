"""Live anomaly scoring on the sensor (milestone M5, docs/07 §8).

Captures the gateway's mirrored traffic with NFStream, attributes each flow
to a user through its tunnel address, scores it with the verified models and
reports to the PDP, which recomputes the trust score and re-tiers access.

  * anomaly >= --report        -> reported (rate-limited to 1/s per user)
  * >= --burst flows scoring >= --critical within --window s -> critical=True
    (PDP floor rule: score forced to 0)
  * every --heartbeat s, active users get their recent max score, so the PDP's
    moving average decays and trust recovers once the activity stops.

usage: python serve.py --iface eth2
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from collections import defaultdict, deque

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdp_client import PdpClient  # noqa: E402
from schema import _NFS, from_nfstream  # noqa: E402
from scoring import Scorer  # noqa: E402

VPN = ipaddress.ip_network("10.8.0.0/24")


def log(event: str, **kw) -> None:
    print(json.dumps({"ts": round(time.time(), 3), "component": "ai", "event": event, **kw}), flush=True)


def flow_frame(flow) -> pd.DataFrame:
    row = {k: getattr(flow, k, 0) for k in _NFS}
    row["dst_port"] = flow.dst_port
    return pd.DataFrame([row])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=os.environ.get("ZT_CAPTURE_IF", "eth2"))
    ap.add_argument("--pdp", default=os.environ.get("ZT_PDP_URL", "https://10.10.99.10:8443"))
    ap.add_argument("--report", type=float, default=0.3)
    ap.add_argument("--critical", type=float, default=0.95)
    ap.add_argument("--burst", type=int, default=5)
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--heartbeat", type=float, default=30.0)
    args = ap.parse_args()

    from nfstream import NFStreamer

    scorer, pdp = Scorer(), PdpClient(args.pdp)
    users, users_at = {}, 0.0
    hot = defaultdict(deque)            # cn -> timestamps of very confident flows
    recent_max = defaultdict(float)     # cn -> max anomaly since last heartbeat
    last_report = defaultdict(float)
    last_beat = time.time()
    log("start", iface=args.iface, pdp=args.pdp)

    stream = NFStreamer(source=args.iface, statistical_analysis=True, promiscuous_mode=True,
                        idle_timeout=5, active_timeout=15)
    for flow in stream:
        now = time.time()
        if now - users_at > 10:
            try:
                users, users_at = pdp.sessions(), now
            except Exception as exc:            # keep scoring; retry next flow
                log("sessions_error", error=str(exc))
        if ipaddress.ip_address(flow.src_ip) not in VPN:
            continue
        cn = users.get(flow.src_ip)
        if not cn:
            continue
        try:
            s = scorer.score(from_nfstream(flow_frame(flow))).iloc[0]
        except Exception as exc:                 # one malformed flow must not stop the engine
            log("score_error", cn=cn, error=str(exc))
            continue
        a = float(s["anomaly"])
        recent_max[cn] = max(recent_max[cn], a)
        q = hot[cn]
        if a >= args.critical:
            q.append(now)
        while q and now - q[0] > args.window:
            q.popleft()
        critical = len(q) >= args.burst
        detail = {"dst": flow.dst_ip, "port": flow.dst_port, "iforest": round(float(s["iforest"]), 3),
                  "ae": round(float(s["ae"]), 3), "rf": round(float(s["rf"]), 3), "burst": len(q)}
        if (a >= args.report and now - last_report[cn] >= 1.0) or critical:
            try:
                r = pdp.report(cn, a, detail, critical)
                last_report[cn] = now
                log("report", cn=cn, anomaly=round(a, 4), critical=critical, pdp=r, **detail)
            except Exception as exc:
                log("report_error", cn=cn, error=str(exc))
        if now - last_beat >= args.heartbeat:
            for user, m in list(recent_max.items()):
                try:
                    pdp.report(user, m, {"heartbeat": True})
                except Exception as exc:
                    log("report_error", cn=user, error=str(exc))
            recent_max.clear()
            last_beat = now


if __name__ == "__main__":
    main()
