#!/usr/bin/env python3
"""Client posture agent — docs/06 §8.

Collects a few device facts and reports a posture score to the PDP over mTLS
(the client certificate is the identity), every 60 s. Runs inside the VPN
tunnel; the connection to the PDP is mutually authenticated.

Configured via /etc/zt-client/posture.env:
    ZT_PDP_URL=https://10.10.99.10:8443
    ZT_CLIENT_CN=alice@lab.local
    ZT_CA=/etc/zt-client/ca-chain.crt
    ZT_CERT=/etc/zt-client/client.crt
    ZT_KEY=/etc/zt-client/client.key
"""
from __future__ import annotations

import json
import os
import platform
import ssl
import subprocess
import time
import urllib.request


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


MARKER = os.environ.get("ZT_MANAGED_MARKER", "/etc/zt-client/managed")


def checks() -> dict:
    lsblk = _run(["lsblk", "-o", "TYPE"])
    return {
        "os": platform.platform(),
        "kernel": platform.release(),
        "firewall_on": "Status: active" in _run(["ufw", "status"]),
        "managed": os.path.exists(MARKER),
        "disk_encrypted": "crypt" in lsblk,
        "ts": int(time.time()),
    }


def score(c: dict) -> float:
    # Scored controls: host firewall active + device enrolled (managed marker).
    # disk_encrypted / secureboot are reported in the detail for the SIEM.
    items = [bool(c["firewall_on"]), bool(c["managed"])]
    return sum(items) / len(items)


def main() -> int:
    url = os.environ.get("ZT_PDP_URL", "https://10.10.99.10:8443")
    cn = os.environ.get("ZT_CLIENT_CN", "")
    ca = os.environ.get("ZT_CA", "/etc/zt-client/ca-chain.crt")
    cert = os.environ.get("ZT_CERT", "/etc/zt-client/client.crt")
    key = os.environ.get("ZT_KEY", "/etc/zt-client/client.key")

    c = checks()
    payload = json.dumps({"cn": cn, "score": score(c), "detail": c}).encode()

    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    req = urllib.request.Request(
        url.rstrip("/") + "/v1/posture",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            print(f"[posture] {cn} score={score(c):.2f} -> {resp.status} {resp.read().decode()[:120]}")
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"[posture] {cn} report failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
