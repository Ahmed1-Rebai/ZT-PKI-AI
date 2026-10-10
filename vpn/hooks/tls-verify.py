#!/usr/bin/env python3
"""OpenVPN --tls-verify hook — the Zero Trust gate at handshake time.

Called for every certificate in the chain; OpenVPN has already validated the
chain against `ca-chain.crt`, the CRL (`crl-verify`) and the client EKU
(`remote-cert-tls client`). We only act on depth 0 (the client cert) and ask
the PDP whether this identity may open a tunnel. Any failure -> deny
(fail-closed, docs/01 ENF4).

Exit 0 = accept, exit 1 = reject.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zt_common as zt  # noqa: E402


def main():
    cfg = zt.load_conf()
    try:
        depth = int(sys.argv[1])
    except (IndexError, ValueError):
        depth = 0
    subject = sys.argv[2] if len(sys.argv) > 2 else ""

    if depth != 0:  # intermediate/root already validated by OpenVPN
        return 0

    cn = os.environ.get("common_name") or zt.cn_from_subject(subject)
    env = {
        "cn": cn,
        "serial": os.environ.get("tls_serial_0", ""),
        "src_ip": os.environ.get("untrusted_ip", ""),
        "src_port": os.environ.get("untrusted_port", ""),
    }

    if not cn or not zt.CN_RE.match(cn):
        zt.log("tls-verify", decision="deny", reason="bad-cn", **env)
        return 1

    if not zt.enforceable(cfg):
        zt.log("tls-verify", decision="allow", mode="local", reason="pdp-not-enforced", **env)
        return 0

    try:
        resp = zt.api(cfg, "/v1/authenticate", {"cn": cn, "serial": env["serial"], "src_ip": env["src_ip"]})
        allow = str(resp.get("decision", "")).lower() == "allow"
        zt.log("tls-verify", decision="allow" if allow else "deny", mode="pdp",
               score=resp.get("score"), **env)
        return 0 if allow else 1
    except Exception as exc:  # noqa: BLE001 - any error means deny
        zt.log("tls-verify", decision="deny", mode="pdp", reason="pdp-unreachable",
               error=str(exc), **env)
        return 1


if __name__ == "__main__":
    sys.exit(main())
