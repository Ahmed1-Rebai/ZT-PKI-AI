#!/usr/bin/env python3
"""OpenVPN --client-connect hook — fixed VPN IP per CN + PDP session open.

Writes an `ifconfig-push` line to the dynamic config file OpenVPN passes as
argv[1], pinning the client to a stable VPN IP derived from its identity
(docs/05 §5.2) so the firewall can write identity-based rules.

Bootstrap (PDP_ENFORCE=0, M2): the IP comes from the static map (or the pool).
Enforced (PDP_ENFORCE=1, M3+): the PDP's `/v1/session/open` returns the IP and
the decision; any failure -> deny (fail-closed).

Exit 0 = accept, exit 1 = reject.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zt_common as zt  # noqa: E402


def main():
    cfg = zt.load_conf()
    if len(sys.argv) < 2:
        zt.log("client-connect", decision="deny", reason="missing-tmp-file")
        return 1
    tmp_cfg = sys.argv[1]

    cn = os.environ.get("common_name", "")
    env = {
        "cn": cn,
        "serial": os.environ.get("tls_serial_0", ""),
        "src_ip": os.environ.get("trusted_ip") or os.environ.get("untrusted_ip", ""),
    }

    vpn_ip = zt.ip_map(cfg).get(cn)  # static fixed-IP map wins if present
    decision = "allow"

    if zt.enforceable(cfg):
        try:
            resp = zt.api(cfg, "/v1/session/open", {"cn": cn, "serial": env["serial"], "src_ip": env["src_ip"]})
            decision = str(resp.get("decision", "")).lower()
            vpn_ip = resp.get("vpn_ip") or vpn_ip
        except Exception as exc:  # noqa: BLE001 - any error means deny
            zt.log("client-connect", decision="deny", mode="pdp",
                   reason="pdp-unreachable", error=str(exc), **env)
            return 1

    if decision != "allow":
        zt.log("client-connect", decision="deny", reason="pdp-denied", vpn_ip=vpn_ip, **env)
        return 1

    if vpn_ip:
        netmask = cfg.get("VPN_NETMASK", "255.255.255.0")
        with open(tmp_cfg, "w", encoding="utf-8") as fh:
            fh.write(f"ifconfig-push {vpn_ip} {netmask}\n")
        zt.log("client-connect", decision="allow", vpn_ip=vpn_ip, source="static-map", **env)
    else:
        # No pin available: fall back to the pool (bootstrap only).
        open(tmp_cfg, "a").close()
        zt.log("client-connect", decision="allow", vpn_ip="pool", source="pool", **env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
