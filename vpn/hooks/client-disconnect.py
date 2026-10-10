#!/usr/bin/env python3
"""OpenVPN --client-disconnect hook — session teardown.

Tells the PDP to drop the session (so it can remove the dynamic nftables
elements and log the end of the session, docs/05 §5.3). A disconnect hook must
never block the teardown, so failures are logged but exit 0 regardless.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zt_common as zt  # noqa: E402


def main():
    cfg = zt.load_conf()
    cn = os.environ.get("common_name", "")
    env = {
        "cn": cn,
        "serial": os.environ.get("tls_serial_0", ""),
        "src_ip": os.environ.get("trusted_ip") or os.environ.get("untrusted_ip", ""),
        "bytes_received": os.environ.get("bytes_received", ""),
        "bytes_sent": os.environ.get("bytes_sent", ""),
        "time_duration": os.environ.get("time_duration", ""),
    }

    if zt.enforceable(cfg):
        try:
            zt.api(cfg, "/v1/session/close", {"cn": cn, "serial": env["serial"]})
            zt.log("client-disconnect", decision="logged", mode="pdp", **env)
        except Exception as exc:  # noqa: BLE001
            zt.log("client-disconnect", decision="logged", mode="pdp",
                   reason="pdp-unreachable", error=str(exc), **env)
    else:
        zt.log("client-disconnect", decision="logged", mode="local", **env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
