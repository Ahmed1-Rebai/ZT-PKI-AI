"""Shared helpers for the OpenVPN Zero Trust hooks.

The hooks are the PEP-side glue between OpenVPN and the PDP (docs/05 §5,
docs/06 §5). They are deliberately small and dependency-free (stdlib only) so
they can run as the unprivileged `nobody` user that OpenVPN drops to.

Decision model
-------------
* ``PDP_ENFORCE=1`` (default): every accept decision comes from the PDP over
  mTLS. If the PDP cannot be reached the hook **denies** (fail-closed, ENF4).
* ``PDP_ENFORCE=0``: bootstrap mode used at M2 while the PDP does not exist
  yet. OpenVPN still enforces mTLS + CRL; the hook only does local sanity
  checks and logs. Flip to ``1`` at M3 (see docs/10, TODO M3).

All output goes to stderr, which OpenVPN captures into openvpn.log, so every
decision is auditable and can later be shipped to the SIEM.
"""

import json
import os
import re
import ssl
import sys
import urllib.request

CONF_PATH = os.environ.get("ZT_HOOK_CONF", "/etc/openvpn/zt/hook.env")

# CNs are user@lab.local, vpn-gw.lab.local, laptop-01 ... keep it strict.
CN_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


def load_conf(path=CONF_PATH):
    """Very small KEY=VALUE reader (no secrets are stored here)."""
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                cfg[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return cfg


def enforceable(cfg):
    return str(cfg.get("PDP_ENFORCE", "1")).lower() not in ("0", "false", "no", "off")


def cn_from_subject(subject):
    """Extract the CN from the RFC2253-ish subject string OpenVPN passes."""
    m = re.search(r"(?:^|,)CN=([^,/]+)", subject or "")
    return m.group(1) if m else ""


def log(event, **fields):
    sys.stderr.write("ZT-HOOK " + json.dumps({"event": event, **fields}, sort_keys=True) + "\n")
    sys.stderr.flush()


def api(cfg, path, payload):
    """POST JSON to the PDP over mTLS. Raises on any transport/TLS error."""
    base = cfg.get("PDP_URL", "").rstrip("/")
    if not base:
        raise RuntimeError("PDP_URL not configured")
    ctx = ssl.create_default_context(cafile=cfg.get("PDP_CA"))
    cert, key = cfg.get("PDP_CERT"), cfg.get("PDP_KEY")
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        ctx.load_cert_chain(cert, key)
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = float(cfg.get("PDP_TIMEOUT", "2"))
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.load(resp)


def ip_map(cfg):
    """Optional static CN -> fixed VPN IP map (docs/05 §5.2)."""
    mapping = {}
    path = cfg.get("IP_MAP", "")
    if not path:
        return mapping
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "," not in line:
                    continue
                cn, ip = (part.strip() for part in line.split(",", 1))
                if cn:
                    mapping[cn] = ip
    except OSError:
        pass
    return mapping
