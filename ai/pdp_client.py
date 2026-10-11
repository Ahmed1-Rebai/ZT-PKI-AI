"""HTTPS client used by the AI engine to report scores to the PDP."""
from __future__ import annotations

import json
import os
import ssl
import urllib.request

CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


class PdpClient:
    def __init__(self, url="https://10.10.99.10:8443", certs=CERTS, timeout=3.0):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=os.path.join(certs, "ca-chain.crt"))
        self.ctx.load_cert_chain(os.path.join(certs, "ai.crt"), os.path.join(certs, "ai.key"))

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def sessions(self):
        """Map of tunnel address -> user, for the active sessions."""
        return {s["vpn_ip"]: s["cn"] for s in self._call("GET", "/v1/sessions")["sessions"]}

    def report(self, cn, anomaly, detail=None, critical=False):
        """Send one anomaly score for a user; returns the PDP's new score and tier."""
        body = {"cn": cn, "anomaly": round(float(anomaly), 4), "source": "ai",
                "critical": bool(critical), "detail": detail or {}}
        return self._call("POST", "/v1/events", body)
