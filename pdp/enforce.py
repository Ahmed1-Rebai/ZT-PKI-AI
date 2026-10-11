"""Gateway enforcement through a narrowly-scoped SSH account.

The PDP VM never opens a shell on the gateway and never interpolates a CN or
an IP into a shell command.  The remote ``ztpdp-nft`` helper is installed by
the gateway role and accepts only its fixed action vocabulary.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass

CN_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
TTL = {"full": "10m", "restricted": "2m", "quarantine": "30m"}


@dataclass
class GatewayEnforcer:
    host: str
    user: str
    key: str
    dry_run: bool = False
    known_hosts: str = ""  # pinned gateway host key; empty = OpenSSH default

    def _run(self, *args: str) -> None:
        if self.dry_run:
            return
        pin = (["-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "StrictHostKeyChecking=yes"]
               if self.known_hosts else [])
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", *pin, "-i", self.key,
               f"{self.user}@{self.host}", "sudo", "/usr/local/sbin/ztpdp-nft", *args]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=8)

    @staticmethod
    def _ip(value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    def apply(self, vpn_ip: str, role: str, tier: str) -> None:
        ip = self._ip(vpn_ip)
        if tier == "revoke":
            self._run("clear", ip)
            return
        if tier == "quarantine":
            self._run("quarantine", ip, TTL[tier])
            return
        if tier not in ("full", "restricted"):
            raise ValueError(f"unknown tier: {tier}")
        self._run("allow", ip, role, TTL[tier])

    def clear(self, vpn_ip: str) -> None:
        self._run("clear", self._ip(vpn_ip))

    def kill(self, cn: str) -> None:
        if not CN_RE.fullmatch(cn):
            raise ValueError("invalid CN")
        self._run("kill", cn)
