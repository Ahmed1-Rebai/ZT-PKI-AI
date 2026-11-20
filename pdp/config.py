"""Configuration for the PDP service.

All operational values come from the environment so images contain neither
private keys nor lab-specific secrets.  See ``pdp/.env.example``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    redis_url: str = os.getenv("ZT_REDIS_URL", "redis://redis:6379/0")
    opa_url: str = os.getenv("ZT_OPA_URL", "http://opa:8181/v1/data/zt/authz/decision")
    audit_log: str = os.getenv("ZT_AUDIT_LOG", "/var/log/zt-pdp/audit.jsonl")
    session_ttl_seconds: int = int(os.getenv("ZT_SESSION_TTL", "600"))
    renewal_interval_seconds: int = int(os.getenv("ZT_RENEWAL_INTERVAL", "60"))
    gateway_host: str = os.getenv("ZT_GATEWAY_HOST", "10.10.99.1")
    gateway_user: str = os.getenv("ZT_GATEWAY_USER", "ztpdp")
    gateway_key: str = os.getenv("ZT_GATEWAY_KEY", "/run/secrets/gateway_ssh_key")
    # Pinned gateway SSH host key (written by the pdp role); refuses an impostor.
    gateway_known_hosts: str = os.getenv("ZT_GATEWAY_KNOWN_HOSTS", "/run/secrets/known_hosts")
    dry_run: bool = _bool("ZT_ENFORCER_DRY_RUN", False)
    # User directory (CN -> role, fixed VPN IP), seeded into the store at start-up.
    # The same file feeds OPA, so roles and identities have one source of truth.
    users_file: str = os.getenv("ZT_USERS_FILE", "/app/policies/data.json")
    # Caller authorization by network. Services (gateway hooks, AI engine) sit on
    # mgmt; VPN clients may only report posture. OpenVPN pins each client's
    # source address to its certificate, so a VPN source IP identifies the CN.
    service_networks: str = os.getenv("ZT_SERVICE_NETWORKS", "10.10.99.0/24")
    client_networks: str = os.getenv("ZT_CLIENT_NETWORKS", "10.8.0.0/24")


settings = Settings()
