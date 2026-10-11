"""FastAPI Policy Decision Point for the M3 control plane."""
from __future__ import annotations

import ipaddress
import json
import os
import time
import asyncio
from contextlib import suppress
from contextlib import asynccontextmanager
from typing import Any

import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from audit import configure, emit
from config import Settings, settings
from enforce import GatewayEnforcer
from policy import OpaPolicy, PolicyError
from store import RedisStore, Store
from trust import Signals, ema, trust_score


class AuthRequest(BaseModel):
    cn: str = Field(pattern=r"^[A-Za-z0-9._@-]{1,128}$")
    serial: str = Field(min_length=1, max_length=128)
    src_ip: str = ""


class SessionRequest(AuthRequest):
    vpn_ip: str | None = None


class PostureRequest(BaseModel):
    cn: str = Field(pattern=r"^[A-Za-z0-9._@-]{1,128}$")
    score: float = Field(ge=0, le=1)
    detail: dict[str, Any] = Field(default_factory=dict)


class EventRequest(BaseModel):
    cn: str = Field(pattern=r"^[A-Za-z0-9._@-]{1,128}$")
    anomaly: float = Field(ge=0, le=1)
    source: str = Field(min_length=1, max_length=64)
    critical: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)


def _in_networks(ip: str, networks: str) -> bool:
    """True if ip belongs to one of the comma-separated CIDRs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n.strip()) for n in networks.split(",") if n.strip())


def _serial(value: str) -> str:
    return value.replace(":", "").upper()


def _vpn_ip(value: str) -> str:
    ip = ipaddress.IPv4Address(value)
    if ip not in ipaddress.IPv4Network("10.8.0.0/24"):
        raise ValueError("VPN IP must be in 10.8.0.0/24")
    return str(ip)


def load_directory(path: str) -> dict[str, dict[str, Any]]:
    """Read the user directory (CN -> role, vpn_ip) from data.json; empty if absent."""
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return dict(json.load(fh).get("users", {}))


def build_app(store: Store | None = None, policy: Any | None = None,
              enforcer: Any | None = None, cfg: Settings = settings) -> FastAPI:
    async def renewal_loop(app: FastAPI) -> None:
        """Refresh only policy-approved rules; a PDP outage lets gateway TTLs expire."""
        while True:
            await asyncio.sleep(cfg.renewal_interval_seconds)
            repo, _, gate = state()
            for session in repo.sessions():
                try:
                    user, score, decision = evaluate(session["cn"], session["serial"])
                    if not user or not decision.get("allow"):
                        gate.clear(session["vpn_ip"])
                        repo.delete_session(session["cn"])
                        emit("ttl_renewal", cn=session["cn"], decision="expired", score=score)
                        continue
                    tier = str(decision.get("tier", "restricted"))
                    gate.apply(session["vpn_ip"], user["role"], tier)
                    session.update({"tier": tier, "score": score, "renewed_at": time.time()})
                    repo.put_session(session["cn"], session, cfg.session_ttl_seconds)
                    emit("ttl_renewal", cn=session["cn"], decision="renewed", score=score, tier=tier)
                except Exception as exc:  # next cycle may recover; do not extend a failed rule
                    emit("ttl_renewal_error", cn=session.get("cn"), error=str(exc))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure(cfg.audit_log)
        if store is None:
            app.state.store = RedisStore(redis.from_url(cfg.redis_url, decode_responses=True))
            app.state.store.r.ping()  # fail the container health/start-up rather than bypass policy
        else:
            app.state.store = store
        directory = load_directory(cfg.users_file)
        if directory:
            app.state.store.load_users(directory)
            emit("directory_loaded", users=sorted(directory))
        app.state.policy = policy or OpaPolicy(cfg.opa_url)
        app.state.enforcer = enforcer or GatewayEnforcer(cfg.gateway_host, cfg.gateway_user, cfg.gateway_key,
                                                         cfg.dry_run, cfg.gateway_known_hosts)
        task = asyncio.create_task(renewal_loop(app))
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="ZT PDP", version="1.0", lifespan=lifespan)

    def state() -> tuple[Store, Any, Any]:
        return app.state.store, app.state.policy, app.state.enforcer

    def require_service(request: Request) -> None:
        """Control endpoints are for the gateway hooks and the AI engine (mgmt)."""
        caller = request.client.host if request.client else ""
        if not _in_networks(caller, cfg.service_networks):
            emit("caller_denied", caller=caller, path=request.url.path)
            raise HTTPException(403, "caller not allowed")

    service = [Depends(require_service)]

    def evaluate(cn: str, serial: str, critical: bool = False) -> tuple[dict[str, Any] | None, float, dict[str, Any]]:
        repo, opa, _ = state()
        user = repo.user(cn)
        revoked = repo.is_revoked(_serial(serial))
        identity = 1.0 if user and not revoked else 0.0
        signals = Signals(identity=identity, device=repo.posture(cn), context=0.8,
                          anomaly=repo.anomaly(cn), critical_alert=critical)
        score = trust_score(signals)
        payload = {"identity": {"cn": cn, "cert_valid": bool(user), "revoked": revoked,
                                "role": user.get("role", "") if user else ""},
                   "device": {"posture_ok": signals.device >= 0.6}, "trust_score": score,
                   "anomaly": signals.anomaly, "critical": critical}
        try:
            decision = opa.decide(payload)
        except PolicyError as exc:
            emit("policy_error", cn=cn, reason=str(exc))
            return user, score, {"allow": False, "tier": "revoke", "reason": "policy-unavailable"}
        return user, score, decision

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/authenticate", dependencies=service)
    def authenticate(req: AuthRequest) -> dict[str, Any]:
        user, score, decision = evaluate(req.cn, req.serial)
        allow = bool(decision.get("allow", False))
        reason = decision.get("reason", "policy")
        emit("authenticate", cn=req.cn, serial=_serial(req.serial), src_ip=req.src_ip, score=score,
             tier=decision.get("tier"), decision="allow" if allow else "deny", reason=reason)
        return {"decision": "allow" if allow else "deny", "score": score, "tier": decision.get("tier", "revoke"), "reason": reason}

    @app.post("/v1/session/open", dependencies=service)
    def session_open(req: SessionRequest) -> dict[str, Any]:
        repo, _, gate = state()
        user, score, decision = evaluate(req.cn, req.serial)
        if not user or not decision.get("allow"):
            emit("session_open", cn=req.cn, decision="deny", score=score, reason=decision.get("reason", "policy"))
            return {"decision": "deny", "score": score, "reason": decision.get("reason", "policy")}
        vpn_ip = _vpn_ip(req.vpn_ip or user.get("vpn_ip", ""))
        tier = str(decision.get("tier", "restricted"))
        try:
            gate.apply(vpn_ip, user["role"], tier)
        except Exception as exc:  # enforcement failure must not create a session
            emit("enforcement_error", cn=req.cn, vpn_ip=vpn_ip, error=str(exc))
            return {"decision": "deny", "score": score, "reason": "enforcement-unavailable"}
        session = {"cn": req.cn, "serial": _serial(req.serial), "vpn_ip": vpn_ip, "role": user["role"],
                   "tier": tier, "score": score, "opened_at": time.time()}
        repo.put_session(req.cn, session, cfg.session_ttl_seconds)
        emit("session_open", **session, decision="allow")
        return {"decision": "allow", "vpn_ip": vpn_ip, "score": score, "tier": tier,
                "ttl": cfg.session_ttl_seconds}

    @app.post("/v1/session/close", dependencies=service)
    def session_close(req: AuthRequest) -> dict[str, str]:
        repo, _, gate = state()
        session = repo.session(req.cn)
        if session:
            try: gate.clear(session["vpn_ip"])
            except Exception as exc: emit("enforcement_error", cn=req.cn, error=str(exc))
            repo.delete_session(req.cn)
        emit("session_close", cn=req.cn, found=bool(session))
        return {"decision": "closed"}

    @app.post("/v1/posture")
    def posture(req: PostureRequest, request: Request) -> dict[str, Any]:
        repo, _, _ = state()
        caller = request.client.host if request.client else ""
        if _in_networks(caller, cfg.client_networks):
            # VPN client: identity is the CN pinned to its tunnel address, not a
            # declared field — a client may only report its own posture.
            bound = repo.user_by_ip(caller)
            if bound != req.cn:
                emit("posture_denied", caller=caller, claimed=req.cn, bound=bound)
                raise HTTPException(403, "posture identity does not match the tunnel address")
        elif not _in_networks(caller, cfg.service_networks):
            emit("caller_denied", caller=caller, path=request.url.path)
            raise HTTPException(403, "caller not allowed")
        if not repo.user(req.cn):
            raise HTTPException(404, "unknown identity")
        repo.set_posture(req.cn, req.score, req.detail)
        emit("posture", cn=req.cn, score=req.score, caller=caller, detail=req.detail)
        return {"decision": "recorded", "score": req.score}

    @app.post("/v1/events", dependencies=service)
    def event(req: EventRequest) -> dict[str, Any]:
        repo, _, gate = state()
        if not repo.user(req.cn):
            raise HTTPException(404, "unknown identity")
        anomaly = ema(repo.anomaly(req.cn), req.anomaly)
        repo.set_anomaly(req.cn, anomaly)
        session = repo.session(req.cn)
        user, score, decision = evaluate(req.cn, session["serial"] if session else "", req.critical)
        tier = str(decision.get("tier", "revoke"))
        if session and user:
            try:
                gate.apply(session["vpn_ip"], user["role"], tier)
                session.update({"tier": tier, "score": score, "last_event": time.time()})
                repo.put_session(req.cn, session, cfg.session_ttl_seconds)
            except Exception as exc:
                emit("enforcement_error", cn=req.cn, error=str(exc))
                tier = "revoke"
        emit("rescore", cn=req.cn, anomaly=anomaly, score=score, tier=tier, source=req.source,
             critical=req.critical, detail=req.detail)
        return {"score": score, "anomaly": anomaly, "tier": tier}

    @app.post("/v1/session/{cn}/kill", dependencies=service)
    def kill(cn: str) -> dict[str, str]:
        repo, _, gate = state()
        session = repo.session(cn)
        if session:
            gate.clear(session["vpn_ip"])
            gate.kill(cn)
            repo.delete_session(cn)
        emit("session_kill", cn=cn, found=bool(session))
        return {"decision": "killed"}

    @app.post("/v1/cert/{serial}/revoke", dependencies=service)
    def revoke(serial: str) -> dict[str, str]:
        repo, _, gate = state()
        serial = _serial(serial)
        repo.revoke(serial)
        for session in repo.sessions():
            if session["serial"] == serial:
                gate.clear(session["vpn_ip"])
                gate.kill(session["cn"])
                repo.delete_session(session["cn"])
        # The online CA is deliberately separate. Its signed CRL update is run
        # by the CA operator; PDP denial takes effect immediately in the meantime.
        emit("certificate_revoke", serial=serial, crl_update="operator-required")
        return {"decision": "revoked", "crl_update": "operator-required"}

    @app.get("/v1/sessions", dependencies=service)
    def sessions() -> dict[str, list[dict[str, Any]]]:
        repo, _, _ = state()
        return {"sessions": repo.sessions()}

    return app


app = build_app()
