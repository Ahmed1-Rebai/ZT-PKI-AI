from dataclasses import replace

from fastapi.testclient import TestClient

from config import settings
from main import build_app
from store import MemoryStore


def as_caller(app, host):
    """Run `app` as if requests came from `host` (sets the ASGI client address)."""
    async def wrapped(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope, client=(host, 50000))
        await app(scope, receive, send)
    return wrapped


class Policy:
    def decide(self, input):
        role = input["identity"]["role"]
        score = input["trust_score"]
        thresholds = {"employee": 60, "admin": 85, "contractor": 70}
        admit = bool(role in thresholds and input["identity"]["cert_valid"] and not input["identity"]["revoked"])
        allow = admit and input["device"]["posture_ok"] and score >= thresholds[role]
        tier = "full" if score >= 80 else "restricted" if score >= 50 else "quarantine" if score >= 20 else "revoke"
        return {"allow": allow, "admit": admit, "tier": tier, "reason": "test"}


class Gate:
    def __init__(self): self.calls = []
    def apply(self, *args): self.calls.append(("apply", *args))
    def clear(self, *args): self.calls.append(("clear", *args))
    def kill(self, *args): self.calls.append(("kill", *args))


def client():
    users = {"alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"}}
    repo, gate = MemoryStore(users), Gate()
    app = build_app(repo, Policy(), gate, replace(settings, session_ttl_seconds=60))
    # Control calls come from the mgmt network (gateway hooks / AI engine).
    return TestClient(as_caller(app, "10.10.99.1")), gate


def test_fresh_device_is_admitted_to_quarantine_then_upgraded_by_posture():
    """Gap (a): no posture yet must not lock the device out of the posture channel."""
    c, gate = client()
    with c:
        auth = c.post("/v1/authenticate", json={"cn": "alice@lab.local", "serial": "20", "src_ip": "x"}).json()
        assert auth["decision"] == "allow" and auth["tier"] == "quarantine"
        opened = c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"}).json()
        assert opened["decision"] == "allow" and opened["tier"] == "quarantine"
        assert opened["vpn_ip"] == "10.8.0.10"
        assert gate.calls[-1] == ("apply", "10.8.0.10", "employee", "quarantine")
        # a good posture report re-scores the open session immediately
        assert c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1}).json()["tier"] == "full"
        assert gate.calls[-1] == ("apply", "10.8.0.10", "employee", "full")


def test_unknown_or_revoked_identity_is_refused_the_tunnel():
    c, gate = client()
    with c:
        assert c.post("/v1/authenticate", json={"cn": "mallory@lab.local", "serial": "99"}).json()["decision"] == "deny"
        c.post("/v1/cert/20/revoke")
        assert c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"}).json()["decision"] == "deny"
        assert not [x for x in gate.calls if x[0] == "apply"]


def test_ai_event_never_grants_more_than_policy_allows():
    """Gap (b): a good score tier must not bypass a failing posture."""
    c, gate = client()
    with c:
        c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1})
        c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"})
        c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 0.2})   # posture now fails
        r = c.post("/v1/events", json={"cn": "alice@lab.local", "anomaly": 0, "source": "test"}).json()
        assert r["tier"] == "quarantine"
        assert gate.calls[-1] == ("apply", "10.8.0.10", "employee", "quarantine")


def test_critical_event_revokes_rights():
    c, gate = client()
    with c:
        c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1})
        c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"})
        r = c.post("/v1/events", json={"cn": "alice@lab.local", "anomaly": 1, "source": "test", "critical": True}).json()
        assert r["tier"] == "revoke"
        assert gate.calls[-1] == ("apply", "10.8.0.10", "employee", "revoke")


def test_revoke_kills_tunnel_even_if_rule_removal_fails():
    """Gap (c): the VPN session is killed whatever happens to the nft step."""
    c, gate = client()
    def broken(*a): raise RuntimeError("gateway unreachable")
    with c:
        c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1})
        c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"})
        gate.clear = broken
        c.post("/v1/cert/20/revoke")
        assert ("kill", "alice@lab.local") in gate.calls
        assert c.get("/v1/sessions").json()["sessions"] == []


def test_revoke_terminates_matching_session():
    c, gate = client()
    with c:
        c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1})
        c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"})
        assert c.post("/v1/cert/20/revoke").json()["decision"] == "revoked"
        assert c.get("/v1/sessions").json()["sessions"] == []
        assert ("kill", "alice@lab.local") in gate.calls


def test_directory_is_seeded_from_data_json(tmp_path):
    """Regression: the real PDP starts with an empty store and must load users."""
    users_file = tmp_path / "data.json"
    users_file.write_text('{"users": {"alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"}}}')
    repo = MemoryStore()  # empty, like a fresh Redis
    cfg = replace(settings, users_file=str(users_file), session_ttl_seconds=60)
    with TestClient(build_app(repo, Policy(), Gate(), cfg)):
        assert repo.user("alice@lab.local") == {"role": "employee", "vpn_ip": "10.8.0.10"}
        assert repo.user_by_ip("10.8.0.10") == "alice@lab.local"


def _app():
    users = {"alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"},
             "bob@lab.local": {"role": "employee", "vpn_ip": "10.8.0.20"}}
    return build_app(MemoryStore(users), Policy(), Gate(), replace(settings, session_ttl_seconds=60))


def test_vpn_client_can_report_only_its_own_posture():
    app = _app()
    alice = TestClient(as_caller(app, "10.8.0.10"))  # alice's tunnel address
    with alice:
        assert alice.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1}).status_code == 200
        # claiming bob's identity from alice's tunnel address is refused
        assert alice.post("/v1/posture", json={"cn": "bob@lab.local", "score": 1}).status_code == 403


def test_vpn_client_cannot_call_control_endpoints():
    app = _app()
    alice = TestClient(as_caller(app, "10.8.0.10"))
    with alice:
        assert alice.post("/v1/cert/20/revoke").status_code == 403
        assert alice.post("/v1/events", json={"cn": "bob@lab.local", "anomaly": 1, "source": "x"}).status_code == 403
        assert alice.get("/v1/sessions").status_code == 403


def test_unknown_network_is_refused():
    app = _app()
    outsider = TestClient(as_caller(app, "192.168.100.66"))
    with outsider:
        assert outsider.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1}).status_code == 403
        assert outsider.post("/v1/authenticate", json={"cn": "alice@lab.local", "serial": "20"}).status_code == 403


def test_decisions_are_written_to_the_audit_file(tmp_path):
    """Wazuh tails this file on zt-pdp (docs/08 §4.2)."""
    import json as _json
    log = tmp_path / "audit.jsonl"
    users = {"alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"}}
    app = build_app(MemoryStore(users), Policy(), Gate(),
                    replace(settings, session_ttl_seconds=60, audit_log=str(log)))
    with TestClient(as_caller(app, "10.10.99.1")) as c:
        c.post("/v1/authenticate", json={"cn": "alice@lab.local", "serial": "20"})
    events = [_json.loads(line)["event"] for line in log.read_text().splitlines()]
    assert "authenticate" in events
