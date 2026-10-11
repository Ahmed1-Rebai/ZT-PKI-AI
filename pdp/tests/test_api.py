from dataclasses import replace

from fastapi.testclient import TestClient

from config import settings
from main import build_app
from store import MemoryStore


class Policy:
    def decide(self, input):
        role = input["identity"]["role"]
        score = input["trust_score"]
        thresholds = {"employee": 60, "admin": 85, "contractor": 70}
        allow = bool(input["identity"]["cert_valid"] and not input["identity"]["revoked"]
                     and input["device"]["posture_ok"] and score >= thresholds.get(role, 101))
        tier = "full" if score >= 80 else "restricted" if score >= 50 else "quarantine" if score >= 20 else "revoke"
        return {"allow": allow, "tier": tier, "reason": "test"}


class Gate:
    def __init__(self): self.calls = []
    def apply(self, *args): self.calls.append(("apply", *args))
    def clear(self, *args): self.calls.append(("clear", *args))
    def kill(self, *args): self.calls.append(("kill", *args))


def client():
    users = {"alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"}}
    repo, gate = MemoryStore(users), Gate()
    app = build_app(repo, Policy(), gate, replace(settings, session_ttl_seconds=60))
    return TestClient(app), gate


def test_authentication_denies_without_posture_then_opens_session():
    c, gate = client()
    with c:
        assert c.post("/v1/authenticate", json={"cn": "alice@lab.local", "serial": "20", "src_ip": "x"}).json()["decision"] == "deny"
        assert c.post("/v1/posture", json={"cn": "alice@lab.local", "score": 1, "detail": {}}).status_code == 200
        opened = c.post("/v1/session/open", json={"cn": "alice@lab.local", "serial": "20"}).json()
        assert opened["decision"] == "allow"
        assert opened["vpn_ip"] == "10.8.0.10"
        assert gate.calls[0][0] == "apply"


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
