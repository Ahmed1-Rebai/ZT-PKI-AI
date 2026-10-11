"""Small Redis repository with an in-memory counterpart for unit tests."""
from __future__ import annotations

import json
import time
from typing import Any, Protocol


class Store(Protocol):
    def load_users(self, users: dict[str, dict[str, Any]]) -> None: ...
    def user(self, cn: str) -> dict[str, Any] | None: ...
    def user_by_ip(self, vpn_ip: str) -> str | None: ...
    def is_revoked(self, serial: str) -> bool: ...
    def revoke(self, serial: str) -> None: ...
    def posture(self, cn: str) -> float: ...
    def set_posture(self, cn: str, score: float, detail: dict[str, Any]) -> None: ...
    def anomaly(self, cn: str) -> float: ...
    def set_anomaly(self, cn: str, score: float) -> None: ...
    def put_session(self, cn: str, session: dict[str, Any], ttl: int) -> None: ...
    def session(self, cn: str) -> dict[str, Any] | None: ...
    def delete_session(self, cn: str) -> None: ...
    def sessions(self) -> list[dict[str, Any]]: ...


class RedisStore:
    """Redis keys are intentionally namespaced to avoid sharing ambiguous state."""
    def __init__(self, client: Any):
        self.r = client

    def load_users(self, users: dict[str, dict[str, Any]]) -> None:
        """Replace the directory wholesale so a user removed from data.json loses access."""
        pipe = self.r.pipeline()
        pipe.delete("zt:users")
        if users:
            pipe.hset("zt:users", mapping={cn: json.dumps(u) for cn, u in users.items()})
        pipe.execute()

    def user(self, cn: str) -> dict[str, Any] | None:
        raw = self.r.hget("zt:users", cn)
        return json.loads(raw) if raw else None

    def user_by_ip(self, vpn_ip: str) -> str | None:
        for cn, raw in self.r.hgetall("zt:users").items():
            if json.loads(raw).get("vpn_ip") == vpn_ip:
                return cn
        return None

    def is_revoked(self, serial: str) -> bool:
        return bool(self.r.sismember("zt:revoked", serial))

    def revoke(self, serial: str) -> None:
        self.r.sadd("zt:revoked", serial)

    def posture(self, cn: str) -> float:
        value = self.r.hget(f"zt:posture:{cn}", "score")
        return float(value) if value is not None else 0.0  # fail closed until attested

    def set_posture(self, cn: str, score: float, detail: dict[str, Any]) -> None:
        self.r.hset(f"zt:posture:{cn}", mapping={"score": score, "detail": json.dumps(detail), "ts": time.time()})

    def anomaly(self, cn: str) -> float:
        value = self.r.hget(f"zt:score:{cn}", "anomaly")
        return float(value) if value is not None else 0.0

    def set_anomaly(self, cn: str, score: float) -> None:
        self.r.hset(f"zt:score:{cn}", mapping={"anomaly": score, "ts": time.time()})

    def put_session(self, cn: str, session: dict[str, Any], ttl: int) -> None:
        key = f"zt:session:{cn}"
        self.r.set(key, json.dumps(session), ex=ttl)
        self.r.sadd("zt:sessions", cn)

    def session(self, cn: str) -> dict[str, Any] | None:
        raw = self.r.get(f"zt:session:{cn}")
        if not raw:
            self.r.srem("zt:sessions", cn)
            return None
        return json.loads(raw)

    def delete_session(self, cn: str) -> None:
        self.r.delete(f"zt:session:{cn}")
        self.r.srem("zt:sessions", cn)

    def sessions(self) -> list[dict[str, Any]]:
        return [s for cn in self.r.smembers("zt:sessions") if (s := self.session(cn))]


class MemoryStore:
    """Test double; its semantics mirror Redis TTL behaviour closely enough for API tests."""
    def __init__(self, users: dict[str, dict[str, Any]] | None = None):
        self.users, self.revoked, self.postures, self.anomalies = users or {}, set(), {}, {}
        self._sessions: dict[str, tuple[dict[str, Any], float]] = {}

    def load_users(self, users: dict[str, dict[str, Any]]) -> None: self.users = dict(users)
    def user(self, cn: str) -> dict[str, Any] | None: return self.users.get(cn)
    def user_by_ip(self, vpn_ip: str) -> str | None:
        return next((cn for cn, u in self.users.items() if u.get("vpn_ip") == vpn_ip), None)
    def is_revoked(self, serial: str) -> bool: return serial in self.revoked
    def revoke(self, serial: str) -> None: self.revoked.add(serial)
    def posture(self, cn: str) -> float: return float(self.postures.get(cn, {}).get("score", 0.0))
    def set_posture(self, cn: str, score: float, detail: dict[str, Any]) -> None: self.postures[cn] = {"score": score, "detail": detail}
    def anomaly(self, cn: str) -> float: return float(self.anomalies.get(cn, 0.0))
    def set_anomaly(self, cn: str, score: float) -> None: self.anomalies[cn] = score
    def put_session(self, cn: str, session: dict[str, Any], ttl: int) -> None: self._sessions[cn] = (session, time.time() + ttl)
    def session(self, cn: str) -> dict[str, Any] | None:
        item = self._sessions.get(cn)
        if not item or item[1] <= time.time():
            self._sessions.pop(cn, None)
            return None
        return item[0]
    def delete_session(self, cn: str) -> None: self._sessions.pop(cn, None)
    def sessions(self) -> list[dict[str, Any]]: return [s for cn in list(self._sessions) if (s := self.session(cn))]
