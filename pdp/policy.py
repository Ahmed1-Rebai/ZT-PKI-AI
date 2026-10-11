"""OPA client.  OPA failure is a denial; there is intentionally no allow fallback."""
from __future__ import annotations

from typing import Any
import httpx


class PolicyError(RuntimeError):
    pass


class OpaPolicy:
    def __init__(self, url: str): self.url = url

    def decide(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(self.url, json={"input": payload}, timeout=1.5)
            response.raise_for_status()
            result = response.json().get("result")
            if not isinstance(result, dict):
                raise PolicyError("OPA returned no decision object")
            return result
        except (httpx.HTTPError, ValueError, PolicyError) as exc:
            raise PolicyError(str(exc)) from exc
