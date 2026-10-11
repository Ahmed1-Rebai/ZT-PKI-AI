"""Structured audit logging; stdout is collected by Docker/systemd and Wazuh."""
from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("zt.pdp.audit")


def configure() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def emit(event: str, **fields: Any) -> None:
    logger.info(json.dumps({"ts": round(time.time(), 3), "component": "pdp", "event": event, **fields}, sort_keys=True))
