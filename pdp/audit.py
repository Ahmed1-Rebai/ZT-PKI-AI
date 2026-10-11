"""Structured audit logging: one JSON object per decision.

Written to stdout (Docker/systemd) and, when a path is given, appended to a
JSON-lines file that the Wazuh agent on zt-pdp collects (docs/08 §4.2).
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger("zt.pdp.audit")


def configure(path: str | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if path and not any(getattr(h, "baseFilename", None) == os.path.abspath(path) for h in logger.handlers):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            handler = logging.FileHandler(path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        except OSError as exc:                      # stdout keeps the trail if the file is unavailable
            logger.warning(json.dumps({"component": "pdp", "event": "audit_file_error", "error": str(exc)}))
    logger.setLevel(logging.INFO)


def emit(event: str, **fields: Any) -> None:
    logger.info(json.dumps({"ts": round(time.time(), 3), "component": "pdp", "event": event, **fields}, sort_keys=True))
