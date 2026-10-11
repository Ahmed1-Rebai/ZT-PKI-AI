"""ZT-PKI-AI demo web app / API (web-app VM, app zone 10.10.20.10:8080).

Sits behind the mTLS reverse proxy, which forwards the verified client
identity in headers (X-Client-CN / X-Client-Serial / X-Client-Verify). The app
never trusts a declared identity: it only reads what the proxy certified.

Routes
  GET /healthz            liveness (no identity needed)
  GET /                   identity echo + logs the access to PostgreSQL
  GET /api/whoami         JSON identity (CN, role, serial)
  GET /api/records        rows the caller is allowed to see (from PostgreSQL)
  GET /portal/            contractor-only area (403 otherwise)

Run:  gunicorn -b 0.0.0.0:8080 -w 2 app:app
"""
from __future__ import annotations

import json
import os

from flask import Flask, jsonify, request

ROLE_FILE = os.environ.get("ZT_ROLE_FILE", "/etc/zt-webapp/roles.json")
DB = {
    "host": os.environ.get("ZT_DB_HOST", "10.10.30.10"),
    "port": int(os.environ.get("ZT_DB_PORT", "5432")),
    "dbname": os.environ.get("ZT_DB_NAME", "ztapp"),
    "user": os.environ.get("ZT_DB_USER", "ztapp"),
    "password": os.environ.get("ZT_DB_PASS", "ztapp-demo-pass"),
}

app = Flask(__name__)


def _roles() -> dict:
    try:
        with open(ROLE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def identity() -> tuple[str, str, str]:
    """(cn, serial, role) as certified by the proxy."""
    cn = request.headers.get("X-Client-CN", "")
    serial = request.headers.get("X-Client-Serial", "")
    role = _roles().get(cn, "unknown")
    return cn, serial, role


def _db():
    import psycopg2

    return psycopg2.connect(connect_timeout=3, **DB)


def _log_access(cn: str, role: str, path: str) -> None:
    try:
        with _db() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO access_log (client_cn, role, path, src) VALUES (%s,%s,%s,%s)",
                (cn, role, path, request.remote_addr),
            )
    except Exception:  # pragma: no cover - DB is best-effort for the demo
        pass


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="zt-webapp")


@app.get("/")
def index():
    cn, serial, role = identity()
    _log_access(cn, role, "/")
    return jsonify(service="zt-webapp", you=cn, role=role, serial=serial,
                   message=f"welcome {cn or 'anonymous'}")


@app.get("/api/whoami")
def whoami():
    cn, serial, role = identity()
    return jsonify(cn=cn, role=role, serial=serial,
                   verify=request.headers.get("X-Client-Verify"))


@app.get("/api/records")
def records():
    cn, _serial, role = identity()
    if role == "unknown":
        return jsonify(error="unknown identity"), 403
    try:
        with _db() as conn, conn.cursor() as cur:
            if role == "admin":
                cur.execute("SELECT owner_cn, label FROM records ORDER BY id")
            else:
                cur.execute("SELECT owner_cn, label FROM records WHERE owner_cn = %s", (cn,))
            rows = [{"owner": r[0], "label": r[1]} for r in cur.fetchall()]
    except Exception as exc:  # pragma: no cover
        return jsonify(error="db-unavailable", detail=str(exc)), 503
    return jsonify(cn=cn, role=role, count=len(rows), records=rows)


@app.get("/portal/")
@app.get("/portal")
def portal():
    cn, _serial, role = identity()
    if role != "contractor":
        return jsonify(error="forbidden", you=cn, role=role), 403
    try:
        with _db() as conn, conn.cursor() as cur:
            cur.execute("SELECT owner_cn, label FROM records WHERE owner_cn = %s", (cn,))
            rows = [{"owner": r[0], "label": r[1]} for r in cur.fetchall()]
    except Exception as exc:  # pragma: no cover
        return jsonify(error="db-unavailable", detail=str(exc)), 503
    return jsonify(portal="contractor", you=cn, files=rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
