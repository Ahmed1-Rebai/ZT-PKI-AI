# apps/webapp

Flask app / API served by gunicorn on `0.0.0.0:8080` (app zone `10.10.20.10`).

It trusts only the headers injected by the mTLS proxy
(`X-Client-CN`, `X-Client-Serial`, `X-Client-Verify`) — never a declared body
field. Roles come from `roles.json` (CN -> role); unknown CNs are `unknown`.

| Route | Behaviour |
|---|---|
| `GET /healthz` | liveness |
| `GET /` | identity echo, logs the access to PostgreSQL |
| `GET /api/whoami` | certified CN / role / serial |
| `GET /api/records` | rows for the caller (admin sees all, others their own) |
| `GET /portal/` | contractor-only (`403` otherwise) |

Config via `/etc/zt-webapp/webapp.env` (DB host/user, `ZT_ROLE_FILE`).
