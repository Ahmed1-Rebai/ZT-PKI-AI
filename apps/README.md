# apps/

Protected workloads for the demo (see [docs/06 §7](../docs/06-zero-trust-pdp-pep.md)).

```
apps/
├── proxy/          # Nginx mTLS reverse proxy config (DMZ 10.10.10.10)
├── webapp/         # demo Flask app / API (10.10.20.10); /portal is contractor-only
├── posture/        # client posture agent + systemd timer (runs on client-lin, reports to the PDP)
└── db/             # PostgreSQL init (10.10.30.10)
```

Reachable only through the gateway; server-to-server flows (proxy → app :8080, app → DB :5432) are explicitly whitelisted.
