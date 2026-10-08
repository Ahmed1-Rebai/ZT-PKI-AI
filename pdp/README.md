# pdp/

Policy Decision Point: FastAPI API, trust engine, OPA policies, nftables enforcement (see [docs/06](../docs/06-zero-trust-pdp-pep.md)).

```
pdp/
├── main.py          # FastAPI endpoints (/authenticate, /session/*, /posture, /events, ...)
├── trust.py         # trust score computation + EMA
├── enforce.py       # nftables dynamic rules + OpenVPN management (kill session)
├── policies/
│   ├── authz.rego   # OPA policy (allow + tier)
│   ├── data.json    # roles, min scores, resources
│   └── authz_test.rego
└── Dockerfile
```

Runs over mTLS; certificates issued by the Issuing CA. No secrets in the repo (`.env`, certs mounted at runtime).
