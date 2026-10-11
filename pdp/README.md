# pdp/

Policy Decision Point: FastAPI API, trust engine, OPA policies, Redis session
state and gateway nftables enforcement (see [docs/06](../docs/06-zero-trust-pdp-pep.md)).

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

## M3 deployment

The control plane is defined in [`infra/docker-compose.yml`](../infra/docker-compose.yml):
Redis stores sessions/posture/revocations, OPA evaluates `policies/`, and the
PDP exposes `https://10.10.99.10:8443` with mandatory client TLS.

1. On `sub-ca`, issue the one-purpose PEP identity, then stage the material:

   ```bash
   PKI_BASE=/home/vagrant PKI_PASS='…' pki/scripts/issue-server.sh \
     gw-client.lab.local gw-client.lab.local server_client_cert 90
   ./pdp/scripts/sync-pki.sh
   ```

2. Deploy the PDP and gateway with enforcement enabled:

   ```bash
   cd infra/ansible
   ansible-playbook -i inventory.ini site.yml --limit pdp,gateway -e vpn_pdp_enforce=1
   ```

   The role refuses to deploy if the staged mTLS key, PDP certificate, or
   restricted gateway SSH key is absent. No credential is committed.

3. Seed/adjust `pdp/policies/data.json` before deployment. A newly known user
   begins with posture `0`: the tunnel is admitted on identity alone (`admit`),
   but the session opens in **quarantine** (posture channel + remediation
   portal only) until the posture agent's report re-scores it. Resource tiers
   apply only when the policy's `allow` holds (`effective_tier`). Every 60
   seconds the PDP re-evaluates active sessions;
   gateway rules expire naturally if that loop or the PDP fails.

`/v1/cert/{serial}/revoke` immediately denies the serial in the PDP and tears
down its active session. The CA operator must still run the signed CRL update
on `sub-ca`; that separation keeps the CA key and revocation authority out of
the PDP container.

## Checks

```bash
cd pdp
pytest -q
opa test policies -v
```

Runs over mTLS; certificates are issued by the Issuing CA. No secrets are
tracked: `.env`, `certs/*.key`, and `ssh/id_ed25519` are ignored.
