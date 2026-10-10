# S3 — Revoked certificate

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S3 — Revoked certificate |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *CRL + OCSP + PDP list* |
| **Tool / method** | `revoke then connect` |
| **MITRE ATT&CK** | T1078 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | CRL + OCSP + PDP list |
| **Expected result** | Refused < 60 s |

## Steps

1. On `sub-ca` revoke alice and regenerate the CRL: `pki/scripts/revoke.sh pki/sub/certs/alice.crt keyCompromise` then `pki/scripts/gencrl.sh`.
2. Publish the new CRL to the gateway `/etc/openvpn/server/crl.pem`; OpenVPN re-reads `crl-verify` when the file changes (no restart needed).
3. Reconnect as alice (`tests/run-m2.sh s3`); the gateway checks the CRL and refuses.

## Measurements

- t0 (start): 2026-10-10 18:52:49Z (revocation)
- t_detect / t_quarantine (if applicable): refusal on the first post-update handshake (< 1 s); end-to-end wall time in the lab 29 s, dominated by the CRL publish + reconnect step, not detection.
- See `tests/evidence/s03_revoked/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | Refused — `VERIFY ERROR: depth=0, error=certificate revoked: C=TN, O=ZT-Lab, CN=alice@lab.local, serial=8204`. Well within 60 s. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s03_revoked/` (`revoke.txt`, `crl.pem`, `timing.txt`, `server.log`) |
| **Notes / improvements** | In production the CRL is served over HTTP/OCSP so propagation is seconds; the gateway reloads it transparently. Also enforced via OCSP at the proxy (M6). |
