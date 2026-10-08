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

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s03_revoked/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s03_revoked/` |
| **Notes / improvements** | |
