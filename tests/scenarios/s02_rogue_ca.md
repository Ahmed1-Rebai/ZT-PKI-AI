# S2 — Certificate from another CA (rogue CA)

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S2 — Certificate from another CA (rogue CA) |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Trust chain* |
| **Tool / method** | `self-signed CA` |
| **MITRE ATT&CK** | T1553 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Trust chain |
| **Expected result** | Refused |

## Steps

1. On `client-lin` generate a rogue self-signed CA and an `eve@lab.local` client certificate.
2. Connect using the **real** CA chain (so the genuine server is trusted) but the rogue client certificate (`tests/run-m2.sh s2`).
3. The gateway verifies the peer chain against `ca-chain.crt` and rejects.

## Measurements

- t0 (start): 2026-10-10 18:52:44Z
- t_detect / t_quarantine (if applicable): < 1 s — `VERIFY ERROR: depth=0, error=unable to get local issuer certificate: CN=eve@lab.local`.
- See `tests/evidence/s02_rogue_ca/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | Refused. The issuing CA is not in the gateway trust anchor, so the client chain does not build. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s02_rogue_ca/` |
| **Notes / improvements** | Trust is anchored on the lab Root/Issuing CA only; certificates from any other CA are rejected at handshake. |
