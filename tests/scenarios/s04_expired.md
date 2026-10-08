# S4 — Expired certificate

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S4 — Expired certificate |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *X.509 validity* |
| **Tool / method** | `clock forward / -days 0` |
| **MITRE ATT&CK** | T1078 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | X.509 validity |
| **Expected result** | Refused |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s04_expired/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s04_expired/` |
| **Notes / improvements** | |
