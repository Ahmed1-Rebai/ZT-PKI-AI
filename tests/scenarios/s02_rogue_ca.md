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

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s02_rogue_ca/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s02_rogue_ca/` |
| **Notes / improvements** | |
