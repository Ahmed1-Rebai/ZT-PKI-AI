# S10 — Large exfiltration

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S10 — Large exfiltration |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *UEBA bytes_ratio* |
| **Tool / method** | `scp/curl large file to lab host` |
| **MITRE ATT&CK** | T1041 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | UEBA bytes_ratio |
| **Expected result** | Alert, reduce then quarantine |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s10_exfiltration/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s10_exfiltration/` |
| **Notes / improvements** | |
