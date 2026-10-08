# S9 — SSH brute force

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S9 — SSH brute force |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Suricata + AI + admin score < 85* |
| **Tool / method** | `hydra ssh (lab account)` |
| **MITRE ATT&CK** | T1110 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Suricata + AI + admin score < 85 |
| **Expected result** | Detected, SSH access removed |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s09_ssh_bruteforce/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s09_ssh_bruteforce/` |
| **Notes / improvements** | |
