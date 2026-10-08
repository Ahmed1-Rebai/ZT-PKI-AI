# S8 — Internal scan from compromised client

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S8 — Internal scan from compromised client |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *AI + Suricata -> quarantine* |
| **Tool / method** | `nmap -sS 10.10.0.0/16` |
| **MITRE ATT&CK** | T1046 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | AI + Suricata -> quarantine |
| **Expected result** | TTQ <= 15 s |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s08_internal_scan/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s08_internal_scan/` |
| **Notes / improvements** | |
