# S7 — Legit client -> out-of-role SSH

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S7 — Legit client -> out-of-role SSH |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Micro-segmentation* |
| **Tool / method** | `ssh 10.10.20.10` |
| **MITRE ATT&CK** | T1021 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Micro-segmentation |
| **Expected result** | Drop + ZT-DROP log |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s07_out_of_role_ssh/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s07_out_of_role_ssh/` |
| **Notes / improvements** | |
