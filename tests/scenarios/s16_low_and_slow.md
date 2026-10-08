# S16 — Low-and-slow evasion

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S16 — Low-and-slow evasion |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Long-window UEBA* |
| **Tool / method** | `nmap -T1, small-volume exfil` |
| **MITRE ATT&CK** | T1046/T1048 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Long-window UEBA |
| **Expected result** | Late detection (limit discussed) |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s16_low_and_slow/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s16_low_and_slow/` |
| **Notes / improvements** | |
