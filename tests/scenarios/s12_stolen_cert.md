# S12 — Stolen cert on another device

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S12 — Stolen cert on another device |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Posture + device fingerprint + UEBA* |
| **Tool / method** | `copy .ovpn to Kali` |
| **MITRE ATT&CK** | T1078 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Posture + device fingerprint + UEBA |
| **Expected result** | Score down, reject / restrict |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s12_stolen_cert/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s12_stolen_cert/` |
| **Notes / improvements** | |
