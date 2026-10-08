# S6 — UDP DoS on the VPN

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S6 — UDP DoS on the VPN |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *tls-crypt + rate-limit* |
| **Tool / method** | `hping3 --udp --flood` |
| **MITRE ATT&CK** | T1498 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | tls-crypt + rate-limit |
| **Expected result** | Service stable, packets ignored |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s06_udp_dos/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s06_udp_dos/` |
| **Notes / improvements** | |
