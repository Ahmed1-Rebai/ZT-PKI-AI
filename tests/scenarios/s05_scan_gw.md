# S5 — UDP/TCP scan of the gateway

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S5 — UDP/TCP scan of the gateway |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *tls-crypt + default drop* |
| **Tool / method** | `nmap -sU -sS 192.168.100.1` |
| **MITRE ATT&CK** | T1046 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | tls-crypt + default drop |
| **Expected result** | No port visible except silent 1194 |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s05_scan_gw/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s05_scan_gw/` |
| **Notes / improvements** | |
