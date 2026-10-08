# S15 — Firewall policy tampering

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S15 — Firewall policy tampering |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *Wazuh FIM* |
| **Tool / method** | `edit nftables.conf` |
| **MITRE ATT&CK** | T1562 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Wazuh FIM |
| **Expected result** | Immediate alert |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s15_fw_tamper/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s15_fw_tamper/` |
| **Notes / improvements** | |
