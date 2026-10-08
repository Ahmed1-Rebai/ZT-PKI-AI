# S11 — DNS tunnel

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S11 — DNS tunnel |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *DNS rule + entropy features* |
| **Tool / method** | `dnscat2 / iodine` |
| **MITRE ATT&CK** | T1071.004 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | DNS rule + entropy features |
| **Expected result** | Alert, score up |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s11_dns_tunnel/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s11_dns_tunnel/` |
| **Notes / improvements** | |
