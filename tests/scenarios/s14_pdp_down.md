# S14 — PDP failure

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S14 — PDP failure |
| **Owner** | Blue Team |
| **Objective** | Verify the Zero Trust control: *Fail-closed + TTL* |
| **Tool / method** | `stop the service` |
| **MITRE ATT&CK** | - |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Fail-closed + TTL |
| **Expected result** | No access, rules expire |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s14_pdp_down/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s14_pdp_down/` |
| **Notes / improvements** | |
