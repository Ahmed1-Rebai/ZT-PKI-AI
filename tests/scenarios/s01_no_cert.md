# S1 — Connection without certificate

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S1 — Connection without certificate |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *PKI / mTLS* |
| **Tool / method** | `openvpn client with no cert` |
| **MITRE ATT&CK** | T1133 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | PKI / mTLS |
| **Expected result** | Handshake refused |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s01_no_cert/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s01_no_cert/` |
| **Notes / improvements** | |
