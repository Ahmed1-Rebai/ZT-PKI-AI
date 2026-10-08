# S13 — MITM / gateway spoofing

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S13 — MITM / gateway spoofing |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *verify-x509-name, remote-cert-tls server* |
| **Tool / method** | `fake OpenVPN server` |
| **MITRE ATT&CK** | T1557 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | verify-x509-name, remote-cert-tls server |
| **Expected result** | Client refuses to connect |

## Steps

1. _(fill in during execution)_

## Measurements

- t0 (start): …
- t_detect / t_quarantine (if applicable): …
- See `tests/evidence/s13_mitm_gw/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | |
| **Status** (OK / KO / partial) | |
| **Proof** (logs, captures) | `tests/evidence/s13_mitm_gw/` |
| **Notes / improvements** | |
