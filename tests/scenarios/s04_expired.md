# S4 — Expired certificate

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S4 — Expired certificate |
| **Objective** | Verify the Zero Trust control: *X.509 validity* |
| **Tool / method** | `clock forward / -days 0` |
| **MITRE ATT&CK** | T1078 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | X.509 validity |
| **Expected result** | Refused |

## Steps

1. Issue an already-expired client certificate `bob` on `sub-ca` (`pki/scripts/issue-client.sh bob 0`, validity window ended one hour ago).
2. Build `bob.ovpn` and connect from `client-lin` (`tests/run-m2.sh s4`).
3. The gateway rejects the peer on X.509 validity.

## Measurements

- t0 (start): 2026-10-10 18:55:01Z
- t_detect / t_quarantine (if applicable): immediate on handshake — `VERIFY ERROR: depth=0, error=certificate has expired: CN=bob@lab.local, serial=8203`.
- See `tests/evidence/s04_expired/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | Refused. `notAfter` was in the past (`bob.validity.txt`), so certificate validation fails. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s04_expired/` |
| **Notes / improvements** | Short-lived client certs (default 7 days) plus strict validity checking limit the window a leaked cert is useful. |
