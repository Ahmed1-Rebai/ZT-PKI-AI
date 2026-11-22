# S10 — PDP failure

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S10 — PDP failure |
| **Objective** | Verify the Zero Trust control: *Fail-closed + TTL* |
| **Tool / method** | `stop the service` |
| **MITRE ATT&CK** | - |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | Fail-closed + TTL |
| **Expected result** | No access, rules expire |

## Steps

1. On the gateway set the hooks to fail-closed: `PDP_ENFORCE=1` in `/etc/openvpn/zt/hook.env` (the PDP does not run until M3) and restart OpenVPN.
2. Connect as alice (`tests/run-m2.sh s10`).
3. The `tls-verify` hook cannot reach the PDP and denies the session.

## Measurements

- t0 (start): 2026-10-10 19:06:00Z
- t_detect / t_quarantine (if applicable): immediate — hook returns deny and the handshake fails; access is blocked (no fail-open).
- See `tests/evidence/s10_pdp_down/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | No access. Hook log: `{"event":"tls-verify","decision":"deny","reason":"pdp-unreachable","mode":"pdp"}`; client logs `TLS handshake failed`. Hook mode was restored to the M2 bootstrap (`PDP_ENFORCE=0`) afterwards. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s10_pdp_down/{gateway.log,client.log,hook.env}` |
| **Notes / improvements** | Fail-closed by default; the M3 PDP adds dynamic role/quarantine decisions on top. |
