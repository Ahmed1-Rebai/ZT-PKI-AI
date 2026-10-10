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

1. From `client-lin` (untrust, `192.168.100.11`) build a profile that keeps only the CA chain and `tls-crypt` key — no `<cert>`/`<key>` — and run `openvpn --config /tmp/nocert.conf` (`tests/run-m2.sh s1`).
2. Confirm the client aborts and no tunnel is created; the gateway sees no authenticated peer.

## Measurements

- t0 (start): 2026-10-10 18:52:17Z
- t_detect / t_quarantine (if applicable): immediate (< 1 s) — `Options error: No client-side authentication method is specified`; no `tun0`, no handshake.
- See `tests/evidence/s01_no_cert/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | Connection refused. OpenVPN aborts because no client cert/key is configured; the gateway (`verify-client-cert require`) would also reject any certless peer. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s01_no_cert/` |
| **Notes / improvements** | mTLS is mandatory before the tunnel can form; there is no password fallback to downgrade to. |
