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

1. From `client-lin` scan the gateway: `nmap -sS -p 1-1024 192.168.100.1` (TCP) and a UDP top-ports scan (`tests/run-m2.sh s5`).
2. Inspect which ports answer and which stay silent.

## Measurements

- t0 (start): 2026-10-10 19:04:05Z
- t_detect / t_quarantine (if applicable): n/a (reconnaissance)
- See `tests/evidence/s05_scan_gw/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | All 1024 TCP ports `filtered`. On UDP, 49 ports are `open|filtered` (silent — including 1194) and only `123/udp` is `closed` (allowlisted NTP). The management socket `7505` is bound to loopback only. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s05_scan_gw/nmap.txt` |
| **Notes / improvements** | `tls-crypt` makes OpenVPN drop unauthenticated datagrams, so 1194 gives no reply; nftables input policy is `drop`. |
