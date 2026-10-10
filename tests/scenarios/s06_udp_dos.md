# S6 — UDP DoS on the VPN

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S6 — UDP DoS on the VPN |
| **Owner** | Red Team |
| **Objective** | Verify the Zero Trust control: *tls-crypt + rate-limit* |
| **Tool / method** | `hping3 --udp --flood` |
| **MITRE ATT&CK** | T1498 |
| **Preconditions** | Lab isolated (NAT removed), target VM up, snapshot taken, NTP in sync |
| **Zero Trust control tested** | tls-crypt + rate-limit |
| **Expected result** | Service stable, packets ignored |

## Steps

1. From `client-lin` flood UDP/1194: `hping3 --udp -p 1194 --flood -d 1000 192.168.100.1` for ~12 s (`tests/run-m2.sh s6`).
2. Check the gateway service stays up and a legitimate client can still connect.

## Measurements

- t0 (start): 2026-10-10 19:04:40Z
- t_detect / t_quarantine (if applicable): n/a (availability)
- See `tests/evidence/s06_udp_dos/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | 600,428 packets sent, **0 received** (100 % loss). After the flood `openvpn=active`, `nftables=active`, load ~0.16, and a valid client reconnected and got `10.8.0.10/24`. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s06_udp_dos/` (`hping3.txt`, `gateway-status.txt`) |
| **Notes / improvements** | Two layers drop the flood: `tls-crypt` discards unauthenticated packets and nftables rate-limits 1194 to 50/s. |
