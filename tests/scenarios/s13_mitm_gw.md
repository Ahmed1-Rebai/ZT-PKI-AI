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

1. On `client-lin` start a fake OpenVPN server with a self-signed certificate `CN=vpn-gw.lab.local` and the **same** `tls-crypt` key (simulating a leaked key) so the client reaches certificate validation (`tests/run-m2.sh s13`).
2. Point a client at it (`remote 192.168.100.11 1195`, `verify-x509-name vpn-gw.lab.local name`, `remote-cert-tls server`).
3. The client validates the fake server certificate against the real CA chain and rejects.

## Measurements

- t0 (start): 2026-10-10 19:05:24Z
- t_detect / t_quarantine (if applicable): refusal at the first TLS verification — `VERIFY ERROR: depth=0, error=self-signed certificate: CN=vpn-gw.lab.local`.
- See `tests/evidence/s13_mitm_gw/` for logs and screenshots.

## Result

| | |
|---|---|
| **Actual result** | The client refuses to connect to the fake gateway (untrusted certificate); no tunnel is established. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s13_mitm_gw/` (`client.log`, `fake-server.log`) |
| **Notes / improvements** | Even with matching CN and a leaked `tls-crypt` key, the client pins the CA chain (`verify-x509-name` + `remote-cert-tls server`) so spoofing fails. |
