# Scenario test sheets (S1–S17)

One sheet per attack scenario from [docs/09](../../docs/09-tests-et-scenarios.md). Fill in Steps / Result during execution; attach proof under `tests/evidence/<slug>/`.

| ID | Title | Owner | MITRE | Sheet |
|---|---|---|---|---|
| S1 | Connection without certificate | 🔴 | T1133 | [s01](s01_no_cert.md) |
| S2 | Rogue CA certificate | 🔴 | T1553 | [s02](s02_rogue_ca.md) |
| S3 | Revoked certificate | 🔴 | T1078 | [s03](s03_revoked.md) |
| S4 | Expired certificate | 🔴 | T1078 | [s04](s04_expired.md) |
| S5 | Gateway scan | 🔴 | T1046 | [s05](s05_scan_gw.md) |
| S6 | UDP DoS on VPN | 🔴 | T1498 | [s06](s06_udp_dos.md) |
| S7 | Out-of-role SSH | 🔴 | T1021 | [s07](s07_out_of_role_ssh.md) |
| S8 | Internal scan (compromised client) | 🔴 | T1046 | [s08](s08_internal_scan.md) |
| S9 | SSH brute force | 🔴 | T1110 | [s09](s09_ssh_bruteforce.md) |
| S10 | Large exfiltration | 🔴 | T1041 | [s10](s10_exfiltration.md) |
| S11 | DNS tunnel | 🔴 | T1071.004 | [s11](s11_dns_tunnel.md) |
| S12 | Stolen cert on another device | 🔴 | T1078 | [s12](s12_stolen_cert.md) |
| S13 | Gateway MITM | 🔴 | T1557 | [s13](s13_mitm_gw.md) |
| S14 | PDP failure (fail-closed) | 🔵 | — | [s14](s14_pdp_down.md) |
| S15 | Firewall policy tampering | 🔴 | T1562 | [s15](s15_fw_tamper.md) |
| S16 | Low-and-slow evasion | 🔴 | T1046/T1048 | [s16](s16_low_and_slow.md) |
| S17 | Model poisoning (theoretical) | 🔵 | ATLAS AML.T0020 | [s17](s17_model_poison.md) |
