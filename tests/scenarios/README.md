# Scenario test sheets (12 scenarios)

One sheet per attack scenario of [docs/09](../../docs/09-tests-et-scenarios.md). Every scenario is played from
`client-lin`, the test machine of the lab, and leaves its proof under `tests/evidence/<slug>/`.

| ID | Title | MITRE | Sheet | Runner | Status |
|---|---|---|---|---|---|
| S1 | Connection without certificate | T1133 | [s01](s01_no_cert.md) | `run-m2.sh` | ✅ 2026-11-21 |
| S2 | Rogue CA certificate | T1553 | [s02](s02_rogue_ca.md) | `run-m2.sh` | ✅ 2026-11-21 |
| S3 | Revoked certificate | T1078 | [s03](s03_revoked.md) | `run-m2.sh` | ✅ 2026-10-10 (10/10) |
| S4 | Expired certificate | T1078 | [s04](s04_expired.md) | `run-m2.sh` | ✅ 2026-11-21 |
| S5 | Gateway scan | T1046 | [s05](s05_scan_gw.md) | `run-m2.sh` (needs `nmap`) | ✅ 2026-10-10 (10/10) |
| S6 | UDP flood on the VPN port | T1498 | [s06](s06_udp_dos.md) | `run-m2.sh` (needs `hping3`) | ✅ 2026-10-10 (10/10) |
| S7 | Out-of-role SSH | T1021 | [s07](s07_out_of_role_ssh.md) | `run-redteam.sh` | ✅ 2026-11-21 |
| S8 | Stolen certificate on a non-compliant device | T1078 | [s08](s08_stolen_cert.md) | `run-redteam.sh` | ✅ 2026-11-21 |
| S9 | Fake gateway (MITM) | T1557 | [s09](s09_mitm_gw.md) | `run-m2.sh` | ✅ 2026-11-21 |
| S10 | PDP failure (fail-closed) | — | [s10](s10_pdp_down.md) | `run-m2.sh` | ✅ 2026-11-21 |
| S11 | Firewall policy tampering | T1562.004 | [s11](s11_fw_tamper.md) | `run-redteam.sh` | ✅ 2026-11-21 |
| S12 | Tampered AI model | ATLAS AML.T0020 | [s12](s12_model_poison.md) | `run-redteam.sh` | ✅ 2026-11-21 |

The initial test plan had 17 scenarios. Five of them (internal scan, SSH brute force, exfiltration, DNS
tunnel, low-and-slow evasion) needed offensive tooling and traffic campaigns that were not carried out;
they were dropped, and the 12 scenarios kept were renumbered S1–S8.
