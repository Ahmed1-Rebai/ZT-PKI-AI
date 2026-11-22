# S8 — Stolen certificate used from a non-compliant device

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S8 — Stolen certificate used from a non-compliant device |
| **Run from** | `client-lin` — `bash tests/run-redteam.sh s8` |
| **Objective** | Verify the Zero Trust control: *device posture* |
| **Tool / method** | alice's valid certificate used on a device that is not enrolled (`/etc/zt-client/managed` removed) and whose firewall is off (`ufw disable`) |
| **MITRE ATT&CK** | T1078 |
| **Preconditions** | Lab in configuration D, alice connected |
| **Zero Trust control tested** | Posture agent → PDP trust score → nftables tier |
| **Expected result** | Score down, quarantine |

## Steps

1. Simulate the attacker's device on `client-lin`: remove the enrolment marker and disable the host firewall.
2. Run the posture agent with its normal environment (`/etc/zt-client/posture.env`): it reports the failed checks to the PDP over mTLS.
3. Read the gateway sets and probe the web proxy from the tunnel.
4. Restore the marker and the firewall; the next posture report brings alice back to tier full.

## Measurements

- 2026-11-21: PDP answers `{"decision":"recorded","score":0.0,"tier":"quarantine"}`; the gateway set `quarantine` holds `10.8.0.10` (timeout 30 min) and the proxy is unreachable (`proxy_http_code=000`).
- See `tests/evidence/s08_stolen_cert/` for the logs.

## Result

| | |
|---|---|
| **Actual result** | Quarantined. The certificate is valid, but the device fails its posture: the PDP moves the session to quarantine and the gateway drops everything except the posture channel to the PDP. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s08_stolen_cert/` |
| **Notes / improvements** | The certificate alone is not enough. Configurations A and B keep the access (no posture check); C and D quarantine it (`tests/reports/abcd/attacks.json`). |
