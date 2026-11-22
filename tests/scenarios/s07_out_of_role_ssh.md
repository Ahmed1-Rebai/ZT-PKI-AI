# S7 — Legit client -> out-of-role SSH

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S7 — Legit client -> out-of-role SSH |
| **Run from** | `client-lin`, inside alice's tunnel (`10.8.0.10`) — `bash tests/run-redteam.sh s7` |
| **Objective** | Verify the Zero Trust control: *Micro-segmentation* |
| **Tool / method** | `ssh 10.10.20.10` from an employee session |
| **MITRE ATT&CK** | T1021 |
| **Preconditions** | Lab in configuration D, alice connected with a compliant posture |
| **Zero Trust control tested** | Micro-segmentation (per-role nftables sets) |
| **Expected result** | Drop + `ZT-DROP` log on the gateway |

## Steps

1. With alice's tunnel up (employee role, tier *full*), try `ssh 10.10.20.10` (the app server) from `client-lin`.
2. Read the gateway kernel log for `ZT-DROP` lines with `SRC=10.8.0.10 DPT=22`.

## Measurements

- 2026-11-21: SSH attempt times out (`SSH_EXIT=255`); every SYN is logged `ZT-DROP IN=tun0 … SRC=10.8.0.10 DST=10.10.20.10 … DPT=22`.
- See `tests/evidence/s07_out_of_role_ssh/` for the logs.

## Result

| | |
|---|---|
| **Actual result** | Blocked. alice's address is only in `allow_web`; `allow_ssh` is reserved to the admin role at tier full, so the SYN falls to the default drop and is logged. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s07_out_of_role_ssh/` |
| **Notes / improvements** | A valid identity does not open the network: rights are per role and per flow. Same result in configurations B, C and D (`tests/reports/abcd/attacks.json`); in A (perimeter VPN) the port is exposed. |
