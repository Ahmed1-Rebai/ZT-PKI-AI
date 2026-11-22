# S11 — Firewall policy tampering

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S11 — Firewall policy tampering |
| **Run from** | the lab host — `bash tests/run-redteam.sh s11` |
| **Objective** | Verify the Zero Trust control: *Wazuh file-integrity monitoring* |
| **Tool / method** | append a marker line to `/etc/nftables.conf` on `zt-gw` |
| **MITRE ATT&CK** | T1562.004 |
| **Preconditions** | Wazuh agent active on `zt-gw`, realtime FIM on `/etc/nftables.conf` |
| **Zero Trust control tested** | Wazuh FIM + correlation rule 100160 |
| **Expected result** | Immediate alert |

## Steps

1. Copy the original `nftables.conf`, append a unique marker comment, keep the file in place (no `mv`: it would break the realtime watch).
2. Poll the Wazuh alerts for rule 100160 on `/etc/nftables.conf`.
3. Restore the original content in place (`cp`), remove the backup.

## Measurements

- 2026-11-21 08:37:16: alert *ZT: gateway firewall policy changed (/etc/nftables.conf)*, rule 100160, level 13, MITRE T1562.004, agent `zt-gw` — size, mtime and hashes changed.
- See `tests/evidence/s11_fw_tamper/` for the logs.

## Result

| | |
|---|---|
| **Actual result** | Detected within seconds. The alert carries the old and new size and hashes, so the change can be audited and reverted. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s11_fw_tamper/` |
| **Notes / improvements** | Wazuh realtime FIM follows the inode: restoring a file with `mv` silently stops the watch. The script restores with `cp`. |
