# Red Team session — coordination runbook

Shared checklist for the joint session (🔵 Ahmed on the lab host, 🔴 partner on
the Kali laptop). This file is the **order of operations**: how to wire the
laptop in, prove isolation, switch configs, time the controls and file the
evidence. The **attack specifics live in the scenario sheets** —
[tests/scenarios/](tests/scenarios/), one sheet per Sx — not here.

Nothing starts until [RULES-OF-ENGAGEMENT.md](RULES-OF-ENGAGEMENT.md) is signed
(both members) and the target snapshot is taken (§3).

---

## 0. Roles

| | Who | Machine | Touches |
|---|---|---|---|
| 🔵 Blue | Ahmed | lab host (VirtualBox) | PDP, gateway, SIEM, config switching, timing |
| 🔴 Red | partner | Kali laptop | only `zt-untrust` 192.168.100.0/24, via the scenario sheets |

The Red Team only ever reaches the lab through the gateway's WAN NIC
(`192.168.100.1`). The internal zones (10.10.x.x) must never be routable from
Kali — that is the whole point of the isolation check in §2.

---

## 1. Blue prep (before the partner arrives) — ~15 min

1. **Unload KVM, resume the lab** (they can't both hold the CPU virt):
   ```bash
   sudo modprobe -r kvm_amd kvm
   cd infra && for v in sub-ca zt-gw zt-pdp web-proxy web-app db client-lin zt-sensor siem; do vagrant resume $v; done
   ```
2. **Fix the VM clocks** (a resume leaves them hours behind, which backdates the
   CRL and breaks cert validity):
   ```bash
   cd infra && for v in sub-ca zt-gw zt-pdp web-proxy web-app db client-lin zt-sensor siem; do vagrant ssh $v -c "sudo date -u -s '@$(date +%s)'"; done
   ```
3. **Refresh the CRL** (valid 24 h only — without this nothing connects):
   ```bash
   bash pki/scripts/refresh-crl.sh
   ```
4. **Confirm the lab is healthy** (tunnel up, proxy mTLS 200, PDP + AI + Suricata up):
   ```bash
   bash vpn/scripts/verify.sh        # expect 9/9 PASS
   ```
5. **Lab starts in config D** (full ZT + AI). Switch later with §4.

---

## 2. Wire in the Kali laptop + prove isolation — ~10 min · **do together**

Physical link: the host's dedicated wired NIC `enp4s0` cabled (Ethernet or
USB-Ethernet) straight to the Kali laptop. `enp4s0` carries **no host IP and no
route** — it exists only to bridge the gateway's WAN into the laptop.

1. **Host:** point the gateway's WAN NIC (adapter 2, the `zt-untrust` net) at the
   cabled NIC as a bridged adapter, with the lab powered off for that VM:
   ```bash
   cd infra && vagrant halt zt-gw
   VMID=$(cat .vagrant/machines/zt-gw/virtualbox/id)
   VBoxManage modifyvm "$VMID" --nic2 bridged --bridgeadapter2 enp4s0
   vagrant up zt-gw --no-provision
   ```
   > To return to the solo lab afterwards, set `--nic2 intnet --intnet2 zt-untrust`
   > and `vagrant reload zt-gw`.
2. **Kali:** static address on the WAN segment, e.g. `192.168.100.50/24`, gateway
   `192.168.100.1`. No other NIC connected (no Wi-Fi, no second cable).
3. **Isolation gate — must all hold before any attack:**
   - `ping 192.168.100.1` → **succeeds** (reaches the gateway WAN).
   - `ping 10.10.30.10` (database) → **fails** (no route to internal zones).
   - `ping 8.8.8.8` → **fails** (no Internet).
   If any of those three is wrong, **stop** and fix the wiring — do not test.
4. **Snapshot** the target VMs so destructive scenarios can be rolled back:
   ```bash
   cd infra && for v in zt-gw zt-pdp web-app db client-lin; do vagrant snapshot save $v pre-redteam; done
   ```

---

## 3. Running order of the scenarios

Each row → its sheet for the tool, method and expected result. Red fills in
Steps/Result on the sheet; Blue watches the PDP audit log, Suricata/Wazuh and
the gateway sets. **One proof file per result** under `tests/evidence/<slug>/`.

| Stage | From | Scenarios (sheet) | Blue watches |
|---|---|---|---|
| A. Outside attacker | Kali (untrust) | [S1](tests/scenarios/s01_no_cert.md) · [S2](tests/scenarios/s02_rogue_ca.md) · [S3](tests/scenarios/s03_revoked.md) · [S4](tests/scenarios/s04_expired.md) · [S5](tests/scenarios/s05_scan_gw.md) · [S6](tests/scenarios/s06_udp_dos.md) · [S13](tests/scenarios/s13_mitm_gw.md) | handshake refused; only UDP/1194 silent |
| B. Stolen identity | Kali | [S12](tests/scenarios/s12_stolen_cert.md) | PDP score ↓, restrict / reject |
| C. Out of role | client-lin | [S7](tests/scenarios/s07_out_of_role_ssh.md) | `ZT-DROP` log on the gateway |
| D. Compromised client | client-lin (alice tunnel) | [S8](tests/scenarios/s08_internal_scan.md) · [S9](tests/scenarios/s09_ssh_bruteforce.md) · [S10](tests/scenarios/s10_exfiltration.md) · [S11](tests/scenarios/s11_dns_tunnel.md) | AI event → tier drop → quarantine/revoke |
| E. Infrastructure | zt-pdp / zt-gw | [S14](tests/scenarios/s14_pdp_down.md) · [S15](tests/scenarios/s15_fw_tamper.md) | fail-closed; Wazuh FIM alert |
| F. Limits | client-lin | [S16](tests/scenarios/s16_low_and_slow.md) · [S17](tests/scenarios/s17_model_poison.md) | late/no detection — discuss honestly |

S1–S6, S13, S14 already passed at M2 (re-run to confirm). S7–S12, S15, S16, S17
are new this session.

---

## 4. A/B/C/D comparison (stage D scenarios in each config)

For the comparative evaluation, run the stage-D scenarios (S8–S11, and S16)
once per configuration, switching with the Phase-10 tooling:

```bash
bash tests/abcd/set-config.sh A    # perimeter VPN   (PDP off, pool routes everywhere)
bash tests/abcd/set-config.sh B    # static ZT       (fixed per-role rules, no PDP)
bash tests/abcd/set-config.sh C    # dynamic PDP     (TTL rules, posture, no AI)
bash tests/abcd/set-config.sh D    # full            (PDP + AI — normal state)
```

For each config record, per scenario: **detected? blocked? TTD, TTQ**. The
benign surface matrix is already measured (`tests/reports/abcd/`); this adds the
attack columns. When done, `bash tests/abcd/set-config.sh D` returns to normal,
then regenerate tables/charts:

```bash
.venv/bin/python tests/reports/make_report.py
```

---

## 5. Timing — how Blue measures TTD / TTQ

For the stage-D scenarios, note the attack start `t0` (Red calls it out / logs
it), then read the control timestamps from:

- **PDP audit** — `zt-pdp:/var/log/zt-pdp/audit.jsonl` (events `rescore`,
  `session_kill`): tier change and revoke time.
- **AI engine** — `zt-sensor:/var/log/zt-ai/events.jsonl`: when the flow scored.
- **Suricata/Wazuh** — SIEM dashboard "Incident timeline": alert time.
- **Gateway** — `allow_web` / `quarantine` set contents (`sudo nft list set inet zt ...`).

Targets: **TTD ≤ 10 s**, **TTQ ≤ 15 s**. Put the numbers on each sheet and in
`tests/reports/` for the report.

---

## 6. Dataset capture (for E2 / E3) — runs alongside stage D

While the stage-D attacks run, capture labelled traffic for the AI evaluation:
benign traffic (Blue's generator) plus each attack campaign, each with a log of
**start/stop time + source IP** so flows can be labelled afterwards. Store under
`tests/evidence/<slug>/` and the capture dir. This feeds E2 (CIC → lab domain
shift) and E3 (UEBA gain).

---

## 7. Teardown

1. `bash tests/abcd/set-config.sh D` — back to the normal config.
2. Restore any snapshot touched by a destructive scenario:
   `cd infra && vagrant snapshot restore <vm> pre-redteam`.
3. Return the gateway WAN NIC to the internal net (§2 note) if the solo lab is
   needed again.
4. Red writes the **Red Team report** (findings, what bypassed controls,
   recommendations); Blue fixes findings and re-tests.

---

## 8. Deliverables from this session

- [ ] Sheets S1–S17 filled, one proof file each in `tests/evidence/`.
- [ ] A/B/C/D attack table + TTD/TTQ (`tests/reports/`), charts regenerated.
- [ ] Labelled capture set for E2/E3.
- [ ] Red Team report.
- [ ] Blue: fixes for findings + re-test.
