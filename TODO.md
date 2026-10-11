# ✅ TODO — ZT-PKI-AI

> Owners: 🔵 **Blue Team** (infrastructure, build, defense, monitoring) · 🔴 **Red Team** (authorized testing, attack scripts, attack traffic) · 👥 **Both**
> Dates follow the roadmap in [docs/10](docs/10-planning-livrables.md) (start 2026-10-12, 14 weeks). Tag `[MVP]` = required, `[EXT]` = bonus.
> Rule: every result we claim needs a **screenshot or log as proof** → store it in `tests/evidence/`.

---

## 0. Repo setup — now

- [x] 🔵 Add `.gitignore` (secrets, captures, models, VM disks; `docs/11-architecture-diagram.md` kept local)
- [x] 🔵 Create the folder skeleton: `pki/ vpn/ firewall/ pdp/ ai/ sensor/ siem/ apps/ tests/ infra/` (one `README.md` each)
- [x] 🔵 Write a **rules of engagement** document (`RULES-OF-ENGAGEMENT.md`) — 👥 both still need to sign §8

## 1. Scoping & state of the art — 12 → 26 Oct

- [ ] 👥 State of the art: NIST SP 800-207, PKI, VPN, IDS, ML for intrusion detection, related work
- [ ] 👥 Finalize the problem statement + hypotheses H1–H4 ([docs/01](docs/01-cadrage-et-modele-de-menaces.md))
- [x] 🔵 STRIDE threat model per component (in [docs/01 §8](docs/01-cadrage-et-modele-de-menaces.md))
- [x] 🔴 Map scenarios S1–S17 to MITRE ATT&CK, write one test sheet per scenario in `tests/scenarios/` (sheets drafted; Steps/Result filled at run time)
- [x] 🔴 Prepare the attacker laptop: Kali, tools (nmap, hydra, hping3, dnscat2/iodine), **no Internet while connected to the lab**
  - Kali VirtualBox image already available: `/mnt/data/kali-linux-2026.2-virtualbox-amd64` (registered as VM `kali-linux-2026.2-virtualbox-amd64`) → copy/export it to the partner's laptop, or keep it as a local backup attacker on `zt-untrust`

## 2. Lab environment — 26 Oct → 2 Nov · milestone M1 (part)

- [x] 🔵 Hypervisor: **VirtualBox 7.0.16** already installed on the Blue Team host (46 GB RAM → batch VMs per milestone)
- [x] 🔵 **IaC scaffolded (Vagrant + Ansible)** in `infra/`: `Vagrantfile` (11 VMs + 5 internal networks), `ansible/` (inventory, `site.yml`, `group_vars`, 12 roles — `common` implemented, rest milestone-stubbed), `Makefile`, `infra/README.md`
  - Networks are declared in the `Vagrantfile` as VirtualBox Internal Networks; `zt-gw` gets 5 NICs, others one per zone
  - Vagrant's NAT (eth0) gives Internet during provisioning; `make isolate` detaches it before attack tests, `make reconnect` restores it
- [x] 🔵 **Tools installed:** Vagrant 2.x + Ansible (via `make tools`); KVM unloaded so VirtualBox gets AMD-V; `10.10.99.0/24` whitelisted in `/etc/vbox/networks.conf`
- [x] 🔵 **All 10 VMs up and provisioned** (`failed=0` each): root-ca, sub-ca, zt-gw, zt-pdp, zt-sensor, siem, web-proxy, web-app, db, client-lin (AI is on the host, not a VM)
- [x] 🔵 Common hardening automated in `roles/common` (SSH keys only, chrony/NTP, auditd, sysctl) ([docs/03 §6](docs/03-environnement-lab.md))
- [x] 🔵 Traffic-mirror script ready `sensor/mirror.sh` (tc mirred on zt-gw) — mirror NIC added + exercised at M4
- [ ] 👥 Connect the Red Team laptop **only** to the untrust network (needs partner + hardware): `zt-gw` WAN NIC as a **Bridged Adapter** on a dedicated Ethernet / USB-Ethernet cabled to the partner's laptop; verify no route to internal zones — **BLOCKED on partner**
- [x] 🔵 Isolation checks: client-lin (untrust) → data zone `10.10.30.10` **unreachable** ✓, → gateway reachable ✓; NTP offset < 1 s (chrony synced, 0.0008 s) ✓
- [x] 🔵 Snapshots saved: `base` (all 10 VMs) + earlier `pki-base` (core 3)

## 3. PKI — 2 → 12 Nov · milestone M1 `[MVP]`

- [x] 🔵 OpenSSL configs written: `pki/root/root.cnf` (P-384, pathlen:1), `pki/sub/sub.cnf` (leaf profiles: client / server / server+client / ocsp)
- [x] 🔵 Lifecycle scripts: `init-root.sh`, `init-sub.sh`, `sign-sub.sh`, `issue-server.sh`, `issue-client.sh`, `revoke.sh`, `gencrl.sh` (+ `inventory.csv`) — **validated end-to-end on the host** (chain verify + revocation via CRL)
- [x] 🔵 Runbook documented in [pki/README.md](pki/README.md); `ca_root`/`ca_sub` roles install OpenSSL
- [x] 🔵 **CA ceremony run on the VMs**: Root CA on root-ca → Issuing CA on sub-ca → signed by root (air-gapped CSR transfer) → leaf certs issued: `vpn-gw`, `pdp` (server+client), `proxy`, `alice` (client), `ocsp` signer. Lab CA passphrase `ZtLabCA-2026` (rotate for real use)
- [x] 🔵 CRL publication (HTTP on `10.10.99.5:80`, systemd `zt-crl`) + OCSP responder on `10.10.99.5:2560` (systemd `zt-ocsp`) — units in `pki/systemd/`
- [x] 🔵 `renew.sh` + `ocsp.sh` added; scripts take optional `PKI_PASS` for non-interactive runs
- [x] 🔵 PKI tests on the VMs: chain verify ✓, CRL over HTTP ✓, OCSP good→revoked ✓ (restart responder after revoke); still optional: expired, wrong EKU ([docs/04 §9](docs/04-pki.md))
- [x] 🔵 Snapshot `pki-ok` (all VMs); root-ca then halted (offline)
- [ ] 🔵 `[EXT]` step-ca + ACME (24 h certs) · keys in SoftHSM / TPM

## 4. VPN + gateway — 12 → 22 Nov · milestone M2 `[MVP]`

- [x] 🔵 OpenVPN server: TLS 1.3, mTLS, `tls-crypt`, `crl-verify`, no pushed routes, management port — `vpn/server/server.conf`
- [x] 🔵 Gateway firewall: nftables input chain (rate-limit 1194, SSH from mgmt only) + deny-by-default forward chain — `firewall/{gw-input.nft,nftables.conf}`
- [x] 🔵 Hooks `tls-verify.py`, `client-connect.py` (fixed VPN IP per CN), `client-disconnect.py` — **fail-closed** (`PDP_ENFORCE=1`); `0` = M2 bootstrap
- [x] 🔵 Client profile `alice.ovpn` (built from staged PKI; embeds CA chain + cert/key + tls-crypt)
- [x] 🔴 Run **S1** (no cert), **S2** (rogue CA), **S3** (revoked), **S4** (expired), **S5** (scan), **S6** (UDP flood), **S13** (fake gateway) — all OK, evidence in `tests/evidence/`
- [x] 🔵 Run **S14** (PDP down → no access) — fail-closed denied, evidence in `tests/evidence/s14_pdp_down/`
- [x] 🔵 Snapshot `vpn-ok` (sub-ca, zt-gw, client-lin)
- [ ] 🔵 `[EXT]` WireGuard performance comparison

## 5. Zero Trust engine: PDP / PEP — 22 Nov → 6 Dec · milestone M3 `[MVP]`

- [x] 🔵 Docker Compose: Redis + OPA + PDP (mTLS) — `infra/docker-compose.yml`
- [x] 🔵 Rego policy `authz.rego` + `data.json` (roles employee / admin / contractor / quarantine) + `opa test`
- [x] 🔵 Trust score `trust.py` (weights 0.30 / 0.25 / 0.15 / 0.30, EMA, floor rule) + pytest
- [x] 🔵 FastAPI endpoints: `/authenticate`, `/session/open|close`, `/posture`, `/events`, `/session/{cn}/kill`, `/cert/{serial}/revoke`, `/sessions`
- [x] 🔵 Dynamic nftables ruleset (sets with timeout) + `enforce.py` (open / restrict / quarantine / revoke)
- [x] 🔵 TTL renewal loop (continuous re-authorization)
- [x] 🔵 JSON audit log for every decision
- [ ] 🔴 Run **S7** (out-of-role SSH → `ZT-DROP`)
- [ ] 👥 PDP tests table ([docs/06 §10](docs/06-zero-trust-pdp-pep.md))
- [x] 🔵 Snapshot `pdp-ok` (then `m3-ok` after the rebuild, all active VMs)
- [x] 🔵 **PDP enforcement ON (`vpn_pdp_enforce: "1"`) and verified end to end**: alice connects → PDP `authenticate: allow` (score 97, tier full) → `session_open` → gateway `allow_web {10.8.0.10 timeout 10m}` → alice reaches proxy → app → db through the tunnel. Without a PDP session the same request is dropped (`ZT-DROP SRC=10.8.0.10 DPT=443`)
- [x] 🔵 Review fixes: users seeded from `data.json`; caller authorization (control endpoints only from mgmt; VPN clients get 403); posture bound to the tunnel address (alice cannot report as bob); gateway SSH host key pinned for the enforcer; gateway reuses the staged `ta.key` on rebuild
- [ ] 🔵 Remaining PDP gaps: (a) a **fresh device** with no posture is denied the tunnel, so it cannot send its first posture report — admit it in quarantine instead (Rego `admit` already separates this); (b) `/v1/events` applies the score tier without checking `allow` (renewal loop corrects it within 60 s); (c) `revoke` tier clears rules but does not kill the session

## 6. Reverse proxy mTLS + posture agent — 6 → 13 Dec `[MVP]`

- [x] 🔵 Nginx DMZ proxy: client-cert mTLS, CRL, forwards CN to app, `/portal/` for contractors — verified: valid cert 200, no cert / foreign CA 400, **revoked cert 400** (CRL), `/portal/` 403 for employee, spoofed `X-Client-CN` ignored
- [x] 🔵 Demo web app (Flask) + PostgreSQL, server-to-server rules (proxy → app :8080, app → DB :5432) — least-privilege DB grants (no `secret` column for the app); alice sees 1 record, admin 3
- [x] 🔵 Lab recovery (VirtualBox 7.0 frame-duplication bug → **VirtualBox 7.1 + virtio**; disk corruption from a full host disk → rebuilt zt-gw/zt-pdp/web-app/db/web-proxy/client-lin; Issuing CA restored and its database rebuilt from evidence, next serial 2016; `ca-recovered` snapshots on both CAs)
- [x] 🔵 Posture agent (firewall on, managed marker…) → `/v1/posture` every 60 s over mTLS **through the tunnel** (PDP logs `caller 10.8.0.10`, score 1.0); NAT isolation leak found and closed (`unreachable 10.10.0.0/16` guard)
- [ ] 🔴 Run **S12** (stolen cert used from the Kali laptop)
- [ ] 🔵 `[EXT]` Keycloak OIDC + MFA (TOTP) in front of the app

## 7. AI pipeline — 22 Nov → 20 Dec · milestone M4 `[MVP]`

> **Runs on the host, not a VM** — VirtualBox has no CUDA passthrough, so the AI
> engine runs natively on this laptop to use the RTX 5050. The host joins the mgmt
> host-only net at `10.10.99.2` (`make mgmt-host`) and reaches the PDP/sensor;
> set up with `make ai`.

Data (22 Nov → 6 Dec)
- [x] 🔵 CIC-IDS2017 downloaded and **verified** (2,830,743 flows / 2,273,097 benign, exact match) — HF mirror `bencorn/CICIDS2017` (official UNB link now needs registration); UNSW-NB15 optional
- [ ] 🔵 Benign traffic generator `tests/traffic_benign.py` (browsing, API, SSH, transfers)
- [ ] 🔴 **Malicious traffic campaigns** for the dataset (nmap, hydra, hping3, exfil, DNS tunnel), with a log of timestamps + IPs for labelling
- [ ] 🔵 Capture with NFStream / pcap, label by timestamp + IP
+
Models (6 → 20 Dec) — train on the RTX 5050
- [x] 🔵 Flow features: 47-feature canonical schema shared by CICFlowMeter and NFStream (`ai/schema.py`, 6 tests) — UEBA 60 s windows need timestamps/IPs → lab captures (E3)
- [x] 🔵 Isolation Forest + Random Forest baseline `ai/train.py` (dedupe 850k duplicates, leakage-safe train/val/test)
- [x] 🔵 Autoencoder (PyTorch 2.11 cu128 on the RTX 5050), threshold = p99.5 on benign validation
- [x] 🔵 Score fusion (docs/07 weights + stacking) + isotonic calibration; SHAP global ranking
- [x] 🔵 **E1** model comparison done (IF 0.0035 / AE 0.66 / RF 0.994 / fusion 0.994 F1)
- [ ] 👥 **E2** (CIC → lab domain shift) and **E3** (UEBA gain) — need lab captures (benign + 🔴 attack campaigns)
- [x] 🔵 Targets met on CIC test split: **F1 0.9943, FPR 0.16 %, 11.6 ms/flow** ([ai/reports/metrics.md](ai/reports/metrics.md))
- [x] 🔵 Sign models: `manifest.json` SHA-256, `ai/registry.py` refuses tampered/missing artefacts (tested)
- [ ] 🔵 `[EXT]` LSTM, XGBoost / LightGBM, stacking

## 8. Closed loop AI → PDP → PEP — 6 → 20 Dec · milestone M5 `[MVP]`

- [x] 🔵 Traffic mirror: dedicated `zt-mirror` internal net, gateway `zt-mirror` unit copies dmz/app/data/mgmt NICs (`tc mirred`) to the sensor (promiscuous); decrypted client flows keep their tunnel source IP
- [x] 🔵 Inference service `ai/serve.py` on the sensor (CPU; training on host GPU): NFStream → user via PDP `/v1/sessions` → signed models → `POST /v1/events` (mTLS `ai.lab.local`); verified on alice's live tunnel traffic (score 0.0084, PDP 96.7 full)
- [x] 🔵 Tiers applied automatically (synthetic events, no attack): full 84.9 → **restricted** 77.7…69.3 → critical → score **0 / revoke**, gateway rule removed, PDP+enforcement in **356 ms**; alice blocked; after low scores → 95.7 full, rule restored in ~5 s, alice 200 again
- [ ] 🔴 Run **S8** (internal scan), **S9** (SSH brute force), **S10** (exfiltration), **S11** (DNS tunnel)
- [ ] 👥 Measure **TTD ≤ 10 s** and **TTQ ≤ 15 s** on real S8–S11 runs (expected: flow expiry ≤ 5 s idle + scoring ms + 5-flow burst + 0.36 s enforcement)
- [x] 🔵 Snapshot `ai-ok` (all active VMs)

## 9. Monitoring: Suricata + Wazuh — 13 → 23 Dec · milestone M6 `[MVP]`

- [x] 🔵 Suricata 7 (bookworm-backports) on the sensor mirror NIC: **46,307 rules** (ET Open + ZT local), `HOME_NET` = lab zones + VPN pool; IDS self-test rule (sid 9000099) proves mirror → Suricata → Wazuh
- [x] 🔵 Wazuh **4.14.8** all-in-one on siem; agents (pinned 4.14.8) on zt-gw, zt-pdp, zt-sensor (AI), sub-ca, web-proxy — all **Active**
- [x] 🔵 Logs: Suricata `eve.json`, AI events, PDP audit (now written to a file), OpenVPN, nftables drops (`kern.log` via rsyslog), Nginx; FIM on firewall/VPN/PKI/policies/models. Fixed: Wazuh dropped all eve events (`decoder_order_size`=1024)
- [x] 🔵 Correlation rules `siem/rules/zt_rules.xml` (100100–100161, MITRE-mapped) — verified live: 100103 revoke (logtest), **100105** unauthorised PDP call from 10.8.0.10, **100161** FIM on `/etc/openvpn`, 86601 Suricata alert
- [x] 🔵 Dashboards as code (`siem/dashboards/`): **ZT-PKI-AI – Zero Trust overview** + 5 saved searches (incident timeline, PDP decisions, PKI, network/IDS+firewall, AI); imported by the siem role (index pattern included). Live data: 55 PDP decisions, 3 incidents, 8 IDS alerts, 6 agents
- [ ] 🔴 Run **S15** (tamper `nftables.conf` → FIM alert)
- [ ] 🔵 `[EXT]` active response / SOAR (TheHive, n8n)

## 10. Validation & evaluation — 23 Dec → 6 Jan · milestone M7

- [ ] 🔴 Full campaign S1–S17 with evidence for each (screenshots, logs, pcaps)
- [ ] 🔴 **S16** low-and-slow evasion, **S17** model poisoning (theoretical / controlled)
- [ ] 👥 Comparative evaluation of configs **A / B / C / D** (perimeter → static ZT → dynamic PDP → AI in the loop)
- [ ] 🔵 Performance: iperf3 throughput, latency, handshake time, CPU/RAM (overhead ≤ 15 %)
- [ ] 👥 Results tables + charts
- [ ] 🔴 Red Team report: findings, what bypassed controls, recommendations
- [ ] 🔵 Fix findings and re-test

## 11. Deliverables — 6 → 20 Jan · milestone M8

- [ ] 👥 Technical report (60–90 pages, outline in [docs/10 §4](docs/10-planning-livrables.md))
- [ ] 🔵 AI notebooks (EDA, training, evaluation, SHAP)
- [ ] 🔴 Test dossier S1–S17 + results + evidence
- [ ] 🔵 Wazuh dashboard exports
- [ ] 🔵 Deployment manual (rebuild the lab from scratch) + `make all`
- [ ] 👥 Slides (20–25) with the architecture diagram
- [ ] 👥 10-minute demo (script in [docs/10 §5](docs/10-planning-livrables.md)): rehearse live + record a backup video

---

## Milestones checklist

| | Milestone | Proof | Target date |
|---|---|---|---|
| [ ] | **M1** Lab + full PKI | `openssl verify`, revocation demo | 12 Nov |
| [ ] | **M2** VPN mTLS + hooks + fail-closed | S1–S4, S13, S14 passed | 22 Nov |
| [ ] | **M3** PDP + dynamic nftables | role rights + TTL | 6 Dec |
| [ ] | **M4** AI pipeline trained | E1–E3 metrics report | 20 Dec |
| [ ] | **M5** Closed loop AI → PDP → PEP | S8–S11 passed, TTQ measured | 20 Dec |
| [ ] | **M6** SIEM + dashboards | screenshots, correlation rules | 23 Dec |
| [ ] | **M7** Comparative evaluation A/B/C/D | tables, charts | 6 Jan |
| [ ] | **M8** Report + final demo | delivered documents | 20 Jan |
