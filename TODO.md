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

- [ ] 🔵 Docker Compose: Redis + OPA + PDP (mTLS) — `infra/docker-compose.yml`
- [ ] 🔵 Rego policy `authz.rego` + `data.json` (roles employee / admin / contractor / quarantine) + `opa test`
- [ ] 🔵 Trust score `trust.py` (weights 0.30 / 0.25 / 0.15 / 0.30, EMA, floor rule) + pytest
- [ ] 🔵 FastAPI endpoints: `/authenticate`, `/session/open|close`, `/posture`, `/events`, `/session/{cn}/kill`, `/cert/{serial}/revoke`, `/sessions`
- [ ] 🔵 Dynamic nftables ruleset (sets with timeout) + `enforce.py` (open / restrict / quarantine / revoke)
- [ ] 🔵 TTL renewal loop (continuous re-authorization)
- [ ] 🔵 JSON audit log for every decision
- [ ] 🔴 Run **S7** (out-of-role SSH → `ZT-DROP`)
- [ ] 👥 PDP tests table ([docs/06 §10](docs/06-zero-trust-pdp-pep.md))
- [ ] 🔵 Snapshot `pdp-ok`

## 6. Reverse proxy mTLS + posture agent — 6 → 13 Dec `[MVP]`

- [ ] 🔵 Nginx DMZ proxy: client-cert mTLS, CRL, forwards CN to app, `/portal/` for contractors
- [ ] 🔵 Demo web app (Flask) + PostgreSQL, server-to-server rules (proxy → app :8080, app → DB :5432)
- [ ] 🔵 Posture agent (firewall on, disk encrypted…) → `/v1/posture` every 60 s over mTLS
- [ ] 🔴 Run **S12** (stolen cert used from the Kali laptop)
- [ ] 🔵 `[EXT]` Keycloak OIDC + MFA (TOTP) in front of the app

## 7. AI pipeline — 22 Nov → 20 Dec · milestone M4 `[MVP]`

> **Runs on the host, not a VM** — VirtualBox has no CUDA passthrough, so the AI
> engine runs natively on this laptop to use the RTX 5050. The host joins the mgmt
> host-only net at `10.10.99.2` (`make mgmt-host`) and reaches the PDP/sensor;
> set up with `make ai`.

Data (22 Nov → 6 Dec)
- [ ] 🔵 Download CIC-IDS2017 / UNSW-NB15 for pre-training and benchmark
- [ ] 🔵 Benign traffic generator `tests/traffic_benign.py` (browsing, API, SSH, transfers)
- [ ] 🔴 **Malicious traffic campaigns** for the dataset (nmap, hydra, hping3, exfil, DNS tunnel), with a log of timestamps + IPs for labelling
- [ ] 🔵 Capture with NFStream / pcap, label by timestamp + IP

Models (6 → 20 Dec) — train on the RTX 5050
- [ ] 🔵 Flow features + 60 s UEBA window features
- [ ] 🔵 Isolation Forest + Random Forest baseline `ai/train.py`
- [ ] 🔵 Autoencoder (PyTorch, GPU), threshold = p99.5 on benign validation
- [ ] 🔵 Score fusion + calibration, SHAP top-3 features
- [ ] 🔵 Experiments **E1** (model comparison), **E2** (domain shift), **E3** (UEBA gain) → notebooks + metrics report
- [ ] 🔵 Targets: F1 ≥ 0.95, FPR ≤ 2 %, inference < 50 ms/flow
- [ ] 🔵 Sign models (SHA-256 checked at load)
- [ ] 🔵 `[EXT]` LSTM, XGBoost / LightGBM, stacking

## 8. Closed loop AI → PDP → PEP — 6 → 20 Dec · milestone M5 `[MVP]`

- [ ] 🔵 Traffic mirror from gateway to sensor (`tc` mirred)
- [ ] 🔵 Inference service `ai/serve.py` → `POST /v1/events` (VPN IP → CN lookup in Redis)
- [ ] 🔵 Tiers applied automatically: restrict / quarantine / revoke
- [ ] 🔴 Run **S8** (internal scan), **S9** (SSH brute force), **S10** (exfiltration), **S11** (DNS tunnel)
- [ ] 👥 Measure **TTD ≤ 10 s** and **TTQ ≤ 15 s** (cross-checked timestamps)
- [ ] 🔵 Snapshot `ai-ok`

## 9. Monitoring: Suricata + Wazuh — 13 → 23 Dec · milestone M6 `[MVP]`

- [ ] 🔵 Suricata 7 on the sensor + local rules
- [ ] 🔵 Wazuh all-in-one, agents on gw / pdp / ai / proxy / sub-ca
- [ ] 🔵 Collect logs: Suricata `eve.json`, OpenVPN, nftables, PDP, AI, Nginx, PKI
- [ ] 🔵 Correlation rules `zt_rules.xml`
- [ ] 🔵 Dashboards: Zero Trust, PKI, network, AI, incident timeline
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
