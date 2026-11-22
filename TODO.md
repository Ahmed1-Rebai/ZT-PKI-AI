# Build log — ZT-PKI-AI

> One team, one repository. Every checked line is done and has its proof in the repository.
> Rule: every result we claim needs a **screenshot or log as proof** → store it in `tests/evidence/`.

---

## 0. Repo setup

- [x] Add `.gitignore` (secrets, captures, models, VM disks; `docs/11-architecture-diagram.md` kept local)
- [x] Create the folder skeleton: `pki/ vpn/ firewall/ pdp/ ai/ sensor/ siem/ apps/ tests/ infra/` (one `README.md` each)
- [x] Write a **rules of engagement** document (`RULES-OF-ENGAGEMENT.md`)

## 1. Scoping & state of the art

- [x] Problem statement + hypotheses H1–H4 ([docs/01](docs/01-cadrage-et-modele-de-menaces.md))
- [x] STRIDE threat model per component (in [docs/01 §8](docs/01-cadrage-et-modele-de-menaces.md))
- [x] Map the attack scenarios to MITRE ATT&CK, one test sheet per scenario in `tests/scenarios/`
- [x] Prepare the test machine: `nmap` (S5) and `hping3` (S6) on `client-lin` (`zt-untrust`), **no Internet while connected to the lab**

## 2. Lab environment · milestone M1 (part)

- [x] Hypervisor: **VirtualBox 7.0.16** already installed on the lab host (46 GB RAM → batch VMs per milestone)
- [x] **IaC scaffolded (Vagrant + Ansible)** in `infra/`: `Vagrantfile` (11 VMs + 5 internal networks), `ansible/` (inventory, `site.yml`, `group_vars`, 12 roles — `common` implemented, rest milestone-stubbed), `Makefile`, `infra/README.md`
  - Networks are declared in the `Vagrantfile` as VirtualBox Internal Networks; `zt-gw` gets 5 NICs, others one per zone
  - Vagrant's NAT (eth0) gives Internet during provisioning; `make isolate` detaches it before attack tests, `make reconnect` restores it
- [x] **Tools installed:** Vagrant 2.x + Ansible (via `make tools`); KVM unloaded so VirtualBox gets AMD-V; `10.10.99.0/24` whitelisted in `/etc/vbox/networks.conf`
- [x] **All 10 VMs up and provisioned** (`failed=0` each): root-ca, sub-ca, zt-gw, zt-pdp, zt-sensor, siem, web-proxy, web-app, db, client-lin (AI: training on the host, inference on zt-sensor)
- [x] Common hardening automated in `roles/common` (SSH keys only, chrony/NTP, auditd, sysctl) ([docs/03 §6](docs/03-environnement-lab.md))
- [x] Traffic-mirror script ready `sensor/mirror.sh` (tc mirred on zt-gw) — mirror NIC added + exercised at M4
- [x] Test machine `client-lin` (`192.168.100.11`) connected **only** to the untrust network `zt-untrust` `192.168.100.0/24`; verified no direct route to internal zones
- [x] Isolation checks: client-lin (untrust) → data zone `10.10.30.10` **unreachable** ✓, → gateway reachable ✓; NTP offset < 1 s (chrony synced, 0.0008 s) ✓
- [x] Snapshots saved: `base` (all 10 VMs) + earlier `pki-base` (core 3)

## 3. PKI · milestone M1

- [x] OpenSSL configs written: `pki/root/root.cnf` (P-384, pathlen:1), `pki/sub/sub.cnf` (leaf profiles: client / server / server+client / ocsp)
- [x] Lifecycle scripts: `init-root.sh`, `init-sub.sh`, `sign-sub.sh`, `issue-server.sh`, `issue-client.sh`, `revoke.sh`, `gencrl.sh` (+ `inventory.csv`) — **validated end-to-end on the host** (chain verify + revocation via CRL)
- [x] Runbook documented in [pki/README.md](pki/README.md); `ca_root`/`ca_sub` roles install OpenSSL
- [x] **CA ceremony run on the VMs**: Root CA on root-ca → Issuing CA on sub-ca → signed by root (air-gapped CSR transfer) → leaf certs issued: `vpn-gw`, `pdp` (server+client), `proxy`, `alice` (client), `ocsp` signer. Lab CA passphrase `ZtLabCA-2026` (rotate for real use)
- [x] CRL publication (HTTP on `10.10.99.5:80`, systemd `zt-crl`) + OCSP responder on `10.10.99.5:2560` (systemd `zt-ocsp`) — units in `pki/systemd/`
- [x] `renew.sh` + `ocsp.sh` added; scripts take optional `PKI_PASS` for non-interactive runs
- [x] PKI tests on the VMs: chain verify ✓, CRL over HTTP ✓, OCSP good→revoked ✓ (restart responder after revoke); still optional: expired, wrong EKU ([docs/04 §9](docs/04-pki.md))
- [x] Snapshot `pki-ok` (all VMs); root-ca then halted (offline)

## 4. VPN + gateway · milestone M2

- [x] OpenVPN server: TLS 1.3, mTLS, `tls-crypt`, `crl-verify`, no pushed routes, management port — `vpn/server/server.conf`
- [x] Gateway firewall: nftables input chain (rate-limit 1194, SSH from mgmt only) + deny-by-default forward chain — `firewall/{gw-input.nft,nftables.conf}`
- [x] Hooks `tls-verify.py`, `client-connect.py` (fixed VPN IP per CN), `client-disconnect.py` — **fail-closed** (`PDP_ENFORCE=1`); `0` = M2 bootstrap
- [x] Client profile `alice.ovpn` (built from staged PKI; embeds CA chain + cert/key + tls-crypt)
- [x] Run **S1** (no cert), **S2** (rogue CA), **S3** (revoked), **S4** (expired), **S5** (scan), **S6** (UDP flood), **S9** (fake gateway) — all OK, evidence in `tests/evidence/`
- [x] Run **S10** (PDP down → no access) — fail-closed denied, evidence in `tests/evidence/s10_pdp_down/`
- [x] Snapshot `vpn-ok` (sub-ca, zt-gw, client-lin)

## 5. Zero Trust engine: PDP / PEP · milestone M3

- [x] Docker Compose: Redis + OPA + PDP (mTLS) — `infra/docker-compose.yml`
- [x] Rego policy `authz.rego` + `data.json` (roles employee / admin / contractor / quarantine) + `opa test`
- [x] Trust score `trust.py` (weights 0.30 / 0.25 / 0.15 / 0.30, EMA, floor rule) + pytest
- [x] FastAPI endpoints: `/authenticate`, `/session/open|close`, `/posture`, `/events`, `/session/{cn}/kill`, `/cert/{serial}/revoke`, `/sessions`
- [x] Dynamic nftables ruleset (sets with timeout) + `enforce.py` (open / restrict / quarantine / revoke)
- [x] TTL renewal loop (continuous re-authorization)
- [x] JSON audit log for every decision
- [x] Run **S7** (out-of-role SSH → `ZT-DROP`) — blocked, evidence in `tests/evidence/s07_out_of_role_ssh/`
- [x] Snapshot `pdp-ok` (then `m3-ok` after the rebuild, all active VMs)
- [x] **PDP enforcement ON (`vpn_pdp_enforce: "1"`) and verified end to end**: alice connects → PDP `authenticate: allow` (score 97, tier full) → `session_open` → gateway `allow_web {10.8.0.10 timeout 10m}` → alice reaches proxy → app → db through the tunnel. Without a PDP session the same request is dropped (`ZT-DROP SRC=10.8.0.10 DPT=443`)
- [x] Review fixes: users seeded from `data.json`; caller authorization (control endpoints only from mgmt; VPN clients get 403); posture bound to the tunnel address (alice cannot report as bob); gateway SSH host key pinned for the enforcer; gateway reuses the staged `ta.key` on rebuild
- [x] PDP gaps closed (Phase 10, [perf.md §5](tests/reports/perf.md)): fresh device admitted in **quarantine** then upgraded by its posture report; `/v1/events` never grants more than `allow` permits (`effective_tier`); revoke/kill always kill the VPN session

## 6. Reverse proxy mTLS + posture agent

- [x] Nginx DMZ proxy: client-cert mTLS, CRL, forwards CN to app, `/portal/` for contractors — verified: valid cert 200, no cert / foreign CA 400, **revoked cert 400** (CRL), `/portal/` 403 for employee, spoofed `X-Client-CN` ignored
- [x] Demo web app (Flask) + PostgreSQL, server-to-server rules (proxy → app :8080, app → DB :5432) — least-privilege DB grants (no `secret` column for the app); alice sees 1 record, admin 3
- [x] Lab recovery (VirtualBox 7.0 frame-duplication bug → **VirtualBox 7.1 + virtio**; disk corruption from a full host disk → rebuilt zt-gw/zt-pdp/web-app/db/web-proxy/client-lin; Issuing CA restored and its database rebuilt from evidence, next serial 2016; `ca-recovered` snapshots on both CAs)
- [x] Posture agent (firewall on, managed marker…) → `/v1/posture` every 60 s over mTLS **through the tunnel** (PDP logs `caller 10.8.0.10`, score 1.0); NAT isolation leak found and closed (`unreachable 10.10.0.0/16` guard)
- [x] Run **S8** (alice's certificate on a non-compliant device, from `client-lin`) — quarantined, evidence in `tests/evidence/s08_stolen_cert/`

## 7. AI pipeline · milestone M4

> **Training on the host, inference on the sensor** — VirtualBox has no CUDA
> passthrough, so the models are trained locally on the host GPU (`make ai` prepares
> the `.venv`). The `sensor` role then deploys the engine and the signed models on
> `zt-sensor`, which scores the mirrored traffic on CPU.

Data
- [x] CIC-IDS2017 downloaded and **verified** (2,830,743 flows / 2,273,097 benign, exact match) — HF mirror `bencorn/CICIDS2017` (official UNB link now needs registration); UNSW-NB15 optional
+
Models — trained locally on the RTX 5050
- [x] Flow features: 47-feature canonical schema shared by CICFlowMeter and NFStream (`ai/schema.py`, 6 tests)
- [x] Isolation Forest + Random Forest baseline `ai/train.py` (dedupe 850k duplicates, leakage-safe train/val/test)
- [x] Autoencoder (PyTorch 2.11 cu128 on the RTX 5050), threshold = p99.5 on benign validation
- [x] Score fusion (docs/07 weights + stacking) + isotonic calibration; SHAP global ranking
- [x] **E1** model comparison done (IF 0.0035 / AE 0.66 / RF 0.994 / fusion 0.994 F1)
- [x] Targets met on CIC test split: **F1 0.9943, FPR 0.16 %, 11.6 ms/flow** ([ai/reports/metrics.md](ai/reports/metrics.md))
- [x] Sign models: `manifest.json` SHA-256, `ai/registry.py` refuses tampered/missing artefacts (tested)

## 8. Closed loop AI → PDP → PEP · milestone M5

- [x] Traffic mirror: dedicated `zt-mirror` internal net, gateway `zt-mirror` unit copies dmz/app/data/mgmt NICs (`tc mirred`) to the sensor (promiscuous); decrypted client flows keep their tunnel source IP
- [x] Inference service `ai/serve.py` on the sensor (CPU; training on host GPU): NFStream → user via PDP `/v1/sessions` → signed models → `POST /v1/events` (mTLS `ai.lab.local`); verified on alice's live tunnel traffic (score 0.0084, PDP 96.7 full)
- [x] Tiers applied automatically (synthetic events, no attack): full 84.9 → **restricted** 77.7…69.3 → critical → score **0 / revoke**, gateway rule removed, PDP+enforcement in **356 ms**; alice blocked; after low scores → 95.7 full, rule restored in ~5 s, alice 200 again
- [x] Snapshot `ai-ok` (all active VMs)

## 9. Monitoring: Suricata + Wazuh · milestone M6

- [x] Suricata 7 (bookworm-backports) on the sensor mirror NIC: **46,307 rules** (ET Open + ZT local), `HOME_NET` = lab zones + VPN pool; IDS self-test rule (sid 9000099) proves mirror → Suricata → Wazuh
- [x] Wazuh **4.14.8** all-in-one on siem; agents (pinned 4.14.8) on zt-gw, zt-pdp, zt-sensor (AI), sub-ca, web-proxy — all **Active**
- [x] Logs: Suricata `eve.json`, AI events, PDP audit (now written to a file), OpenVPN, nftables drops (`kern.log` via rsyslog), Nginx; FIM on firewall/VPN/PKI/policies/models. Fixed: Wazuh dropped all eve events (`decoder_order_size`=1024)
- [x] Correlation rules `siem/rules/zt_rules.xml` (100100–100161, MITRE-mapped) — verified live: 100103 revoke (logtest), **100105** unauthorised PDP call from 10.8.0.10, **100161** FIM on `/etc/openvpn`, 86601 Suricata alert
- [x] Dashboards as code (`siem/dashboards/`): **ZT-PKI-AI – Zero Trust overview** + 5 saved searches (incident timeline, PDP decisions, PKI, network/IDS+firewall, AI); imported by the siem role (index pattern included). Live data: 55 PDP decisions, 3 incidents, 8 IDS alerts, 6 agents
- [x] Run **S11** (tamper `nftables.conf` → FIM alert) — Wazuh rule 100160, evidence in `tests/evidence/s11_fw_tamper/`

## 10. Validation & evaluation · milestone M7

- [x] Run **S12** (tampered model refused by the SHA-256 manifest) — evidence in `tests/evidence/s12_model_poison/`
- [x] A/B/C/D tooling: `tests/abcd/set-config.sh` switches the lab, `probe.sh` measures the exposed surface, `run-all.sh` runs all four and returns to D. Benign result: **A 7/7 services reachable (5 ZT violations), B/C/D 2/7 (0)**
- [x] Performance ([tests/reports/perf.md](tests/reports/perf.md)): PDP decision **20.8 ms** (≤ 500 ms ✔), no measurable ZT controls overhead on the same path (≤ 15 % ✔), re-measured on 2026-11-21. The software traffic mirror costs 60 % (VirtualBox has no port mirroring) → hypervisor SPAN / DCO / WireGuard
- [x] Results tables + charts generator `tests/reports/make_report.py` → [results.md](tests/reports/results.md), `charts/*.png`
- [x] Fix the findings of the evaluation and re-test (F1–F6 in [perf.md §5](tests/reports/perf.md)): fresh-device quarantine admission, `effective_tier` everywhere, fail-safe revoke/kill, immediate critical floor, posture call rate, `verify.sh` 9/9; PDP tests 14/14

## 11. Deliverables · milestone M8

- [x] A/B/C/D under attack (`tests/abcd/attack-abcd.sh`): S7 exposed in A, blocked in B/C/D; S8 kept in A/B, quarantined in C/D
- [x] Demo video (French, 4 min 16 s): real screen recordings of the lab bring-up, scenarios and benchmark
- [ ] Report (analysis, design, tutorial, tools) — LambdaTeX
- [ ] Presentation

---

## Milestones checklist

| | Milestone | Proof |
|---|---|---|
| [x] | **M1** Lab + full PKI | `openssl verify`, revocation demo |
| [x] | **M2** VPN mTLS + hooks + fail-closed | S1–S6, S9, S10 passed |
| [x] | **M3** PDP + dynamic nftables | role rights + TTL, S7 passed |
| [x] | **M4** AI models trained locally | E1 metrics report ([ai/reports/metrics.md](ai/reports/metrics.md)) |
| [x] | **M5** Closed loop AI → PDP → PEP | simulated critical alert → rule removed in 0.36–0.43 s |
| [x] | **M6** SIEM + dashboards | correlation rules, FIM (S11), Discover views |
| [x] | **M7** Comparative evaluation A/B/C/D | `tests/reports/results.md`, `perf.md`, charts |
| [ ] | **M8** Report, presentation, demo video | video done (real screen recordings); report and slides in progress |
