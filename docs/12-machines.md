# 12 — Virtual machines: description and rationale

> The lab runs **10 VirtualBox VMs** plus the **host** (which doubles as the AI node).
> Each VM maps to a role in the NIST SP 800-207 Zero Trust model (see [docs/02](02-architecture.md)).
> Provisioned with Vagrant + Ansible (see [infra/](../infra/)). Base boxes: `bento/debian-12`, `bento/ubuntu-22.04`.

## Why this split (one role per VM)

Zero Trust assumes any host can be compromised, so the design keeps the **control plane**
(decisions), the **data plane** (traffic), and the **security plane** (observation) on
separate machines in separate network zones. One role per VM means a breach of one
component (say the web app) does not hand the attacker the CA, the policy engine, or the
logs. It also lets us snapshot, break, and rebuild any single piece without touching the
rest — essential for the attack scenarios.

---

## Identity plane (PKI)

### `root-ca` — offline Root Certificate Authority
- **Why:** the Root CA is the single anchor of trust for the whole lab. If its private key leaks, every certificate becomes forgeable, so it must never sit on a reachable machine.
- **What it does:** signs **one** thing — the Issuing CA — then is powered off. `pathlen:1`, ECDSA P-384, 10-year cert, AES-256-encrypted key.
- **Network:** none in the lab (NAT only, used once to provision; **kept halted** afterwards). The air-gap is the point.
- **OS/size:** Debian 12 · 1 vCPU · 512 MB.

### `sub-ca` — Issuing CA, OCSP, CRL
- **Why:** day-to-day certificate work (issue, renew, revoke) has to be online, but we keep it separate from the Root so a compromise here cannot re-sign the trust anchor (`pathlen:0` blocks it from issuing new CAs).
- **What it does:** issues short-lived user/machine/service certs; publishes the **CRL over HTTP** (`:80`) and runs the **OCSP responder** (`:2560`) so revocation is checkable.
- **Network:** mgmt `10.10.99.5`.
- **OS/size:** Debian 12 · 1 vCPU · 1 GB.

---

## Control plane (the Zero Trust brain + enforcement edge)

### `zt-gw` — VPN gateway + firewall (Policy Enforcement Point)
- **Why:** this is the **only** path between the untrusted side and the protected zones, and the only router between zones. Concentrating enforcement here is what makes "deny by default, allow per identity" possible.
- **What it does:** terminates the OpenVPN mTLS tunnel, runs nftables with dynamic, time-limited allow-rules driven by the PDP, and enforces every access decision (the PEP).
- **Network:** all five zones — untrust `192.168.100.1`, dmz `10.10.10.1`, app `10.10.20.1`, data `10.10.30.1`, mgmt `10.10.99.1`.
- **OS/size:** Debian 12 · 2 vCPU · 2 GB.

### `zt-pdp` — Policy Decision Point
- **Why:** decisions must be centralized and auditable, and kept off the enforcement edge so policy logic can change without touching the gateway. This is the "always verify" engine.
- **What it does:** FastAPI trust engine + OPA (Rego) policies + Redis (sessions, scores, revocation list, posture). Computes the trust score and tells the PEP what to allow.
- **Network:** mgmt `10.10.99.10`.
- **OS/size:** Debian 12 · 2 vCPU · 2 GB.

---

## Security / observability plane

### `zt-sensor` — network sensor
- **Why:** detection must watch real traffic without sitting in the data path (so it can't break connectivity or be bypassed). It receives a mirror of gateway traffic.
- **What it does:** Suricata (signatures) + NFStream (flow features) — the raw material for the AI and the SIEM.
- **Network:** mgmt `10.10.99.12` (+ a mirror NIC at M4).
- **OS/size:** Debian 12 · 2 vCPU · 2 GB.

### `siem` — Wazuh
- **Why:** Zero Trust requires "collect everything, correlate, respond". A dedicated SIEM gives tamper-resistant, centralized evidence — and the proof files for every test result.
- **What it does:** ingests logs from gateway, PDP, AI, proxy, PKI; correlation rules; dashboards; optional active response.
- **Network:** mgmt `10.10.99.20`.
- **OS/size:** Ubuntu 22.04 · 4 vCPU · 6 GB (Wazuh is the heaviest service).

### host (this laptop) — AI anomaly-detection engine
- **Why:** the models need the **RTX 5050 GPU**, and VirtualBox cannot pass a GPU into a guest. So the AI runs natively on the host, which joins the mgmt network as a node.
- **What it does:** feature extraction, model training (CUDA), and an inference service that sends risk scores to the PDP.
- **Network:** mgmt `10.10.99.2` (host-only).

---

## Data plane (the workloads we protect)

### `web-proxy` — Nginx mTLS reverse proxy (PEP layer 2)
- **Why:** Zero Trust verifies at every layer, not just the network. Even inside the tunnel, the app is reached only through a proxy that re-checks the client certificate.
- **What it does:** terminates mTLS, checks the client cert against the CRL, forwards the identity (CN) to the app.
- **Network:** dmz `10.10.10.10`.
- **OS/size:** Debian 12 · 1 vCPU · 1 GB.

### `web-app` — protected application / API
- **Why:** the thing an attacker actually wants — the target that proves the controls work (or don't).
- **What it does:** demo business app/API, reachable only via the proxy.
- **Network:** app `10.10.20.10`.
- **OS/size:** Debian 12 · 1 vCPU · 1 GB.

### `db` — PostgreSQL
- **Why:** the most sensitive asset; isolated in its own zone to demonstrate that even the app tier has least-privilege, single-purpose access to data.
- **What it does:** database, reachable **only** from `web-app` on `:5432` (explicit server-to-server rule).
- **Network:** data `10.10.30.10`.
- **OS/size:** Debian 12 · 1 vCPU · 1 GB.

---

## Untrusted zone (users and attacker)

### `client-lin` — legitimate / compromised client
- **Why:** we need a real endpoint to (a) show a normal user getting least-privilege access and (b) play the "valid cert, malicious behaviour" insider that the AI must catch.
- **What it does:** OpenVPN client + posture agent; also the launch point for post-authentication attack scenarios (S8–S12).
- **Network:** untrust `192.168.100.11`.
- **OS/size:** Ubuntu 22.04 · 2 vCPU · 2 GB.

### `kali` — Red Team attacker *(partner's laptop, not a VM here)*
- **Why:** external attacker with no credentials, used for authorized testing against the lab only.
- **What it does:** reconnaissance, access attempts, DoS, exploitation (S1–S6, S13…).
- **Network:** untrust only (cabled to the gateway's WAN side), **no Internet during tests**.

### `client-win` — Windows client *(optional)*
- **Why:** shows the posture agent and client flow on Windows too; skipped unless needed (Ansible-over-WinRM overhead).

---

## Summary table

| VM | Plane | Role | Zone (IP) | OS | vCPU/RAM |
|---|---|---|---|---|---|
| root-ca | Identity | Offline Root CA | none (offline) | Debian 12 | 1 / 512 MB |
| sub-ca | Identity | Issuing CA, OCSP, CRL | mgmt `10.10.99.5` | Debian 12 | 1 / 1 GB |
| zt-gw | Control/edge | VPN gateway + firewall (PEP) | all 5 zones | Debian 12 | 2 / 2 GB |
| zt-pdp | Control | Policy Decision Point | mgmt `10.10.99.10` | Debian 12 | 2 / 2 GB |
| zt-sensor | Security | Suricata + NFStream | mgmt `10.10.99.12` | Debian 12 | 2 / 2 GB |
| siem | Security | Wazuh | mgmt `10.10.99.20` | Ubuntu 22.04 | 4 / 6 GB |
| host | Security | AI engine (GPU) | mgmt `10.10.99.2` | — | RTX 5050 |
| web-proxy | Data | Nginx mTLS proxy | dmz `10.10.10.10` | Debian 12 | 1 / 1 GB |
| web-app | Data | App / API | app `10.10.20.10` | Debian 12 | 1 / 1 GB |
| db | Data | PostgreSQL | data `10.10.30.10` | Debian 12 | 1 / 1 GB |
| client-lin | Untrusted | Legit/compromised client | untrust `192.168.100.11` | Ubuntu 22.04 | 2 / 2 GB |
| kali | Untrusted | Red Team attacker (partner laptop) | untrust (cabled) | Kali 2026.2 | — |

**Total VM footprint:** ≈ 18 GB RAM for the 10 lab VMs (AI offloaded to the host).
