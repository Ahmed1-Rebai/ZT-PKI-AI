# 12 — Virtual machines: description and rationale

> The lab runs **10 VirtualBox VMs**. The host that runs VirtualBox is not part of the architecture: it trains the AI models and serves as the admin station.
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
- **What it does:** issues short-lived client and server/service certs; publishes the **CRL over HTTP** (`:80`) and runs the **OCSP responder** (`:2560`) so revocation is checkable.
- **Network:** mgmt `10.10.99.5`.
- **OS/size:** Debian 12 · 1 vCPU · 1 GB.

---

## Control plane (the Zero Trust brain + enforcement edge)

### `zt-gw` — VPN gateway + firewall (Policy Enforcement Point)
- **Why:** this is the **only** path between the untrusted side and the protected zones, and the only router between zones. Concentrating enforcement here is what makes "deny by default, allow per identity" possible.
- **What it does:** terminates the OpenVPN mTLS tunnel, runs nftables with dynamic, time-limited allow-rules driven by the PDP, and enforces every access decision (the PEP).
- **Network:** all five zones — untrust `192.168.100.1`, dmz `10.10.10.1`, app `10.10.20.1`, data `10.10.30.1`, mgmt `10.10.99.1` — plus a mirror NIC on `zt-mirror` (`10.10.98.1`) where it copies its zone traffic (`tc mirred`) for the sensor.
- **OS/size:** Debian 12 · 2 vCPU · 2 GB.

### `zt-pdp` — Policy Decision Point
- **Why:** decisions must be centralized and auditable, and kept off the enforcement edge so policy logic can change without touching the gateway. This is the "always verify" engine.
- **What it does:** FastAPI trust engine + OPA (Rego) policies + Redis (sessions, scores, revocation list, posture). Computes the trust score and tells the PEP what to allow.
- **Network:** mgmt `10.10.99.10`.
- **OS/size:** Debian 12 · 2 vCPU · 2 GB.

---

## Security / observability plane

### `zt-sensor` — network sensor + AI inference
- **Why:** detection must watch real traffic without sitting in the data path (so it can't break connectivity or be bypassed). It receives a mirror of gateway traffic.
- **What it does:** Suricata (signatures, alerts go to Wazuh) + NFStream (per-flow features) feeding the `zt-ai` systemd service, which scores each flow with the IF + AE + RF models and posts anomaly events to the PDP over mTLS. Models are checked against a SHA-256 manifest before loading.
- **Network:** mgmt `10.10.99.12` + mirror `10.10.98.12` (promiscuous).
- **OS/size:** Debian 12 · 2 vCPU · 3 GB.

### `siem` — Wazuh
- **Why:** Zero Trust requires "collect everything, correlate, respond". A dedicated SIEM gives tamper-resistant, centralized evidence — and the proof files for every test result.
- **What it does:** agents on zt-gw, zt-pdp, zt-sensor, sub-ca and web-proxy ship the VPN, firewall, PDP audit, Suricata, AI and nginx logs; file integrity monitoring on the security configs; custom correlation rules; dashboards.
- **Network:** mgmt `10.10.99.20`.
- **OS/size:** Ubuntu 22.04 · 4 vCPU · 6 GB (Wazuh is the heaviest service).

### The host (not an architecture node)
- **Why:** training needs the **RTX 5050 GPU**, and VirtualBox cannot pass a GPU into a guest, so the models are trained on the host and the resulting artifacts are deployed to `zt-sensor`.
- **What it does:** runs VirtualBox, Vagrant and Ansible; trains the models (`ai/train.py`, `.venv` prepared by `make ai`); acts as the admin station (Wazuh dashboard). It does not run inference and takes no part in access decisions.
- **Network:** mgmt `10.10.99.2` (host-only, set with `make mgmt-host`).

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

## Untrusted zone

### `client-lin` — user workstation and test machine
- **Why:** we need a real endpoint to (a) show a normal user (alice) getting least-privilege access and (b) play the attacker, both outside the tunnel and as a "valid cert, malicious behaviour" insider.
- **What it does:** OpenVPN client + posture agent. It is also the machine every one of the 12 scenarios is played from (`make scenarios`), including the post-authentication ones: S7 out-of-role SSH, S8 stolen cert on a non-compliant device, S11 firewall config tampering, S12 tampered model. There is no separate attacker VM.
- **Network:** untrust `192.168.100.11`, no Internet during tests (`make isolate`).
- **OS/size:** Ubuntu 22.04 · 2 vCPU · 2 GB.

---

## Summary table

| VM | Plane | Role | Zone (IP) | OS | vCPU/RAM |
|---|---|---|---|---|---|
| root-ca | Identity | Offline Root CA | none (offline) | Debian 12 | 1 / 512 MB |
| sub-ca | Identity | Issuing CA, OCSP, CRL | mgmt `10.10.99.5` | Debian 12 | 1 / 1 GB |
| zt-gw | Control/edge | VPN gateway + firewall (PEP) | all 5 zones + mirror | Debian 12 | 2 / 2 GB |
| zt-pdp | Control | Policy Decision Point | mgmt `10.10.99.10` | Debian 12 | 2 / 2 GB |
| zt-sensor | Security | Suricata + NFStream + AI inference | mgmt `10.10.99.12`, mirror `10.10.98.12` | Debian 12 | 2 / 3 GB |
| siem | Security | Wazuh | mgmt `10.10.99.20` | Ubuntu 22.04 | 4 / 6 GB |
| web-proxy | Data | Nginx mTLS proxy | dmz `10.10.10.10` | Debian 12 | 1 / 1 GB |
| web-app | Data | App / API | app `10.10.20.10` | Debian 12 | 1 / 1 GB |
| db | Data | PostgreSQL | data `10.10.30.10` | Debian 12 | 1 / 1 GB |
| client-lin | Untrusted | User workstation + scenario test machine | untrust `192.168.100.11` | Ubuntu 22.04 | 2 / 2 GB |

**Total VM footprint:** ≈ 18 GB RAM for the 10 lab VMs (root-ca stays powered off).
