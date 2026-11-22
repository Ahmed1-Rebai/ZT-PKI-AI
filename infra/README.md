# infra/ — Infrastructure as Code (Vagrant + Ansible on VirtualBox)

Hypervisor: **VirtualBox 7.1 (virtio)** on the lab host.
VM layer: **Vagrant** (`Vagrantfile`). Configuration: **Ansible** (`ansible/`).

## ⚠️ Requires VirtualBox ≥ 7.1

VirtualBox **7.0.x duplicates frames on Internal Networks** (confirmed with
packet counters: the gateway forwards 1 SYN, the receiver sees 2), which resets
every cross-zone TCP connection and breaks the whole data plane. **Upgrade to
VirtualBox 7.1.x** (Oracle repo). The Vagrantfile also sets `virtio` on all
adapters (`vb.default_nic_type`), which keeps the fix stable and the adapter
order correct (eth0 = NAT).

## Why Vagrant and not Terraform

Terraform has no maintained VirtualBox provider. On VirtualBox the declarative
VM tool is Vagrant; Ansible then configures each VM. (Terraform would only apply
if we moved to libvirt/KVM or Proxmox.)

## VMs (9 running + offline Root CA)

| Node | Role | Zone(s) | Box |
|---|---|---|---|
| root-ca | Offline Root CA (powered off) | none | debian-12 |
| sub-ca | Issuing CA, CRL, OCSP | mgmt | debian-12 |
| zt-gw | OpenVPN + nftables (PEP), traffic mirror | all 5 + mirror | debian-12 |
| zt-pdp | PDP + OPA + Redis (Docker) | mgmt | debian-12 |
| zt-sensor | Suricata 7 + AI inference service (`zt-ai`) | mgmt + mirror | debian-12 |
| siem | Wazuh 4.14.8 | mgmt | ubuntu-22.04 |
| web-proxy | Nginx mTLS proxy | dmz | debian-12 |
| web-app | Flask app (gunicorn) | app | debian-12 |
| db | PostgreSQL | data | debian-12 |
| client-lin | alice's workstation and test machine of the scenarios | untrust | ubuntu-22.04 |

Total VM RAM ≈ 18 GB.

## The host

The host runs VirtualBox, Vagrant and Ansible. It is not a node of the
architecture. It also has two side roles:

- **Local training of the AI models** (`ai/train.py`, GPU): the trained models and
  their signed `manifest.json` are then deployed by the `sensor` role on
  `zt-sensor`, where inference runs (CPU). `make ai` prepares the local `.venv`;
  install the dependencies with `.venv/bin/pip install -r infra/requirements.txt`.
- **Admin station**: the mgmt network is a VirtualBox host-only net, so the host
  can open the Wazuh dashboard (`https://10.10.99.20`). Give it its mgmt address
  once with `make mgmt-host` (10.10.99.2). The four other zones stay internal.

## Workflow

```bash
cd infra

# 0. One-time: install the tools (needs sudo; downloads boxes from the Internet)
make tools

# 1. Bring up the lab (= vagrant up, stage by stage; first boot runs Ansible)
make core detection workloads client
#   core: sub-ca zt-gw zt-pdp · detection: zt-sensor siem
#   workloads: web-proxy web-app db · client: client-lin
#   (`make up` would also start root-ca, which must stay off)
make mgmt-host     # once: host address 10.10.99.2 on the mgmt net (Wazuh dashboard)

# 2. Re-apply configuration after editing a role
make provision

# 3. Tests: cut Internet from the lab VMs first
make isolate       # detaches each VM's NAT adapter (eth0)
make scenarios     # the 12 attack scenarios, played from client-lin
make abcd          # A/B/C/D benchmark: exposed surface + attacks
make perf          # PDP latency, VPN connect, throughput per path and per config
make reconnect     # re-attach when you need apt again
```

`root-ca`: after `vagrant up root-ca` signs the Issuing CA (USB transfer of the
CSR), detach its NIC and keep it halted — it must stay offline.

## Layout

```
infra/
├── Vagrantfile              # 10 VMs + zone networks + mirror net + Ansible provisioner
├── Makefile                 # tools / core / detection / workloads / vpn / scenarios / abcd / perf / isolate ...
├── docker-compose.yml       # PDP + OPA + Redis control-plane stack
├── requirements.txt         # Python deps for pdp/ and ai/
└── ansible/
    ├── ansible.cfg
    ├── inventory.ini        # static inventory (mgmt-net IPs)
    ├── site.yml             # common + one play per role + wazuh_agent
    ├── group_vars/all.yml   # networks, IPs, versions
    ├── tasks/routes.yml     # shared internal-route guard
    └── roles/
        └── common, ca_root, ca_sub, gateway, pdp, sensor, ai, siem, wazuh_agent, proxy, webapp, db, client
```

The role stubs reference the matching top-level folders (`../pki`, `../vpn`,
`../firewall`, `../pdp`, `../ai`, `../sensor`, `../siem`, `../apps`) where the
real configs live.
