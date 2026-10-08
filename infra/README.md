# infra/ — Infrastructure as Code (Vagrant + Ansible on VirtualBox)

Hypervisor: **VirtualBox 7.0.16** on the Blue Team host.
VM layer: **Vagrant** (`Vagrantfile`). Configuration: **Ansible** (`ansible/`).

## Why Vagrant and not Terraform

Terraform has no maintained VirtualBox provider. On VirtualBox the declarative
VM tool is Vagrant; Ansible then configures each VM. (Terraform would only apply
if we moved to libvirt/KVM or Proxmox.)

## VMs (10 automated + offline Root CA) + AI on the host

| Node | Role | Zone(s) | Box | Milestone |
|---|---|---|---|---|
| root-ca | Offline Root CA | none (detach after signing) | debian-12 | M1 |
| sub-ca | Issuing CA, CRL, OCSP | mgmt | debian-12 | M1 |
| zt-gw | OpenVPN + nftables (PEP) | all 5 | debian-12 | M2/M3 |
| zt-pdp | PDP + OPA + Redis | mgmt | debian-12 | M3 |
| zt-sensor | Suricata + NFStream | mgmt (+mirror) | debian-12 | M4/M6 |
| **(host)** | **AI detection — runs on THIS laptop** | mgmt (10.10.99.2) | — GPU | M4/M5 |
| siem | Wazuh | mgmt | ubuntu-22.04 | M6 |
| web-proxy | Nginx mTLS proxy | dmz | debian-12 | M6 |
| web-app | Demo app/API | app | debian-12 | M6 |
| db | PostgreSQL | data | debian-12 | M6 |
| client-lin | Legit/compromised client | untrust | ubuntu-22.04 | M2/M6 |

`client-win` (Windows) and `kali` (partner's laptop) are set up by hand, not via this IaC.
Total VM RAM ≈ 18 GB (AI moved off-VM onto the host).

## AI on the host

VirtualBox cannot pass the RTX 5050 into a guest (no CUDA passthrough), so the AI
engine runs natively on the host and the host joins the lab's **mgmt** network:

- The mgmt network is a VirtualBox **host-only** net (not internal), so the host
  can reach `zt-pdp` (:8443) and `zt-sensor`, while still having no Internet route.
- The host's mgmt address is **10.10.99.2**. Set it once after the first mgmt VM
  is up: `make mgmt-host`.
- Configure the AI venv/service on the host: `make ai` (Ansible, local connection).
- Training uses the GPU (`torch` CUDA); inference posts risk scores to the PDP.
- The other four zones (untrust/dmz/app/data) stay fully **internal** (VM-only).

## Workflow

```bash
cd infra

# 0. One-time: install the tools (needs sudo; downloads boxes from the Internet)
make tools

# 1. Bring up VMs in milestone-sized batches (RAM is ~28-32 GB for the full set)
make core          # sub-ca, zt-gw, zt-pdp
make mgmt-host     # give THIS host 10.10.99.2 on the mgmt net (AI node)
make detection     # zt-sensor, siem
make ai            # configure the AI engine on the host (GPU)
make workloads     # web-proxy, web-app, db
make client        # client-lin
#   ... or `make up` for every VM, `vagrant up <name>` for one.

# 2. Re-apply configuration after editing a role
make provision

# 3. For attack-test runs, cut Internet from the lab VMs
make isolate       # detaches each VM's NAT adapter (eth0)
make reconnect     # re-attach when you need apt again
```

`root-ca`: after `vagrant up root-ca` signs the Issuing CA (USB transfer of the
CSR), detach its NIC and keep it halted — it must stay offline.

## Layout

```
infra/
├── Vagrantfile              # 11 VMs + 5 internal networks + Ansible provisioner
├── Makefile                 # tools / core / detection / workloads / isolate ...
├── requirements.txt         # Python deps for pdp/ and ai/
└── ansible/
    ├── ansible.cfg
    ├── inventory.ini        # static inventory (mgmt-net IPs)
    ├── site.yml             # common + one play per role
    ├── group_vars/all.yml   # networks, IPs, versions
    └── roles/
        ├── common/          # baseline (NTP, SSH keys, sysctl, auditd) — implemented
        └── ca_root, ca_sub, gateway, pdp, sensor, ai, siem, proxy, webapp, db, client
                              # milestone-annotated stubs, filled per phase
```

The role stubs reference the matching top-level folders (`../pki`, `../vpn`,
`../firewall`, `../pdp`, `../ai`, `../sensor`, `../siem`, `../apps`) where the
real configs live.
