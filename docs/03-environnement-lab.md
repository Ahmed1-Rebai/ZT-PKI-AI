# 03 — Environnement de laboratoire

## 1. Prérequis matériels

| Profil | CPU | RAM | Disque | Remarque |
|---|---|---|---|---|
| **Complet** | 8 cœurs | 32 Go | 250 Go SSD | Toutes les VMs séparées |
| **Léger** | 4–6 cœurs | 16 Go | 150 Go SSD | VMs fusionnées (voir §4) |

Hyperviseur recommandé : **Proxmox VE** (bridges Linux/OVS, miroir de ports). Alternatives : VMware Workstation, VirtualBox, libvirt/KVM.

## 2. Machines virtuelles (profil complet)

| VM | OS | vCPU | RAM | Disque | Rôle |
|---|---|---|---|---|---|
| `root-ca` | Debian 12 | 1 | 512 Mo | 8 Go | Root CA **hors-ligne** (sans NIC, éteinte) |
| `sub-ca` | Debian 12 | 1 | 1 Go | 10 Go | Issuing CA, OCSP |
| `zt-gw` | Debian 12 | 2 | 2 Go | 16 Go | OpenVPN + nftables (5 NICs) |
| `zt-pdp` | Debian 12 | 2 | 2 Go | 16 Go | PDP, OPA, Redis |
| `zt-sensor` | Debian 12 | 2 | 2 Go | 20 Go | Suricata + NFStream |
| `zt-ai` | Ubuntu 22.04 | 4 | 4 Go | 30 Go | Entraînement + inférence |
| `siem` | Ubuntu 22.04 | 4 | 8 Go | 60 Go | Wazuh all-in-one |
| `web-proxy` | Debian 12 | 1 | 1 Go | 8 Go | Nginx mTLS (DMZ) |
| `web-app` | Debian 12 | 1 | 1 Go | 10 Go | Application métier |
| `db` | Debian 12 | 1 | 1 Go | 10 Go | PostgreSQL |
| `client-win` | Windows 10/11 | 2 | 4 Go | 40 Go | Client légitime |
| `client-lin` | Ubuntu Desktop | 2 | 2 Go | 20 Go | Client légitime / compromis |
| `kali` | Kali Linux | 2 | 4 Go | 40 Go | Attaquant |

**Total ≈ 32 Go RAM** (profil complet).

## 3. Réseaux virtuels

| Bridge | Réseau | Usage |
|---|---|---|
| `vmbr-untrust` | 192.168.100.0/24 | Clients, attaquant, WAN de la gateway |
| `vmbr-dmz` | 10.10.10.0/24 | Reverse proxy |
| `vmbr-app` | 10.10.20.0/24 | Application |
| `vmbr-data` | 10.10.30.0/24 | Base de données |
| `vmbr-mgmt` | 10.10.99.0/24 | PKI, PDP, IA, sonde, SIEM |
| *(logique)* `tun0` | 10.8.0.0/24 | Pool VPN (IP fixes par CN) |

> Aucun bridge n'est relié à Internet pendant les tests d'attaque (NAT temporaire pour installer les paquets, puis retiré).

## 4. Plan d'adressage

| Hôte | Interface | Adresse |
|---|---|---|
| `zt-gw` | WAN | 192.168.100.1 |
| `zt-gw` | DMZ / App / Data / Mgmt | 10.10.10.1 / 10.10.20.1 / 10.10.30.1 / 10.10.99.1 |
| `sub-ca` | mgmt | 10.10.99.5 |
| `zt-pdp` | mgmt | 10.10.99.10 |
| `zt-ai` | mgmt | 10.10.99.11 |
| `zt-sensor` | mgmt (+ NIC miroir) | 10.10.99.12 |
| `siem` | mgmt | 10.10.99.20 |
| `web-proxy` | dmz | 10.10.10.10 |
| `web-app` | app | 10.10.20.10 |
| `db` | data | 10.10.30.10 |
| `client-win` | untrust | 192.168.100.10 |
| `client-lin` | untrust | 192.168.100.11 |
| `kali` | untrust | 192.168.100.66 |
| Clients VPN | tun0 | 10.8.0.10–10.8.0.250 (fixe par CN) |

### Profil léger (16 Go)
Fusionner : `sub-ca` + `zt-pdp` ; `zt-sensor` + `zt-ai` ; `web-proxy` + `web-app` + `db` (conteneurs) ; un seul client Linux + Kali.

## 5. Versions logicielles

| Logiciel | Version cible |
|---|---|
| OpenSSL | ≥ 3.0 |
| OpenVPN | ≥ 2.6 |
| nftables | ≥ 1.0 |
| Suricata | ≥ 7.0 |
| Python | 3.11 |
| OPA | ≥ 0.60 |
| Redis | ≥ 7 |
| Wazuh | 4.x (dernière stable) |
| Docker / Compose | ≥ 24 / v2 |

## 6. Préparation commune (toutes les VMs Linux)

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install chrony curl git vim auditd ca-certificates
sudo timedatectl set-timezone Africa/Tunis
# SSH : clés uniquement
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

> **NTP indispensable** : validité des certificats et corrélation des logs dépendent de l'heure. Faire pointer `chrony` vers `zt-gw` ou un serveur interne.

## 7. Gateway : installation de base

```bash
sudo apt -y install openvpn nftables easy-rsa python3-venv netcat-openbsd
# Routage
cat <<'SYS' | sudo tee /etc/sysctl.d/90-zt.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
SYS
sudo sysctl --system
sudo systemctl enable nftables
```

## 8. Services Python (PDP / IA) en Docker Compose

`infra/docker-compose.yml`

```yaml
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    networks: [zt]
  opa:
    image: openpolicyagent/opa:latest
    command: ["run", "--server", "--addr=:8181", "/policies"]
    volumes: ["../pdp/policies:/policies:ro"]
    networks: [zt]
  pdp:
    build: ../pdp
    environment:
      - REDIS_URL=redis://redis:6379/0
      - OPA_URL=http://opa:8181
      - PDP_TLS_CERT=/certs/pdp.crt
      - PDP_TLS_KEY=/certs/pdp.key
      - PDP_CA=/certs/ca-chain.crt
    volumes: ["./certs:/certs:ro"]
    ports: ["8443:8443"]
    depends_on: [redis, opa]
    networks: [zt]
networks:
  zt: {}
```

`infra/requirements.txt`

```
fastapi
uvicorn[standard]
redis
httpx
pydantic
pyyaml
pandas
numpy
scikit-learn
torch
nfstream
shap
joblib
matplotlib
pytest
```

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r infra/requirements.txt
```

## 9. Reproductibilité

- **Snapshots** après chaque jalon (`base`, `pki-ok`, `vpn-ok`, `pdp-ok`, `ai-ok`).
- Scripts Ansible (`infra/ansible/`) ou Vagrantfile pour recréer les VMs.
- Fichier `Makefile` : `make pki`, `make vpn`, `make pdp`, `make ai`, `make tests`.

## 10. Vérification de l'environnement

| Test | Commande | Attendu |
|---|---|---|
| Isolation | `ping 10.10.30.10` depuis `kali` | Échec |
| Routage gateway | `ping 10.10.20.10` depuis `zt-gw` | OK |
| Heure | `chronyc tracking` | Écart < 1 s |
| Services | `docker compose ps` | Tous *running* |
