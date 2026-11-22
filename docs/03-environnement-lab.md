# 03 — Environnement de laboratoire

## 1. Prérequis matériels

Le lab tourne sur une seule machine hôte Linux avec **VirtualBox 7.1 + Vagrant + Ansible** (`make tools` installe Vagrant et Ansible). Les VMs du lab consomment **≈ 18 Go de RAM** au total, `root-ca` restant éteinte ; prévoir un hôte avec au moins 8 cœurs et 32 Go de RAM pour garder de la marge. Les disques sont ceux des boxes Vagrant (allocation dynamique).

L'hôte n'est pas un nœud de l'architecture : il sert de station d'administration (adresse 10.10.99.2 sur le réseau mgmt, tableau de bord Wazuh) et de machine d'entraînement des modèles IA sur son GPU.

## 2. Machines virtuelles

Définies dans `infra/Vagrantfile` (boxes `bento/debian-12` et `bento/ubuntu-22.04`), chacune provisionnée par son rôle Ansible (`infra/ansible/site.yml`).

| VM | OS | vCPU | RAM | Rôle |
|---|---|---|---|---|
| `root-ca` | Debian 12 | 1 | 512 Mo | Root CA **hors-ligne** (sans NIC interne, éteinte) |
| `sub-ca` | Debian 12 | 1 | 1 Go | Issuing CA, CRL HTTP, répondeur OCSP |
| `zt-gw` | Debian 12 | 2 | 2 Go | OpenVPN + nftables (5 NICs de zone + NIC miroir) |
| `zt-pdp` | Debian 12 | 2 | 2 Go | PDP, OPA, Redis (Docker Compose) |
| `zt-sensor` | Debian 12 | 2 | 3 Go | Suricata + NFStream + inférence IA (`zt-ai`) |
| `siem` | Ubuntu 22.04 | 4 | 6 Go | Wazuh all-in-one |
| `web-proxy` | Debian 12 | 1 | 1 Go | Nginx mTLS (DMZ) |
| `web-app` | Debian 12 | 1 | 1 Go | Application Flask |
| `db` | Debian 12 | 1 | 1 Go | PostgreSQL |
| `client-lin` | Ubuntu 22.04 | 2 | 2 Go | Poste de l'utilisateur et machine de test des scénarios |

**Total ≈ 18 Go RAM.**

## 3. Réseaux virtuels

| Réseau VirtualBox | Plage | Usage |
|---|---|---|
| intnet `zt-untrust` | 192.168.100.0/24 | Client, WAN de la gateway |
| intnet `zt-dmz` | 10.10.10.0/24 | Reverse proxy |
| intnet `zt-app` | 10.10.20.0/24 | Application |
| intnet `zt-data` | 10.10.30.0/24 | Base de données |
| host-only (mgmt) | 10.10.99.0/24 | PKI, PDP, sonde, SIEM ; l'hôte y prend 10.10.99.2 (`make mgmt-host`) |
| intnet `zt-mirror` | 10.10.98.0/24 | Copie du trafic de la gateway (`tc mirred`) vers la sonde (promiscuous) |
| *(logique)* `tun0` | 10.8.0.0/24 | Pool VPN (IP fixes par CN) |

> Les réseaux internes n'ont aucune route vers l'hôte ni vers Internet. Chaque VM garde l'adaptateur NAT de Vagrant (`eth0`) pour l'installation des paquets ; `make isolate` le détache avant les tests d'attaque, `make reconnect` le rattache.

## 4. Plan d'adressage

| Hôte | Interface | Adresse |
|---|---|---|
| `zt-gw` | WAN | 192.168.100.1 |
| `zt-gw` | DMZ / App / Data / Mgmt | 10.10.10.1 / 10.10.20.1 / 10.10.30.1 / 10.10.99.1 |
| `zt-gw` | miroir | 10.10.98.1 |
| hôte | mgmt | 10.10.99.2 |
| `sub-ca` | mgmt | 10.10.99.5 |
| `zt-pdp` | mgmt | 10.10.99.10 |
| `zt-sensor` | mgmt + miroir | 10.10.99.12 / 10.10.98.12 |
| `siem` | mgmt | 10.10.99.20 |
| `web-proxy` | dmz | 10.10.10.10 |
| `web-app` | app | 10.10.20.10 |
| `db` | data | 10.10.30.10 |
| `client-lin` | untrust | 192.168.100.11 |
| Clients VPN | tun0 | 10.8.0.0/24, IP fixe par CN (`vpn/zt/ip-map.csv`) |

## 5. Versions logicielles

| Logiciel | Version utilisée |
|---|---|
| VirtualBox / Vagrant | 7.1 / paquet de la distribution de l'hôte |
| OpenSSL | 3.0 (Debian 12) |
| OpenVPN | 2.6 |
| nftables | 1.0 (Debian 12) |
| Suricata | 7 (bookworm-backports) |
| Python | 3.11 (Debian 12) |
| OPA | 0.70.0 (`openpolicyagent/opa:0.70.0-static`) |
| Redis | 7.4 (`redis:7.4-alpine`) |
| Wazuh | 4.14.8 |
| Docker Compose | v2.29.7 (plugin installé sur `zt-pdp`) |

## 6. Préparation commune (rôle Ansible `common`)

Appliquée à toutes les VMs :

- fuseau horaire `Africa/Tunis` ;
- paquets de base : `chrony curl git vim auditd ca-certificates python3` ;
- `chrony` reçoit `server 10.10.99.1 iburst` (zt-gw) en plus de ses sources par défaut ; `zt-gw` n'est pas configuré comme serveur NTP, donc la synchronisation passe en pratique par les sources par défaut tant que le NAT est attaché ;
- authentification SSH par mot de passe désactivée (`PasswordAuthentication no`) ;
- sysctl `/etc/sysctl.d/90-zt.conf` : `rp_filter = 1`, pas de redirections ICMP, `tcp_syncookies = 1`.

> L'heure compte : la validité des certificats et la corrélation des journaux en dépendent.

## 7. Gateway : installation de base (rôle `gateway`)

- paquets : `openvpn nftables openssl netcat-openbsd python3` ;
- `net.ipv4.ip_forward = 1` ;
- configuration OpenVPN, matériel PKI copié depuis `sub-ca`, clé `tls-crypt`, hooks Python du PDP, table d'IP fixes ;
- compte restreint `ztpdp` dont la clé SSH ne peut lancer que `ztpdp-nft` (commande forcée) ;
- jeu de règles `firewall/nftables.conf`.

## 8. Plan de contrôle en Docker Compose (`zt-pdp`)

`infra/docker-compose.yml` est déployé sur `zt-pdp` par le rôle `pdp` (code dans `/opt/zt-pdp/app`). Il contient trois services sur un réseau bridge `control` :

| Service | Image | Détails |
|---|---|---|
| `redis` | `redis:7.4-alpine` | AOF activé, volume `redis-data` |
| `opa` | `openpolicyagent/opa:0.70.0-static` | `authz.rego` + `data.json` montés en lecture seule |
| `pdp` | construit depuis `pdp/Dockerfile` | écoute sur `10.10.99.10:8443` ; montages `/etc/zt-pdp/certs` → `/run/certs` (ro), `/etc/zt-pdp/ssh` → `/run/secrets` (ro), `/var/log/zt-pdp` ; variables dans `/etc/zt-pdp/pdp.env` |

Le moteur IA ne tourne pas dans Compose : son inférence est un service systemd `zt-ai` sur `zt-sensor` (rôle `sensor`). L'entraînement se fait sur l'hôte, dans un `.venv` préparé par `make ai` à partir de `infra/requirements.txt`.

## 9. Reproductibilité

- `infra/Vagrantfile` + rôles Ansible (`infra/ansible/`) recréent toutes les VMs.
- Démarrage par étapes depuis `infra/` : `make core detection workloads client` (`make up` démarrerait aussi `root-ca`).
- Autres cibles du `Makefile` : `provision`, `vpn`, `vpn-check`, `ai`, `mgmt-host`, `scenarios`, `abcd`, `perf`, `isolate`, `reconnect`, `status`, `halt`, `destroy`, `lint`.

## 10. Vérification de l'environnement

| Test | Commande | Attendu |
|---|---|---|
| Isolation | `ping 10.10.30.10` depuis `client-lin` (hors tunnel) | Échec |
| Routage gateway | `ping 10.10.20.10` depuis `zt-gw` | OK |
| Heure | `chronyc tracking` | Écart < 1 s |
| Plan de contrôle | `docker compose ps` sur `zt-pdp` | `redis`, `opa`, `pdp` *running* |
| VPN | `make vpn-check` | Contrôles OK |
