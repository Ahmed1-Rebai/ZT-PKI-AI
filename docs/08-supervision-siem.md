# 08 — Supervision, détection et réponse (Suricata + Wazuh)

## 1. Objectifs

- Centraliser ce qui se passe sur le réseau, le VPN, le PDP, le moteur IA et le reverse proxy.
- Corréler des événements de sources différentes (signature IDS + anomalie IA).
- Détecter la modification des fichiers sensibles (pare-feu, VPN, PKI, politiques, modèles).
- Fournir des vues de recherche et un tableau de bord pour les preuves de l'évaluation.

## 2. Sources de données

| Source | Contenu | Hôte / chemin |
|---|---|---|
| Suricata | Alertes, flux, DNS, TLS (`eve.json`) | `zt-sensor` — `/var/log/suricata/eve.json` |
| OpenVPN | Connexions, échecs, déconnexions | `zt-gw` — `/var/log/openvpn/openvpn.log` |
| nftables | Paquets rejetés (`ZT-DROP`, `ZT-QUAR`) | `zt-gw` — `/var/log/kern.log` (rsyslog) |
| PDP | Décisions, rescoring, refus (JSON) | `zt-pdp` — `/var/log/zt-pdp/audit.jsonl` |
| Moteur IA | Scores par flux, alertes critiques (JSON) | `zt-sensor` — `/var/log/zt-ai/events.jsonl` |
| Nginx | Accès, erreurs du reverse proxy mTLS | `web-proxy` — `/var/log/nginx/zt-proxy.{access,error}.log` |
| PKI | Intégrité de la base de la CA | `sub-ca` — FIM sur `index.txt` et `certs/` |

## 3. Sonde réseau

### 3.1 Placement
Tout le trafic inter-zones passe par `zt-gw`. VirtualBox n'offrant pas de port mirroring, la gateway copie elle-même le trafic avec `tc mirred` : `sensor/mirror.sh`, installé en `/usr/local/sbin/zt-mirror.sh` et lancé par l'unité `zt-mirror`, recopie l'entrée et la sortie des interfaces dmz, app, data et mgmt vers l'interface `zt-mirror` (10.10.98.1). Les interfaces sont résolues par adresse IP au provisioning et écrites dans `/etc/default/zt-mirror` :

```
SRC_IFACES="enp0s9 enp0s10 enp0s16 enp0s17"   # 10.10.10.1 10.10.20.1 10.10.30.1 10.10.99.1
MIRROR_IF=enp0s18                              # 10.10.98.1
```
(les noms `enp0s*` dépendent de la VM ; seules les adresses sont fixes.)

`zt-sensor` reçoit cette copie sur son interface 10.10.98.12 en mode promiscuous ; Suricata et le service `zt-ai` (docs/07) y écoutent tous les deux.

### 3.2 Configuration Suricata
Le rôle Ansible `sensor` installe Suricata 7 (bookworm-backports) et `suricata-update` (règles Emerging Threats Open), puis :

- remplace `HOME_NET` dans `/etc/suricata/suricata.yaml` par `[10.8.0.0/24,10.10.0.0/16,192.168.100.0/24]` ;
- génère `/etc/suricata/zt.yaml`, inclus depuis `suricata.yaml` :

```yaml
af-packet:
  - interface: <interface de 10.10.98.12>
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
```
- valide la configuration (`suricata -T`) et active le service.

### 3.3 Règles locales (`sensor/local.rules` → `/var/lib/suricata/rules/local.rules`)

| SID | Détection |
|---|---|
| 9000001 | Rafale de SYN depuis une même source (≥ 50 en 10 s) : scan |
| 9000002 | ≥ 10 connexions en 30 s vers SSH de `web-app` (10.10.20.10:22) |
| 9000003 | Requête DNS de 60 caractères ou plus |
| 9000004 | Client VPN (10.8.0.0/24) vers la zone mgmt hors port 8443 (canal de posture) |
| 9000099 | Auto-test du pipeline : marqueur `zt-ids-selftest` dans une URL proxy → app |

La règle 9000099 sert à vérifier la chaîne miroir → Suricata → `eve.json` → Wazuh de bout en bout.

## 4. SIEM Wazuh

### 4.1 Installation (all-in-one)
Le rôle `siem` installe Wazuh 4.14.8 all-in-one sur `siem` (10.10.99.20) avec le script officiel `wazuh-install.sh -a`, relève la limite de champs du décodeur JSON (`analysisd.decoder_order_size=1024`, sinon les événements `eve.json` de Suricata sont rejetés), déploie les règles ZT et importe les tableaux de bord.

Agents (rôle `wazuh_agent`, même version que le manager) : `zt-gw`, `zt-pdp`, `zt-sensor`, `sub-ca`, `web-proxy`.

### 4.2 Collecte de fichiers et FIM
Les sources et les chemins surveillés sont définis par groupe d'inventaire dans `infra/ansible/roles/wazuh_agent/defaults/main.yml` ; le rôle en génère un bloc `<ossec_config>` dans `/var/ossec/etc/ossec.conf` de chaque agent. Le FIM est en temps réel avec `report_changes` :

| Hôte | Chemins surveillés |
|---|---|
| `zt-gw` | `/etc/openvpn`, `/etc/nftables.conf`, `/etc/nftables.d` |
| `zt-pdp` | `/opt/zt-pdp/app/policies` |
| `zt-sensor` | `/opt/zt-ai/models`, `/etc/suricata` |
| `sub-ca` | `/home/vagrant/pki/sub/index.txt`, `/home/vagrant/pki/sub/certs` |
| `web-proxy` | `/etc/nginx` |

### 4.3 Règles personnalisées (`siem/rules/zt_rules.xml` → `/var/ossec/etc/rules/zt_rules.xml`)

| ID | Niveau | Condition |
|---|---|---|
| 100100 | 3 | Tout événement JSON `component=pdp` |
| 100101 | 8 | `rescore` vers le palier `restricted` |
| 100102 | 12 | `rescore` vers `quarantine` |
| 100103 | 14 | `rescore` vers `revoke` |
| 100104 | 10 | `authenticate` / `session_open` refusé |
| 100105 | 12 | Appel non autorisé au PDP (`caller_denied`, `posture_denied`) |
| 100106 | 12 | `certificate_revoke` par le PDP |
| 100107 | 10 | Échec du plan de contrôle (`enforcement_error`, `policy_error`, `ttl_renewal_error`) |
| 100120 | 3 | Tout événement `component=ai` |
| 100121 | 7 | Rapport d'anomalie non critique |
| 100122 | 13 | Rapport critique (rafale de flux d'attaque) |
| 100140 | 12 | Alerte Suricata d'une règle locale (SID 900000x) |
| 100150 | 15 | Alerte Suricata puis alerte IA critique en moins de 120 s : identité probablement compromise |
| 100160 | 13 | FIM : modification sous `/etc/nftables` |
| 100161 | 12 | FIM : modification sous `/etc/openvpn` ou de la PKI |

Extrait (corrélation IDS + IA) :

```xml
<rule id="100150" level="15" frequency="2" timeframe="120">
  <if_matched_sid>86601</if_matched_sid>
  <if_sid>100122</if_sid>
  <description>ZT: probable compromised identity — IDS signature AND AI critical anomaly</description>
</rule>
```

Wazuh ne déclenche aucune action : la réponse automatique passe uniquement par le moteur IA et le PDP (docs/06, docs/07).

## 5. Tableaux de bord

Les objets sont versionnés dans `siem/dashboards/zt-dashboards.ndjson` et importés par `siem/dashboards/import.sh` (appelé par le rôle `siem`) : un tableau de bord « ZT-PKI-AI - Zero Trust overview » et cinq recherches enregistrées sur `wazuh-alerts-*`.

| Recherche | Requête |
|---|---|
| ZT - Incident timeline | règles 100102, 100103, 100105, 100107, 100122, 100150, 100160 |
| ZT - PDP decisions | `data.component:pdp` |
| ZT - PKI (revocations, CA files) | règles 100106, 100161 et agent `sub-ca` |
| ZT - Network: IDS and firewall | règles 86601, 100140, 100160 |
| ZT - AI engine | `data.component:ai` |

## 6. Exigences de journalisation

- PDP et moteur IA écrivent une ligne JSON par événement avec `ts` (epoch en secondes), `component`, `event` et les champs utiles (`cn`, `tier`, `score`, `decision`, `reason`, `anomaly`…).
- Horloges synchronisées par chrony sur `zt-gw` (10.10.99.1).
- Aucun secret ni clé dans les journaux.

## 7. Tests supervision

| Test | Résultat |
|---|---|
| Modification de `/etc/nftables.conf` (S11) | Alerte FIM règle 100160 avec anciennes et nouvelles empreintes |
| Modification sous `/etc/openvpn` | Alerte FIM règle 100161 |
| Requête contenant `zt-ids-selftest` | Alerte Suricata 9000099 reçue dans Wazuh (règle 86601) |
| Appel au PDP depuis un tunnel client (10.8.0.10) | Règle 100105 |
| Événement `rescore` vers `revoke` (via `wazuh-logtest`) | Règle 100103 |
