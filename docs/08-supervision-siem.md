# 08 — Supervision, détection et réponse (Suricata + Wazuh)

## 1. Objectifs

- Voir **tout** ce qui se passe : réseau, VPN, décisions Zero Trust, IA, applications.
- Corréler des événements de sources différentes.
- Fournir tableaux de bord, alertes et preuves pour l'évaluation.

## 2. Sources de données

| Source | Contenu | Chemin / méthode |
|---|---|---|
| Suricata | Alertes, flux, DNS, TLS (`eve.json`) | `/var/log/suricata/eve.json` |
| OpenVPN | Connexions, échecs, déconnexions | `/var/log/openvpn/openvpn.log` |
| nftables | Paquets rejetés (`ZT-DROP`, `ZT-QUAR`) | `journald` / `/var/log/kern.log` |
| PDP | Décisions, rescoring (JSON) | stdout → fichier → agent Wazuh |
| Moteur IA | Scores, top features | JSON |
| Nginx | Accès, erreurs, CN client | `/var/log/nginx/*.log` |
| PKI | Émissions, révocations | `index.txt`, logs scripts |
| Système | auth, auditd, FIM | agent Wazuh |

## 3. Sonde réseau

### 3.1 Placement
Toute communication inter-zones passe par la gateway ; la sonde reçoit une **copie** du trafic.

```bash
# Exemple de miroir tc sur la gateway (eth1..eth4 -> eth5 vers la sonde)
for IF in eth1 eth2 eth3 eth4; do
  # trafic entrant
  tc qdisc add dev $IF ingress
  tc filter add dev $IF parent ffff: protocol all u32 match u8 0 0 \
     action mirred egress mirror dev eth5
  # trafic sortant
  tc qdisc add dev $IF root handle 1: prio
  tc filter add dev $IF parent 1: protocol all u32 match u8 0 0 \
     action mirred egress mirror dev eth5
done
```
> Sous Proxmox/VMware/OVS, le **port mirroring de l'hyperviseur** est plus propre. Option simple : exécuter NFStream directement sur `tun0` de la gateway pour le trafic VPN.

### 3.2 Configuration Suricata (`/etc/suricata/suricata.yaml`, extraits)
```yaml
af-packet:
  - interface: eth1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow, dns, tls, http, anomaly]
```
```bash
sudo suricata-update                      # règles Emerging Threats Open
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
```

### 3.3 Règles locales (`/var/lib/suricata/rules/local.rules`)
```
alert tcp $HOME_NET any -> $HOME_NET any (msg:"ZT Horizontal scan interne"; flags:S; \
  threshold:type both, track by_src, count 50, seconds 10; sid:9000001; rev:1;)
alert tcp any any -> 10.10.20.10 22 (msg:"ZT SSH brute force"; flow:to_server; flags:S; \
  threshold:type both, track by_src, count 10, seconds 30; sid:9000002; rev:1;)
alert udp any any -> any 53 (msg:"ZT DNS long query (tunnel?)"; dns.query; \
  content:"."; pcre:"/^.{60,}$/"; sid:9000003; rev:1;)
```

## 4. SIEM Wazuh

### 4.1 Installation (all-in-one)
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a
```
Agents installés sur : `zt-gw`, `zt-pdp`, `zt-sensor`, `zt-ai`, `sub-ca`, `web-proxy`, `web-app`, `db`.

### 4.2 Collecte de fichiers (`ossec.conf` de l'agent)
```xml
<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>
<localfile><log_format>json</log_format><location>/var/log/zt/pdp-audit.json</location></localfile>
<localfile><log_format>json</log_format><location>/var/log/zt/ai-events.json</location></localfile>
<localfile><log_format>syslog</log_format><location>/var/log/openvpn/openvpn.log</location></localfile>
<syscheck><directories check_all="yes" realtime="yes">/etc/openvpn,/pki,/etc/nftables.conf</directories></syscheck>
```
Le FIM (*File Integrity Monitoring*) alerte si la config VPN, la PKI ou le pare-feu est modifiée.

### 4.3 Règles de corrélation personnalisées (`/var/ossec/etc/rules/zt_rules.xml`)
> À adapter aux noms de champs réels après décodage.

```xml
<group name="zerotrust,">

  <rule id="100100" level="8">
    <decoded_as>json</decoded_as>
    <field name="event">rescore</field>
    <field name="tier">restricted</field>
    <description>ZT: privilèges réduits pour $(cn) (score $(score))</description>
  </rule>

  <rule id="100101" level="12">
    <decoded_as>json</decoded_as>
    <field name="event">rescore</field>
    <field name="tier">quarantine</field>
    <description>ZT: session en QUARANTAINE pour $(cn)</description>
    <mitre><id>T1078</id></mitre>
  </rule>

  <rule id="100102" level="14">
    <decoded_as>json</decoded_as>
    <field name="event">rescore</field>
    <field name="tier">revoke</field>
    <description>ZT: certificat REVOQUE pour $(cn)</description>
  </rule>

  <!-- Corrélation : connexion VPN suivie de scan interne par la même identité -->
  <rule id="100110" level="13" frequency="2" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <if_sid>86601</if_sid>   <!-- alerte Suricata (à ajuster) -->
    <description>ZT: identité compromise probable (anomalie IA + signature IDS)</description>
  </rule>

</group>
```

### 4.4 Réponse active (optionnel)
Un script Wazuh *active response* appelle le PDP :
```bash
#!/bin/bash
# /var/ossec/active-response/bin/zt-quarantine.sh
read -r INPUT
CN=$(echo "$INPUT" | jq -r '.parameters.alert.data.cn')
curl -s --cert /etc/wazuh/zt.crt --key /etc/wazuh/zt.key \
  -X POST "https://10.10.99.10:8443/v1/events" \
  -H "Content-Type: application/json" \
  -d "{\"cn\":\"$CN\",\"anomaly\":1.0,\"source\":\"wazuh-ar\"}"
```

## 5. Tableaux de bord

| Dashboard | Panneaux |
|---|---|
| **Vue Zero Trust** | Sessions actives, scores par identité, répartition des paliers, refus d'accès |
| **PKI** | Certificats émis / expirant / révoqués, échecs de validation |
| **Réseau** | Top talkers, flux bloqués `ZT-DROP`, alertes Suricata par signature |
| **IA** | Score d'anomalie dans le temps, top features, taux de faux positifs |
| **Incident** | Chronologie : alerte → score → quarantaine → révocation |

## 6. Exigences de journalisation

- Format **JSON**, horodatage ISO-8601 UTC, champ `cn`, `src_ip`, `decision`, `reason`.
- **Synchronisation NTP** obligatoire.
- Pas de secrets ni de clés dans les logs.
- Rétention minimale : 30 jours (lab), logs intégrité protégés (envoi temps réel).

## 7. Tests supervision

| Test | Attendu |
|---|---|
| `nmap` interne | Alerte Suricata + règle 100110 |
| Révocation d'un cert | Événement `revoke` dans Wazuh < 5 s |
| Modification `server.conf` | Alerte FIM |
| Arrêt de l'agent | Alerte « agent disconnected » |
