# 05 — VPN (OpenVPN, authentification mutuelle par certificats)

## 1. Rôle dans l'architecture

Le VPN n'est **pas** un « accès au réseau interne » : c'est un **canal chiffré authentifié** dont les droits réseau sont décidés par le PDP. Le serveur pousse quatre routes /32 vers les points publiés, mais un client connecté n'atteint que ce que les ensembles nftables de la passerelle autorisent pour son IP VPN (politique par défaut : drop).

## 2. Pourquoi OpenVPN ?

| Critère | OpenVPN | WireGuard | strongSwan (IKEv2) |
|---|---|---|---|
| Authentification par X.509 | oui, natif | non (clés brutes) | oui |
| Hooks / scripts (`tls-verify`, `client-connect`) | oui | non | limité |
| Interface de management (kill session) | oui | non | partielle |
| Adapté à une PKI | oui | non | oui |

WireGuard n'a pas été déployé ni mesuré ; le choix repose sur l'intégration X.509 et les hooks.

## 3. Configuration serveur — `vpn/server/server.conf`

Déployée dans `/etc/openvpn/server/server.conf` et lancée par l'unité `openvpn-server@server` (OpenVPN 2.6). Extrait du fichier :

```conf
port 1194
proto udp
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

push "route 10.10.10.10 255.255.255.255"   # web-proxy (mTLS app entry)
push "route 10.10.20.10 255.255.255.255"   # web-app SSH (admin-only; others hit ZT-DROP)
push "route 10.10.99.10 255.255.255.255"   # PDP posture channel (opened in nftables later)
push "route 10.10.99.30 255.255.255.255"   # reserved for a remediation service (none deployed)

ca   /etc/openvpn/server/ca-chain.crt
cert /etc/openvpn/server/vpn-gw.crt
key  /etc/openvpn/server/vpn-gw.key
crl-verify /etc/openvpn/server/crl.pem
dh none
ecdh-curve prime256v1

tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
data-ciphers AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
tls-crypt /etc/openvpn/server/ta.key
remote-cert-tls client
verify-client-cert require
reneg-sec 3600
allow-compression no

script-security 2
tls-verify        /etc/openvpn/hooks/tls-verify.py
client-connect    /etc/openvpn/hooks/client-connect.py
client-disconnect /etc/openvpn/hooks/client-disconnect.py
management 127.0.0.1 7505

user nobody
group nogroup
status /var/log/openvpn/status.log 10
log-append /var/log/openvpn/openvpn.log
```

Seules des routes d'hôte sont poussées, pas de sous-réseaux. L'adresse 10.10.99.30 est réservée dans le plan d'adressage : aucun service n'y répond (il n'existe pas de portail de remédiation).

La clé `tls-crypt` est générée sur la passerelle au provisionnement (`openvpn --genkey secret /etc/openvpn/server/ta.key`), puis rapatriée par `vpn/scripts/sync-pki.sh` pour être intégrée aux profils clients.

## 4. Configuration client — `vpn/client/client.ovpn.template`

`vpn/scripts/make-client.sh <user>` remplit le modèle avec la chaîne de CA, le certificat et la clé du client et la clé `tls-crypt` :

```conf
client
dev tun
proto udp
remote __GW_HOST__ 1194
nobind
remote-cert-tls server
verify-x509-name vpn-gw.lab.local name
tls-version-min 1.3
data-ciphers AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
auth-nocache

<ca> __CA_CHAIN__ </ca>
<cert> __CLIENT_CERT__ </cert>
<key> __CLIENT_KEY__ </key>
<tls-crypt> __TLS_CRYPT__ </tls-crypt>
```

Les `.ovpn` générés ne sont pas versionnés.

## 5. Hooks Zero Trust

Les trois hooks (`vpn/hooks/`) sont en Python standard et tournent sous `nobody`. Ils partagent `zt_common.py`, qui lit `/etc/openvpn/zt/hook.env` (modèle : `hook.env.example`), appelle le PDP en mTLS et écrit une ligne `ZT-HOOK {json}` sur stderr, donc dans `openvpn.log`.

```
PDP_ENFORCE=1                       # positionné par Ansible (group_vars/all.yml)
PDP_URL=https://10.10.99.10:8443
PDP_TIMEOUT=2
PDP_CA=/etc/openvpn/hooks/ca-chain.crt
PDP_CERT=/etc/openvpn/hooks/gw-client.crt
PDP_KEY=/etc/openvpn/hooks/gw-client.key
IP_MAP=/etc/openvpn/zt/ip-map.csv
```

Avec `PDP_ENFORCE=1`, toute décision vient du PDP et toute erreur (PDP injoignable, TLS, timeout) entraîne un refus : fail-closed. `PDP_ENFORCE=0` est le mode d'amorçage utilisé avant que le PDP n'existe : OpenVPN applique encore mTLS et CRL, les hooks ne font que journaliser.

### 5.1 `tls-verify.py` — décision à l'authentification
Appelé pour chaque certificat de la chaîne ; seul le niveau 0 (le client) est traité. OpenVPN a déjà vérifié la chaîne, la CRL et l'EKU. Extrait :

```python
if not cn or not zt.CN_RE.match(cn):
    zt.log("tls-verify", decision="deny", reason="bad-cn", **env)
    return 1
...
try:
    resp = zt.api(cfg, "/v1/authenticate", {"cn": cn, "serial": env["serial"], "src_ip": env["src_ip"]})
    allow = str(resp.get("decision", "")).lower() == "allow"
    return 0 if allow else 1
except Exception as exc:  # noqa: BLE001 - any error means deny
    zt.log("tls-verify", decision="deny", mode="pdp", reason="pdp-unreachable", ...)
    return 1
```

### 5.2 `client-connect.py` — IP fixe + ouverture de session
Le hook appelle `POST /v1/session/open` ; le PDP renvoie la décision et l'IP VPN, et pose les règles nftables correspondant au palier de confiance. L'IP est écrite dans le fichier de configuration dynamique passé en argument :

```python
vpn_ip = zt.ip_map(cfg).get(cn)  # static fixed-IP map wins if present
...
resp = zt.api(cfg, "/v1/session/open", {"cn": cn, "serial": env["serial"], "src_ip": env["src_ip"]})
decision = str(resp.get("decision", "")).lower()
vpn_ip = resp.get("vpn_ip") or vpn_ip
...
fh.write(f"ifconfig-push {vpn_ip} {netmask}\n")
```

`vpn/zt/ip-map.csv` (déployé dans `/etc/openvpn/zt/ip-map.csv`) contient la correspondance CN → IP, par exemple `alice@lab.local,10.8.0.10`. L'**IP VPN fixe par identité** permet au pare-feu d'écrire des règles par identité.

### 5.3 `client-disconnect.py`
Appelle `POST /v1/session/close` (le PDP retire les éléments nftables de la session) et journalise les compteurs de la session. Il renvoie toujours 0 pour ne jamais bloquer la fermeture.

## 6. Coupure d'une session (depuis le PDP)

`POST /v1/session/{cn}/kill` (et la révocation `POST /v1/cert/{serial}/revoke`) coupent le tunnel sans shell distant : le PDP exécute

```
ssh -i <clé> ztpdp@zt-gw sudo /usr/local/sbin/ztpdp-nft kill <cn>
```

Sur la passerelle, la clé SSH du compte `ztpdp` a pour commande forcée `ztpdp-ssh`, qui n'accepte que `sudo /usr/local/sbin/ztpdp-nft ...`. L'action `kill` de `ztpdp-nft` valide le CN puis l'envoie à l'interface de management locale :

```bash
printf 'kill %s\n' "$2" | nc -w 1 127.0.0.1 7505
```

## 7. Pare-feu : protection de l'hôte VPN (`firewall/gw-input.nft`)

Inclus par `/etc/nftables.conf` ; les règles portent sur les adresses et non sur les noms d'interfaces. Extrait :

```nft
table inet zt_input {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type echo-request limit rate 5/second burst 10 packets accept
    ip saddr 192.168.100.0/24 udp dport 1194 limit rate 50/second burst 100 packets accept
    ip saddr 10.10.99.0/24 tcp dport 22 accept
    ip saddr 10.0.2.0/24 tcp dport 22 accept      # NAT Vagrant (provisionnement)
    ip saddr { 10.10.10.0/24, ... } udp dport 123 accept   # NTP du labo
    ip saddr 127.0.0.1 tcp dport 7505 accept
    log prefix "GW-IN-DROP " level info limit rate 5/second
    counter
  }
}
```

## 8. Durcissement OpenVPN

- `tls-crypt` : les paquets sans HMAC valide sont ignorés (scan, DoS, fingerprinting).
- TLS 1.3 uniquement, ECDHE P-256, AES-256-GCM pour les données.
- Pas de compression (`allow-compression no`, évite VORACLE).
- Processus sous `user nobody` / `group nogroup` ; unité systemd fournie par le paquet, sans surcharge de durcissement.
- Pas de `client-to-client` ; routes /32 uniquement.
- Interface de management liée à 127.0.0.1.
- `openvpn.log` (y compris les lignes `ZT-HOOK`) est collecté par l'agent Wazuh de zt-gw.

## 9. Tests VPN

| Test | Scénario | Résultat |
|---|---|---|
| Connexion avec certificat valide | — | Tunnel OK, IP fixe 10.8.0.10 pour alice |
| Sans certificat | S1 | Refus (handshake) |
| Certificat d'une autre CA | S2 | Refus (handshake) |
| Certificat révoqué | S3 | Refus (`crl-verify`) |
| Certificat expiré | S4 | Refus |
| Scan UDP de la passerelle | S5 | Aucune réponse (`tls-crypt`) |
| Flood UDP (hping3) | S6 | Paquets ignorés (`tls-crypt` + `limit rate`), service stable |
| Fausse passerelle (MITM) | S9 | Le client refuse le faux serveur (certificat hors chaîne de CA) |
| PDP arrêté | S10 | Connexion refusée (fail-closed) |

Les scénarios S1–S6, S9 et S10 sont exécutés par `tests/run-m2.sh` (preuves dans `tests/evidence/`). Le refus d'un certificat portant un mauvais EKU (`remote-cert-tls client`) est configuré mais n'a pas été testé.

## 10. Mesure de performance

`tests/perf/perf.sh` (lancé depuis l'hôte) compare trois chemins avec iperf3 (TCP, 4 flux, 10 s, médiane de 3 essais) : lien direct client-lin → zt-gw, tunnel OpenVPN seul, et chemin Zero Trust complet (tunnel → nftables → web-app). Il mesure aussi le RTT, le temps de connexion OpenVPN, la latence de décision du PDP et la charge CPU de la passerelle.

| Mesure (21 nov. 2026) | Valeur |
|---|---:|
| Lien direct | 3859 Mbit/s |
| Tunnel OpenVPN | 312 Mbit/s |
| Chemin ZT complet | 32,3 Mbit/s |
| Connexion OpenVPN (mTLS + hooks + PDP + règle) | 1,28 s |
| Décision PDP (médiane) | 20,8 ms |

Le débit est limité par le cœur de la passerelle qui porte le chiffrement OpenVPN en espace utilisateur, le routage et la copie du trafic vers le capteur ; détails dans `tests/reports/perf.md`.
