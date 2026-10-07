# 05 — VPN (OpenVPN, authentification mutuelle par certificats)

## 1. Rôle dans l'architecture

Le VPN n'est **pas** un « accès au réseau interne » : il est un **canal chiffré authentifié** dont les droits réseau sont décidés **après coup** par le PDP. Par défaut, un client connecté ne peut rien atteindre.

## 2. Pourquoi OpenVPN ?

| Critère | OpenVPN | WireGuard | strongSwan (IKEv2) |
|---|---|---|---|
| Authentification par X.509 | ✅ natif | ❌ clés brutes | ✅ |
| Hooks / scripts (`tls-verify`, `client-connect`) | ✅ | ❌ | limité |
| Interface de management (kill session) | ✅ | ❌ | partielle |
| Performances | bonnes | excellentes | très bonnes |
| Adapté à une PKI | ✅ | ❌ | ✅ |

WireGuard est conservé pour un **benchmark comparatif** (débit/latence) dans le chapitre performances.

## 3. Configuration serveur — `/etc/openvpn/server/server.conf`

```conf
port 1194
proto udp
dev tun
topology subnet
server 10.8.0.0 255.255.255.0

# PKI
ca       /etc/openvpn/server/ca-chain.crt
cert     /etc/openvpn/server/vpn-gw.crt
key      /etc/openvpn/server/vpn-gw.key
crl-verify /etc/openvpn/server/crl.pem
dh none
ecdh-curve prime256v1

# Durcissement TLS
tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
data-ciphers AES-256-GCM:CHACHA20-POLY1305
tls-crypt /etc/openvpn/server/ta.key        # anti scan/DoS non authentifié
remote-cert-tls client                      # EKU clientAuth obligatoire
verify-client-cert require
reneg-sec 3600

# Intégration Zero Trust
script-security 2
tls-verify        /etc/openvpn/hooks/tls-verify.py
client-connect    /etc/openvpn/hooks/client-connect.py
client-disconnect /etc/openvpn/hooks/client-disconnect.py
management 127.0.0.1 7505

# Aucune route poussée : le PDP décide
# (seulement le DNS interne éventuel)
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
status /var/log/openvpn/status.log 10
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
```

Génération de la clé `tls-crypt` :
```bash
openvpn --genkey secret /etc/openvpn/server/ta.key
```

## 4. Configuration client — `alice.ovpn`

```conf
client
dev tun
proto udp
remote 192.168.100.1 1194
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name vpn-gw.lab.local name
tls-version-min 1.3
data-ciphers AES-256-GCM:CHACHA20-POLY1305
<ca>
-----BEGIN CERTIFICATE-----
...ca-chain...
-----END CERTIFICATE-----
</ca>
<cert>
...alice.crt...
</cert>
<key>
...alice.key...
</key>
<tls-crypt>
...ta.key...
</tls-crypt>
```

## 5. Hooks Zero Trust

### 5.1 `tls-verify.py` — décision à l'authentification
Appelé pour chaque certificat de la chaîne ; on ne décide qu'au niveau 0 (le client). Code de sortie `0` = accepté.

```python
#!/usr/bin/env python3
import os, re, sys, json, ssl, urllib.request

PDP = "https://10.10.99.10:8443/v1/authenticate"
depth, subject = int(sys.argv[1]), sys.argv[2]
if depth != 0:
    sys.exit(0)                       # chaîne déjà validée par OpenVPN

m = re.search(r"CN=([^,/]+)", subject)
payload = {
    "cn": m.group(1) if m else "",
    "serial": os.environ.get("tls_serial_0", ""),
    "src_ip": os.environ.get("untrusted_ip", ""),
}

ctx = ssl.create_default_context(cafile="/etc/openvpn/hooks/ca-chain.crt")
ctx.load_cert_chain("/etc/openvpn/hooks/gw-client.crt", "/etc/openvpn/hooks/gw-client.key")

try:
    req = urllib.request.Request(PDP, json.dumps(payload).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2, context=ctx) as r:
        sys.exit(0 if json.load(r).get("decision") == "allow" else 1)
except Exception:
    sys.exit(1)                       # FAIL-CLOSED
```

### 5.2 `client-connect.py` — IP fixe + ouverture de session
```python
#!/usr/bin/env python3
import os, sys, json, ssl, urllib.request

tmp = sys.argv[1]                     # fichier de config dynamique
cn  = os.environ["common_name"]
payload = {"cn": cn, "serial": os.environ.get("tls_serial_0", ""),
           "src_ip": os.environ.get("trusted_ip", "")}

# ... appel POST /v1/session/open (mTLS, comme ci-dessus)
resp = {"vpn_ip": "10.8.0.10", "decision": "allow"}   # réponse PDP

if resp["decision"] != "allow":
    sys.exit(1)
with open(tmp, "w") as f:
    f.write(f"ifconfig-push {resp['vpn_ip']} 255.255.255.0\n")
sys.exit(0)
```
L'**IP VPN fixe par identité** permet au pare-feu d'écrire des règles basées sur l'identité.

### 5.3 `client-disconnect.py`
Appelle `POST /v1/session/close` : suppression des éléments nftables de la session et journalisation.

## 6. Coupure d'une session (depuis le PDP)

```bash
echo "kill alice@lab.local" | nc -q1 127.0.0.1 7505
```
Via l'API : `POST /v1/session/{cn}/kill`.

## 7. Pare-feu : protection de l'hôte VPN (extrait)

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    iifname "eth0" udp dport 1194 limit rate 50/second burst 100 packets accept
    iifname "eth4" tcp dport 22 ip saddr 10.10.99.0/24 accept     # SSH mgmt
    iifname "eth4" tcp dport 7505 drop
    log prefix "GW-IN-DROP " level info limit rate 5/second
  }
}
```

## 8. Durcissement OpenVPN

- `tls-crypt` : les paquets sans HMAC valide sont ignorés (scan, DoS, fingerprinting).
- Pas de compression (`compress` désactivé → évite VORACLE).
- Service sous `user nobody`, unité systemd avec `ProtectSystem=strict`, `NoNewPrivileges=yes`.
- Aucune route poussée ; pas de `client-to-client`.
- Rotation du `ta.key` documentée.
- Journalisation vers le SIEM (`openvpn.log`, `status.log`).

## 9. Tests VPN

| Test | Attendu |
|---|---|
| Connexion avec cert valide | Tunnel OK, IP fixe attribuée |
| Sans cert / cert d'une autre CA | Refus (handshake) |
| Cert expiré / révoqué | Refus |
| Cert avec mauvais EKU | Refus |
| Paquet UDP sans `tls-crypt` | Ignoré (aucune réponse, `nmap -sU` ne voit rien) |
| PDP arrêté | Connexion refusée (fail-closed) |
| Client connecté sans règle nft | Aucun accès (ping vers 10.10.x.x échoue) |

## 10. Mesure de performance

```bash
# serveur (derrière la gateway)
iperf3 -s
# client via le tunnel
iperf3 -c 10.10.20.10 -t 30 -P 4
ping -c 100 10.10.20.10
```
Comparer : sans VPN / OpenVPN (AES-GCM) / OpenVPN (ChaCha20) / WireGuard. Mesurer aussi le temps de handshake et la charge CPU.
