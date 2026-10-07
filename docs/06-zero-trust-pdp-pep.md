# 06 — Moteur Zero Trust : PDP, politique, PEP

## 1. Responsabilités

| Élément | Rôle |
|---|---|
| **PDP** (Policy Decision Point) | Évalue chaque demande : identité + appareil + contexte + anomalie |
| **PEP** (Policy Enforcement Point) | Applique la décision : OpenVPN, nftables, reverse proxy |
| **Store** (Redis) | Sessions, scores, liste de révocation, état de posture |

## 2. Modèle de rôles et ressources

| Rôle | Ressources autorisées | Score minimum |
|---|---|---|
| `employee` | Reverse proxy `10.10.10.10:443` | 60 |
| `admin` | Reverse proxy + SSH `10.10.20.10:22` | 85 |
| `contractor` | Reverse proxy, chemin `/portal/*` seulement | 70 |
| `quarantine` | Portail de remédiation `10.10.99.30:443` | — |

`pdp/policies/data.json`
```json
{
  "roles": {
    "employee":   {"min_score": 60, "resources": [{"dst": "10.10.10.10", "port": 443}]},
    "admin":      {"min_score": 85, "resources": [
                    {"dst": "10.10.10.10", "port": 443},
                    {"dst": "10.10.20.10", "port": 22}]},
    "contractor": {"min_score": 70, "resources": [{"dst": "10.10.10.10", "port": 443}]}
  }
}
```

## 3. Politique en Rego (OPA)

`pdp/policies/authz.rego`
```rego
package zt.authz
import rego.v1

default allow := false

allow if {
    input.identity.cert_valid
    not input.identity.revoked
    input.device.posture_ok
    input.trust_score >= data.roles[input.identity.role].min_score
}

# Ressources autorisées pour la session
allowed_resources contains r if {
    allow
    some r in data.roles[input.identity.role].resources
}

# Niveau de réponse selon le score
tier := "full"       if input.trust_score >= 80
tier := "restricted" if { input.trust_score >= 50; input.trust_score < 80 }
tier := "quarantine" if { input.trust_score >= 20; input.trust_score < 50 }
tier := "revoke"     if input.trust_score < 20
```

Tests unitaires de politique : `opa test pdp/policies -v`.

## 4. Score de confiance

```
TrustScore = 100 × ( w_i·I + w_d·D + w_c·C + w_a·(1 − A) )
w_i = 0.30   w_d = 0.25   w_c = 0.15   w_a = 0.30
```

| Facteur | Calcul | Valeur ∈ [0,1] |
|---|---|---|
| **I** Identité | Cert valide + non révoqué + OCSP good + âge du cert | 1 si tout OK, 0 sinon |
| **D** Appareil | Posture : OS à jour, pare-feu, disque chiffré, AV, empreinte attendue | Proportion de critères respectés |
| **C** Contexte | Heure usuelle, IP source connue, géographie, fréquence de connexions | Écart à la norme de l'utilisateur |
| **A** Anomalie | Score du moteur IA (0 normal → 1 très anormal), lissé | Moyenne mobile exponentielle |

```python
# pdp/trust.py
from dataclasses import dataclass

W = dict(identity=0.30, device=0.25, context=0.15, anomaly=0.30)

@dataclass
class Signals:
    identity: float
    device: float
    context: float
    anomaly: float          # 0 = normal, 1 = très anormal

def trust_score(s: Signals) -> float:
    raw = (W["identity"] * s.identity +
           W["device"]   * s.device +
           W["context"]  * s.context +
           W["anomaly"]  * (1.0 - s.anomaly))
    return round(100 * raw, 1)

def ema(prev: float, new: float, alpha: float = 0.4) -> float:
    return alpha * new + (1 - alpha) * prev
```

> Règle de **plancher** : si l'identité = 0 (cert invalide/révoqué) ou si l'anomalie > 0,9 sur une signature Suricata critique, le score est forcé à 0 quel que soit le reste (pas de compensation).

## 5. API du PDP (FastAPI)

| Méthode | Endpoint | Appelant | Fonction |
|---|---|---|---|
| POST | `/v1/authenticate` | Hook `tls-verify` | Valide identité + OCSP, décision initiale |
| POST | `/v1/session/open` | Hook `client-connect` | Crée la session, IP fixe, règles nft |
| POST | `/v1/session/close` | Hook `client-disconnect` | Nettoie |
| POST | `/v1/posture` | Agent client | Rapport de posture signé |
| POST | `/v1/events` | Moteur IA / Suricata | Reçoit score d'anomalie / alerte |
| POST | `/v1/session/{cn}/kill` | Admin / PDP | Coupe la session |
| POST | `/v1/cert/{serial}/revoke` | PDP / admin | Révoque + régénère CRL |
| GET | `/v1/sessions` | Admin | Liste des sessions et scores |

```python
# pdp/main.py (squelette)
import json, time, httpx, redis
from fastapi import FastAPI
from pydantic import BaseModel
from trust import Signals, trust_score, ema
import enforce                         # wrapper nftables / management OpenVPN

app = FastAPI(title="ZT PDP")
r = redis.from_url("redis://redis:6379/0", decode_responses=True)
OPA = "http://opa:8181/v1/data/zt/authz"

class AuthReq(BaseModel):
    cn: str; serial: str; src_ip: str

def audit(event: str, **kw):
    print(json.dumps({"ts": time.time(), "event": event, **kw}), flush=True)   # → Wazuh

@app.post("/v1/authenticate")
def authenticate(req: AuthReq):
    if r.sismember("revoked", req.serial):
        audit("deny", cn=req.cn, reason="revoked"); return {"decision": "deny"}
    user = json.loads(r.hget("users", req.cn) or "{}")
    if not user:
        audit("deny", cn=req.cn, reason="unknown"); return {"decision": "deny"}
    posture = float(r.hget(f"posture:{req.cn}", "score") or 0.5)
    sig = Signals(identity=1.0, device=posture, context=0.8, anomaly=0.0)
    score = trust_score(sig)
    q = {"input": {"identity": {"cert_valid": True, "revoked": False, "role": user["role"]},
                   "device": {"posture_ok": posture >= 0.6}, "trust_score": score}}
    ok = httpx.post(OPA, json=q, timeout=1).json()["result"]["allow"]
    audit("authenticate", cn=req.cn, score=score, decision="allow" if ok else "deny")
    return {"decision": "allow" if ok else "deny", "score": score}

class Event(BaseModel):
    cn: str; anomaly: float; source: str; detail: dict = {}

@app.post("/v1/events")
def event(e: Event):
    prev = float(r.hget(f"score:{e.cn}", "anomaly") or 0.0)
    a = ema(prev, e.anomaly)
    r.hset(f"score:{e.cn}", mapping={"anomaly": a, "ts": time.time()})
    sig = Signals(identity=1.0, device=float(r.hget(f"posture:{e.cn}", "score") or 0.5),
                  context=0.8, anomaly=a)
    score = trust_score(sig)
    tier = httpx.post(OPA, json={"input": {"trust_score": score}}, timeout=1).json()["result"]["tier"]
    enforce.apply(e.cn, tier)
    audit("rescore", cn=e.cn, score=score, tier=tier, source=e.source, detail=e.detail)
    return {"score": score, "tier": tier}
```

## 6. Enforcement : nftables dynamique

### Ruleset de base — `firewall/nftables.conf`
```nft
table inet zt {
  # Éléments à durée de vie limitée : (src VPN) . (dst) . (port)
  set allow_web   { type ipv4_addr; flags timeout; }
  set allow_ssh   { type ipv4_addr; flags timeout; }
  set allow_remed { type ipv4_addr; flags timeout; }
  set quarantine  { type ipv4_addr; flags timeout; }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept
    ct state invalid drop

    # 1. Quarantaine prioritaire
    ip saddr @quarantine ip daddr 10.10.99.30 tcp dport 443 accept
    ip saddr @quarantine log prefix "ZT-QUAR " drop

    # 2. Droits par rôle (alimentés par le PDP)
    ip saddr @allow_web  ip daddr 10.10.10.10 tcp dport 443 accept
    ip saddr @allow_ssh  ip daddr 10.10.20.10 tcp dport 22  accept

    # 3. Flux serveur à serveur (explicites)
    ip saddr 10.10.10.10 ip daddr 10.10.20.10 tcp dport 8080 accept   # proxy → app
    ip saddr 10.10.20.10 ip daddr 10.10.30.10 tcp dport 5432 accept   # app → DB

    # 4. Tout le reste est journalisé et rejeté
    log prefix "ZT-DROP " level info limit rate 10/second
  }
}
```

### Mise à jour dynamique — `pdp/enforce.py`
```python
import subprocess

TTL = {"full": "10m", "restricted": "2m"}

def nft(cmd: str):
    subprocess.run(["nft"] + cmd.split(), check=True)

def open_session(vpn_ip: str, role: str, tier: str = "full"):
    ttl = TTL.get(tier, "2m")
    nft(f"add element inet zt allow_web {{ {vpn_ip} timeout {ttl} }}")
    if role == "admin" and tier == "full":
        nft(f"add element inet zt allow_ssh {{ {vpn_ip} timeout {ttl} }}")

def quarantine(vpn_ip: str):
    for s in ("allow_web", "allow_ssh"):
        subprocess.run(["nft", "delete", "element", "inet", "zt", s, f"{{ {vpn_ip} }}"])
    nft(f"add element inet zt quarantine {{ {vpn_ip} timeout 30m }}")

def kill(cn: str):
    subprocess.run(f'echo "kill {cn}" | nc -q1 127.0.0.1 7505', shell=True)

def apply(cn: str, tier: str):
    ip = lookup_ip(cn)                 # depuis Redis
    if tier == "full":         open_session(ip, role_of(cn), "full")
    elif tier == "restricted": open_session(ip, "employee", "restricted")
    elif tier == "quarantine": quarantine(ip)
    elif tier == "revoke":     quarantine(ip); kill(cn); revoke_cert(cn)
```
Le **TTL court** impose une **ré-autorisation continue** : tant que le score reste bon, le PDP renouvelle l'élément avant expiration ; si le PDP tombe, les droits expirent seuls (fail-closed).

## 7. Second niveau : application (reverse proxy mTLS)

Même après le VPN, le proxy exige un certificat client et transmet l'identité à l'application.

```nginx
server {
  listen 10.10.10.10:443 ssl http2;
  server_name app.lab.local;

  ssl_certificate         /etc/nginx/certs/proxy.crt;
  ssl_certificate_key     /etc/nginx/certs/proxy.key;
  ssl_protocols           TLSv1.3;
  ssl_client_certificate  /etc/nginx/certs/ca-chain.crt;
  ssl_verify_client       on;
  ssl_crl                 /etc/nginx/certs/crl.pem;

  location / {
    proxy_pass http://10.10.20.10:8080;
    proxy_set_header X-Client-CN     $ssl_client_s_dn_cn;
    proxy_set_header X-Client-Serial $ssl_client_serial;
  }
  location /portal/ { # contractors
    if ($ssl_client_s_dn_cn !~ "@contractor\.lab\.local$") { return 403; }
    proxy_pass http://10.10.20.10:8080;
  }
}
```

## 8. Agent de posture (client)

```python
# client/posture_agent.py (Linux ; adapter pour Windows via PowerShell/WMI)
import json, platform, subprocess, time, ssl, urllib.request

def checks():
    return {
        "os": platform.platform(),
        "firewall_on": subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout.startswith("Status: active"),
        "disk_encrypted": "crypt" in subprocess.run(["lsblk", "-o", "TYPE"], capture_output=True, text=True).stdout,
        "kernel": platform.release(),
        "ts": int(time.time()),
    }

def score(c):
    items = [c["firewall_on"], c["disk_encrypted"]]
    return sum(items) / len(items)

# envoi en mTLS (cert client = identité) toutes les 60 s vers /v1/posture
```
Le rapport est envoyé **dans le tunnel et sur mTLS** : l'identité est celle du certificat, pas un champ déclaré.

## 9. Journal d'audit (JSON)

```json
{"ts":1759760000.2,"event":"rescore","cn":"alice@lab.local","score":41.5,"tier":"quarantine","source":"ai","detail":{"model":"iforest+ae","top_features":["dst_port_entropy","flows_per_min"]}}
```
Chaque décision est expliquée (modèle, features dominantes) et envoyée au SIEM.

## 10. Tests

| Test | Attendu |
|---|---|
| Employé score 90 → accès proxy | OK |
| Employé → SSH app | Refusé (nft drop) |
| Admin score 70 → SSH | Refusé (seuil 85) |
| Injection d'anomalie 0,9 | Score ↓, quarantaine < 15 s |
| Arrêt du PDP | Règles expirent, plus d'accès |
| Révocation via API | Session coupée, reconnexion refusée |
| `opa test` | Tous verts |
