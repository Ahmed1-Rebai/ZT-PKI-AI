# 06 — Moteur Zero Trust : PDP, politique, PEP

## 1. Responsabilités

| Élément | Rôle |
|---|---|
| **PDP** (Policy Decision Point, zt-pdp 10.10.99.10:8443) | FastAPI : calcule le score de confiance et interroge OPA pour chaque demande (identité, posture de l'appareil, anomalie) |
| **OPA** | Évalue `pdp/policies/authz.rego` avec `data.json` |
| **PEP** (Policy Enforcement Point) | OpenVPN (hooks), nftables sur zt-gw, reverse proxy mTLS |
| **Store** (Redis) | Annuaire, sessions, anomalie lissée, posture, liste de révocation (`zt:revoked`) |

## 2. Modèle de rôles et ressources

| Rôle | Ressources autorisées | Score minimum |
|---|---|---|
| `employee` | Reverse proxy `10.10.10.10:443` | 60 |
| `admin` | Reverse proxy + SSH `10.10.20.10:22` | 85 |
| `contractor` | Reverse proxy ; seul rôle accepté sur `/portal` (contrôle fait par `apps/webapp/app.py`) | 70 |

Le palier quarantaine n'est pas un rôle utilisateur : une session en quarantaine ne peut joindre que le canal de posture du PDP. `data.json` déclare une ressource `10.10.99.30:443` pour ce palier et nftables l'autorise, mais aucun service n'écoute à cette adresse (pas de portail de remédiation).

`pdp/policies/data.json` (annuaire + rôles, source unique pour OPA et pour le PDP) :
```json
{
  "users": {
    "alice@lab.local": {"role": "employee", "vpn_ip": "10.8.0.10"},
    "admin@lab.local": {"role": "admin", "vpn_ip": "10.8.0.11"},
    "carol@lab.local": {"role": "contractor", "vpn_ip": "10.8.0.12"}
  },
  "roles": {
    "employee": {"min_score": 60, "resources": [{"dst": "10.10.10.10", "port": 443}]},
    "admin": {"min_score": 85, "resources": [{"dst": "10.10.10.10", "port": 443}, {"dst": "10.10.20.10", "port": 22}]},
    "contractor": {"min_score": 70, "resources": [{"dst": "10.10.10.10", "port": 443}]},
    "quarantine": {"min_score": 0, "resources": [{"dst": "10.10.99.30", "port": 443}]}
  }
}
```

## 3. Politique en Rego (OPA)

`pdp/policies/authz.rego` distingue l'**admission** dans le tunnel (identité connue, certificat non révoqué) de l'**accès** aux ressources (admission + posture + score minimal du rôle). Le PDP interroge `data.zt.authz.decision`. Extrait :

```rego
default decision := {"allow": false, "admit": false, "tier": "revoke", "reason": "default-deny", "resources": []}

tier := "full" if { input.trust_score >= 80 }
tier := "restricted" if { input.trust_score >= 50; input.trust_score < 80 }
tier := "quarantine" if { input.trust_score >= 20; input.trust_score < 50 }
tier := "revoke" if { input.trust_score < 20 }

admit if {
  role
  input.identity.cert_valid
  not input.identity.revoked
}

allow if {
  admit
  input.device.posture_ok
  input.trust_score >= data.roles[role].min_score
}
```

La posture ne conditionne pas l'admission : sinon un appareil sans rapport de posture ne pourrait jamais ouvrir le tunnel pour l'envoyer. Le PDP en déduit le palier effectivement appliqué (`effective_tier` dans `pdp/main.py`) : non admis → `revoke` ; admis mais refusé (posture ou score insuffisant) → au mieux `quarantine` ; autorisé → palier du score.

Tests de politique : `opa test pdp/policies -v` (`authz_test.rego`, 5 tests).

## 4. Score de confiance

```
TrustScore = 100 × ( 0,30·I + 0,25·D + 0,15·C + 0,30·(1 − A) )
```

| Facteur | Calcul réel |
|---|---|
| **I** Identité | 1 si le CN est dans l'annuaire et que le numéro de série n'est pas dans l'ensemble Redis `zt:revoked`, sinon 0. Le PDP n'interroge pas l'OCSP (la CRL est vérifiée en amont par OpenVPN et nginx). |
| **D** Appareil | Score envoyé par l'agent de posture : moyenne de `firewall_on` (ufw actif) et `managed` (présence du fichier marqueur `/etc/zt-client/managed`). `posture_ok` = D ≥ 0,6. Sans rapport, D = 0 jusqu'à la première attestation. |
| **C** Contexte | Constante 0,8 codée dans `pdp/main.py` ; aucun signal de contexte n'est calculé. |
| **A** Anomalie | Score du moteur IA (0 normal → 1 très anormal), lissé par moyenne mobile exponentielle (α = 0,4). Un événement critique est appliqué sans lissage. |

`pdp/trust.py` (extrait) :
```python
WEIGHTS = {"identity": 0.30, "device": 0.25, "context": 0.15, "anomaly": 0.30}

def trust_score(signals: Signals) -> float:
    identity = _unit(signals.identity)
    anomaly = _unit(signals.anomaly)
    if identity == 0 or (signals.critical_alert and anomaly > 0.9):
        return 0.0
    raw = (WEIGHTS["identity"] * identity + WEIGHTS["device"] * _unit(signals.device)
           + WEIGHTS["context"] * _unit(signals.context) + WEIGHTS["anomaly"] * (1.0 - anomaly))
    return round(100.0 * raw, 1)
```

> Règle de **plancher** : si l'identité vaut 0 (inconnue ou révoquée), ou si le moteur IA signale un événement `critical` avec une anomalie > 0,9, le score est forcé à 0 (pas de compensation par les autres facteurs). L'indicateur `critical` est levé par le moteur IA en cas de rafale : au moins 5 flux à ≥ 0,95 en 10 s. Suricata n'intervient pas dans le score ; ses alertes vont uniquement vers Wazuh.

## 5. API du PDP (FastAPI)

| Méthode | Endpoint | Appelant | Fonction |
|---|---|---|---|
| POST | `/v1/authenticate` | Hook `tls-verify` | Admission dans le tunnel (identité, liste de révocation, politique) |
| POST | `/v1/session/open` | Hook `client-connect` | Crée la session, renvoie l'IP fixe, pose les règles nft du palier |
| POST | `/v1/session/close` | Hook `client-disconnect` | Retire les règles et la session |
| POST | `/v1/posture` | Agent de posture (dans le tunnel) | Enregistre la posture et réévalue la session |
| POST | `/v1/events` | Moteur IA (zt-sensor) | Reçoit un score d'anomalie, réévalue et applique le palier |
| POST | `/v1/session/{cn}/kill` | Opérateur | Retire les règles et coupe le tunnel |
| POST | `/v1/cert/{serial}/revoke` | Opérateur | Ajoute le numéro de série à `zt:revoked` et coupe les sessions ; ne régénère pas la CRL (réponse `"crl_update": "operator-required"`) |
| GET | `/v1/sessions` | Opérateur | Sessions et scores |

Contrôle de l'appelant par réseau source : les endpoints de contrôle n'acceptent que le réseau de management (`10.10.99.0/24`) ; depuis le réseau VPN (`10.8.0.0/24`) seul `/v1/posture` est accepté, et uniquement pour le CN associé à l'IP du tunnel.

Une boucle de renouvellement (toutes les 60 s, `ZT_RENEWAL_INTERVAL`) réévalue chaque session ouverte et ne repose que les règles approuvées par la politique ; si l'évaluation échoue, la règle n'est pas prolongée.

Extrait de `pdp/main.py` (évaluation commune à tous les endpoints) :
```python
def evaluate(cn: str, serial: str, critical: bool = False):
    repo, opa, _ = state()
    user = repo.user(cn)
    revoked = repo.is_revoked(_serial(serial))
    identity = 1.0 if user and not revoked else 0.0
    signals = Signals(identity=identity, device=repo.posture(cn), context=0.8,
                      anomaly=repo.anomaly(cn), critical_alert=critical)
    score = trust_score(signals)
    payload = {"identity": {"cn": cn, "cert_valid": bool(user), "revoked": revoked,
                            "role": user.get("role", "") if user else ""},
               "device": {"posture_ok": signals.device >= 0.6}, "trust_score": score, ...}
    try:
        decision = opa.decide(payload)
    except PolicyError as exc:
        emit("policy_error", cn=cn, reason=str(exc))
        return user, score, {"allow": False, "tier": "revoke", "reason": "policy-unavailable"}
    return user, score, decision
```

OPA injoignable → `revoke` (fail-closed). Une erreur d'application sur la passerelle à l'ouverture de session → refus de la session.

## 6. Enforcement : nftables dynamique

### Ruleset de base — `firewall/nftables.conf`
Extrait :
```nft
include "/etc/nftables.d/gw-input.nft"

table inet zt {
  set allow_web   { type ipv4_addr; flags timeout; }
  set allow_ssh   { type ipv4_addr; flags timeout; }
  set quarantine  { type ipv4_addr; flags timeout; }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop

    # 0. canal de posture : tout client du tunnel peut joindre l'API du PDP
    ip saddr 10.8.0.0/24 ip daddr 10.10.99.10 tcp dport 8443 accept

    # 1. quarantaine prioritaire
    ip saddr @quarantine ip daddr 10.10.99.30 tcp dport 443 accept
    ip saddr @quarantine log prefix "ZT-QUAR " level warn drop

    # 2. droits par rôle (alimentés par le PDP, avec TTL)
    ip saddr @allow_web ip daddr 10.10.10.10 tcp dport 443 accept
    ip saddr @allow_ssh ip daddr 10.10.20.10 tcp dport 22  accept

    # 3. flux serveur à serveur
    ip saddr 10.10.10.10 ip daddr 10.10.20.10 tcp dport 8080 accept   # proxy -> app
    ip saddr 10.10.20.10 ip daddr 10.10.30.10 tcp dport 5432 accept   # app   -> db
    ip saddr 10.10.10.10 ip daddr 10.10.99.20 tcp dport { 1514, 1515 } accept   # agent Wazuh du proxy -> SIEM

    log prefix "ZT-DROP " level info limit rate 10/second
    counter
  }
}
```

La chaîne d'entrée de la passerelle est dans `firewall/gw-input.nft` (voir docs/05 §7).

### Mise à jour dynamique — `pdp/enforce.py` et `ztpdp-nft`
Le PDP ne lance pas `nft` lui-même : il se connecte en SSH au compte `ztpdp` de zt-gw (clé dédiée, clé d'hôte épinglée). La commande forcée `firewall/ztpdp-ssh` n'autorise que `sudo /usr/local/sbin/ztpdp-nft`, qui valide l'action, l'IP (10.8.0.0/24), le rôle et le TTL.

```python
TTL = {"full": "10m", "restricted": "2m", "quarantine": "30m"}

def apply(self, vpn_ip: str, role: str, tier: str) -> None:
    ip = self._ip(vpn_ip)
    if tier == "revoke":
        self._run("clear", ip)
        return
    if tier == "quarantine":
        self._run("quarantine", ip, TTL[tier])
        return
    ...
    self._run("allow", ip, role, TTL[tier])
```

Côté passerelle (`firewall/ztpdp-nft`) :
```bash
allow)
  clear "$2"
  nft add element inet zt allow_web "{ $2 timeout $4 }"
  # SSH is an admin privilege only at the full-trust (10 minute) tier.
  if [[ "$3" == "admin" && "$4" == "10m" ]]; then nft add element inet zt allow_ssh "{ $2 timeout $4 }"; fi
  ;;
quarantine)
  clear "$2"; nft add element inet zt quarantine "{ $2 timeout $3 }"
  ;;
kill)
  printf 'kill %s\n' "$2" | nc -w 1 127.0.0.1 7505
  ;;
```

| Palier | Score | Effet |
|---|---|---|
| `full` | ≥ 80 | `allow_web` (+ `allow_ssh` pour un admin), TTL 10 min |
| `restricted` | 50–79 | `allow_web` seul, TTL 2 min (pas de SSH admin) |
| `quarantine` | 20–49 | `quarantine`, TTL 30 min : seul le canal de posture reste joignable |
| `revoke` | < 20 | toutes les règles de l'IP sont retirées |

Le **TTL court** impose une **ré-autorisation continue** : tant que la politique l'approuve, la boucle de renouvellement repose l'élément avant expiration ; si le PDP tombe, les droits expirent seuls (fail-closed, S10).

## 7. Second niveau : application (reverse proxy mTLS)

Même après le VPN, le proxy (web-proxy, 10.10.10.10:443) exige un certificat client de l'Issuing CA, vérifie la CRL et transmet l'identité certifiée à l'application. Extrait de `apps/proxy/nginx/zt-proxy.conf` :

```nginx
ssl_client_certificate /etc/nginx/zt/ca-chain.crt;
ssl_crl                /etc/nginx/zt/crl.pem;
ssl_verify_client      on;
ssl_verify_depth       3;

proxy_set_header X-Client-CN      $zt_client_cn;
proxy_set_header X-Client-Serial  $ssl_client_serial;
proxy_set_header X-Client-Verify  $ssl_client_verify;

location / {
    proxy_pass http://10.10.20.10:8080;
}
```

`$zt_client_cn` est extrait du DN par une `map` (`apps/proxy/nginx/zt-map.conf`), car `$ssl_client_s_dn_cn` n'existe pas sur le nginx de Debian 12. Le proxy ne décide pas des rôles : la restriction de `/portal` aux prestataires est appliquée par l'application (`apps/webapp/app.py`) à partir du CN transmis et de `apps/webapp/roles.json`.

## 8. Agent de posture (client)

`apps/posture/posture_agent.py` (Linux, client-lin), lancé toutes les 60 s par `zt-posture.timer` :

```python
def checks() -> dict:
    lsblk = _run(["lsblk", "-o", "TYPE"])
    return {
        "os": platform.platform(),
        "kernel": platform.release(),
        "firewall_on": "Status: active" in _run(["ufw", "status"]),
        "managed": os.path.exists(MARKER),
        "disk_encrypted": "crypt" in lsblk,
        "ts": int(time.time()),
    }

def score(c: dict) -> float:
    items = [bool(c["firewall_on"]), bool(c["managed"])]
    return sum(items) / len(items)
```

Le rapport (`score` + `detail`) part **dans le tunnel et sur mTLS** vers `/v1/posture`. Il n'est pas signé : le PDP rattache le rapport au CN à partir de l'IP du tunnel, fixée par OpenVPN selon le certificat, et refuse un rapport pour un autre CN. `disk_encrypted` est transmis dans le détail mais n'entre pas dans le score.

## 9. Journal d'audit (JSON)

Chaque décision est écrite par `pdp/audit.py` sur stdout et dans `/var/log/zt-pdp/audit.jsonl`, collecté par l'agent Wazuh de zt-pdp. Forme d'une réévaluation déclenchée par le moteur IA (valeurs d'exemple) :

```json
{"allow": false, "anomaly": 0.98, "cn": "alice@lab.local", "component": "pdp", "critical": true,
 "detail": {"ae": 0.97, "burst": 5, "dst": "10.10.20.10", "iforest": 0.91, "port": 22, "rf": 0.99},
 "event": "rescore", "score": 0.0, "source": "ai", "tier": "revoke", "ts": 1763740000.123}
```

Le détail reprend la destination et le port du flux, les scores des trois modèles (Isolation Forest, autoencodeur, Random Forest) et la taille de la rafale.

## 10. Tests

| Test | Résultat |
|---|---|
| `opa test pdp/policies -v` | 5 tests : employé autorisé, admin sous le seuil refusé, révoqué toujours refusé, appareil sans posture admis sans accès, rôle inconnu non admis |
| `pytest pdp/tests` | Score et plancher, EMA, quarantaine puis montée de palier par la posture, événement critique → `revoke`, révocation coupant le tunnel, contrôle de l'appelant, écriture du journal d'audit |
| S7 — SSH hors rôle (employé → 10.10.20.10:22) | Refusé (`ZT-DROP`) |
| S8 — certificat volé sur un appareil non conforme | Mis en quarantaine (posture) |
| S10 — PDP arrêté | Connexion refusée (fail-closed) |
| Boucle fermée IA → PDP → nftables | 356 ms (octobre) et 0,43 s (novembre), mesurés avec des événements critiques simulés envoyés par le client du moteur IA, pas avec du trafic réel |
