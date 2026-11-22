# 09 — Tests, scénarios d'attaque et évaluation

> Toutes les attaques sont jouées depuis `client-lin` (192.168.100.11 dans `zt-untrust`, 10.8.0.10 dans le tunnel d'alice), à l'intérieur du lab isolé. Il n'y a pas de machine attaquante séparée.

## 1. Stratégie de test

| Niveau | Objet | Outils |
|---|---|---|
| Unitaire | Politique Rego, score de confiance, API du PDP, schéma et scoring IA, intégrité des modèles | `opa test` (`pdp/policies/authz_test.rego`), `pytest` (`pdp/tests`, `ai/tests`) |
| Intégration | Hooks VPN ↔ PDP ↔ nftables | `vpn/scripts/verify.sh` (9/9) |
| Système / sécurité | 12 scénarios d'attaque depuis `client-lin` | `tests/run-m2.sh`, `tests/run-redteam.sh` (openvpn, nmap, hping3, ssh, curl) |
| Comparaison | Configurations A/B/C/D | `tests/abcd/` |
| Performance | Débit, RTT, latence du PDP, temps de connexion | `tests/perf/` (iperf3, ping) |
| ML | Qualité des modèles sur CIC-IDS2017 | `ai/train.py` → `ai/reports/metrics.md` |

Depuis l'hôte : `cd infra && make scenarios`, `make abcd`, `make perf`.

## 2. Matrice des scénarios

| ID | Scénario | MITRE ATT&CK | Contrôle testé | Script | Résultat | Date |
|---|---|---|---|---|---|---|
| **S1** | Connexion sans certificat | T1133 | mTLS obligatoire | `run-m2.sh` | Refus au handshake | 2026-11-21 |
| **S2** | Certificat d'une autre CA | T1553 | Chaîne de confiance | `run-m2.sh` | Refus, chaîne non construite | 2026-11-21 |
| **S3** | Certificat révoqué | T1078 | CRL (`crl-verify`) | `run-m2.sh` | `certificate revoked`, refus en moins de 60 s | 2026-10-10 (10/10) |
| **S4** | Certificat expiré | T1078 | Validité X.509 | `run-m2.sh` | Refus (`notAfter` dépassé) | 2026-11-21 |
| **S5** | Scan de la gateway (`nmap`) | T1046 | `tls-crypt` + politique `drop` | `run-m2.sh` | 1024 ports TCP filtrés, 1194/udp muet | 2026-10-10 (10/10) |
| **S6** | Flood UDP sur le port VPN (`hping3`) | T1498 | `tls-crypt` + limite 50 paquets/s | `run-m2.sh` | 600 428 paquets, 0 réponse, service stable | 2026-10-10 (10/10) |
| **S7** | SSH hors rôle vers `web-app` | T1021 | Micro-segmentation par rôle | `run-redteam.sh` | Drop + log `ZT-DROP` | 2026-11-21 |
| **S8** | Certificat volé sur un poste non conforme | T1078 | Posture → quarantaine | `run-redteam.sh` | Session en quarantaine, proxy injoignable | 2026-11-21 |
| **S9** | Fausse gateway (MITM) | T1557 | `verify-x509-name`, `remote-cert-tls server` | `run-m2.sh` | Le client refuse de se connecter | 2026-11-21 |
| **S10** | PDP arrêté | — | Fail-closed (`PDP_ENFORCE=1`) | `run-m2.sh` | `deny pdp-unreachable`, aucun tunnel | 2026-11-21 |
| **S11** | Altération de `nftables.conf` | T1562.004 | FIM Wazuh | `run-redteam.sh` | Alerte règle 100160 en quelques secondes | 2026-11-21 |
| **S12** | Modèle IA altéré | ATLAS AML.T0020 | Manifeste SHA-256 (`ai/registry.py`) | `run-redteam.sh` | Modèle refusé au chargement | 2026-11-21 |

Le plan de test initial comptait 17 scénarios ; cinq ont été abandonnés (scan interne, force brute SSH, exfiltration, tunnel DNS, évasion lente) et les douze retenus ont été renumérotés de S1 à S8. Les fiches détaillées et les preuves sont dans [`tests/scenarios/`](../tests/scenarios/README.md) et `tests/evidence/<scénario>/`.

## 3. Procédures détaillées (exemples)

### S3 — Révocation (`run-m2.sh s3`)
1. Révocation d'alice sur `sub-ca` : `pki/scripts/revoke.sh pki/sub/certs/alice.crt keyCompromise`, puis `gencrl.sh`.
2. Copie de la nouvelle CRL sur `zt-gw` (`/etc/openvpn/server/crl.pem`, relue par `crl-verify`).
3. Reconnexion depuis `client-lin` → `VERIFY ERROR: ... certificate revoked`.
4. Le script réémet ensuite un certificat pour alice et restaure le lab.

Preuves : `revoke.txt`, `crl.pem`, `timing.txt`, `server.log`.

### S8 — Certificat volé sur un poste non conforme (`run-redteam.sh s8`)
1. Sur `client-lin`, le marqueur `/etc/zt-client/managed` est retiré et `ufw` désactivé.
2. L'agent de posture envoie son rapport au PDP (mTLS) ; le score de l'appareil baisse.
3. Le PDP place la session en quarantaine : l'adresse 10.8.0.10 passe dans le set `quarantine` de `zt-gw`, seul le canal de posture reste joignable.
4. `curl` vers le reverse proxy échoue (`proxy_http_code=000`) ; le script remet ensuite le poste en conformité.

### S10 — PDP arrêté (`run-m2.sh s10`)
Avec `PDP_ENFORCE=1`, le hook `tls-verify` ne joint plus le PDP et refuse : `{"event":"tls-verify","decision":"deny","reason":"pdp-unreachable"}` ; le client échoue au handshake.

## 4. Métriques collectées

| Catégorie | Métrique | Source |
|---|---|---|
| Sécurité | Verdict de chaque scénario (refus, drop, quarantaine, alerte) | `tests/evidence/` |
| Exposition | Services joignables depuis le tunnel d'un employé, par configuration | `tests/abcd/probe.sh` |
| Détection | F1, FPR, ROC-AUC, latence par flux (CIC-IDS2017) | `ai/reports/metrics.md` |
| Réactivité | Décision du PDP, connexion OpenVPN, boucle IA → PDP → PEP (événement simulé) | `tests/perf/perf.sh`, `TODO.md` (M5) |
| Performance | Débit iperf3, RTT, CPU de la gateway | `tests/perf/` |

## 5. Comparaison A/B/C/D

| Configuration | Description |
|---|---|
| **A** | VPN + PKI, le pool VPN joint toutes les zones (VPN de périmètre) |
| **B** | Tunnel de A + règles par rôle permanentes ; PDP arrêté |
| **C** | PDP dynamique : décision à la connexion, posture, règles avec TTL ; IA arrêtée |
| **D** | C + moteur IA dans la boucle (état normal du lab) |

`tests/abcd/set-config.sh A|B|C|D` bascule le lab ; `run-all.sh` mesure la surface exposée dans chaque configuration (une connexion par service depuis le tunnel d'alice, sans scan) ; `attack-abcd.sh` rejoue S7 et S8 dans chaque configuration ; `tests/perf/perf-abcd.sh` mesure le débit sur le même chemin.

Résultats du 2026-11-21 ([`tests/reports/results.md`](../tests/reports/results.md), analyse dans [`perf.md`](../tests/reports/perf.md)) :

| | A | B | C | D |
|---|---|---|---|---|
| Services joignables (sur 7) | 7 | 2 | 2 | 2 |
| Violations Zero Trust | 5 | 0 | 0 | 0 |
| Droits limités dans le temps | non | non | oui (TTL) | oui (TTL) |
| S7 — SSH hors rôle | EXPOSÉ | BLOQUÉ | BLOQUÉ | BLOQUÉ |
| S8 — certificat volé, poste non conforme | AUTORISÉ | AUTORISÉ | QUARANTAINE | QUARANTAINE |
| Débit, même chemin (Mbit/s) | 27,3 | 28,6 | 35,0 | 32,5 |

Les écarts de débit entre A, B, C et D restent dans le bruit de mesure : les contrôles Zero Trust n'ajoutent pas de surcoût mesurable. D sans le miroir de trafic atteint 70,8 Mbit/s : c'est la copie logicielle `tc mirred` sur la gateway qui coûte environ 54 %. Autres mesures : décision du PDP 20,8 ms (médiane), connexion OpenVPN 1,28 s, débit brut 3 859 Mbit/s, tunnel 312 Mbit/s, chemin Zero Trust complet 32,3 Mbit/s.

## 6. Automatisation

```
tests/
├── run-m2.sh          # S1–S6, S9, S10 (scénarios à la connexion)
├── run-redteam.sh     # S7, S8, S11, S12 (scénarios après connexion)
├── scenarios/         # une fiche .md par scénario
├── evidence/          # preuves brutes par scénario
├── abcd/              # set-config.sh, probe.sh, attack-abcd.sh, run-all.sh
├── perf/              # perf.sh, perf-abcd.sh
└── reports/           # JSON, make_report.py → results.md + charts/, perf.md
```

Chaque scénario rend un verdict automatique (PASS / FAIL / SKIP) et écrit ses preuves dans `tests/evidence/<scénario>/`.

## 7. Critères d'acceptation

- [x] S1–S4, S9 : 100 % de refus.
- [x] S5, S6 : gateway stable, aucun port TCP visible, 1194/udp muet.
- [x] S7 : aucun flux hors rôle accepté (B, C, D).
- [x] S8 : poste non conforme mis en quarantaine (C, D).
- [x] S10 : fail-closed vérifié.
- [x] S11 : alerte FIM dans Wazuh ; S12 : modèle altéré refusé.
- [x] FPR ≤ 2 % et F1 ≥ 0,95 sur le test CIC-IDS2017 (0,16 %, 0,9943).
- [x] Surcoût des contrôles Zero Trust ≤ 15 % (aucun surcoût mesurable).
- [x] Décision du PDP ≤ 500 ms (20,8 ms).

## 8. Gabarit de fiche de test

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
| Remarques | |
