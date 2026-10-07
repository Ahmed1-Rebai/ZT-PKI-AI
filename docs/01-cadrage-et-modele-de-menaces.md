# 01 — Cadrage et modèle de menaces

## 1. Contexte

Le modèle de sécurité périmétrique (« château fort ») est obsolète : télétravail, cloud, BYOD, mouvements latéraux après compromission. Le **Zero Trust** (NIST SP 800-207) supprime la confiance implicite liée à la localisation réseau : chaque demande d'accès est **authentifiée, autorisée et évaluée en continu**.

## 2. Problématique

> Dans quelle mesure l'intégration d'une détection d'anomalies par IA dans la boucle de décision d'une architecture Zero Trust fondée sur PKI et VPN permet-elle de **détecter plus tôt** et de **contenir automatiquement** des comportements malveillants, par rapport à une architecture Zero Trust statique ?

### Hypothèses de recherche
- **H1** : une authentification mutuelle par certificats élimine les accès non autorisés au niveau transport.
- **H2** : la micro-segmentation dynamique limite le mouvement latéral d'un client compromis.
- **H3** : un score de confiance alimenté par l'IA réduit le temps de confinement (TTQ) par rapport à une politique statique.
- **H4** : le surcoût (latence, débit, ressources) reste acceptable.

## 3. Objectifs

### Objectif général
Concevoir, déployer et évaluer une architecture Zero Trust opérationnelle intégrant PKI, VPN et IA.

### Objectifs spécifiques (SMART)
| ID | Objectif | Mesure |
|---|---|---|
| O1 | PKI à 2 niveaux avec révocation (CRL + OCSP) | Émission/révocation testées |
| O2 | VPN mTLS TLS 1.3 avec contrôle d'accès par PDP | 0 connexion sans cert valide |
| O3 | Micro-segmentation dynamique avec TTL | Règles créées/supprimées automatiquement |
| O4 | Moteur IA multi-modèles sur flux réseau | F1 ≥ 0,95 ; FPR ≤ 2 % |
| O5 | Réponse automatique (réduction, quarantaine, révocation) | TTQ ≤ 15 s |
| O6 | Supervision centralisée et traçabilité | 100 % des décisions journalisées |
| O7 | Évaluation par scénarios ATT&CK | Matrice de tests complète |

## 4. Périmètre

**Inclus** : PKI, VPN d'accès distant, gateway/pare-feu, PDP, détection IA, SIEM, applications de démonstration, scénarios d'attaque en lab.

**Exclus** : haute disponibilité de production, HSM matériel (en extension), conformité certifiée, ZTNA cloud commercial, protection endpoint (EDR) complète.

## 5. Acteurs

| Acteur | Description | Niveau de confiance initial |
|---|---|---|
| Employé | Accès à l'application métier | Moyen |
| Administrateur | Accès SSH/administration | Faible par défaut, élevé après posture + score |
| Prestataire | Accès restreint à une seule application | Faible |
| Appareil géré | Machine avec cert machine + posture | Moyen |
| Attaquant externe | Aucun cert, scan, DoS | Nul |
| Attaquant interne / client compromis | Cert valide mais comportement malveillant | À détecter par l'IA |

## 6. Exigences

### Fonctionnelles
- **EF1** Émettre, renouveler, révoquer des certificats (utilisateur, machine, service).
- **EF2** Authentifier mutuellement client et gateway (mTLS).
- **EF3** Décider l'accès selon identité, appareil, contexte, score de confiance.
- **EF4** Appliquer des règles réseau dynamiques à durée limitée.
- **EF5** Collecter les flux, calculer des features, scorer en quasi temps réel.
- **EF6** Réagir automatiquement selon des seuils (réduire, isoler, révoquer).
- **EF7** Journaliser toute décision (audit) et alerter.

### Non fonctionnelles
- **ENF1** Sécurité : TLS ≥ 1.3, clés ECDSA, pas de secrets en clair dans le dépôt.
- **ENF2** Performance : décision d'accès < 500 ms ; inférence < 1 s/flux.
- **ENF3** Reproductibilité : déploiement scripté (Docker Compose / Ansible).
- **ENF4** Fail-closed : en cas de panne du PDP, l'accès est refusé.
- **ENF5** Traçabilité et horodatage cohérent (NTP).

## 7. Actifs à protéger

| Actif | Valeur | Menace principale |
|---|---|---|
| Clé privée Root CA | Critique | Vol / compromission |
| Clé Issuing CA | Critique | Émission frauduleuse |
| Application et BD métier | Élevée | Exfiltration, intrusion |
| Gateway VPN / PEP | Élevée | Contournement, DoS |
| PDP et modèles IA | Élevée | Manipulation, empoisonnement |
| Logs / SIEM | Moyenne | Altération |

## 8. Modèle de menaces (STRIDE)

| Composant | Menace | Catégorie | Contre-mesure |
|---|---|---|---|
| VPN | Usurpation d'identité (cert volé) | **S**poofing | Certificats courts, révocation, liaison appareil, posture, détection comportementale |
| VPN | Attaque MITM / fausse CA | **S**/**T** | Chaîne épinglée, `remote-cert-tls`, `tls-crypt` |
| Gateway | Scan et DoS UDP non authentifié | **D**oS | `tls-crypt`, rate-limit nftables, drop par défaut |
| PDP | Altération des décisions | **T**ampering | mTLS PDP↔PEP, signatures, journal immuable |
| Logs | Effacement des traces | **R**epudiation | Envoi vers SIEM, WORM/forwarding temps réel |
| Flux | Écoute | **I**nfo disclosure | Tunnel TLS 1.3, mTLS interne |
| Modèle IA | Empoisonnement / évasion | **T**/**E** | Données d'entraînement contrôlées, ensemble de modèles, règles Suricata en complément |
| Client | Élévation de privilège / mouvement latéral | **E**oP | Micro-segmentation, moindre privilège, TTL |
| CA | Émission non autorisée | **E**oP | Root offline, `pathlen:0`, journal d'émission, contrôle double |

## 9. Référentiels

- NIST SP 800-207 *Zero Trust Architecture*
- NIST SP 800-53 (AC, IA, SC, SI), NIST CSF 2.0
- CISA *Zero Trust Maturity Model*
- ANSSI : recommandations TLS et IPsec/VPN, guide de segmentation
- ISO/IEC 27001:2022 (A.5.15, A.8.20, A.8.22, A.8.16)
- MITRE ATT&CK (Enterprise), MITRE D3FEND
- RFC 5280 (X.509), RFC 6960 (OCSP), RFC 8446 (TLS 1.3)
