# pki/

OpenSSL configuration and scripts for the two-level PKI (see [docs/04](../docs/04-pki.md)).

```
pki/
├── root/           # Root CA (offline VM): root.cnf, private/, certs/, newcerts/, index.txt, serial, crlnumber
├── sub/            # Issuing CA: sub.cnf, private/, certs/, csr/, crl/, index.txt, serial, crlnumber
├── scripts/        # init-root, init-sub, sign-sub, issue-server, issue-client, revoke,
│                   # gencrl, renew, ocsp, refresh-crl (all .sh)
└── systemd/        # zt-crl.service (CRL over HTTP :80), zt-ocsp.service (OCSP :2560)
```

> Private keys (`*.key`), PEM material and `inventory.csv` are **never committed** (see repo `.gitignore`).
> Root CA key stays on the offline `root-ca` VM only.

## Scripts

| Script | Where it runs | What it does |
|---|---|---|
| `init-root.sh` | root-ca (offline) | Root CA dir + encrypted P-384 key + self-signed root cert (10 y) |
| `init-sub.sh` | sub-ca | Issuing CA dir + encrypted P-384 key + CSR |
| `sign-sub.sh <csr>` | root-ca (offline) | Root signs the Issuing CA (`pathlen:0`, 3 y) + builds `ca-chain.crt` |
| `issue-server.sh <CN> <SANs> [ext] [days]` | sub-ca | Server cert; `ext`=`server_cert` or `server_client_cert` (mTLS services) |
| `issue-client.sh <user> [days] [dev]` | sub-ca | Short-lived user cert (`clientAuth`) + inventory row |
| `revoke.sh <cert> [reason]` | sub-ca | Revoke + regenerate CRL |
| `gencrl.sh` | sub-ca | (Re)generate the CRL (24 h validity) and copy it to the HTTP publish dir; called by `revoke.sh` |
| `renew.sh <cert> [days]` | sub-ca | Re-issue a leaf with the same key and CN; profile picked from the EKU |
| `ocsp.sh` | sub-ca | Create the OCSP signer if missing, run the OCSP responder on :2560 (foreground) |
| `refresh-crl.sh` | host | Regenerate the CRL on sub-ca and deploy it to zt-gw and web-proxy (manual, before a demo/test session; no cron) |

The units in `systemd/` are installed by hand on sub-ca: `zt-crl.service` serves
`/home/vagrant/crlpub` on port 80 (`http://10.10.99.5/crl/sub.crl`), `zt-ocsp.service`
runs the OCSP responder (restart it after a revocation: it reads `index.txt` at start-up).

All scripts resolve the PKI base as the repo root, or honor `PKI_BASE=<dir>`.
Validated end-to-end on the host (chain verify + revocation via CRL).

## Runbook (CA ceremony)

```bash
# --- on root-ca (bring up with temporary NAT, then keep offline) ---
vagrant ssh root-ca
cd /path/to/repo && pki/scripts/init-root.sh          # type a strong passphrase

# --- on sub-ca ---
vagrant ssh sub-ca
cd /path/to/repo && pki/scripts/init-sub.sh            # creates pki/sub/csr/sub.csr

# --- move pki/sub/csr/sub.csr to root-ca (USB / scp via host), then on root-ca: ---
pki/scripts/sign-sub.sh pki/sub/csr/sub.csr            # -> sub.crt + ca-chain.crt

# --- move sub.crt + ca-chain.crt back to sub-ca/pki/sub/certs/, then issue leaves ---
pki/scripts/issue-server.sh vpn-gw.lab.local vpn-gw.lab.local,IP:192.168.100.1 server_cert 365
pki/scripts/issue-server.sh pdp.lab.local    pdp.lab.local,IP:10.10.99.10 server_client_cert 365
pki/scripts/issue-client.sh alice 7 laptop-01
pki/scripts/gencrl.sh

# then power root-ca off and keep it offline (detach NIC).
```

> The Root CA and Issuing CA private keys are AES-256 encrypted, so each `init`/
> `sign` step prompts for a passphrase — this is intentional and not automated.
