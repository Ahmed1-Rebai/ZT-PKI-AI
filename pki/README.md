# pki/

OpenSSL configuration and scripts for the two-level PKI (see [docs/04](../docs/04-pki.md)).

```
pki/
├── root/           # Root CA (offline VM): root.cnf, private/, certs/, newcerts/, index.txt, serial, crlnumber
├── sub/            # Issuing CA: sub.cnf, private/, certs/, csr/, crl/, index.txt, serial, crlnumber
└── scripts/        # issue-client.sh, revoke.sh, gencrl.sh, renew.sh
```

> Private keys (`*.key`), PEM material and `inventory.csv` are **never committed** (see repo `.gitignore`).
> Root CA key stays on the offline `root-ca` VM only.
