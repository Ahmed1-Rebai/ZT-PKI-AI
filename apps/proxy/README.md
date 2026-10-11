# apps/proxy

Nginx mTLS reverse proxy on the `web-proxy` VM (DMZ `10.10.10.10:443`).

- `nginx/zt-proxy.conf` — requires a client certificate from the lab CA,
  enforces the CRL, forwards the certified `CN`/serial to the app, and proxies
  to `http://10.10.20.10:8080`.
- `sync-pki.sh` — stages `proxy.lab.local.{crt,key}`, `ca-chain.crt` and
  `crl.pem` from the Issuing CA into `apps/proxy/pki/` (git-ignored).
- Material deployed to `/etc/nginx/zt/` with the key `0600`.
