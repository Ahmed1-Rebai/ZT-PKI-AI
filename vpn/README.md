# vpn/

OpenVPN gateway configuration and Zero Trust hooks (see [docs/05](../docs/05-vpn.md)).

```
vpn/
├── server/
│   ├── server.conf       # OpenVPN server (TLS 1.3 mTLS, tls-crypt, crl-verify)
│   └── pki/              # staged certs (git-ignored) — filled by scripts/sync-pki.sh
├── hooks/
│   ├── zt_common.py      # shared helpers (config, PDP client, logging)
│   ├── tls-verify.py     # handshake gate: identity -> PDP decision (fail-closed)
│   ├── client-connect.py # fixed VPN IP per CN + PDP session open
│   ├── client-disconnect.py
│   └── hook.env.example  # deployed to /etc/openvpn/zt/hook.env
├── zt/
│   └── ip-map.csv        # static CN -> VPN IP map (M2; PDP is source of truth at M3)
├── client/
│   ├── client.ovpn.template  # committed template (no embedded keys)
│   └── pki/                  # staged client certs (git-ignored)
└── scripts/
    ├── sync-pki.sh       # fetch PKI material from sub-ca into the staging dirs
    ├── make-client.sh    # render <user>.ovpn from staged material
    ├── deploy.sh         # one-shot: sync + provision gateway + build client profile
    └── verify.sh         # M2 checks (S1/S2/S3/S10 + services); `make vpn-check`
```

> Generated `*.ovpn`, `ta.key` and all private keys are **not committed**.

## Deploy (M2)

From `infra/`:

```bash
make vpn          # sync PKI, provision zt-gw, build alice.ovpn, provision client-lin
```

Or by hand:

```bash
vpn/scripts/sync-pki.sh alice        # sub-ca -> vpn/{server,client}/pki/ (run from repo root)
vagrant provision zt-gw              # installs OpenVPN + nftables, generates ta.key
vpn/scripts/sync-pki.sh alice        # now also fetches ta.key
vpn/scripts/make-client.sh alice     # -> vpn/client/alice.ovpn (deploy to client-lin)
```

## Fail-closed modes

The hooks read `/etc/openvpn/zt/hook.env`:

* `PDP_ENFORCE=0` — **M2 bootstrap**: OpenVPN enforces mTLS + CRL; the hooks only
  log and pin IPs. Used while the PDP (M3) is not built yet.
* `PDP_ENFORCE=1` — **M3+**: every decision comes from the PDP; if it is
  unreachable the connection is denied (ENF4 / S10).

## Operational notes

* **CRL lifetime.** The Issuing CA CRL is valid 24 h. `crl-verify` refuses *every*
  client once it expires (`CRL has expired`). There is no scheduled refresh:
  before a demo or test session run `bash pki/scripts/refresh-crl.sh` from the
  host. It regenerates the CRL on `sub-ca` and installs it on the gateway
  (`/etc/openvpn/server/crl.pem`, re-read on each connection) and on the proxy.
* `docker`/`vagrant` deployment assumes the host has VirtualBox with AMD-V free —
  unload KVM first if it is loaded (`sudo modprobe -r kvm_amd kvm`).

## Verify (M2)

```bash
make vpn-check                 # services + S1/S2 + fail-closed (safe)
bash ../vpn/scripts/verify.sh --full   # also S3 (revoked) + S10
tests/run-m2.sh                # run S1-S6, S9, S10 and write tests/evidence/
```
