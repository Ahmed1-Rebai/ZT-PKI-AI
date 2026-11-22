# firewall/

nftables rulesets for the gateway (see [docs/05 §7](../docs/05-vpn.md) and [docs/06 §6](../docs/06-zero-trust-pdp-pep.md)).

```
firewall/
├── nftables.conf       # main ruleset: deny-by-default forward chain + dynamic sets; includes the input chain
├── gw-input.nft        # gateway host protection (input chain)
├── ztpdp-nft           # restricted helper the PDP runs via sudo: allow | quarantine | clear | kill
└── ztpdp-ssh           # forced command of the ztpdp SSH key: only `sudo /usr/local/sbin/ztpdp-nft ...`
```

Deployed by `infra/ansible/roles/gateway` as:

| repo file | target on `zt-gw` |
|---|---|
| `nftables.conf` | `/etc/nftables.conf` |
| `gw-input.nft`  | `/etc/nftables.d/gw-input.nft` (included by `/etc/nftables.conf`) |
| `ztpdp-nft`     | `/usr/local/sbin/ztpdp-nft` (sudoers entry for the `ztpdp` user) |
| `ztpdp-ssh`     | `/usr/local/sbin/ztpdp-ssh` (forced command for the PDP's SSH key) |

Dynamic set elements (`allow_web`, `allow_ssh`, `quarantine`) are
populated at runtime by the PDP (`pdp/enforce.py` -> `ssh ztpdp@zt-gw` -> `ztpdp-nft`)
with a timeout; without a PDP decision the sets are empty and a connected client
reaches only the PDP posture channel (deny-by-default).

Test syntax before loading: `sudo nft -c -f firewall/nftables.conf` (from the repo root).
