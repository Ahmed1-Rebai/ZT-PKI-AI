# firewall/

nftables rulesets for the gateway (see [docs/05 §7](../docs/05-vpn.md) and [docs/06 §6](../docs/06-zero-trust-pdp-pep.md)).

```
firewall/
├── nftables.conf       # main ruleset: deny-by-default forward chain + dynamic sets; includes the input chain
└── gw-input.nft        # gateway host protection (input chain)
```

Deployed by `infra/ansible/roles/gateway` as:

| repo file | target on `zt-gw` |
|---|---|
| `nftables.conf` | `/etc/nftables.conf` |
| `gw-input.nft`  | `/etc/nftables.d/gw-input.nft` (included by `/etc/nftables.conf`) |

Dynamic set elements (`allow_web`, `allow_ssh`, `quarantine`) are
populated at runtime by the PDP (`pdp/enforce.py`) with a timeout; at M2 the
sets are empty so a connected client reaches nothing (deny-by-default).

Test syntax before loading: `sudo nft -c -f firewall/nftables.conf` (from the repo root).
