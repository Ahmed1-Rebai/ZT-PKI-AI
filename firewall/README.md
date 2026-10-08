# firewall/

nftables rulesets for the gateway (see [docs/05 §7](../docs/05-vpn.md) and [docs/06 §6](../docs/06-zero-trust-pdp-pep.md)).

```
firewall/
├── nftables.conf       # base ruleset: deny-by-default forward chain + dynamic sets with timeout
└── gw-input.nft        # gateway host protection (input chain)
```

Dynamic set elements (`allow_web`, `allow_ssh`, `quarantine`) are managed at runtime by the PDP (`pdp/enforce.py`).
