# siem/

Wazuh decoders, correlation rules and dashboards (see [docs/08](../docs/08-supervision-siem.md)).

```
siem/
├── ossec-agent.conf        # log collection (localfile blocks)
├── rules/zt_rules.xml      # custom correlation rules
├── active-response/        # zt-quarantine.sh (optional)
└── dashboards/             # exported dashboard JSON
```

Dashboards: Zero Trust view, PKI, network, AI, incident timeline.
