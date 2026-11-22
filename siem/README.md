# siem/

Wazuh correlation rules and dashboards (see [docs/08](../docs/08-supervision-siem.md)).

```
siem/
├── rules/zt_rules.xml          # custom rules 100100-100161 (PDP, AI, IDS, correlation, FIM)
└── dashboards/
    ├── zt-dashboards.ndjson    # overview dashboard + 5 saved searches (+ index pattern)
    └── import.sh               # imports the ndjson through the dashboard API (run on siem)
```

Agent log collection and FIM paths are not in this folder: the `wazuh_agent` role generates them
in each agent's `ossec.conf` from `infra/ansible/roles/wazuh_agent/defaults/main.yml`. The `siem`
role deploys the rules and runs `import.sh`.
