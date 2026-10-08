# sensor/

Network sensor: Suricata signatures + NFStream flow extraction (see [docs/08 §3](../docs/08-supervision-siem.md)).

```
sensor/
├── suricata.yaml       # Suricata config (extracts)
├── local.rules         # local detection rules
└── mirror.sh           # tc mirred mirror setup on the gateway (VirtualBox has no port mirroring)
```

Fed by a traffic mirror from `zt-gw`. On VirtualBox use `tc mirred` or a promiscuous ("Allow All") sensor NIC.
