# sensor/

Network sensor files (see [docs/08 §3](../docs/08-supervision-siem.md)). `zt-sensor` runs Suricata
and the `zt-ai` inference service ([docs/07 §8](../docs/07-detection-ia.md)) on the mirrored traffic.

```
sensor/
├── local.rules         # ZT Suricata rules (SIDs 9000001-9000004, self-test 9000099)
└── mirror.sh           # tc mirred copy of the gateway zone NICs to the zt-mirror NIC
```

`mirror.sh` is installed on `zt-gw` by the `gateway` role (`/usr/local/sbin/zt-mirror.sh`, unit
`zt-mirror`, interfaces resolved by address into `/etc/default/zt-mirror`). The `sensor` role installs
Suricata 7, deploys `local.rules` and generates `/etc/suricata/zt.yaml` (af-packet on the mirror NIC,
rule files), sets `HOME_NET` in `suricata.yaml`, and deploys the `zt-ai` service.
