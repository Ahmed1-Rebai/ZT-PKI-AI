# vpn/

OpenVPN gateway configuration and Zero Trust hooks (see [docs/05](../docs/05-vpn.md)).

```
vpn/
├── server/         # server.conf
├── hooks/          # tls-verify.py, client-connect.py, client-disconnect.py
└── client/         # alice.ovpn template (without embedded keys)
```

> `*.ovpn` client profiles, `ta.key` and all private keys are **not committed**.
