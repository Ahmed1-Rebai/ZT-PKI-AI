# apps/posture

Client posture agent (docs/06 §8). Runs on the legitimate client (inside the
VPN tunnel) and POSTs a posture score to the PDP `/v1/posture` over **mTLS**,
where the client certificate is the identity.

- `posture_agent.py` — collects firewall / disk-encryption / OS facts, scores
  them `0.0..1.0`, sends `{cn, score, detail}`.
- `zt-posture.{service,timer}` — systemd oneshot run every 60 s.

Deployed to `/opt/zt-posture/` + `/etc/zt-client/posture.env` by the `client`
Ansible role.
