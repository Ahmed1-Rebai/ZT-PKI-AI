# Rules of Engagement — ZT-PKI-AI lab

> Authorization and boundaries for the authorized security testing performed in this academic project.
> Both team members sign at the bottom before any test is run.

## 1. Parties

| Role | Member | Machine |
|---|---|---|
| 🔵 Blue Team | Ahmed Rebai | Blue Team host — Linux · Ryzen 5 · 48 GB RAM · RTX 5050 8 GB · VirtualBox 7.0.16 |
| 🔴 Red Team | Partner | Attacker laptop — Kali Linux 2026.2 |

## 2. Purpose

Evaluate the ZT-PKI-AI Zero Trust architecture by running the attack scenarios S1–S17 ([docs/09](docs/09-tests-et-scenarios.md)) against the lab, measuring the defensive controls (detection, containment, logging) and documenting the results.

## 3. Authorized scope

**In scope — the isolated lab only:**

- The `zt-untrust` network `192.168.100.0/24` (the only network the Red Team touches directly).
- The VMs reachable from it as a legitimate or compromised client, strictly through the published scenarios.
- All VirtualBox VMs belonging to this project on the Blue Team host.

**Out of scope — strictly forbidden:**

- Any host, network, or service **outside** the project lab.
- The Internet, the home/university network, the host OS, and any third-party system.
- Any real personal or production data.
- Any denial-of-service test against anything other than the lab gateway (S6), and only at the agreed intensity.

## 4. Isolation requirements

- Lab networks are VirtualBox **Internal Networks** with no host/Internet route.
- A temporary NAT adapter may be used **only** to install packages, and is **removed** before any test.
- The Red Team laptop connects **only** to the gateway's WAN NIC (dedicated/bridged cabled link), never to the internal zones.
- Isolation is verified before each campaign: from Kali, `ping 10.10.30.10` must fail.

## 5. Rules

1. No attack starts before this document is signed and the target snapshot is taken.
2. Only the tools and methods listed in the scenario sheets are used (nmap, hydra, hping3, dnscat2/iodine, openvpn, openssl).
3. `rockyou.txt` and similar wordlists are used **only** against lab accounts created for the test.
4. No destructive action beyond what a scenario defines; no data is exfiltrated outside the lab (S10/S11 send to lab hosts only).
5. Every test is timestamped and logged; one proof file per result goes in `tests/evidence/`.
6. If anything unexpected reaches outside the lab, testing stops immediately and both members are notified.
7. VM snapshots are taken before destructive scenarios and restored afterward.

## 6. Schedule

Testing windows are agreed per milestone (see [TODO.md](TODO.md)); no out-of-window testing.

## 7. Legal / ethical note

This is an academic exercise on infrastructure owned by the Blue Team member. No system belonging to a third party is targeted. All activity complies with the project's ethics statement ([README.md §9](README.md)).

## 8. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| 🔵 Blue Team | | | |
| 🔴 Red Team | | | |
