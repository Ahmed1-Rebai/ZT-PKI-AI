# Rules of Engagement — ZT-PKI-AI lab

> Authorization and boundaries for the security tests run in this academic project.
> The project team signs at the bottom before any test is run.

## 1. Parties and machines

The project is carried out by one team of two students, on one shared repository.

| Machine | Role in the tests |
|---|---|
| Lab host — Linux · Ryzen 5 · 48 GB RAM · VirtualBox 7.1 | runs the VMs, launches the test scripts, switches the A/B/C/D configurations |
| `client-lin` (`192.168.100.11`, untrust zone) | alice's workstation **and** the test machine: every attack scenario is played from it |

There is no external attacker machine: the attacks start from `client-lin`, outside or inside
alice's tunnel.

## 2. Purpose

Evaluate the ZT-PKI-AI Zero Trust architecture with the 12 attack scenarios of
[docs/09](docs/09-tests-et-scenarios.md) and the A/B/C/D benchmark, measure the defensive controls
(refusal, segmentation, quarantine, revocation, logging) and keep a proof of every result.

## 3. Authorized scope

**In scope — the isolated lab only:**

- The `zt-untrust` network `192.168.100.0/24` and the VMs reachable from it as a legitimate or
  compromised client, strictly through the published scenarios.
- All VirtualBox VMs of this project on the lab host.

**Out of scope — strictly forbidden:**

- Any host, network or service **outside** the project lab.
- The Internet, the home/university network, the host OS and any third-party system.
- Any real personal or production data (the lab only holds test accounts and fake records).
- Any denial-of-service test against anything other than the lab gateway (S6), and only at the agreed intensity.

## 4. Isolation requirements

- Lab zones are VirtualBox **internal networks** with no host or Internet route.
- The temporary NAT adapter used to install packages is **removed** before any test (`make isolate`).
- Isolation is verified before each campaign: from `client-lin`, `ping 10.10.30.10` must fail.

## 5. Rules

1. No test starts before this document is signed and a VM snapshot is taken.
2. Only the tools and methods listed in the scenario sheets are used (openvpn, openssl, curl, ssh,
   nmap for S5, hping3 for S6, iperf3 for the performance runs).
3. No destructive action beyond what a scenario defines; every modified file is restored by the script.
4. Every test is timestamped and logged; one proof file per result goes in `tests/evidence/`.
5. If anything unexpected reaches outside the lab, testing stops immediately.
6. VM snapshots are restored if a scenario leaves the lab in an unexpected state.

## 6. Legal / ethical note

This is an academic exercise on infrastructure owned by the project team. No system belonging to a
third party is targeted. All activity complies with the project's ethics statement
([README.md §9](README.md)).

## 7. Sign-off

| Member | Date | Signature |
|---|---|---|
| | | |
| | | |
