# tests/

Attack scenarios, benign traffic generation, orchestration and evidence (see [docs/09](../docs/09-tests-et-scenarios.md)).

```
tests/
├── scenarios/      # one test sheet (.md) per scenario S1-S17
├── evidence/       # screenshots, logs, pcaps attached as proof (per scenario)
├── run-m2.sh       # runs the M2 VPN/gateway scenarios (S1-S6, S13, S14) from client-lin + collects evidence
├── run-redteam.sh  # runs the M5/M7 Red Team scenarios (S7-S12, S15-S17) from client-lin + collects evidence
├── abcd/           # set-config.sh A|B|C|D, probe.sh (exposed surface), attack-abcd.sh (attack comparison), run-all.sh
├── perf/           # perf.sh (plain/tunnel/full ZT), perf-abcd.sh (same path per config)
└── reports/        # JSON results, make_report.py -> results.md + charts/, perf.md (analysis)
```

**Rule:** every claimed result must have a proof file in `evidence/`. All attacks run **only** inside the isolated lab — see [RULES-OF-ENGAGEMENT.md](../RULES-OF-ENGAGEMENT.md).
