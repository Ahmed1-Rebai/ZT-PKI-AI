# tests/

Attack scenarios, A/B/C/D benchmark, performance measurements and evidence (see [docs/09](../docs/09-tests-et-scenarios.md)).

```
tests/
├── scenarios/      # one test sheet (.md) per scenario (12 scenarios)
├── evidence/       # screenshots, logs, pcaps attached as proof (per scenario)
├── run-m2.sh       # connection-time scenarios (S1-S6, S9, S10) played from client-lin + evidence
├── run-redteam.sh  # post-connection scenarios (S7, S8, S11, S12) played from client-lin + evidence
├── abcd/           # set-config.sh A|B|C|D, probe.sh (exposed surface), attack-abcd.sh (attack comparison), run-all.sh
├── perf/           # perf.sh (plain/tunnel/full ZT), perf-abcd.sh (same path per config)
└── reports/        # JSON results, make_report.py -> results.md + charts/, perf.md (analysis)
```

**Rule:** every claimed result must have a proof file in `evidence/`. All attacks run **only** inside the isolated lab — see [RULES-OF-ENGAGEMENT.md](../RULES-OF-ENGAGEMENT.md).
