# tests/

Attack scenarios, benign traffic generation, orchestration and evidence (see [docs/09](../docs/09-tests-et-scenarios.md)).

```
tests/
├── scenarios/      # one test sheet (.md) + one script (.sh) per scenario S1-S17
├── evidence/       # screenshots, logs, pcaps attached as proof (per scenario)
├── run-m2.sh       # runs the M2 VPN/gateway scenarios (S1-S6, S13, S14) + collects evidence
├── abcd/           # set-config.sh A|B|C|D (switch the lab), probe.sh (exposed surface), run-all.sh
├── perf/           # perf.sh (plain/tunnel/full ZT), perf-abcd.sh (same path per config)
├── traffic_benign.py
├── run_all.py      # orchestrates, timestamps, collects results
├── analyze.ipynb   # computes TTD/TTQ/metrics, generates figures
└── reports/        # JSON results, make_report.py -> results.md + charts/, perf.md (analysis)
```

**Rule:** every claimed result must have a proof file in `evidence/`. All attacks run **only** inside the isolated lab — see [RULES-OF-ENGAGEMENT.md](../RULES-OF-ENGAGEMENT.md).
