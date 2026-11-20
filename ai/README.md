# ai/

Anomaly-detection engine (docs/07), milestone **M4**. Runs on the **host** (RTX 5050)
— VirtualBox has no CUDA passthrough; the host sits on mgmt at `10.10.99.2`.

```
ai/
├── schema.py          # 47 canonical flow features — CICFlowMeter AND NFStream map onto them
├── data.py            # CIC-IDS2017 loader: clean labels, families, dedupe, stratified split
├── models.py          # preprocessing (log1p+std), GPU autoencoder, docs/07 §6 normalisations
├── train.py           # train + evaluate (E1), SHAP, latency, signed manifest
├── registry.py        # load models ONLY if SHA-256 matches the manifest
├── scoring.py         # offline/online scorer turning 47 features into calibrated anomaly probability
├── pdp_client.py      # mTLS client reporting anomaly events to PDP (/v1/events)
├── serve.py           # live NFStream capture + scoring daemon running on zt-sensor
├── reports/           # metrics.md (human) + metrics.json (raw) — tracked
├── models/            # baseline.joblib, ae.pt (git-ignored) + manifest.json (tracked)
└── tests/             # schema, scoring + integrity tests
```

## Setup (once)

```bash
conda create -y -p ./.venv python=3.11
./.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cu128   # Blackwell needs cu128+
./.venv/bin/pip install scikit-learn pandas numpy pyarrow shap joblib matplotlib nfstream pytest
```

Dataset: CIC-IDS2017 `MachineLearningCSV.zip` → `datasets/cic-ids2017/` (git-ignored).
The official UNB link now requires registration; the Hugging Face mirror
`bencorn/CICIDS2017` matches the published totals exactly (2,830,743 flows).

## Run

```bash
./.venv/bin/python ai/train.py --quick   # smoke run (~1.5 min)
./.venv/bin/python ai/train.py           # full run (~6 min: AE on GPU, RF on CPU)
./.venv/bin/python -m pytest -q ai/tests
```

## Results (E1, CIC-IDS2017 test split) — details in [reports/metrics.md](reports/metrics.md)

Served model (stacking fusion): **F1 0.9943 · FPR 0.16 % · ROC-AUC 0.9999 · 11.6 ms/flow**.
All M4 targets met. CIC-IDS2017 is optimistic; the decisive test is **E2** on lab traffic.
