# ai/

Anomaly-detection pipeline: feature extraction, training, inference (see [docs/07](../docs/07-detection-ia.md)).

```
ai/
├── features.py       # NFStream flow features + 60 s UEBA window features
├── train.py          # Isolation Forest + Random Forest baseline
├── autoencoder.py    # PyTorch autoencoder (trained on benign traffic)
├── serve.py          # inference service -> POST /v1/events to the PDP
├── notebooks/        # EDA, evaluation, SHAP (E1-E3)
└── models/           # trained artifacts (.joblib / .pt) -- NOT committed
```

Targets: F1 ≥ 0.95, FPR ≤ 2 %, inference < 50 ms/flow. Models are signed (SHA-256 verified at load).

## Runs on the host (GPU)

This engine runs **natively on the Blue Team laptop**, not in a VM — VirtualBox
has no CUDA passthrough, so the RTX 5050 is only reachable from the host. The host
joins the lab's **mgmt** network at `10.10.99.2` (host-only), reaching the PDP
(`https://10.10.99.10:8443/v1/events`) and the sensor. Training uses CUDA; the
inference service is light. Set up with `make ai` from `infra/` (see
[infra/README.md](../infra/README.md#ai-on-the-host)).
