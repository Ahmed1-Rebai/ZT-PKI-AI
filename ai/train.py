"""Train and evaluate the anomaly engine on CIC-IDS2017 (milestone M4, E1).

Protocol (no test leakage):
  train  -> IF / AE fitted on benign only; RF fitted on attacks + benign
  val    -> IF/AE normalisation (docs/07 §6), stacking + calibration, threshold
  test   -> every reported metric

usage: .venv/bin/python ai/train.py [--quick]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time

import joblib
import numpy as np
import torch
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from data import load_cic, split  # noqa: E402
from models import (Preprocessor, fixed_weight_fusion, norm_ae, norm_if,  # noqa: E402
                    recon_error, train_autoencoder)
from schema import FEATURES  # noqa: E402

REPO = os.path.dirname(HERE)
CSV_DIR = os.path.join(REPO, "datasets", "cic-ids2017", "MachineLearningCVE")
CACHE = os.path.join(REPO, "datasets", "cic-ids2017", "cic-canonical.parquet")
OUT = os.path.join(HERE, "models")
REPORTS = os.path.join(HERE, "reports")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def metrics(y: np.ndarray, score: np.ndarray, thr: float) -> dict:
    pred = (score >= thr).astype(int)
    neg = y == 0
    return {
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "fpr": round(float(pred[neg].mean()), 4),
        "roc_auc": round(float(roc_auc_score(y, score)), 4),
        "pr_auc": round(float(average_precision_score(y, score)), 4),
        "threshold": round(float(thr), 4),
    }


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small subsample for a smoke run")
    ap.add_argument("--target-fpr", type=float, default=0.01, help="IF/AE stand-alone threshold")
    args = ap.parse_args()
    t0 = time.time()
    rng = np.random.default_rng(42)

    log("loading CIC-IDS2017 (canonical schema)")
    df = load_cic(CSV_DIR, CACHE)
    if args.quick:
        # up to 20k flows per label (pandas 3: groupby.apply drops the key column)
        df = df.sample(frac=1.0, random_state=0).groupby("label").head(20000).reset_index(drop=True)
    log(f"  {len(df):,} unique flows, {int(df['attack'].sum()):,} attacks")
    tr, va, te = split(df)
    X = df[FEATURES].to_numpy(np.float32)
    y = df["attack"].to_numpy(np.int8)

    pre = Preprocessor().fit(X[tr][y[tr] == 0])
    Z = pre.transform(X)
    btr, bva = tr[y[tr] == 0], va[y[va] == 0]

    # ---- Isolation Forest (benign only) -------------------------------------
    log("isolation forest")
    sub = rng.choice(btr, size=min(len(btr), 300_000), replace=False)
    iforest = IsolationForest(n_estimators=200, random_state=0, n_jobs=-1).fit(Z[sub])
    raw_if = -iforest.score_samples(Z)
    if_lo, if_hi = np.percentile(raw_if[bva], [1, 99.9])
    s_if = norm_if(raw_if, if_lo, if_hi)

    # ---- Autoencoder (benign only, GPU) -------------------------------------
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"autoencoder on {device}" + (f" ({torch.cuda.get_device_name(0)})" if device == "cuda" else ""))
    sub = rng.choice(btr, size=min(len(btr), 1_000_000), replace=False)
    ae = train_autoencoder(Z[sub], Z[bva], epochs=5 if args.quick else 15, device=device, log=log)
    err = recon_error(ae, Z)
    ae_thr = float(np.percentile(err[bva], 99.5))
    s_ae = norm_ae(err, ae_thr)

    # ---- Random Forest (supervised) -----------------------------------------
    log("random forest")
    atk_tr = tr[y[tr] == 1]
    ben_tr = rng.choice(btr, size=min(len(btr), 600_000), replace=False)
    rf_idx = np.concatenate([atk_tr, ben_tr])
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0,
                                class_weight="balanced_subsample", min_samples_leaf=2)
    rf.fit(Z[rf_idx], y[rf_idx])
    s_rf = rf.predict_proba(Z)[:, 1]

    # ---- Fusion + calibration (fitted on validation) ------------------------
    log("fusion: stacking + calibration on validation")
    S = np.column_stack([s_if, s_ae, s_rf])
    stack = LogisticRegression(max_iter=1000).fit(S[va], y[va])
    p_stack = stack.predict_proba(S)[:, 1]
    fixed = fixed_weight_fusion({"iforest": s_if, "ae": s_ae, "rf": s_rf})
    iso = IsotonicRegression(out_of_bounds="clip").fit(fixed[va], y[va])
    p_fixed = iso.predict(fixed)

    # IF / AE stand-alone thresholds: target FPR on benign validation.
    thr_if = float(np.percentile(s_if[bva], 100 * (1 - args.target_fpr)))
    thr_ae = float(np.percentile(s_ae[bva], 100 * (1 - args.target_fpr)))

    # ---- Test metrics (E1) --------------------------------------------------
    log("evaluating on the held-out test split")
    yt = y[te]
    results = {
        "isolation_forest": metrics(yt, s_if[te], thr_if),
        "autoencoder": metrics(yt, s_ae[te], thr_ae),
        "random_forest": metrics(yt, s_rf[te], 0.5),
        "fusion_fixed_weights_isotonic": metrics(yt, p_fixed[te], 0.5),
        "fusion_stacking": metrics(yt, p_stack[te], 0.5),
    }
    fam = df["family"].to_numpy()
    per_family = {}
    for f in sorted(set(fam[te])):
        m = fam[te] == f
        per_family[f] = {"n_test": int(m.sum()),
                         "detected" if f != "benign" else "flagged": round(float((p_stack[te][m] >= 0.5).mean()), 4)}

    # ---- Explainability (docs/07 §7) ----------------------------------------
    log("shap: global feature importance on test attacks")
    import shap
    atk_te = te[y[te] == 1]
    sample = rng.choice(atk_te, size=min(len(atk_te), 1500), replace=False)
    sv = shap.TreeExplainer(rf).shap_values(Z[sample], check_additivity=False)
    sv = sv[1] if isinstance(sv, list) else (sv[..., 1] if sv.ndim == 3 else sv)
    imp = np.abs(sv).mean(axis=0)
    top = [{"feature": FEATURES[i], "mean_abs_shap": round(float(imp[i]), 5)} for i in np.argsort(imp)[::-1][:10]]

    # ---- Single-flow latency (serving path, CPU) ----------------------------
    # One flow at a time: thread fan-out (n_jobs=-1) costs more than it saves.
    rf.set_params(n_jobs=1)
    iforest.set_params(n_jobs=1)
    probe = X[te[:1000]]
    tl = time.perf_counter()
    for row in probe:
        z = pre.transform(row[None, :])
        a = norm_if(-iforest.score_samples(z), if_lo, if_hi)
        b = norm_ae(recon_error(ae, z), ae_thr)
        c = rf.predict_proba(z)[:, 1]
        stack.predict_proba(np.column_stack([a, b, c]))
    latency_ms = (time.perf_counter() - tl) / len(probe) * 1e3

    # ---- Persist artefacts + signed manifest --------------------------------
    os.makedirs(OUT, exist_ok=True); os.makedirs(REPORTS, exist_ok=True)
    bundle = os.path.join(OUT, "baseline.joblib")
    joblib.dump({"features": FEATURES, "preprocessor": pre, "iforest": iforest, "if_lo": float(if_lo),
                 "if_hi": float(if_hi), "rf": rf, "ae_threshold": ae_thr, "stacker": stack,
                 "stack_inputs": ["iforest", "ae", "rf"]}, bundle, compress=3)
    ae_path = os.path.join(OUT, "ae.pt")
    torch.save({"state_dict": ae.state_dict(), "d": len(FEATURES)}, ae_path)
    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": "CIC-IDS2017 MachineLearningCSV (2,830,743 flows, verified)",
        "rows_unique": int(len(df)), "quick": args.quick,
        "artifacts": {"baseline.joblib": sha256(bundle), "ae.pt": sha256(ae_path)},
        "env": {"python": platform.python_version(), "torch": torch.__version__, "device": device},
    }
    with open(os.path.join(OUT, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    report = {"test_metrics": results, "per_family_detection": per_family, "top_features_shap": top,
              "latency_ms_per_flow_cpu": round(latency_ms, 2), "targets": {"f1": 0.95, "fpr": 0.02, "latency_ms": 50},
              "split_sizes": {"train": len(tr), "val": len(va), "test": len(te)},
              "duration_s": round(time.time() - t0, 1), "manifest": manifest}
    with open(os.path.join(REPORTS, "metrics.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    log(f"done in {report['duration_s']} s")
    for name, m in results.items():
        log(f"  {name:32s} F1 {m['f1']:.4f}  FPR {m['fpr']:.4f}  ROC-AUC {m['roc_auc']:.4f}")
    log(f"  latency {latency_ms:.2f} ms/flow (CPU)")


if __name__ == "__main__":
    main()
