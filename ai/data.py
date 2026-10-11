"""CIC-IDS2017 loading: canonical features, clean labels, attack families.

The CSVs are untrusted downloaded data: they are only parsed (pandas), never
executed, and are expected under datasets/cic-ids2017/MachineLearningCVE/.
"""
from __future__ import annotations

import glob
import os
import re

import numpy as np
import pandas as pd

from schema import FEATURES, from_cic

FAMILY = {
    "BENIGN": "benign",
    "DoS Hulk": "dos", "DoS GoldenEye": "dos", "DoS slowloris": "dos", "DoS Slowhttptest": "dos",
    "DDoS": "ddos",
    "PortScan": "portscan",
    "FTP-Patator": "bruteforce", "SSH-Patator": "bruteforce",
    "Web Attack - Brute Force": "web", "Web Attack - XSS": "web", "Web Attack - Sql Injection": "web",
    "Bot": "bot",
    "Infiltration": "infiltration",
    "Heartbleed": "heartbleed",
}


def clean_label(label: str) -> str:
    # The original files carry a mangled en dash ("Web Attack � XSS").
    return re.sub(r"\s*[^\x20-\x7e]+\s*", " - ", label.strip())


def load_cic(csv_dir: str, cache: str | None = None) -> pd.DataFrame:
    """Return FEATURES + `label` + `family` + `attack` (0/1), deduplicated."""
    if cache and os.path.exists(cache):
        return pd.read_parquet(cache)
    parts = []
    for path in sorted(glob.glob(os.path.join(csv_dir, "*.csv"))):
        raw = pd.read_csv(path, encoding="latin-1", low_memory=False)
        feats = from_cic(raw)
        lab = raw[raw.columns[-1]].astype(str).map(clean_label)
        feats["label"] = lab.values
        feats["day"] = os.path.basename(path).split("-")[0]
        parts.append(feats)
    df = pd.concat(parts, ignore_index=True)
    unknown = sorted(set(df["label"]) - set(FAMILY))
    if unknown:
        raise ValueError(f"unmapped labels: {unknown}")
    df["family"] = df["label"].map(FAMILY)
    df["attack"] = (df["family"] != "benign").astype(np.int8)
    before = len(df)
    df = df.drop_duplicates(subset=FEATURES + ["label"]).reset_index(drop=True)
    df.attrs["dropped_duplicates"] = before - len(df)
    if cache:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        df.to_parquet(cache, index=False)
    return df


def split(df: pd.DataFrame, seed: int = 42, val: float = 0.2, test: float = 0.2):
    """Stratified (by fine label) train / val / test indices."""
    rng = np.random.default_rng(seed)
    tr, va, te = [], [], []
    for _, idx in df.groupby("label").indices.items():
        idx = rng.permutation(idx)
        n_te, n_va = int(round(len(idx) * test)), int(round(len(idx) * val))
        te.extend(idx[:n_te]); va.extend(idx[n_te:n_te + n_va]); tr.extend(idx[n_te + n_va:])
    return np.array(tr), np.array(va), np.array(te)
