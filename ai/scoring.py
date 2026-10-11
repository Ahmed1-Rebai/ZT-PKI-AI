"""Offline scoring core of the anomaly engine (milestone M5, step 1).

Turns canonical flow features (ai/schema.py) into the calibrated anomaly
probability the PDP uses as the trust score's anomaly term. No network here:
the PDP link and live capture are separate layers on top of this module.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

import registry
from models import norm_ae, norm_if, recon_error
from schema import FEATURES


class Scorer:
    def __init__(self, model_dir: str = registry.DEFAULT_DIR):
        b = registry.load(model_dir)              # refuses tampered artefacts
        self.pre, self.iforest, self.rf = b["preprocessor"], b["iforest"], b["rf"]
        self.ae, self.stacker = b["ae"], b["stacker"]
        self.if_lo, self.if_hi, self.ae_thr = b["if_lo"], b["if_hi"], b["ae_threshold"]
        self.rf.set_params(n_jobs=1)              # small batches: avoid thread fan-out
        self.iforest.set_params(n_jobs=1)

    def components(self, feats: pd.DataFrame) -> dict[str, np.ndarray]:
        z = self.pre.transform(feats[FEATURES].to_numpy(np.float32))
        return {
            "iforest": norm_if(-self.iforest.score_samples(z), self.if_lo, self.if_hi),
            "ae": norm_ae(recon_error(self.ae, z), self.ae_thr),
            "rf": self.rf.predict_proba(z)[:, 1],
        }

    def score(self, feats: pd.DataFrame) -> pd.DataFrame:
        """One row per flow: component scores + fused, calibrated `anomaly` in [0, 1]."""
        c = self.components(feats)
        fused = self.stacker.predict_proba(np.column_stack([c["iforest"], c["ae"], c["rf"]]))[:, 1]
        out = pd.DataFrame(c, index=feats.index)
        out["anomaly"] = fused
        return out
