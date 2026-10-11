"""Model zoo for the anomaly engine (docs/07 §5-§6).

  * Isolation Forest — unsupervised, benign-only: unknown anomalies.
  * Autoencoder      — unsupervised, benign-only: reconstruction error (GPU).
  * Random Forest    — supervised: known attack patterns.
Each yields a score in [0, 1]; a stacking logistic regression fuses them into a
calibrated attack probability (docs/07 §6: "0.8 ~ 80 % chance of attack").
"""
from __future__ import annotations

import numpy as np
import torch
from torch import nn

# docs/07 §6 weights; UEBA joins once lab windows exist (renormalised meanwhile).
WEIGHTS = {"iforest": 0.25, "ae": 0.25, "rf": 0.30, "ueba": 0.20}


class Preprocessor:
    """log1p (features are non-negative and heavy-tailed) + standardisation."""

    def fit(self, X: np.ndarray) -> "Preprocessor":
        Z = np.log1p(X.astype(np.float64))
        self.mean_ = Z.mean(axis=0)
        self.std_ = Z.std(axis=0)
        self.std_[self.std_ < 1e-9] = 1.0
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        return ((np.log1p(X.astype(np.float64)) - self.mean_) / self.std_).astype(np.float32)


class AutoEncoder(nn.Module):
    def __init__(self, d: int):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 8))
        self.dec = nn.Sequential(nn.Linear(8, 16), nn.ReLU(), nn.Linear(16, 32), nn.ReLU(), nn.Linear(32, d))

    def forward(self, x):
        return self.dec(self.enc(x))


def train_autoencoder(Xb_train: np.ndarray, Xb_val: np.ndarray, epochs: int = 15,
                      batch: int = 4096, lr: float = 1e-3, device: str | None = None,
                      log=print) -> AutoEncoder:
    """Fit on benign flows only; keep the epoch with the best benign-val loss."""
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(0)
    model = AutoEncoder(Xb_train.shape[1]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    xt = torch.from_numpy(Xb_train).to(device)
    xv = torch.from_numpy(Xb_val).to(device)
    best, best_state = float("inf"), None
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(len(xt), device=device)
        for i in range(0, len(xt), batch):
            b = xt[perm[i:i + batch]]
            opt.zero_grad()
            loss = loss_fn(model(b), b)
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            v = float(loss_fn(model(xv), xv))
        log(f"  ae epoch {ep + 1:2d}/{epochs}  benign-val mse {v:.5f}")
        if v < best:
            best, best_state = v, {k: t.detach().cpu().clone() for k, t in model.state_dict().items()}
    model.load_state_dict(best_state)
    return model.cpu().eval()


def recon_error(model: AutoEncoder, X: np.ndarray, batch: int = 65536) -> np.ndarray:
    out = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            x = torch.from_numpy(X[i:i + batch])
            out.append(((model(x) - x) ** 2).mean(dim=1).numpy())
    return np.concatenate(out)


# ---- docs/07 §6 normalisations (parameters fitted on benign validation) ----

def norm_if(raw: np.ndarray, lo: float, hi: float) -> np.ndarray:
    return np.clip((raw - lo) / (hi - lo), 0.0, 1.0)


def norm_ae(err: np.ndarray, thr: float) -> np.ndarray:
    return np.clip(err / (2.0 * thr), 0.0, 1.0)


def fixed_weight_fusion(scores: dict[str, np.ndarray]) -> np.ndarray:
    """docs/07 weights, renormalised over the models present."""
    w = {k: WEIGHTS[k] for k in scores}
    total = sum(w.values())
    return sum((w[k] / total) * scores[k] for k in scores)
