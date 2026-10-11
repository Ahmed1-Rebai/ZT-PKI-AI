"""Load the trained engine only if every artefact matches its signed manifest.

docs/02 §9: "Modèles IA signés (hash SHA-256 vérifié au chargement)". A model
file that was swapped or tampered with is refused instead of being served.
"""
from __future__ import annotations

import hashlib
import json
import os

import joblib
import torch

from models import AutoEncoder

DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")


class IntegrityError(RuntimeError):
    pass


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(model_dir: str = DEFAULT_DIR) -> dict:
    """Check every artefact listed in manifest.json; return the manifest."""
    with open(os.path.join(model_dir, "manifest.json")) as fh:
        manifest = json.load(fh)
    for name, expected in manifest["artifacts"].items():
        path = os.path.join(model_dir, name)
        if not os.path.exists(path):
            raise IntegrityError(f"missing artefact: {name}")
        actual = _sha256(path)
        if actual != expected:
            raise IntegrityError(f"hash mismatch for {name}: {actual[:16]}... != {expected[:16]}...")
    return manifest


def load(model_dir: str = DEFAULT_DIR) -> dict:
    """Verified bundle: sklearn models + preprocessing + the autoencoder."""
    verify(model_dir)                                  # before unpickling anything
    bundle = joblib.load(os.path.join(model_dir, "baseline.joblib"))
    ckpt = torch.load(os.path.join(model_dir, "ae.pt"), map_location="cpu", weights_only=True)
    ae = AutoEncoder(ckpt["d"])
    ae.load_state_dict(ckpt["state_dict"])
    bundle["ae"] = ae.eval()
    return bundle
