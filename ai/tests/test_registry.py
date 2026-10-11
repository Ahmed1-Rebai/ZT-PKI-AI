import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import registry  # noqa: E402

TRAINED = registry.DEFAULT_DIR
pytestmark = pytest.mark.skipif(not os.path.exists(os.path.join(TRAINED, "manifest.json")),
                                reason="run ai/train.py first")


def test_trained_bundle_verifies_and_loads():
    bundle = registry.load()
    assert {"rf", "iforest", "preprocessor", "stacker", "ae"} <= set(bundle)


def test_tampered_artefact_is_refused(tmp_path):
    for name in ("manifest.json", "ae.pt", "baseline.joblib"):
        shutil.copy(os.path.join(TRAINED, name), tmp_path / name)
    with open(tmp_path / "ae.pt", "ab") as fh:
        fh.write(b"tampered")
    with pytest.raises(registry.IntegrityError, match="hash mismatch"):
        registry.load(str(tmp_path))


def test_missing_artefact_is_refused(tmp_path):
    shutil.copy(os.path.join(TRAINED, "manifest.json"), tmp_path / "manifest.json")
    with pytest.raises(registry.IntegrityError, match="missing"):
        registry.verify(str(tmp_path))
