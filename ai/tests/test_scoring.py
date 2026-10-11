import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import registry  # noqa: E402

CACHE = os.path.join(HERE, "..", "..", "datasets", "cic-ids2017", "cic-canonical.parquet")
pytestmark = pytest.mark.skipif(
    not (os.path.exists(os.path.join(registry.DEFAULT_DIR, "manifest.json")) and os.path.exists(CACHE)),
    reason="needs a trained model and the cached dataset")


@pytest.fixture(scope="module")
def scored():
    import pandas as pd
    from scoring import Scorer
    df = pd.read_parquet(CACHE)
    sample = pd.concat([df[df.attack == 0].sample(2000, random_state=1),
                        df[df.attack == 1].sample(2000, random_state=1)])
    return sample, Scorer().score(sample)


def test_scores_are_probabilities(scored):
    _, s = scored
    assert s["anomaly"].between(0, 1).all()
    assert set(s.columns) == {"iforest", "ae", "rf", "anomaly"}


def test_attacks_score_higher_than_benign(scored):
    sample, s = scored
    benign = s.loc[sample.attack == 0, "anomaly"]
    attack = s.loc[sample.attack == 1, "anomaly"]
    assert benign.median() < 0.1 and attack.median() > 0.9
    assert (benign >= 0.5).mean() < 0.02        # FPR budget
