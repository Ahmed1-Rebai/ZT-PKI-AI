from trust import Signals, ema, trust_score


def test_weighted_score_matches_design():
    assert trust_score(Signals(identity=1, device=1, context=1, anomaly=0)) == 100.0
    assert trust_score(Signals(identity=1, device=0, context=0, anomaly=1)) == 30.0


def test_identity_and_critical_floor_cannot_be_compensated():
    assert trust_score(Signals(identity=0, device=1, context=1, anomaly=0)) == 0.0
    assert trust_score(Signals(identity=1, device=1, context=1, anomaly=0.91, critical_alert=True)) == 0.0


def test_ema_is_bounded_and_smooth():
    assert ema(0, 1) == 0.4
    assert ema(0.4, 1) == 0.64
    assert ema(1, 2) == 1.0
