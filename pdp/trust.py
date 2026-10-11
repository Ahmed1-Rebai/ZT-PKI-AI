"""Deterministic trust-score calculation used by every PDP decision."""
from __future__ import annotations

from dataclasses import dataclass

WEIGHTS = {"identity": 0.30, "device": 0.25, "context": 0.15, "anomaly": 0.30}


def _unit(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class Signals:
    identity: float
    device: float
    context: float
    anomaly: float  # 0 = benign, 1 = highly anomalous
    critical_alert: bool = False


def ema(previous: float, observed: float, alpha: float = 0.4) -> float:
    """Exponential moving average, bounded even for malformed upstream data."""
    if not 0 < alpha <= 1:
        raise ValueError("alpha must be in (0, 1]")
    return round(alpha * _unit(observed) + (1 - alpha) * _unit(previous), 4)


def trust_score(signals: Signals) -> float:
    """Return the 0..100 score, including the documented non-compensation floor."""
    identity = _unit(signals.identity)
    anomaly = _unit(signals.anomaly)
    if identity == 0 or (signals.critical_alert and anomaly > 0.9):
        return 0.0
    raw = (
        WEIGHTS["identity"] * identity
        + WEIGHTS["device"] * _unit(signals.device)
        + WEIGHTS["context"] * _unit(signals.context)
        + WEIGHTS["anomaly"] * (1.0 - anomaly)
    )
    return round(100.0 * raw, 1)
