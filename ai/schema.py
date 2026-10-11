"""Canonical flow-feature schema shared by training data and live traffic.

Two extractors feed the models:
  * CICFlowMeter  — the CIC-IDS2017 `MachineLearningCSV` files (pre-training).
  * NFStream      — live/lab flows on the sensor or the host (inference, E2).

Both are mapped onto the same names and units (durations and IATs in ms,
sizes in bytes, flag counts bidirectional), and the rate/ratio features are
recomputed here from base counters rather than trusted from the extractor
(CICFlowMeter's `Flow Bytes/s` is known to contain inf/NaN).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

BASE = [
    "duration_ms",
    "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "fwd_ps_max", "fwd_ps_min", "fwd_ps_mean", "fwd_ps_std",
    "bwd_ps_max", "bwd_ps_min", "bwd_ps_mean", "bwd_ps_std",
    "ps_max", "ps_min", "ps_mean", "ps_std",
    "iat_mean", "iat_std", "iat_max", "iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "syn", "fin", "rst", "psh", "ack", "urg",
]
PORT = ["port_web", "port_ssh", "port_dns", "port_ftp", "port_mail", "port_low", "port_high"]
DERIVED = ["bytes_per_s", "pkts_per_s", "bytes_per_pkt", "bytes_ratio", "pkts_ratio"]
FEATURES = BASE + PORT + DERIVED

# CICFlowMeter column -> (canonical name, unit scale). IATs/duration are µs.
_CIC = {
    "Flow Duration": ("duration_ms", 1e-3),
    "Total Fwd Packets": ("fwd_pkts", 1), "Total Backward Packets": ("bwd_pkts", 1),
    "Total Length of Fwd Packets": ("fwd_bytes", 1), "Total Length of Bwd Packets": ("bwd_bytes", 1),
    "Fwd Packet Length Max": ("fwd_ps_max", 1), "Fwd Packet Length Min": ("fwd_ps_min", 1),
    "Fwd Packet Length Mean": ("fwd_ps_mean", 1), "Fwd Packet Length Std": ("fwd_ps_std", 1),
    "Bwd Packet Length Max": ("bwd_ps_max", 1), "Bwd Packet Length Min": ("bwd_ps_min", 1),
    "Bwd Packet Length Mean": ("bwd_ps_mean", 1), "Bwd Packet Length Std": ("bwd_ps_std", 1),
    "Max Packet Length": ("ps_max", 1), "Min Packet Length": ("ps_min", 1),
    "Packet Length Mean": ("ps_mean", 1), "Packet Length Std": ("ps_std", 1),
    "Flow IAT Mean": ("iat_mean", 1e-3), "Flow IAT Std": ("iat_std", 1e-3),
    "Flow IAT Max": ("iat_max", 1e-3), "Flow IAT Min": ("iat_min", 1e-3),
    "Fwd IAT Mean": ("fwd_iat_mean", 1e-3), "Fwd IAT Std": ("fwd_iat_std", 1e-3),
    "Fwd IAT Max": ("fwd_iat_max", 1e-3), "Fwd IAT Min": ("fwd_iat_min", 1e-3),
    "Bwd IAT Mean": ("bwd_iat_mean", 1e-3), "Bwd IAT Std": ("bwd_iat_std", 1e-3),
    "Bwd IAT Max": ("bwd_iat_max", 1e-3), "Bwd IAT Min": ("bwd_iat_min", 1e-3),
    "SYN Flag Count": ("syn", 1), "FIN Flag Count": ("fin", 1), "RST Flag Count": ("rst", 1),
    "PSH Flag Count": ("psh", 1), "ACK Flag Count": ("ack", 1), "URG Flag Count": ("urg", 1),
}

# NFStream attribute (statistical_analysis=True) -> canonical name (already ms/bytes).
_NFS = {
    "bidirectional_duration_ms": "duration_ms",
    "src2dst_packets": "fwd_pkts", "dst2src_packets": "bwd_pkts",
    "src2dst_bytes": "fwd_bytes", "dst2src_bytes": "bwd_bytes",
    "src2dst_max_ps": "fwd_ps_max", "src2dst_min_ps": "fwd_ps_min",
    "src2dst_mean_ps": "fwd_ps_mean", "src2dst_stddev_ps": "fwd_ps_std",
    "dst2src_max_ps": "bwd_ps_max", "dst2src_min_ps": "bwd_ps_min",
    "dst2src_mean_ps": "bwd_ps_mean", "dst2src_stddev_ps": "bwd_ps_std",
    "bidirectional_max_ps": "ps_max", "bidirectional_min_ps": "ps_min",
    "bidirectional_mean_ps": "ps_mean", "bidirectional_stddev_ps": "ps_std",
    "bidirectional_mean_piat_ms": "iat_mean", "bidirectional_stddev_piat_ms": "iat_std",
    "bidirectional_max_piat_ms": "iat_max", "bidirectional_min_piat_ms": "iat_min",
    "src2dst_mean_piat_ms": "fwd_iat_mean", "src2dst_stddev_piat_ms": "fwd_iat_std",
    "src2dst_max_piat_ms": "fwd_iat_max", "src2dst_min_piat_ms": "fwd_iat_min",
    "dst2src_mean_piat_ms": "bwd_iat_mean", "dst2src_stddev_piat_ms": "bwd_iat_std",
    "dst2src_max_piat_ms": "bwd_iat_max", "dst2src_min_piat_ms": "bwd_iat_min",
    "bidirectional_syn_packets": "syn", "bidirectional_fin_packets": "fin",
    "bidirectional_rst_packets": "rst", "bidirectional_psh_packets": "psh",
    "bidirectional_ack_packets": "ack", "bidirectional_urg_packets": "urg",
}


def _port_flags(port: pd.Series) -> pd.DataFrame:
    p = pd.to_numeric(port, errors="coerce").fillna(-1).astype(int)
    return pd.DataFrame({
        "port_web": p.isin([80, 443, 8080, 8443]),
        "port_ssh": p.eq(22),
        "port_dns": p.eq(53),
        "port_ftp": p.isin([20, 21]),
        "port_mail": p.isin([25, 110, 143, 465, 587, 993, 995]),
        "port_low": (p >= 0) & (p < 1024),
        "port_high": p >= 49152,
    }, index=port.index).astype(np.float32)


def _derive(df: pd.DataFrame) -> pd.DataFrame:
    pkts = df["fwd_pkts"] + df["bwd_pkts"]
    byts = df["fwd_bytes"] + df["bwd_bytes"]
    secs = (df["duration_ms"] / 1e3).clip(lower=1e-3)          # avoid /0 on 0-ms flows
    df["bytes_per_s"] = byts / secs
    df["pkts_per_s"] = pkts / secs
    df["bytes_per_pkt"] = byts / pkts.clip(lower=1)
    df["bytes_ratio"] = (df["fwd_bytes"] + 1) / (df["bwd_bytes"] + 1)
    df["pkts_ratio"] = (df["fwd_pkts"] + 1) / (df["bwd_pkts"] + 1)
    return df


def _finish(df: pd.DataFrame) -> pd.DataFrame:
    df = _derive(df)
    out = df[FEATURES].astype(np.float64)
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    out = out.clip(lower=0.0)              # CICFlowMeter emits a few negative IATs
    return out.astype(np.float32)


def from_cic(raw: pd.DataFrame) -> pd.DataFrame:
    """CICFlowMeter frame (column names may carry leading spaces) -> FEATURES."""
    raw = raw.rename(columns=lambda c: c.strip())
    df = pd.DataFrame({dst: pd.to_numeric(raw[src], errors="coerce") * scale
                       for src, (dst, scale) in _CIC.items()})
    df = pd.concat([df, _port_flags(raw["Destination Port"])], axis=1)
    return _finish(df)


def from_nfstream(flows: pd.DataFrame) -> pd.DataFrame:
    """NFStream frame (`to_pandas()` or a list of flow dicts) -> FEATURES."""
    df = pd.DataFrame({dst: pd.to_numeric(flows[src], errors="coerce") for src, dst in _NFS.items()})
    df = pd.concat([df, _port_flags(flows["dst_port"])], axis=1)
    return _finish(df)
