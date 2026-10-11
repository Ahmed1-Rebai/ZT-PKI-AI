import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from data import FAMILY, clean_label  # noqa: E402
from schema import _CIC, _NFS, FEATURES, from_cic, from_nfstream  # noqa: E402


def _cic_row(**over):
    row = {f" {src}": 0.0 for src in _CIC}          # CIC headers carry a leading space
    row[" Destination Port"] = 443
    row.update({f" {k}": v for k, v in over.items()})
    return pd.DataFrame([row])


def test_both_extractors_produce_the_same_columns():
    nfs = {src: 0.0 for src in _NFS}
    nfs["dst_port"] = 22
    assert list(from_cic(_cic_row()).columns) == FEATURES
    assert list(from_nfstream(pd.DataFrame([nfs])).columns) == FEATURES


def test_cic_microseconds_become_milliseconds():
    out = from_cic(_cic_row(**{"Flow Duration": 2_000_000, "Flow IAT Mean": 5_000}))
    assert out.loc[0, "duration_ms"] == 2000.0
    assert out.loc[0, "iat_mean"] == 5.0


def test_derived_rates_are_recomputed_and_finite():
    out = from_cic(_cic_row(**{"Flow Duration": 0, "Total Fwd Packets": 3,
                               "Total Length of Fwd Packets": 300}))
    assert np.isfinite(out.to_numpy()).all()          # 0-ms flow must not yield inf
    assert out.loc[0, "bytes_per_pkt"] == 100.0


def test_negative_and_infinite_inputs_are_neutralised():
    out = from_cic(_cic_row(**{"Flow IAT Min": -12, "Flow IAT Max": np.inf}))
    assert out.loc[0, "iat_min"] == 0.0 and out.loc[0, "iat_max"] == 0.0


def test_port_buckets():
    out = from_cic(_cic_row(**{"Destination Port": 22}))
    assert out.loc[0, "port_ssh"] == 1.0 and out.loc[0, "port_web"] == 0.0 and out.loc[0, "port_low"] == 1.0


def test_mangled_web_attack_labels_are_normalised():
    assert clean_label(" Web Attack � XSS ") == "Web Attack - XSS"
    assert clean_label("Web Attack ï¿½ Sql Injection") == "Web Attack - Sql Injection"
    assert all(clean_label(k) in FAMILY for k in FAMILY)
