"""Module 2: preprocessing of the 2015 data (Chapter 3, Section 3.5.2; design F3, F6).

- parse timestamps (text such as ' 22/12/2015 4:30:00 PM'); gaps are left as gaps
- normalise labels ('A ttack' -> Attack); keep the raw label
- flag impossible readings (negative sensor values) instead of deleting them
- keep only the tags that passed the 2019 mapping check
- time-ordered 70/15/15 split
"""
from __future__ import annotations

import numpy as np
import pandas as pd

TS_FORMAT = "%d/%m/%Y %I:%M:%S %p"
GAP_FACTOR = 1.5  # a step of more than 1.5 s between rows is a gap (rows are 1 Hz)


class PrepError(Exception):
    pass


def parse_timestamps(raw: pd.Series) -> pd.Series:
    s = raw.astype(str).str.strip()
    ts = pd.to_datetime(s, format=TS_FORMAT, errors="coerce")
    bad = ts.isna()
    if bad.any():
        fallback = pd.to_datetime(s[bad], dayfirst=True, errors="coerce", format="mixed")
        ts = ts.copy()
        ts[bad] = fallback
    if ts.isna().any():
        first = s[ts.isna()].head(3).tolist()
        raise PrepError(f"{int(ts.isna().sum())} timestamps could not be parsed, for example {first}")
    return ts


def normalise_labels(label_raw: pd.Series) -> tuple[np.ndarray, dict]:
    """Return y (1 = Attack) and the counts of each raw label variant."""
    counts = label_raw.astype(str).str.strip().value_counts().to_dict()
    key = label_raw.astype(str).str.replace(r"\s+", "", regex=True).str.lower()
    mapped = key.map({"normal": 0, "attack": 1})
    if mapped.isna().any():
        unknown = sorted(set(label_raw[mapped.isna()].astype(str)))
        raise PrepError(f"Unknown label values: {unknown}")
    return mapped.to_numpy(dtype=np.int8), {str(k): int(v) for k, v in counts.items()}


def load_tag_mapping(csv_path) -> pd.DataFrame:
    m = pd.read_csv(csv_path)
    need = {"tag_2015", "kind", "status"}
    if not need <= set(m.columns):
        raise PrepError(f"{csv_path} must contain columns {sorted(need)}")
    return m


def prepare(df: pd.DataFrame, mapping: pd.DataFrame, expected_n_tags: int = 51) -> tuple[pd.DataFrame, dict]:
    """Add ts, t_s, dt, new_segment, y and quality flags. Rows are never deleted or created."""
    info: dict = {}
    all_tags = list(mapping["tag_2015"])
    missing = [t for t in all_tags if t not in df.columns]
    if missing:
        raise PrepError(f"Tags in the mapping file but not in the workbook: {missing}")
    extra = [c for c in df.columns if c not in all_tags + ["src_row", "timestamp_raw", "label_raw"]]
    if extra:
        raise PrepError(f"Workbook columns not in the mapping file: {extra}")
    if len(all_tags) != expected_n_tags:
        raise PrepError(f"Expected {expected_n_tags} tags, mapping has {len(all_tags)}")
    kept = list(mapping.loc[mapping["status"] == "kept", "tag_2015"])
    sensors = list(mapping.loc[mapping["kind"] == "sensor", "tag_2015"])

    out = df.copy()
    out["ts"] = parse_timestamps(out["timestamp_raw"])
    out["t_s"] = (out["ts"] - out["ts"].iloc[0]).dt.total_seconds()
    if not out["ts"].is_monotonic_increasing:
        raise PrepError("Timestamps are not in increasing order")
    dt = out["t_s"].diff()
    out["dt"] = dt
    out["new_segment"] = (dt.isna()) | (dt > GAP_FACTOR)
    info["rows"] = int(len(out))
    info["median_dt_s"] = float(dt.median())
    gaps = out.loc[dt > GAP_FACTOR, ["src_row", "ts", "dt"]]
    info["gaps"] = [{"before_src_row": int(r.src_row), "at": str(r.ts), "step_s": float(r.dt)} for r in gaps.itertuples()]

    y, label_counts = normalise_labels(out["label_raw"])
    out["y"] = y
    info["label_counts_raw"] = label_counts

    # quality flags (rows are kept)
    out["q_negative"] = (out[sensors] < 0).any(axis=1)
    miss = out[kept].isna()
    out["q_missing"] = miss.any(axis=1)
    info["n_rows_negative_sensor"] = int(out["q_negative"].sum())
    info["n_rows_missing_kept_tag"] = int(out["q_missing"].sum())
    if out["q_missing"].any():
        # documented fallback: carry the last value forward (no rows are removed)
        out[kept] = out[kept].ffill().bfill()
    info["kept_tags"] = kept
    info["n_kept_tags"] = len(kept)
    return out, info


def split_bounds(n: int, train: float, calibration: float) -> tuple[int, int]:
    """Row boundaries of the time-ordered split: [0,i1) train, [i1,i2) calibration, [i2,n) hold-out."""
    i1 = int(round(n * train))
    i2 = i1 + int(round(n * calibration))
    return i1, i2
