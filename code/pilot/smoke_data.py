"""Made-up SWaT-shaped files for testing the code end to end.

These are NOT SWaT data. They have the same layout as the 2015 workbooks (group header on
row 1, tag names on row 2, text timestamps, 'Normal/Attack' label) and contain the same
quirks the real attack file is known to have: an 'A ttack' label variant, one gap in the
timestamps, and an attack list with entries that have no end time or the wrong year.
Only the code is tested with them; nothing about the real detectors can be learned from them.
"""
from __future__ import annotations

import shutil
from datetime import datetime, time, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 20261114
N_NORMAL = 12_000
N_ATTACK = 14_400
GAP_AFTER_ROW = 6_000   # attack file: rows from 6000 on start 82 s later (between attacks 1 and 2)
GAP_S = 82
ATTACK_START = datetime(2015, 12, 31, 22, 0, 0)
NORMAL_START = datetime(2015, 12, 22, 16, 30, 0)
# (id, start, length_s, kind)
ATTACKS = [
    (1, datetime(2015, 12, 31, 23, 0, 0), 300, "range"),       # LIT101 +400: outside learned range
    (2, datetime(2016, 1, 1, 0, 30, 0), 400, "invariant"),     # MV101 forced open, FIT101 forced 0
    (3, datetime(2016, 1, 1, 1, 30, 0), 300, "small_bias"),    # AIT402 +1.0: small; a range check misses it
]


def _blocks(rng, n, on=(300, 700), off=(100, 300)):
    s = np.zeros(n, dtype=bool)
    i, state = 0, bool(rng.integers(0, 2))
    while i < n:
        d = int(rng.integers(*(on if state else off)))
        s[i:i + d] = state
        i += d
        state = not state
    return s


def _delay(x, d):
    out = np.zeros_like(x)
    out[d:] = x[:-d]
    return out


def _process(rng, tags, kinds, n):
    t = np.arange(n)
    df = {}
    a, b, c = _blocks(rng, n), _blocks(rng, n), _blocks(rng, n)
    flow = lambda on, d: np.clip(2.0 * _delay(on.astype(float), d) + rng.normal(0, 0.02, n), 0, None)
    for k, tag in enumerate(tags):
        if tag == "MV101":
            df[tag] = np.where(a, 2.0, 1.0)
        elif tag == "FIT101":
            df[tag] = flow(a, 8)
        elif tag == "P101":
            df[tag] = np.where(b, 2.0, 1.0)
        elif tag == "P102":
            df[tag] = np.ones(n)
        elif tag == "FIT201":
            df[tag] = flow(b, 12)
        elif tag == "P301":
            df[tag] = np.where(c, 2.0, 1.0)
        elif tag == "P302":
            df[tag] = np.where(~c, 2.0, 1.0)
        elif tag == "FIT301":
            df[tag] = flow(np.ones(n, dtype=bool), 10)
        elif kinds[tag] == "actuator":
            df[tag] = (2.0 if k % 2 == 0 else 1.0) * np.ones(n)   # constant state, same in every file
        elif tag.startswith("FIT"):
            df[tag] = np.clip(1.0 + rng.normal(0, 0.03, n), 0, None)
        else:
            base = 50 + 20 * k
            df[tag] = base + 5 * np.sin(2 * np.pi * t / (3000 + 37 * k)) + rng.normal(0, 0.5, n)
    return pd.DataFrame(df)


def _ts_text(d: datetime) -> str:
    h12 = d.hour % 12 or 12
    return f" {d:%d/%m/%Y} {h12}:{d:%M:%S} {'AM' if d.hour < 12 else 'PM'}"


def _write_workbook(path: Path, tags, ts_list, values: pd.DataFrame, labels):
    import openpyxl

    wb = openpyxl.Workbook(write_only=True)
    ws = wb.create_sheet("Sheet1")
    ws.append([None, "P1"] + [None] * (len(tags) + 1 - 1))
    ws.append([" Timestamp"] + list(tags) + ["Normal/Attack"])
    arr = values[tags].to_numpy()
    for i in range(len(ts_list)):
        ws.append([_ts_text(ts_list[i])] + arr[i].tolist() + [labels[i]])
    wb.save(path)


def make(out_dir="tests/data", tag_mapping=None):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)
    if tag_mapping is None:
        for cand in ("../research/chapter-3/analysis/tag_mapping_2015_2019.csv",
                     "../../research/chapter-3/analysis/tag_mapping_2015_2019.csv"):
            if Path(cand).exists():
                tag_mapping = cand
                break
    if tag_mapping is None or not Path(tag_mapping).exists():
        raise FileNotFoundError("Pass --tag-mapping with the path to tag_mapping_2015_2019.csv")
    m = pd.read_csv(tag_mapping)[["tag_2015", "kind", "status"]]
    m.to_csv(out / "tag_mapping_smoke.csv", index=False)
    tags = list(m["tag_2015"])
    kinds = dict(zip(m["tag_2015"], m["kind"]))

    # normal file
    ts = [NORMAL_START + timedelta(seconds=i) for i in range(N_NORMAL)]
    _write_workbook(out / "smoke_normal.xlsx", tags, ts, _process(rng, tags, kinds, N_NORMAL), ["Normal"] * N_NORMAL)

    # attack file: same process, attacks injected, one gap, a few 'A ttack' labels
    v = _process(rng, tags, kinds, N_ATTACK)
    labels = np.array(["Normal"] * N_ATTACK, dtype=object)
    for _id, start, length, kind in ATTACKS:
        i0 = int((start - ATTACK_START).total_seconds())
        sl = slice(i0, i0 + length)
        if kind == "range":
            v.loc[sl, "LIT101"] += 400
        elif kind == "invariant":
            v.loc[sl, "MV101"] = 2.0
            v.loc[sl, "FIT101"] = 0.0
        elif kind == "small_bias":
            v.loc[sl, "AIT402"] += 1.0
        labels[sl] = "Attack"
        labels[i0 + 10:i0 + 15] = "A ttack"
    secs = np.arange(N_ATTACK)
    secs = np.where(secs >= GAP_AFTER_ROW, secs + (GAP_S - 1), secs)
    ts = [ATTACK_START + timedelta(seconds=int(s)) for s in secs]
    _write_workbook(out / "smoke_attack.xlsx", tags, ts, v, labels.tolist())

    # attack list (same columns as List_of_attacks_Final.xlsx)
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Attack #", "Start Time", "End Time", "Attack Point", "Start State", "Attack", "Actual Change", "Intent", "Outcome"])
    for _id, start, length, kind in ATTACKS:
        i0 = int((start - ATTACK_START).total_seconds())
        shift = (GAP_S - 1) if i0 >= GAP_AFTER_ROW else 0
        s = start + timedelta(seconds=shift)
        e = s + timedelta(seconds=length - 1)
        if _id == 3:
            s_listed = s.replace(year=2015)  # the January-2015 typo of the real list (year wrong)
            ws.append([_id, s_listed, e.time(), kind, None, None, None, None, None])
        else:
            ws.append([_id, s, e.time(), kind, None, None, None, None, None])
    ws.append([4, datetime(2016, 1, 1, 1, 10, 0), None, "No Physical Impact Attack", None, None, None, None, None])
    wb.save(out / "smoke_attack_list.xlsx")
    print(f"Smoke data written to {out.resolve()}")
    return out
