"""Audit checks TC1-TC5 of the Chapter 4 test table (design Section 4.7).

Each check returns {"id", "name", "status": PASS | FAIL | NOT_RUN | INFO, "detail": ...}.
A failed check never stops the run; it is recorded so the student can read it in audit.json.
"""
from __future__ import annotations

import re

import numpy as np

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _r(id_, name, status, detail):
    return {"id": id_, "name": name, "status": status, "detail": detail}


def tc1_ingestion(entries: dict, frames: dict) -> dict:
    """Hashes recorded; every row keeps its file and row number."""
    problems = []
    for key, e in entries.items():
        if not (HEX64.match(e["source_sha256"]) and HEX64.match(e["parquet_sha256"])):
            problems.append(f"{key}: hash missing or malformed")
        df = frames[key]
        if len(df) != e["rows"]:
            problems.append(f"{key}: manifest says {e['rows']} rows, frame has {len(df)}")
        if "src_row" not in df.columns or df["src_row"].isna().any():
            problems.append(f"{key}: src_row missing")
        elif not df["src_row"].is_monotonic_increasing or df["src_row"].duplicated().any():
            problems.append(f"{key}: src_row not unique and increasing")
    detail = {k: {"rows": e["rows"], "source_sha256": e["source_sha256"], "parquet_sha256": e["parquet_sha256"],
                  "first_src_row": int(frames[k]["src_row"].iloc[0]), "last_src_row": int(frames[k]["src_row"].iloc[-1])}
              for k, e in entries.items()}
    return _r("TC1", "Ingestion records hashes and keeps row IDs", "FAIL" if problems else "PASS",
              {"problems": problems, "sources": detail})


def tc2_labels(info_attack: dict | None, exp: dict) -> dict:
    """'A ttack' normalised; total Attack = Attack + 'A ttack'."""
    if info_attack is None:
        return _r("TC2", "'A ttack' label normalised", "NOT_RUN", "attack file not loaded in this stage")
    c = info_attack["label_counts_raw"]
    got = {"Normal": c.get("Normal", 0), "Attack": c.get("Attack", 0), "A ttack": c.get("A ttack", 0)}
    total_attack = info_attack["n_attack_rows_after_normalisation"]
    want_total = exp["attack_label"] + exp["a_ttack_label"]
    ok = (got["Normal"] == exp["normal_label"] and got["Attack"] == exp["attack_label"]
          and got["A ttack"] == exp["a_ttack_label"] and total_attack == want_total and info_attack["rows"] == exp["rows"])
    return _r("TC2", "'A ttack' label normalised", "PASS" if ok else "FAIL",
              {"counts_raw": c, "expected": {k: exp[k] for k in ("rows", "normal_label", "attack_label", "a_ttack_label")},
               "attack_rows_after_normalisation": total_attack, "expected_total_attack": want_total})


def tc3_gap(prep_info: dict, n_ingested_rows: int, exp_gaps: int | None, name: str) -> dict:
    """Gaps stay gaps: no rows created, no interpolation."""
    problems = []
    if prep_info["rows"] != n_ingested_rows:
        problems.append(f"row count changed: {n_ingested_rows} ingested, {prep_info['rows']} after preparation")
    gaps = prep_info["gaps"]
    if exp_gaps is not None and len(gaps) != exp_gaps:
        problems.append(f"expected {exp_gaps} gap(s), found {len(gaps)}")
    return _r("TC3", f"Gap not interpolated ({name})", "FAIL" if problems else "PASS",
              {"problems": problems, "gaps": gaps, "note": "step_s is the time between the two rows around the gap; missing seconds = step_s - 1"})


def tc4_split(ts_train, ts_cal, first_hold_ts, n, bounds) -> dict:
    i1, i2 = bounds
    ok = ts_train.iloc[-1] < ts_cal.iloc[0] and ts_cal.iloc[-1] < first_hold_ts
    return _r("TC4", "Split is time-ordered with no overlap", "PASS" if ok else "FAIL",
              {"train": [str(ts_train.iloc[0]), str(ts_train.iloc[-1]), int(i1)],
               "calibration": [str(ts_cal.iloc[0]), str(ts_cal.iloc[-1]), int(i2 - i1)],
               "holdout_first_timestamp": str(first_hold_ts), "holdout_rows": int(n - i2), "total_rows": int(n)})


def tc5_budget(shares: dict, budget: float, rule_share: float) -> dict:
    """Isolation forest flags at most the budget of calibration rows (the rule baseline has no tuned threshold)."""
    bad = {k: v for k, v in shares.items() if v > budget + 1e-12}
    return _r("TC5", "Calibration flags at most the budget of rows", "FAIL" if bad else "PASS",
              {"budget": budget, "isolation_forest_calibration_share_by_seed": shares,
               "rule_baseline_calibration_share_reported_not_set": rule_share})


def example_rows(df, rows_exp: list[dict]) -> dict:
    """Reproduce the report's example: Excel rows 1756 and 1757 of the attack file."""
    out, ok = [], True
    idx = df.set_index("src_row")
    for e in rows_exp:
        if e["src_row"] not in idx.index:
            out.append({"src_row": e["src_row"], "found": False})
            ok = False
            continue
        r = idx.loc[e["src_row"]]
        match = str(r["ts"]) == e["timestamp"] and str(r["label_raw"]).strip() == e["label"]
        ok &= match
        out.append({"src_row": e["src_row"], "timestamp": str(r["ts"]), "label": str(r["label_raw"]).strip(), "matches_report": bool(match)})
    return _r("EX1", "Example rows quoted in Section 3.4.1", "PASS" if ok else "FAIL", out)
