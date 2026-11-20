"""Detection measures (Chapter 3, Section 3.7.1, Table 3.6).

Primary: unadjusted one-second-row precision, recall, F1, false-positive rate.
Secondary: recall per attack, point-adjusted F1 (counting rule written next to each result),
false alarms per hour on the normal hold-out.
"""
from __future__ import annotations

import numpy as np

NAN = float("nan")


def confusion(y: np.ndarray, p: np.ndarray) -> dict:
    y = np.asarray(y).astype(bool)
    p = np.asarray(p).astype(bool)
    return {"tp": int((y & p).sum()), "fp": int((~y & p).sum()), "fn": int((y & ~p).sum()), "tn": int((~y & ~p).sum())}


def _div(a, b):
    return a / b if b else NAN


def prf(c: dict) -> dict:
    prec = _div(c["tp"], c["tp"] + c["fp"])
    rec = _div(c["tp"], c["tp"] + c["fn"])
    f1 = _div(2 * prec * rec, prec + rec) if (prec == prec and rec == rec) else NAN
    fpr = _div(c["fp"], c["fp"] + c["tn"])
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr}


def label_segments(y: np.ndarray) -> list[tuple[int, int]]:
    """Contiguous runs of y == 1 as (start, end) row positions, end inclusive."""
    y = np.asarray(y).astype(np.int8)
    if len(y) == 0:
        return []
    d = np.diff(np.concatenate(([0], y, [0])))
    starts = np.flatnonzero(d == 1)
    ends = np.flatnonzero(d == -1) - 1
    return list(zip(starts.tolist(), ends.tolist()))


def point_adjust(y: np.ndarray, p: np.ndarray) -> np.ndarray:
    """Counting rule: if any alarm falls inside a labelled attack run, the whole run counts as detected."""
    adj = np.asarray(p).astype(bool).copy()
    for s, e in label_segments(y):
        if adj[s:e + 1].any():
            adj[s:e + 1] = True
    return adj


def alarm_episodes(alarm: np.ndarray, t_s: np.ndarray, merge_gap_s: float) -> int:
    """Alarm rows closer than or equal to merge_gap_s apart count as one episode (same rule as event merging, P1)."""
    t = np.asarray(t_s, dtype=float)[np.asarray(alarm).astype(bool)]
    if len(t) == 0:
        return 0
    return int(1 + (np.diff(t) > merge_gap_s).sum())


def per_attack_recall(attacks: list[dict], ts, alarm: np.ndarray) -> list[dict]:
    """Share of rows inside each logged attack window that raise an alarm; detected = at least one alarm."""
    alarm = np.asarray(alarm).astype(bool)
    out = []
    for a in attacks:
        m = ((ts >= a["start"]) & (ts <= a["end"])).to_numpy()
        n = int(m.sum())
        k = int(alarm[m].sum())
        out.append({"attack_id": a["id"], "window_rows": n, "flagged_rows": k,
                    "recall": _div(k, n), "detected": bool(k > 0) if n else None})
    return out
