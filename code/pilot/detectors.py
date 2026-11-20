"""Detectors for the 2015 pilot (Chapter 3, Section 3.6; design Section 4.5).

RuleBaseline   : min/max of each kept tag from the training split, plus three actuator -> flow
                 rules, each with a delay learned from the training split.
IsolationForest: trained on the training split only; alarm threshold = score above which
                 `budget` (1%) of calibration rows lie.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class DetectorError(Exception):
    pass


def run_length(cond: np.ndarray, new_segment: np.ndarray) -> np.ndarray:
    """Number of consecutive rows (ending at each row) for which `cond` has been True.

    A run is also cut at a gap (new_segment True), so a gap is never bridged. At 1 Hz the
    value equals the number of seconds the condition has held.
    """
    cond = np.asarray(cond, dtype=bool)
    seg = np.asarray(new_segment, dtype=bool)
    n = len(cond)
    if n == 0:
        return np.zeros(0, dtype=np.int64)
    prev = np.empty(n, dtype=bool)
    prev[0] = False
    prev[1:] = cond[:-1]
    start = cond & (~prev | seg)
    idx = np.arange(n)
    last_start = np.maximum.accumulate(np.where(start, idx, -1))
    return np.where(cond, idx - last_start + 1, 0)


def threshold_for_budget(scores: np.ndarray, budget: float) -> float:
    """Score above which at most `budget` of the rows lie (never more than the budget)."""
    s = np.sort(np.asarray(scores, dtype=float))[::-1]
    k = int(np.floor(budget * len(s)))
    return float(s[k]) if k < len(s) else float(s[-1])


def _rule_condition(df: pd.DataFrame, rule: dict) -> np.ndarray:
    cond = np.zeros(len(df), dtype=bool)
    for c in rule["when_any"]:
        cond |= (df[c["tag"]].to_numpy() == c["equals"])
    return cond


class RuleBaseline:
    def __init__(self, kept_tags, rules, flow_above=0.1, delay_grid_max_s=120, max_violation_share=0.0,
                 range_margin_fraction=0.0, range_exclude_tags=(), diagnostic_exclude_tags=()):
        """range_margin_fraction and range_exclude_tags default to the Chapter 3 rule (plain training min/max on
        every kept tag). They exist only so a design change can be made in the config, not in the code.

        diagnostic_exclude_tags (decision D8): if set, predict() also returns `alarm_excl_drift`, the same
        alarm with the range check on these tags ignored. It is a diagnostic only; `alarm` is unchanged."""
        self.kept = list(kept_tags)
        self.margin = float(range_margin_fraction)
        self.excluded = list(range_exclude_tags)
        for t in self.excluded:
            if t not in self.kept:
                raise DetectorError(f"range_exclude_tags: {t} is not a kept tag")
        self.range_tags = [t for t in self.kept if t not in self.excluded]
        self.diag_excluded = list(diagnostic_exclude_tags)
        for t in self.diag_excluded:
            if t not in self.kept:
                raise DetectorError(f"diagnostic_exclude_tags: {t} is not a kept tag")
        self.diag_tags = [t for t in self.range_tags if t not in self.diag_excluded]
        self.rules = rules
        self.flow_above = float(flow_above)
        self.grid_max = int(delay_grid_max_s)
        self.max_viol = float(max_violation_share)
        for r in rules:
            for c in r["when_any"]:
                if c["tag"] not in self.kept:
                    raise DetectorError(f"rule {r['id']} uses {c['tag']}, which is not a kept tag")
            if r["flow_tag"] not in self.kept:
                raise DetectorError(f"rule {r['id']} uses {r['flow_tag']}, which is not a kept tag")
        self.lo = self.hi = None
        self.delays: dict[str, dict] = {}

    def fit(self, train: pd.DataFrame) -> "RuleBaseline":
        X = train[self.kept]
        span = X.max() - X.min()
        self.lo = X.min() - self.margin * span
        self.hi = X.max() + self.margin * span
        seg = train["new_segment"].to_numpy()
        for r in self.rules:
            cond = _rule_condition(train, r)
            viol = train[r["flow_tag"]].to_numpy() <= self.flow_above
            runs = run_length(cond, seg)
            found = None
            for L in range(1, self.grid_max + 1):
                m = runs >= L
                n = int(m.sum())
                if n == 0:
                    break
                share = float((m & viol).sum()) / n
                if share <= self.max_viol:
                    found = {"delay_s": L, "support_rows": n, "violation_share_at_delay": share}
                    break
            if found is None:
                raise DetectorError(
                    f"Rule {r['id']} ({r['name']}): no delay up to {self.grid_max} s keeps the violation share "
                    f"of the training split at or below {self.max_viol}. Check the rule or the grid.")
            found["rule_name"] = r["name"]
            self.delays[r["id"]] = found
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        if self.lo is None:
            raise DetectorError("fit() first")
        X = df[self.range_tags]
        out = pd.DataFrame(index=df.index)
        out["range_alarm"] = ((X < self.lo[self.range_tags]) | (X > self.hi[self.range_tags])).any(axis=1).to_numpy()
        seg = df["new_segment"].to_numpy()
        inv_any = np.zeros(len(df), dtype=bool)
        for r in self.rules:
            cond = _rule_condition(df, r)
            runs = run_length(cond, seg)
            viol = df[r["flow_tag"]].to_numpy() <= self.flow_above
            a = (runs >= self.delays[r["id"]]["delay_s"]) & viol
            out[f"inv_{r['id']}"] = a
            inv_any |= a
        out["invariant_alarm"] = inv_any
        out["alarm"] = out["range_alarm"].to_numpy() | inv_any
        if self.diag_excluded:
            Xd = df[self.diag_tags]
            rd = ((Xd < self.lo[self.diag_tags]) | (Xd > self.hi[self.diag_tags])).any(axis=1).to_numpy()
            out["range_alarm_excl_drift"] = rd
            out["alarm_excl_drift"] = rd | inv_any
        return out

    def out_of_range_share(self, df: pd.DataFrame) -> pd.Series:
        """Share of rows in which each tag is outside its training range (diagnostic, all kept tags)."""
        X = df[self.kept]
        return ((X < self.lo) | (X > self.hi)).mean()

    def describe(self) -> dict:
        return {
            "n_tags": len(self.kept),
            "range_margin_fraction": self.margin,
            "range_excluded_tags": self.excluded,
            "diagnostic_excluded_tags": self.diag_excluded,
            "flow_above": self.flow_above,
            "range": {t: [float(self.lo[t]), float(self.hi[t])] for t in self.kept},
            "delays": self.delays,
        }


class IsolationForestDetector:
    def __init__(self, kept_tags, n_estimators=100, seed=0, max_samples="auto"):
        self.kept = list(kept_tags)
        self.model = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                                     contamination="auto", random_state=seed, n_jobs=1)
        self.seed = seed
        self.threshold = None

    def fit(self, train: pd.DataFrame) -> "IsolationForestDetector":
        self.model.fit(train[self.kept].to_numpy(dtype=float))
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Anomaly score: higher = more anomalous (the negative of sklearn's score_samples)."""
        return -self.model.score_samples(df[self.kept].to_numpy(dtype=float))

    def calibrate(self, cal: pd.DataFrame, budget: float) -> float:
        self.threshold = threshold_for_budget(self.score(cal), budget)
        return self.threshold

    def predict(self, scores: np.ndarray) -> np.ndarray:
        if self.threshold is None:
            raise DetectorError("calibrate() first")
        return scores > self.threshold
