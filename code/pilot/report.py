"""Environment record and the draft of Table 4.9 (Markdown)."""
from __future__ import annotations

import os
import platform
import sys
from importlib import metadata

import numpy as np
import pandas as pd


def environment() -> dict:
    env = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil
        env["memory_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    except Exception:
        env["memory_gb"] = None
    pkgs = {}
    for p in ("pandas", "numpy", "scikit-learn", "pyarrow", "openpyxl", "PyYAML", "psutil"):
        try:
            pkgs[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            pkgs[p] = None
    env["packages"] = pkgs
    return env


def _f(x, nd=4):
    return "n/a" if x is None or x != x else f"{x:.{nd}f}"


def _ms(vals, nd=4):
    v = np.array([x for x in vals if x == x], dtype=float)
    if len(v) == 0:
        return "n/a"
    sd = v.std(ddof=1) if len(v) > 1 else 0.0
    return f"{v.mean():.{nd}f} ± {sd:.{nd}f}"


def table_4_9(metrics: pd.DataFrame, pa: pd.DataFrame, fa: pd.DataFrame, timings: pd.DataFrame, env: dict, stage: str) -> str:
    lines = ["# Table 4.9 draft: 2015 detection pilot", "",
             f"Stage: **{stage}**. Row-level results are unadjusted, one-second rows (Chapter 3, Section 3.7.1).",
             "Isolation forest: mean ± sample SD over the seeds. The rule baseline is deterministic.", ""]
    att = metrics[metrics["split"] == "attack_file"]
    if att.empty:
        lines += ["No attack-file results in this stage."]
        return "\n".join(lines)
    lines += ["| Detector | Precision | Recall | F1 | FPR | Point-adjusted F1 | False-alarm episodes per hour (hold-out) | False-alarm rows per hour (hold-out) |",
              "|---|---|---|---|---|---|---|---|"]
    for det in ["rule_baseline", "isolation_forest"]:
        a = att[att["detector"] == det]
        p = pa[pa["detector"] == det]
        f = fa[fa["detector"] == det]
        lines.append(f"| {det} | {_ms(a['precision'])} | {_ms(a['recall'])} | {_ms(a['f1'])} | {_ms(a['fpr'], 5)} | "
                     f"{_ms(p['f1'])} | {_ms(f['episodes_per_hour'], 2)} | {_ms(f['alarm_rows_per_hour'], 1)} |")
    if (att["detector"] == "rule_baseline_excl_drift").any():
        d = att[att["detector"] == "rule_baseline_excl_drift"]
        lines += ["", "Diagnostic only (decision D8, not part of Table 4.9): rule baseline with the range check on the "
                  "drifting tags ignored: " f"precision {_ms(d['precision'])}, recall {_ms(d['recall'])}, F1 {_ms(d['f1'])}, "
                  f"FPR {_ms(d['fpr'], 5)}. All results for it are in the CSV files under detector `rule_baseline_excl_drift`."]
    t = timings.assign(group=timings["step"].str.replace(r"_seed\d+$", "", regex=True)).groupby("group", sort=False)["seconds"].sum().round(1)
    lines += ["", "Run time per step (seconds; the isolation-forest steps add up the seeds):", ""]
    lines += [f"- {k}: {v}" for k, v in t.items()]
    lines += ["", f"Hardware: {env.get('processor')}, {env.get('cpu_count')} logical CPUs, {env.get('memory_gb')} GB, {env.get('platform')}; Python {env.get('python')}."]
    return "\n".join(lines)
