"""The whole pilot in one call: ingest -> audit -> split -> detectors -> metrics -> files.

Stages (config key `stage`)
  dev    development. Only the training and calibration parts of the NORMAL file are read.
         The attack file and the normal hold-out are never loaded or scored.
  pilot  the real run. Refuses to start unless Expected_Outcomes.md exists and its SHA-256
         equals the hash written in the config (the freeze rule, Chapter 4 Plan Section 8a).
  smoke  made-up files under tests/data only; used to test the code end to end.
"""
from __future__ import annotations

import json
import shutil
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from . import audit as A
from .attacks import load_attack_list
from .config import ConfigError, resolve, sha256_file
from .detectors import IsolationForestDetector, RuleBaseline
from .ingest import ingest
from .metrics import alarm_episodes, confusion, per_attack_recall, point_adjust, prf
from .prep import load_tag_mapping, prepare, split_bounds, parse_timestamps
from .report import environment, table_4_9


class GateError(ConfigError):
    pass


def _log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


class Timer:
    def __init__(self):
        self.rows = []

    @contextmanager
    def step(self, name):
        t = time.perf_counter()
        yield
        self.rows.append({"step": name, "seconds": round(time.perf_counter() - t, 3)})

    def frame(self):
        return pd.DataFrame(self.rows)


def check_gate(cfg: dict, log=_log) -> dict:
    """Mechanical version of the student's rule: no run on the attack file or hold-out before Part A is frozen."""
    stage = cfg["stage"]
    if stage == "dev":
        return {"stage": "dev", "note": "attack file and normal hold-out are not loaded"}
    if stage == "smoke":
        smoke_dir = (Path(cfg["_root"]) / "tests" / "data").resolve()
        for k in ("normal_xlsx", "attack_xlsx", "attack_list_xlsx"):
            p = resolve(cfg, cfg["data"][k])
            if smoke_dir not in p.parents:
                raise GateError(f"smoke stage may only read made-up files under {smoke_dir}; {k} points to {p}")
        return {"stage": "smoke", "note": "made-up files only"}
    eo = cfg.get("expected_outcomes") or {}
    path = resolve(cfg, eo.get("path", "")) if eo.get("path") else None
    if path is None or not path.exists():
        raise GateError(
            "STOP: the pilot stage needs the frozen Expected Outcomes file, and it was not found at "
            f"{path}. Part A must be written, reviewed and frozen before the pilot is run.")
    actual = sha256_file(path)
    want = eo.get("sha256")
    if not want:
        raise GateError(
            "STOP: expected_outcomes.sha256 is empty in the config. After you freeze Part A, run\n"
            f'  Get-FileHash "{path}"\nwrite the hash in the logbook AND paste it into the config, then run again.')
    if actual.lower() != str(want).lower():
        raise GateError(
            "STOP: Expected_Outcomes.md has changed since it was frozen.\n"
            f"  hash in config: {want}\n  hash of file:   {actual}\n"
            "Any later note must be a dated addendum, and the hash then needs to be re-frozen and re-recorded.")
    log(f"Freeze gate passed: Expected_Outcomes.md SHA-256 {actual[:16]}... matches the config")
    return {"stage": "pilot", "expected_outcomes_path": str(path), "expected_outcomes_sha256": actual}


def run(cfg: dict, log=_log) -> Path:
    stage = cfg["stage"]
    gate = check_gate(cfg, log)
    data = cfg["data"]
    cache_dir = resolve(cfg, data["cache_dir"])
    runs_dir = resolve(cfg, data["runs_dir"])
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")  # local time, as in the logbook
    run_dir = runs_dir / f"{stamp}_{cfg['_config_sha256'][:8]}_{stage}"
    run_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy(cfg["_config_path"], run_dir / "config_used.yaml")
    env = environment()
    (run_dir / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    log(f"Run folder: {run_dir}")
    log(f"Stage: {stage}. Config SHA-256: {cfg['_config_sha256']}")
    timer = Timer()
    budget = cfg["detection_budget"]
    merge_gap = cfg["events"]["merge_gap_s"]
    seeds = cfg["isolation_forest"]["seeds"]
    expected = cfg.get("expected_audit", {})

    # ---- ingestion (module 1) -------------------------------------------------
    mapping_path = resolve(cfg, data["tag_mapping_csv"])
    mapping = load_tag_mapping(mapping_path)
    entries, frames = {}, {}
    log("Ingestion: normal file")
    with timer.step("ingest_normal"):
        dfN, eN = ingest("normal", resolve(cfg, data["normal_xlsx"]), cache_dir, log=log)
    entries["normal"], frames["normal"] = eN, dfN
    n_total = len(dfN)
    i1, i2 = split_bounds(n_total, cfg["split"]["train"], cfg["split"]["calibration"])

    dfA = eA = None
    if stage != "dev":
        log("Ingestion: attack file")
        with timer.step("ingest_attack"):
            dfA, eA = ingest("attack", resolve(cfg, data["attack_xlsx"]), cache_dir, log=log)
        entries["attack"], frames["attack"] = eA, dfA

    # ---- preprocessing (module 2) ---------------------------------------------
    hold_first_ts = parse_timestamps(dfN["timestamp_raw"].iloc[[i2]]).iloc[0]
    if stage == "dev":
        dfN = dfN.iloc[:i2]  # the hold-out rows are dropped here and never used again
    with timer.step("prep_normal"):
        N, infoN = prepare(dfN, mapping, cfg.get("expected_n_tags", 51))
    infoN["rows"] = len(N)
    kept = infoN["kept_tags"]
    train, cal = N.iloc[:i1], N.iloc[i1:i2]
    hold = N.iloc[i2:] if stage != "dev" else None
    if infoN["label_counts_raw"].get("Attack", 0) or infoN["label_counts_raw"].get("A ttack", 0):
        log("  WARNING: the normal file contains rows labelled Attack")

    AF, infoA = None, None
    if stage != "dev":
        with timer.step("prep_attack"):
            AF, infoA = prepare(dfA, mapping, cfg.get("expected_n_tags", 51))
        infoA["n_attack_rows_after_normalisation"] = int(AF["y"].sum())

    audit_results = [A.tc1_ingestion(entries, frames)]
    audit_results.append(A.tc2_labels(infoA, expected.get("attack_file", {})) if infoA else A.tc2_labels(None, {}))
    audit_results.append(A.tc3_gap(infoN, len(dfN), expected.get("normal_gaps"), "normal file"))
    if infoA:
        audit_results.append(A.tc3_gap(infoA, len(dfA), expected.get("attack_gaps"), "attack file"))
        if expected.get("example_rows"):
            audit_results.append(A.example_rows(AF, expected["example_rows"]))
    audit_results.append(A.tc4_split(train["ts"], cal["ts"], hold_first_ts, n_total, (i1, i2)))
    log(f"Split (time order): train {len(train):,} | calibration {len(cal):,} | hold-out {n_total - i2:,} rows; {len(kept)} kept tags")

    sets = {"calibration": cal}
    if stage != "dev":
        sets["normal_holdout"] = hold
        sets["attack_file"] = AF

    attacks_scored, attacks_unscored = [], []
    if stage != "dev":
        attacks_scored, attacks_unscored = load_attack_list(
            resolve(cfg, data["attack_list_xlsx"]), AF["ts"].iloc[0], AF["ts"].iloc[-1], log=log)
        log(f"Attack list: {len(attacks_scored)} attacks with a time window, {len(attacks_unscored)} without an end time")

    # ---- detector 1: rule baseline --------------------------------------------
    rb_cfg = cfg["rule_baseline"]
    log("Rule baseline: fitting on the training split")
    with timer.step("rule_fit"):
        rule = RuleBaseline(kept, rb_cfg["rules"], rb_cfg["flow_above"], rb_cfg["delay_grid_max_s"], rb_cfg["max_violation_share"],
                            rb_cfg.get("range_margin_fraction", 0.0), rb_cfg.get("range_exclude_tags", []),
                            rb_cfg.get("diagnostic_exclude_tags", [])).fit(train)
    for rid, d in rule.delays.items():
        log(f"  {rid} {d['rule_name']}: learned delay {d['delay_s']} s (violation share {d['violation_share_at_delay']:.5f} on {d['support_rows']:,} rows)")
    preds = {s: {} for s in sets}
    rule_out = {}
    with timer.step("rule_predict"):
        for s, df in sets.items():
            rule_out[s] = rule.predict(df)

    # ---- detector 2: isolation forest -----------------------------------------
    if_out = {s: {} for s in sets}
    if_thr, if_cal_share = {}, {}
    for seed in seeds:
        log(f"Isolation forest seed {seed}: fitting")
        det = IsolationForestDetector(kept, cfg["isolation_forest"]["n_estimators"], seed, cfg["isolation_forest"].get("max_samples", "auto"))
        with timer.step(f"if_fit_seed{seed}"):
            det.fit(train)
        with timer.step(f"if_calibrate_seed{seed}"):
            thr = det.calibrate(cal, budget)
        if_thr[seed] = thr
        with timer.step(f"if_score_seed{seed}"):
            for s, df in sets.items():
                sc = det.score(df)
                if_out[s][seed] = (sc, det.predict(sc))
        if_cal_share[seed] = float(if_out["calibration"][seed][1].mean())
    audit_results.append(A.tc5_budget({str(k): v for k, v in if_cal_share.items()}, budget, float(rule_out["calibration"]["alarm"].mean())))

    # ---- evaluation ------------------------------------------------------------
    mrows, parows, farows, pa_rows = [], [], [], []

    def add_metrics(split, det, seed, y, alarm):
        c = confusion(y, alarm)
        mrows.append({"detector": det, "seed": seed, "split": split, "rows": len(y), "positives": int(np.sum(y)),
                      "alarms": int(np.sum(alarm)), **c, **prf(c), "alarm_share": float(np.mean(alarm))})

    def add_fa(split, det, seed, df, alarm):
        hours = (df["t_s"].iloc[-1] - df["t_s"].iloc[0] + 1) / 3600.0
        ep = alarm_episodes(alarm, df["t_s"].to_numpy(), merge_gap)
        n_al = int(np.sum(alarm))
        farows.append({"detector": det, "seed": seed, "split": split, "hours": hours, "alarm_rows": n_al,
                       "alarm_rows_per_hour": n_al / hours, "episodes": ep, "episodes_per_hour": ep / hours})

    with timer.step("evaluate"):
        for s, df in sets.items():
            y = df["y"].to_numpy()
            ra = rule_out[s]["alarm"].to_numpy()
            add_metrics(s, "rule_baseline", "", y, ra)
            if s != "attack_file":
                add_fa(s, "rule_baseline", "", df, ra)
            has_diag = "alarm_excl_drift" in rule_out[s]
            if has_diag:  # decision D8: diagnostic only, never the primary result
                rd = rule_out[s]["alarm_excl_drift"].to_numpy()
                add_metrics(s, "rule_baseline_excl_drift", "", y, rd)
                if s != "attack_file":
                    add_fa(s, "rule_baseline_excl_drift", "", df, rd)
            for seed in seeds:
                ia = if_out[s][seed][1]
                add_metrics(s, "isolation_forest", seed, y, ia)
                if s != "attack_file":
                    add_fa(s, "isolation_forest", seed, df, ia)
            if s == "attack_file":
                diag = [("rule_baseline_excl_drift", "", rd)] if has_diag else []
                for det, seed, alarm in [("rule_baseline", "", ra)] + diag + [("isolation_forest", sd, if_out[s][sd][1]) for sd in seeds]:
                    adj = point_adjust(y, alarm)
                    c = confusion(y, adj)
                    pa_rows.append({"detector": det, "seed": seed, **c, **prf(c)})
                    for r in per_attack_recall(attacks_scored, df["ts"], alarm):
                        a = next(x for x in attacks_scored if x["id"] == r["attack_id"])
                        parows.append({"detector": det, "seed": seed, **r, "start": a["start"], "end": a["end"],
                                       "point": a["point"], "year_corrected": a["year_corrected"]})

    metrics = pd.DataFrame(mrows)
    pa = pd.DataFrame(pa_rows)
    fa = pd.DataFrame(farows)
    per_attack = pd.DataFrame(parows)
    timings = timer.frame()

    # ---- write everything -----------------------------------------------------
    metrics.to_csv(run_dir / "metrics_rowlevel.csv", index=False)
    if not pa.empty:
        pa.to_csv(run_dir / "metrics_point_adjusted.csv", index=False)
        per_attack.to_csv(run_dir / "per_attack_recall.csv", index=False)
        pd.DataFrame(attacks_unscored).to_csv(run_dir / "attacks_not_scored.csv", index=False)
    fa.to_csv(run_dir / "false_alarms.csv", index=False)
    timings.to_csv(run_dir / "timings.csv", index=False)
    (run_dir / "audit.json").write_text(json.dumps(audit_results, indent=2, default=str), encoding="utf-8")
    (run_dir / "thresholds.json").write_text(json.dumps({
        "rule_baseline": rule.describe(),
        "isolation_forest": {"budget": budget, "n_estimators": cfg["isolation_forest"]["n_estimators"],
                             "score_threshold_by_seed": {str(k): v for k, v in if_thr.items()},
                             "calibration_alarm_share_by_seed": {str(k): v for k, v in if_cal_share.items()}},
    }, indent=2), encoding="utf-8")
    pred_parts = []
    for s, df in sets.items():
        p = pd.DataFrame({"split": s, "src_row": df["src_row"].to_numpy(), "ts": df["ts"].to_numpy(), "y": df["y"].to_numpy()})
        for c in rule_out[s].columns:
            p[f"rule_{c}"] = rule_out[s][c].to_numpy()
        for seed in seeds:
            p[f"if{seed}_score"] = if_out[s][seed][0]
            p[f"if{seed}_alarm"] = if_out[s][seed][1]
        pred_parts.append(p)
    pd.concat(pred_parts, ignore_index=True).to_parquet(run_dir / "predictions.parquet", index=False)
    pd.DataFrame({s: rule.out_of_range_share(df) for s, df in sets.items()}).rename_axis("tag").reset_index().to_csv(
        run_dir / "rule_range_share_by_tag.csv", index=False)
    manifest = {"stage": stage, "gate": gate, "config_sha256": cfg["_config_sha256"], "code_version": __import__("pilot").__version__,
                "sources": entries, "tag_mapping_csv": {"path": str(mapping_path), "sha256": sha256_file(mapping_path)}}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    summary = table_4_9(metrics, pa, fa[fa["split"] == "normal_holdout"] if not fa.empty else fa, timings, env, stage)
    (run_dir / "table_4_9_draft.md").write_text(summary, encoding="utf-8")

    # ---- console summary -------------------------------------------------------
    log("Audit checks:")
    for r in audit_results:
        log(f"  {r['id']} {r['status']:8s} {r['name']}")
    log("Calibration alarm share: rule baseline {:.4f}; isolation forest {}".format(
        float(rule_out["calibration"]["alarm"].mean()), {k: round(v, 4) for k, v in if_cal_share.items()}))
    log(f"Done. Results are in {run_dir}")
    return run_dir
