"""Tests for the pilot code. Run from the code folder:   python -m unittest discover -s tests -v

The end-to-end tests use made-up files (tests/data, made by `python -m pilot make-smoke-data`).
No SWaT attack data or normal hold-out is read by any test.
"""
import copy
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pilot import metrics as M
from pilot.config import load_config
from pilot.detectors import DetectorError, RuleBaseline, run_length, threshold_for_budget
from pilot.ingest import IngestError, ingest
from pilot.pipeline import GateError, check_gate, run
from pilot.prep import PrepError, normalise_labels, parse_timestamps, split_bounds

DATA = ROOT / "tests" / "data"


def ensure_smoke_data():
    if not (DATA / "smoke_normal.xlsx").exists():
        from pilot.smoke_data import make
        make(str(DATA))


class TestBuildingBlocks(unittest.TestCase):
    def test_run_length_counts_and_cuts_at_gap(self):
        cond = np.array([0, 1, 1, 1, 0, 1, 1, 1, 1], dtype=bool)
        seg = np.zeros(9, dtype=bool)
        self.assertEqual(run_length(cond, seg).tolist(), [0, 1, 2, 3, 0, 1, 2, 3, 4])
        seg[7] = True  # a gap before row 7 restarts the count
        self.assertEqual(run_length(cond, seg).tolist(), [0, 1, 2, 3, 0, 1, 2, 1, 2])

    def test_threshold_never_flags_more_than_budget_even_with_ties(self):
        rng = np.random.default_rng(0)
        for scores in (rng.normal(size=1000), np.round(rng.normal(size=1000), 1), np.ones(1000)):
            thr = threshold_for_budget(scores, 0.01)
            self.assertLessEqual((scores > thr).mean(), 0.01)
        scores = np.arange(1000, dtype=float)
        self.assertEqual(int((scores > threshold_for_budget(scores, 0.01)).sum()), 10)

    def test_split_bounds_match_chapter_3(self):
        self.assertEqual(split_bounds(495_000, 0.70, 0.15), (346_500, 420_750))

    def test_labels_a_ttack_is_attack(self):
        y, counts = normalise_labels(pd.Series(["Normal", "Attack", "A ttack", " Attack "]))
        self.assertEqual(y.tolist(), [0, 1, 1, 1])
        self.assertEqual(counts["A ttack"], 1)
        with self.assertRaises(PrepError):
            normalise_labels(pd.Series(["Normal", "Maybe"]))

    def test_timestamps_12_hour_clock(self):
        ts = parse_timestamps(pd.Series([" 28/12/2015 10:29:14 AM", " 28/12/2015 12:00:00 AM", " 28/12/2015 12:30:00 PM", " 28/12/2015 4:30:00 PM"]))
        self.assertEqual([t.strftime("%H:%M:%S") for t in ts], ["10:29:14", "00:00:00", "12:30:00", "16:30:00"])

    def test_confusion_and_measures(self):
        y = np.array([0, 0, 1, 1, 1, 0])
        p = np.array([0, 1, 1, 0, 0, 0])
        c = M.confusion(y, p)
        self.assertEqual(c, {"tp": 1, "fp": 1, "fn": 2, "tn": 2})
        r = M.prf(c)
        self.assertAlmostEqual(r["precision"], 0.5)
        self.assertAlmostEqual(r["recall"], 1 / 3)
        self.assertAlmostEqual(r["fpr"], 1 / 3)
        self.assertTrue(np.isnan(M.prf({"tp": 0, "fp": 0, "fn": 0, "tn": 5})["precision"]))

    def test_point_adjust_counts_whole_run_when_any_alarm(self):
        y = np.array([0, 1, 1, 1, 0, 1, 1, 0])
        p = np.array([0, 0, 1, 0, 0, 0, 0, 0])
        self.assertEqual(M.point_adjust(y, p).astype(int).tolist(), [0, 1, 1, 1, 0, 0, 0, 0])
        self.assertEqual(M.label_segments(y), [(1, 3), (5, 6)])

    def test_alarm_episodes_merge_gap_is_inclusive(self):
        t = np.arange(30, dtype=float)
        a = np.zeros(30, dtype=bool)
        a[[2, 7]] = True      # 5 s apart -> one episode
        a[[15, 21]] = True    # 6 s apart -> two episodes
        self.assertEqual(M.alarm_episodes(a, t, 5), 3)
        self.assertEqual(M.alarm_episodes(np.zeros(5, dtype=bool), t[:5], 5), 0)

    def test_per_attack_recall(self):
        ts = pd.Series(pd.date_range("2016-01-01 10:00:00", periods=20, freq="s"))
        alarm = np.zeros(20, dtype=bool)
        alarm[5:8] = True
        att = [{"id": 1, "start": pd.Timestamp("2016-01-01 10:00:04"), "end": pd.Timestamp("2016-01-01 10:00:09")},
               {"id": 2, "start": pd.Timestamp("2016-01-01 10:00:12"), "end": pd.Timestamp("2016-01-01 10:00:15")}]
        r = M.per_attack_recall(att, ts, alarm)
        self.assertEqual((r[0]["window_rows"], r[0]["flagged_rows"], r[0]["detected"]), (6, 3, True))
        self.assertEqual((r[1]["flagged_rows"], r[1]["detected"]), (0, False))


class TestRuleBaseline(unittest.TestCase):
    def _frame(self, n=400, delay=5):
        valve = np.zeros(n)
        valve[50:150] = 2
        valve[250:330] = 2
        valve[valve == 0] = 1
        flow = np.zeros(n)
        for s, e in ((50, 150), (250, 330)):
            flow[s + delay:e + delay] = 2.0
        return pd.DataFrame({"MV101": valve, "FIT101": flow, "new_segment": np.r_[True, np.zeros(n - 1, dtype=bool)]})

    RULES = [{"id": "R1", "name": "MV-101 open -> FIT-101", "when_any": [{"tag": "MV101", "equals": 2}], "flow_tag": "FIT101"}]

    def test_delay_is_learned_and_applied(self):
        train = self._frame()
        rb = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0).fit(train)
        self.assertEqual(rb.delays["R1"]["delay_s"], 6)  # 5 s of lag; first row with flow is the 6th row open
        broken = self._frame()
        broken.loc[260:300, "FIT101"] = 0.0   # valve open, flow stays zero
        out = rb.predict(broken)
        self.assertTrue(out["inv_R1"].iloc[270:300].all())
        self.assertFalse(out["inv_R1"].iloc[250:253].any())  # inside the learned delay: no alarm
        self.assertFalse(rb.predict(train)["alarm"].any())

    def test_range_alarm_outside_training_min_max(self):
        train = self._frame()
        rb = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0).fit(train)
        t2 = train.copy()
        t2.loc[10, "FIT101"] = 9.0
        self.assertTrue(rb.predict(t2)["range_alarm"].iloc[10])

    def test_range_margin_and_exclusion_are_off_by_default_and_work_when_set(self):
        train = self._frame()
        probe = train.copy()
        probe.loc[10, "FIT101"] = 2.1          # slightly above the training max of 2.0
        default = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0).fit(train)
        self.assertTrue(default.predict(probe)["range_alarm"].iloc[10])
        wide = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0, range_margin_fraction=0.10).fit(train)
        self.assertFalse(wide.predict(probe)["range_alarm"].iloc[10])    # max widened by 10% of 2.0 -> 2.2
        skip = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0, range_exclude_tags=["FIT101"]).fit(train)
        self.assertFalse(skip.predict(probe)["range_alarm"].iloc[10])
        self.assertAlmostEqual(float(skip.out_of_range_share(probe)["FIT101"]), 1 / len(probe))

    def test_diagnostic_exclusion_d8_leaves_primary_alarm_unchanged(self):
        train = self._frame()
        probe = train.copy()
        probe.loc[10, "FIT101"] = 9.0          # out of range on the tag the diagnostic ignores
        probe.loc[20, "MV101"] = 3.0           # out of range on a tag it still checks
        plain = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0).fit(train)
        diag = RuleBaseline(["MV101", "FIT101"], self.RULES, 0.1, 60, 0.0, diagnostic_exclude_tags=["FIT101"]).fit(train)
        self.assertNotIn("alarm_excl_drift", plain.predict(probe))
        out = diag.predict(probe)
        self.assertTrue((out["alarm"].to_numpy() == plain.predict(probe)["alarm"].to_numpy()).all())
        self.assertTrue(out["alarm"].iloc[10] and not out["alarm_excl_drift"].iloc[10])
        self.assertTrue(out["alarm_excl_drift"].iloc[20])
        with self.assertRaises(DetectorError):
            RuleBaseline(["MV101", "FIT101"], self.RULES, diagnostic_exclude_tags=["AIT402"])

    def test_rule_with_unkept_tag_is_refused(self):
        with self.assertRaises(DetectorError):
            RuleBaseline(["FIT101"], self.RULES)


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_smoke_data()
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def cfg(self, name, stage=None):
        cfg = load_config(ROOT / "configs" / "smoke_test.yaml")
        cfg["data"]["cache_dir"] = str(self.tmp / name / "cache")
        cfg["data"]["runs_dir"] = str(self.tmp / name / "runs")
        if stage:
            cfg["stage"] = stage
        return cfg

    def test_smoke_run_passes_the_audit_and_finds_the_big_attacks(self):
        run_dir = run(self.cfg("a"), log=lambda *_: None)
        audit = pd.read_json(run_dir / "audit.json")
        self.assertTrue((audit["status"] == "PASS").all(), audit[["id", "status"]])
        pa = pd.read_csv(run_dir / "per_attack_recall.csv")
        rb = pa[pa.detector == "rule_baseline"].set_index("attack_id")
        self.assertEqual(rb.loc[1, "recall"], 1.0)   # value outside learned range
        self.assertEqual(rb.loc[2, "recall"], 1.0)   # valve open, flow zero
        self.assertLess(rb.loc[3, "recall"], 0.5)    # small bias: the range rule only catches the noise tail
        self.assertTrue(bool(rb.loc[3, "year_corrected"]))
        m = pd.read_csv(run_dir / "metrics_rowlevel.csv")
        for split in ("calibration", "normal_holdout", "attack_file"):   # D8 diagnostic is reported for every split
            self.assertEqual(int(((m.detector == "rule_baseline_excl_drift") & (m.split == split)).sum()), 1)
        self.assertIn("rule_baseline_excl_drift", set(pa.detector))
        self.assertIn("rule_alarm_excl_drift", pd.read_parquet(run_dir / "predictions.parquet").columns)
        isof = m[(m.detector == "isolation_forest") & (m.split == "calibration")]
        self.assertTrue((isof["alarm_share"] <= 0.01 + 1e-12).all())
        for f in ("manifest.json", "thresholds.json", "timings.csv", "environment.json", "predictions.parquet", "table_4_9_draft.md", "config_used.yaml"):
            self.assertTrue((run_dir / f).exists(), f)

    def test_same_configuration_gives_identical_results(self):
        cfg = self.cfg("b")
        d1 = run(cfg, log=lambda *_: None)
        import time; time.sleep(1.1)
        d2 = run(cfg, log=lambda *_: None)
        a = pd.read_csv(d1 / "metrics_rowlevel.csv")
        b = pd.read_csv(d2 / "metrics_rowlevel.csv")
        pd.testing.assert_frame_equal(a, b)

    def test_dev_stage_never_touches_attack_file_or_holdout(self):
        cfg = self.cfg("c", "dev")
        for k in ("attack_xlsx", "attack_list_xlsx"):
            cfg["data"][k] = str(self.tmp / "does_not_exist.xlsx")   # would fail if the stage tried to read them
        run_dir = run(cfg, log=lambda *_: None)
        m = pd.read_csv(run_dir / "metrics_rowlevel.csv")
        self.assertEqual(set(m["split"]), {"calibration"})
        pred = pd.read_parquet(run_dir / "predictions.parquet")
        self.assertEqual(set(pred["split"]), {"calibration"})
        self.assertFalse((run_dir / "per_attack_recall.csv").exists())
        n_total = 12_000
        self.assertEqual(pred["src_row"].max(), 3 + int(round(n_total * 0.85)) - 1)  # last calibration row; nothing after it

    def test_changed_source_stops_the_run(self):
        cfg = self.cfg("d")
        src = Path(cfg["_root"]) / "tests" / "data" / "smoke_normal.xlsx"
        copy = self.tmp / "d" / "copy.xlsx"
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, copy)
        cache = self.tmp / "d" / "cache2"
        ingest("normal", copy, cache, log=lambda *_: None)
        ingest("normal", copy, cache, log=lambda *_: None)        # unchanged: fine
        with open(copy, "ab") as f:
            f.write(b"x")
        with self.assertRaises(IngestError):
            ingest("normal", copy, cache, log=lambda *_: None)

    def test_freeze_gate(self):
        cfg = copy.deepcopy(self.cfg("e", "pilot"))
        eo = self.tmp / "Expected_Outcomes.md"
        cfg["expected_outcomes"] = {"path": str(eo), "sha256": None}
        with self.assertRaises(GateError):               # file missing
            check_gate(cfg, log=lambda *_: None)
        eo.write_text("Part A\n", encoding="utf-8")
        with self.assertRaises(GateError):               # hash not pasted into the config
            check_gate(cfg, log=lambda *_: None)
        cfg["expected_outcomes"]["sha256"] = "0" * 64
        with self.assertRaises(GateError):               # wrong hash
            check_gate(cfg, log=lambda *_: None)
        cfg["expected_outcomes"]["sha256"] = hashlib.sha256(eo.read_bytes()).hexdigest().upper()
        self.assertEqual(check_gate(cfg, log=lambda *_: None)["stage"], "pilot")
        eo.write_text("Part A edited after freezing\n", encoding="utf-8")
        with self.assertRaises(GateError):               # edited after the freeze
            check_gate(cfg, log=lambda *_: None)

    def test_smoke_stage_refuses_real_paths(self):
        cfg = self.cfg("f")
        cfg["data"]["attack_xlsx"] = "C:/somewhere/SWaT_Dataset_Attack_v0.xlsx"
        with self.assertRaises(GateError):
            check_gate(cfg, log=lambda *_: None)


if __name__ == "__main__":
    unittest.main()
