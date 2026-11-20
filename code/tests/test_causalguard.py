"""Tests for the CausalGuard-OT minimal prototype on the MADE-UP campaign (Table 4.8, TC6-TC13).

The expected numbers come from tests/part_b_key.yaml, a transcription of the frozen Expected Outcomes Part B.
The tests refuse to run if the frozen Part B file is missing or its hash differs from the config.
Run from the code folder:   python -m pytest tests/test_causalguard.py -q
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml

from causalguard import events as events_mod
from causalguard import groundtruth, linking, paths as paths_mod, recheck
from causalguard.compare import build as build_comparison
from causalguard.config import GateError, check_gate, load_config, modules_view, resolve
from causalguard.ingest import capture_gaps, ingest
from causalguard.pipeline import run
from causalguard.scorer import score
from causalguard.synthetic import make
from causalguard.timeutil import parse_ms

CODE = Path(__file__).resolve().parents[1]
KEY = yaml.safe_load((CODE / "tests" / "part_b_key.yaml").read_text(encoding="utf-8"))
QUIET = lambda *a, **k: None


def _csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _root(tmp: Path, part_b: Path | None = None) -> Path:
    """A throw-away copy of the code folder layout, so tests never write into the real runs/ folder."""
    (tmp / "configs").mkdir(parents=True)
    (tmp / "tests").mkdir()
    shutil.copy(CODE / "tests" / "part_b_key.yaml", tmp / "tests" / "part_b_key.yaml")
    cfg = yaml.safe_load((CODE / "configs" / "synthetic.yaml").read_text(encoding="utf-8"))
    real = (CODE / cfg["expected_outcomes"]["path"]).resolve()
    cfg["expected_outcomes"]["path"] = str(part_b or real)
    (tmp / "configs" / "synthetic.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    make(tmp / "tests" / "data_synthetic")
    return tmp


@pytest.fixture(scope="module")
def R(tmp_path_factory):
    root = _root(tmp_path_factory.mktemp("cgot"))
    cfg = load_config(root / "configs" / "synthetic.yaml")
    check_gate(cfg, QUIET)                      # the frozen answer key must be present and unchanged
    run_dir = run(cfg, QUIET)
    scores = score(run_dir, cfg, QUIET)
    links = _csv(run_dir / "links.csv")
    return {
        "root": root, "cfg": cfg, "run": run_dir, "scores": scores, "events": _csv(run_dir / "events.csv"), "links": links,
        "paths": json.loads((run_dir / "paths.json").read_text(encoding="utf-8")),
        "cg": {(l["from_event"], l["to_event"]): l for l in links if l["linker"] == "causalguard"},
        "t": {(l["from_event"], l["to_event"]): l for l in links if l["linker"] == "temporal"},
    }


# ---- freeze gate and fixture -------------------------------------------------------------------------
def test_gate_refuses_a_changed_answer_key(tmp_path):
    changed = tmp_path / "Part_B_changed.md"
    changed.write_text("changed", encoding="utf-8")
    root = _root(tmp_path / "r", part_b=changed)
    with pytest.raises(GateError):
        check_gate(load_config(root / "configs" / "synthetic.yaml"), QUIET)


def test_fixture_follows_part_b_section_b2(R):
    data = ingest(modules_view(R["cfg"]))
    rows = data["historian"]["rows"]
    assert len(rows) == 2700 and len(data["flows"]) == 12
    v = lambda s: rows[s]["values"]
    assert rows[0]["row"] == 2 and rows[2467]["row"] == 2469                      # second s is workbook row s + 2
    assert v(2466)["MV101"] == 2 and v(2467)["MV101"] == 1
    assert [v(s)["FIT101"] for s in (1799, 1800, 1801, 1802, 1806, 1807, 2468, 2469)] == [2.51, 0, 0, 2.5, 0, 2.51, 2.5, 0]
    assert [v(s)["LIT101"] for s in (2468, 2469, 2489, 2490, 2699)] == [600.0, 599.5, 589.5, 588.0, 274.5]
    assert [(g["t_start"], g["t_end"]) for g in data["data_gaps"]] == [(parse_ms("2000-01-01 09:05:00"), parse_ms("2000-01-01 09:07:00"))]


# ---- events (TC11, Part B B3) ------------------------------------------------------------------------
def test_tc11_events_as_in_part_b(R):
    ev = {e["event_id"]: e for e in R["events"]}
    assert len(ev) == KEY["counts"]["events"]
    for k in KEY["events"]:
        e = ev[k["id"]]
        assert parse_ms(e["t_start"]) == parse_ms("2000-01-01 " + k["start"]), k["id"]
        assert parse_ms(e["t_end"]) == parse_ms("2000-01-01 " + k["end"]), k["id"]
        assert e["event_type"] == k["type"] and e["record_ref"] == k["ref"], k["id"]
    used = {e["record_ref"] for e in R["events"]}
    assert not used & set(KEY["non_events"]["flows"])


def test_merge_gap_2s_splits_only_ev04(R):
    cfg2 = modules_view(R["cfg"])
    cfg2["thresholds"] = dict(R["cfg"]["thresholds"], merge_gap_s=2)
    ev2 = events_mod.extract(ingest(cfg2), cfg2)
    assert len(ev2) == KEY["merge_gap_2s"]["events"]
    t = lambda x: parse_ms("2000-01-01 " + x)
    got = [[e["t_start"], e["t_end"]] for e in ev2 if e["source"] == "FIT101" and e["t_start"] < t("09:35:00")]
    assert got == [[t(a), t(b)] for a, b in KEY["merge_gap_2s"]["ev04_becomes"]]


# ---- typed linking (TC6, TC7, TC8) -------------------------------------------------------------------
def test_tc6_temporal_only_support_is_rejected_by_causalguard(R):
    assert R["cg"][("ev05", "ev08")]["decision"] == "rejected"
    assert R["t"][("ev05", "ev08")]["decision"] == "accepted"
    rejected = [k for k, l in R["cg"].items() if l["decision"] == "rejected"]
    assert len(rejected) == 14 and all(k in R["t"] for k in rejected)
    assert all(l["reason_text"].startswith("no rule held") for k, l in R["cg"].items() if l["decision"] == "rejected")


def test_tc7_no_candidate_from_a_later_to_an_earlier_event(R):
    start = {e["event_id"]: parse_ms(e["t_start"]) for e in R["events"]}
    assert all(start[l["from_event"]] < start[l["to_event"]] for l in R["links"])
    assert len(R["t"]) == KEY["temporal_links"]["count"]
    for a, b, _ in KEY["temporal_links"]["no_link"]:
        assert (a, b) not in R["t"]


def test_tc7_events_with_the_same_start_time_are_not_linked():
    ev = [{"event_id": f"ev0{i}", "t_start": t, "source_kind": "process", "tag": "X", "hosts": [], "source": "X"} for i, t in ((1, 0), (2, 0), (3, 1000))]
    cfg = {"linking": {"window_s": 900, "weights": {}}}
    out = linking.link(ev, {"name": "temporal", "mode": "temporal"}, cfg, [], [])
    assert sorted((l["from_event"], l["to_event"]) for l in out) == [("ev01", "ev03"), ("ev02", "ev03")]


def test_tc8_long_provenance_joins_only_the_next_later_event_on_the_host(R):
    long = [(k, float(l["dt_s"])) for k, l in R["cg"].items() if l["long_window"] == "true"]
    assert long == [(("ev02", "ev05"), 1770.0)]
    assert ("ev02", "ev06") not in R["cg"] and ("ev02", "ev07") not in R["cg"]
    assert len(R["cg"]) == KEY["causalguard"]["candidates"]
    assert not any(l["long_window"] == "true" for l in R["t"].values())           # the baseline has no long links


def test_every_accepted_link_stores_rule_reason_evidence_and_status(R):
    for l in R["links"]:
        if l["decision"] == "accepted":
            assert l["link_types"] and l["rule_id"] and l["reason_text"] and l["evidence_ref"] and l["status"] in ("observed", "inferred")
    for (a, b), l in R["cg"].items():
        if l["decision"] == "accepted":
            assert (l["status"] == "observed") == ("provenance" in l["link_types"])


# ---- path search (TC10) ------------------------------------------------------------------------------
def test_tc10_top3_paths_as_in_part_b(R):
    for name in ("causalguard", "temporal"):
        got = [(p["rank"], p["events"], p["score"]) for p in R["paths"] if p["linker"] == name]
        assert got == [(k["rank"], k["events"], k["score"]) for k in KEY["paths"][name]], name


def _toy(edges, starts):
    ev = [{"event_id": k, "t_start": v} for k, v in starts.items()]
    lk = [{"link_id": f"L{i}", "from_event": a, "to_event": b, "score": s, "decision": "accepted"} for i, (a, b, s) in enumerate(edges)]
    return ev, lk


def test_tc10_toy_graph_tie_rules():
    # a->c and b->c both score 1: the path that starts earlier wins. a->c->d and a->b2->d tie on start: position 2 decides.
    ev, lk = _toy([("a", "c", 1), ("b", "c", 1)], {"a": 0, "b": 5, "c": 10})
    assert [p["events"] for p in paths_mod.top_k(ev, lk, 3)] == [["a", "c"], ["b", "c"]]
    ev, lk = _toy([("a", "x", 1), ("a", "y", 1), ("x", "d", 1), ("y", "d", 1)], {"a": 0, "x": 3, "y": 4, "d": 9})
    got = [p["events"] for p in paths_mod.top_k(ev, lk, 3)]
    assert got[0] == ["a", "x", "d"] and got[1] == ["a", "y", "d"]
    # a higher score beats an earlier start
    ev, lk = _toy([("a", "b", 1), ("c", "d", 2)], {"a": 0, "b": 1, "c": 2, "d": 3})
    assert paths_mod.top_k(ev, lk, 1)[0]["events"] == ["c", "d"]


def test_tc10_top_k_equals_brute_force_on_the_campaign_graph(R):
    """Independent check of Algorithm 4.3: list every path by brute force and rank them with the same RANK rule."""
    for name in ("causalguard", "temporal"):
        start = {e["event_id"]: parse_ms(e["t_start"]) for e in R["events"]}
        acc = [l for l in R["links"] if l["linker"] == name and l["decision"] == "accepted"]
        nxt = {}
        for l in acc:
            nxt.setdefault(l["from_event"], []).append((l["to_event"], float(l["score"])))
        every = []
        def walk(path, sc):
            if len(path) > 1:
                every.append((-sc, tuple(start[e] for e in path), tuple(path)))
            for b, s in nxt.get(path[-1], []):
                walk(path + [b], sc + s)
        for e in start:
            walk([e], 0.0)
        brute = [list(p[2]) for p in sorted(every)[:3]]
        assert brute == [p["events"] for p in R["paths"] if p["linker"] == name]


# ---- scorer (TC11) -----------------------------------------------------------------------------------
def test_tc11_step_assignment_as_in_part_b(R):
    assert R["scores"]["step_assignment"] == KEY["assignment"]


def test_tc11_measures_as_in_part_b(R):
    for name in ("causalguard", "temporal"):
        k, s = KEY["measures"][name], R["scores"]["linkers"][name]
        assert (s["candidate_links"], s["accepted_links"], s["correct_links"]) == (k["candidate_links"], k["accepted_links"], k["correct_links"])
        assert s["link_precision"] == pytest.approx(k["link_precision"], abs=5e-4)
        assert s["link_recall"] == pytest.approx(k["link_recall"]) and s["expected_links_recovered"] == k["recovered"]
        assert s["step_coverage"] == pytest.approx(k["step_coverage"]) and s["step_order"] == k["step_order"]
        assert (s["pairs_right"], s["pairs_total"]) == (k["pairs_right"], k["pairs_total"])
        assert s["kendall_tau"] == pytest.approx(k["kendall_tau"], abs=5e-4)
        assert s["observed_links_top_path"] == k["observed_links_top_path"]
    assert R["scores"]["success_rule"] == KEY["measures"]["success_rule"]


# ---- explanation export (TC9, TC13) ------------------------------------------------------------------
def test_tc9_unobserved_step_s0_and_the_gap_are_reported(R):
    want = KEY["explanation"]["unknown_steps"]
    for p in R["paths"]:
        assert p["unknown_steps"] == want[p["linker"]][p["rank"]]
        assert [(g["t_start"][11:19], g["t_end"][11:19]) for g in p["data_gaps"]] == [tuple(KEY["explanation"]["data_gap"])]
    html = (R["run"] / "report.html").read_text(encoding="utf-8")
    assert "<b>S0</b>: unknown" in html and "09:05:00&ndash;09:07:00" in html
    rows = _csv(R["run"] / "unknown_steps.csv")
    assert sum(r["kind"] == "unknown_step" and r["item"] == "S0" for r in rows) == 6
    assert sum(r["kind"] == "data_gap" for r in rows) == 6


def test_tc13_every_stored_reason_holds_on_recheck(R):
    c = json.loads((R["run"] / "checklist.json").read_text(encoding="utf-8"))
    assert c["links"]["causalguard"] == {"accepted": 12, "reasons_hold": 12, "failed": []}
    for r in c["paths"]:
        assert r["explanation"] and r["meaningful"] and r["explanation_accuracy"] and r["knowledge_limits"], r


def test_tc13_recheck_catches_a_wrong_reason(R, tmp_path):
    """The re-check is a real check: give ev08->ev09 the wrong layout row and it must fail."""
    bad = tmp_path / "run"
    shutil.copytree(R["run"], bad)
    rows = _csv(bad / "links.csv")
    for r in rows:
        if r["linker"] == "causalguard" and (r["from_event"], r["to_event"]) == ("ev08", "ev09"):
            r["rule_id"] = "D-4"
    with open(bad / "links.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    ds = {k: resolve(R["cfg"], R["cfg"]["dataset"][k]) for k in ("flows", "layout_table", "statistical_table")}
    c = recheck.checklist(bad, R["cfg"], json.loads((bad / "paths.json").read_text(encoding="utf-8")), ds)
    assert c["links"]["causalguard"]["reasons_hold"] == 11
    assert not next(r for r in c["paths"] if r["linker"] == "causalguard" and r["rank"] == 1)["explanation_accuracy"]


# ---- repeatability (TC12) ----------------------------------------------------------------------------
def test_tc12_same_configuration_twice_gives_identical_files(R):
    again = run(R["cfg"], QUIET)
    assert again != R["run"]
    for name in ("events.csv", "links.csv", "paths.json"):
        assert _sha(again / name) == _sha(R["run"] / name), name


# ---- decision D9 / R5: the documented steps cannot reach modules 1-5 -----------------------------------
def test_d9_modules_1_to_5_never_touch_the_documented_steps(R):
    for mod in ("ingest.py", "events.py", "linking.py", "paths.py"):
        src = (CODE / "causalguard" / mod).read_text(encoding="utf-8")
        assert "groundtruth" not in src and "documented_steps" not in src and "reference_links" not in src, mod
    view = modules_view(R["cfg"])
    assert "documented_steps" not in view["dataset"] and "reference_links" not in view["dataset"]
    with pytest.raises(groundtruth.GroundTruthError):
        groundtruth.load("x", "y", paths_fixed_sha256="")


def test_d9_different_documented_steps_change_no_event_link_or_path(R, tmp_path):
    root = _root(tmp_path / "r")
    steps = root / "tests" / "data_synthetic" / "syn_documented_steps.csv"
    steps.write_text(steps.read_text(encoding="utf-8").replace("09:10:00", "09:20:00").replace("09:15:00", "09:25:00"), encoding="utf-8")
    other = run(load_config(root / "configs" / "synthetic.yaml"), QUIET)
    assert _sha(other / "events.csv") == _sha(R["run"] / "events.csv")
    assert _sha(other / "links.csv") == _sha(R["run"] / "links.csv")
    core = lambda d: [{k: p[k] for k in ("linker", "rank", "events", "links", "score")} for p in json.loads((d / "paths.json").read_text(encoding="utf-8"))]
    assert core(other) == core(R["run"])


# ---- whole answer key ----------------------------------------------------------------------------------
def test_run_against_every_number_in_part_b(R):
    """Every line of the Part B comparison must match, except the differences written down, with their
    reasons, in tests/part_b_known_differences.yaml (and in research/chapter-4/Prototype_Results_vs_Part_B.md)."""
    known_file = CODE / "tests" / "part_b_known_differences.yaml"
    known = yaml.safe_load(known_file.read_text(encoding="utf-8")) if known_file.exists() else {}
    known_items = sorted(d["item"] for d in (known or {}).get("differences", []))
    miss = sorted(r["item"] for r in build_comparison(R["run"], R["cfg"]).rows if r["result"] == "MISMATCH")
    assert miss == known_items
