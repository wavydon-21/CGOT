"""Check a finished run against the frozen answer key (Expected Outcomes Part B).

Reads tests/part_b_key.yaml (a transcription of Part B, Sections B3-B8) and the files of one run, and writes
part_b_comparison.csv and part_b_comparison.md into the run folder: one line per number in Part B, with the
expected value, the value the run gave, and MATCH or MISMATCH. Mismatches are listed, never hidden.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml

from . import events as events_mod
from . import paths as paths_mod
from .config import check_gate, modules_view, resolve
from .ingest import ingest
from .timeutil import parse_ms

DAY = "2000-01-01 "


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _t(text):
    return parse_ms(DAY + text)


def _norm(x):
    if isinstance(x, float):
        return round(x, 3)
    if isinstance(x, (list, tuple)):
        return [_norm(v) for v in x]
    return x


class Table:
    def __init__(self):
        self.rows = []

    def add(self, section, item, expected, actual, match=None):
        e, a = _norm(expected), _norm(actual)
        ok = (e == a) if match is None else bool(match)
        self.rows.append({"n": len(self.rows) + 1, "section": section, "item": item,
                          "expected": json.dumps(e, ensure_ascii=False) if not isinstance(e, str) else e,
                          "actual": json.dumps(a, ensure_ascii=False) if not isinstance(a, str) else a,
                          "result": "MATCH" if ok else "MISMATCH"})


def build(run_dir: Path, cfg: dict) -> Table:
    key = yaml.safe_load((Path(cfg["_root"]) / "tests" / "part_b_key.yaml").read_text(encoding="utf-8"))
    events = _read_csv(run_dir / "events.csv")
    links = _read_csv(run_dir / "links.csv")
    paths = json.loads((run_dir / "paths.json").read_text(encoding="utf-8"))
    scores = json.loads((run_dir / "scores.json").read_text(encoding="utf-8"))
    checklist = json.loads((run_dir / "checklist.json").read_text(encoding="utf-8"))
    report = (run_dir / "report.html").read_text(encoding="utf-8")
    data = ingest(modules_view(cfg))
    flows = {f["flow_id"]: f for f in data["flows"]}
    ev = {e["event_id"]: e for e in events}
    T = Table()

    # ---- B2/B3 counts and events ----
    c = key["counts"]
    T.add("B2.3", "historian rows", c["historian_rows"], len(data["historian"]["rows"]))
    T.add("B2.4", "flows", c["flows"], len(data["flows"]))
    T.add("B3", "event count", c["events"], len(events))
    T.add("B3", "network events", c["network_events"], sum(e["source_kind"] == "network" for e in events))
    T.add("B3", "process events", c["process_events"], sum(e["source_kind"] == "process" for e in events))
    for k in key["events"]:
        e = ev.get(k["id"])
        if e is None:
            T.add("B3", f"{k['id']} exists", "yes", "no")
            continue
        T.add("B3", f"{k['id']} start", k["start"], e["t_start"][11:], _t(k["start"]) == parse_ms(e["t_start"]))
        T.add("B3", f"{k['id']} end", k["end"], e["t_end"][11:], _t(k["end"]) == parse_ms(e["t_end"]))
        T.add("B3", f"{k['id']} type", k["type"], e["event_type"])
        T.add("B3", f"{k['id']} record reference", k["ref"], e["record_ref"])
        if k["kind"] == "process":
            T.add("B3", f"{k['id']} source tag", k["source"], e["source"])
        else:
            T.add("B3", f"{k['id']} capture file", k["file"], e["source_file"])
        if "also" in k:
            also = [w.strip() for part in e["detail"].split(";") if part.strip().startswith("also ") for w in part.strip()[5:].split(",")]
            T.add("B3", f"{k['id']} other types matched (detail)", sorted(k["also"]), sorted(also))
        if "value" in k:
            T.add("B3", f"{k['id']} value change", k["value"], e["value_or_change"])
    n = key["event_numbers"]
    f06, f03, f05, f01 = flows["f06"], flows["f03"], flows["f05"], flows["f01"]
    rate = lambda f: f["bytes"] * 1000 / (f["t_end"] - f["t_start"])
    factor = float(cfg["thresholds"]["volume_factor"])
    T.add("B3", "ev01 volume, B/s", n["ev01_rate_bps"], round(rate(f06)))
    T.add("B3", "ev01 volume limit, B/s", n["ev01_limit_bps"], round(factor * rate(f03)))
    T.add("B3", "f05 volume, B/s", n["f05_rate_bps"], round(rate(f05)))
    T.add("B3", "f05 volume limit, B/s", n["f05_limit_bps"], round(factor * rate(f01)))
    T.add("B3", "ev04 flagged seconds (count in detail)", f"{len(n['ev04_flagged_seconds'])} flagged second(s)", ev.get("ev04", {}).get("detail", ""))
    ne = key["non_events"]
    used = {e["record_ref"] for e in events if e["source_kind"] == "network"}
    T.add("B3", "flows that must not be events", [], sorted(set(ne["flows"]) & used))
    base = parse_ms(DAY + "09:00:00")

    def covered(tag, s):
        return any(e["source"] == tag and parse_ms(e["t_start"]) <= base + s * 1000 <= parse_ms(e["t_end"]) for e in events)
    T.add("B3", "FIT101 at s = 2467, 2468 not in an event", [False, False], [covered("FIT101", s) for s in ne["FIT101_not_flagged_seconds"]])
    lo, hi = ne["LIT101_not_flagged_seconds"]
    T.add("B3", "LIT101 s = 2469..2489 not in an event", 0, sum(covered("LIT101", s) for s in range(lo, hi + 1)))

    # ---- B4 assignment ----
    for eid, step in key["assignment"].items():
        T.add("B4", f"{eid} assigned step", step or "none", scores["step_assignment"].get(eid) or "none")

    # ---- B5.1 temporal links ----
    tl = {(l["from_event"], l["to_event"]): l for l in links if l["linker"] == "temporal"}
    kt = key["temporal_links"]
    T.add("B5.1", "temporal-only links", kt["count"], len(tl))
    T.add("B5.1", "temporal-only link set", sorted(f"{a}->{b}" for a, b, _ in kt["links"]), sorted(f"{a}->{b}" for a, b in tl))
    for a, b, dt in kt["links"]:
        if dt is not None:
            T.add("B5.1", f"{a}->{b} time difference, s", dt, float(tl[(a, b)]["dt_s"]) if (a, b) in tl else "no link", (a, b) in tl and float(tl[(a, b)]["dt_s"]) == dt)
    for a, b, dt in kt["no_link"]:
        gap = (parse_ms(ev[b]["t_start"]) - parse_ms(ev[a]["t_start"])) / 1000 if a in ev and b in ev else None
        T.add("B5.1", f"{a}->{b} outside the window ({dt} s): no link", f"no link, {dt} s", f"{'link' if (a, b) in tl else 'no link'}, {gap:g} s")
    T.add("B5.1 / TC7", "links that point backward in time", 0, sum(float(l["dt_s"]) <= 0 for l in links))

    # ---- B5.2-B5.4 CausalGuard-OT ----
    cg = {(l["from_event"], l["to_event"]): l for l in links if l["linker"] == "causalguard"}
    kc = key["causalguard"]
    T.add("B5.2", "CausalGuard-OT candidates", kc["candidates"], len(cg))
    T.add("B5.2 / TC8", "long same-host candidates", [f"{a}->{b} ({dt} s)" for a, b, dt in kc["long_candidates"]],
          [f"{a}->{b} ({float(l['dt_s']):g} s)" for (a, b), l in sorted(cg.items()) if l["long_window"] == "true"])
    acc = {k: l for k, l in cg.items() if l["decision"] == "accepted"}
    rej = {k: l for k, l in cg.items() if l["decision"] == "rejected"}
    T.add("B5.3", "accepted links", len(kc["accepted"]), len(acc))
    T.add("B5.3", "accepted link set", sorted(f"{k['from']}->{k['to']}" for k in kc["accepted"]), sorted(f"{a}->{b}" for a, b in acc))
    wrong = set(scores["linkers"]["causalguard"]["wrong_links"])
    for k in kc["accepted"]:
        name = f"{k['from']}->{k['to']}"
        l = acc.get((k["from"], k["to"]))
        if l is None:
            T.add("B5.3", f"{name} accepted", "yes", "no")
            continue
        T.add("B5.3", f"{name} link types", sorted(k["types"]), sorted(l["link_types"].split("; ")))
        T.add("B5.3", f"{name} rule (reason)", sorted(k["rule"]), sorted(l["rule_id"].split("; ")))
        if "flows" in k:
            T.add("B5.3", f"{name} evidence flows", k["flows"], [x.strip() for x in l["evidence_ref"].split(";")])
        T.add("B5.3", f"{name} status", k["status"], l["status"])
        T.add("B5.3", f"{name} score", k["score"], float(l["score"]))
        T.add("B5.3", f"{name} correct (scorer)", k["correct"], name not in wrong)
        if "stat_lag_s" in k:
            T.add("B5.3", f"{name} statistical lag, s", k["stat_lag_s"], float(l["dt_s"]))
    krej = [(a, b, g) for g in kc["rejected"] for a, b in g["pairs"]]
    T.add("B5.4", "rejected candidates", len(krej), len(rej))
    T.add("B5.4", "rejected candidate set", sorted(f"{a}->{b}" for a, b, _ in krej), sorted(f"{a}->{b}" for a, b in rej))
    for a, b, g in krej:
        l = rej.get((a, b))
        T.add("B5.4", f"{a}->{b} reason (meaning: {g['reason']})", f"says: {g['must_say']}", l["reason_text"] if l else "not rejected",
              bool(l) and g["must_say"] in l["reason_text"])
    T.add("B5.4 / TC6", "rejected by CausalGuard-OT but accepted by temporal-only", len(krej), sum(k in tl for k in rej))

    # ---- B6 paths ----
    for name in ("causalguard", "temporal"):
        got = {p["rank"]: p for p in paths if p["linker"] == name}
        T.add("B6", f"{name} paths exported", len(key["paths"][name]), len(got))
        for k in key["paths"][name]:
            p = got.get(k["rank"], {})
            T.add("B6", f"{name} rank {k['rank']} events", " ".join(k["events"]), " ".join(p.get("events", [])))
            T.add("B6", f"{name} rank {k['rank']} score", k["score"], p.get("score"))
    mem_events = [{"event_id": e["event_id"], "t_start": parse_ms(e["t_start"])} for e in events]
    def mem_links(name):
        return [dict(l, score=float(l["score"])) for l in links if l["linker"] == name]
    top4 = paths_mod.top_k(mem_events, mem_links("causalguard"), 4)
    k4 = key["paths"]["causalguard_rank4_not_exported"]
    T.add("B6", "causalguard 4th path (not exported) events", " ".join(k4["events"]), " ".join(top4[3]["events"]) if len(top4) > 3 else "")
    T.add("B6", "causalguard 4th path score", k4["score"], top4[3]["score"] if len(top4) > 3 else None)
    many = paths_mod.top_k(mem_events, mem_links("temporal"), 50)
    T.add("B6", "temporal paths that score 8", key["paths"]["temporal_paths_with_score_8"], sum(p["score"] == 8 for p in many))

    # ---- B7 measures ----
    for name in ("causalguard", "temporal"):
        k, s = key["measures"][name], scores["linkers"][name]
        for field, label in (("candidate_links", "candidate links"), ("accepted_links", "accepted links"), ("correct_links", "correct accepted links"),
                             ("link_precision", "link precision"), ("link_recall", "link recall"), ("step_coverage", "step coverage, top path"),
                             ("step_order", "step order in top path"), ("pairs_right", "step pairs in the right order"), ("pairs_total", "step pairs"),
                             ("kendall_tau", "Kendall's tau"), ("observed_links_top_path", "observed links in top path")):
            T.add("B7", f"{name} {label}", k[field], s[field])
        T.add("B7", f"{name} expected links recovered", k["recovered"], s["expected_links_recovered"])
    for field, want in key["measures"]["success_rule"].items():
        T.add("B7", f"success rule: {field}", want, scores.get("success_rule", {}).get(field))

    # ---- B8 explanation ----
    x = key["explanation"]
    gaps = paths[0]["data_gaps"] if paths else []
    T.add("B8 / TC9", "data gap listed", [x["data_gap"]], [[g["t_start"][11:19], g["t_end"][11:19]] for g in gaps])
    for name in ("causalguard", "temporal"):
        for rank, want in x["unknown_steps"][name].items():
            p = next((p for p in paths if p["linker"] == name and p["rank"] == int(rank)), {})
            T.add("B8 / TC9", f"{name} path {rank} unknown steps", want, p.get("unknown_steps"))
    T.add("B8 / TC9", "report.html lists S0 as unknown and shows the gap", True,
          "<b>S0</b>: unknown" in report and "09:05:00&ndash;09:07:00" in report)
    rows = [r for r in checklist["paths"] if r["linker"] == "causalguard"]
    T.add("B8 / TC13", "checklist: 4 principles pass on CausalGuard-OT paths 1-3", [True] * 12,
          [r[p] for r in rows for p in ("explanation", "meaningful", "explanation_accuracy", "knowledge_limits")])
    d = checklist["links"].get("causalguard", {})
    T.add("B8 / TC13", "reasons that hold on re-check", x["reasons_hold"], f"{d.get('reasons_hold')}/{d.get('accepted')}")
    f = x["files"]
    T.add("B8", "events.csv rows", f["events_rows"], len(events))
    T.add("B8", "links.csv causalguard accepted", f["links_causalguard_accepted"], len(acc))
    T.add("B8", "links.csv causalguard rejected", f["links_causalguard_rejected"], len(rej))
    T.add("B8", "links.csv temporal", f["links_temporal"], len(tl))
    T.add("B8", "files written", f["present"], [name for name in f["present"] if (run_dir / name).exists()])

    # ---- B8.1 merge gap 2 s (event list only) ----
    cfg2 = modules_view(cfg)
    cfg2["thresholds"] = dict(cfg["thresholds"], merge_gap_s=2)
    ev2 = events_mod.extract(data, cfg2)
    k2 = key["merge_gap_2s"]
    T.add("B8.1", "merge gap 2 s: event count", k2["events"], len(ev2))
    noise = [[e["t_start"], e["t_end"]] for e in ev2 if e["source"] == "FIT101" and e["t_start"] < _t("09:35:00")]
    T.add("B8.1", "merge gap 2 s: ev04 splits into", k2["ev04_becomes"], "; ".join(f"{(a - base) // 1000}-{(b - base) // 1000} s" for a, b in noise),
          noise == [[_t(a), _t(b)] for a, b in k2["ev04_becomes"]])
    sig = lambda e: (e["t_start"], e["t_end"], e["source"], e["event_type"], e["record_ref"])
    ev5 = events_mod.extract(data, modules_view(cfg))
    T.add("B8.1", "merge gap 2 s: every other event unchanged", True,
          sorted(sig(e) for e in ev2 if not (e["source"] == "FIT101" and e["t_start"] < _t("09:35:00")))
          == sorted(sig(e) for e in ev5 if e["event_id"] != "ev04"))
    return T


def compare(run_dir, cfg: dict, log=print) -> dict:
    run_dir = Path(run_dir)
    gate = check_gate(cfg, log)                       # refuses if the frozen Part B is missing or changed
    T = build(run_dir, cfg)
    fields = ["n", "section", "item", "expected", "actual", "result"]
    with open(run_dir / "part_b_comparison.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(T.rows)
    miss = [r for r in T.rows if r["result"] == "MISMATCH"]
    md = [f"# Run {run_dir.name} against the frozen Part B", "",
          f"Part B SHA-256: `{gate['expected_outcomes_sha256'].upper()}`", "",
          f"**{len(T.rows) - len(miss)} of {len(T.rows)} checks match; {len(miss)} mismatch.**", "",
          "| # | Part B | Item | Expected | Run | Result |", "|---|---|---|---|---|---|"]
    cell = lambda s: str(s).replace("|", "\\|")
    for r in T.rows:
        md.append(f"| {r['n']} | {r['section']} | {cell(r['item'])} | {cell(r['expected'])} | {cell(r['actual'])} | {'**MISMATCH**' if r['result'] == 'MISMATCH' else 'Match'} |")
    (run_dir / "part_b_comparison.md").write_text("\n".join(md) + "\n", encoding="utf-8", newline="\n")
    log(f"Part B comparison: {len(T.rows) - len(miss)} of {len(T.rows)} checks match, {len(miss)} mismatch")
    for r in miss:
        log(f"  MISMATCH [{r['section']}] {r['item']}: expected {r['expected']}; run gave {r['actual']}")
    return {"checks": len(T.rows), "mismatches": miss}
