"""Evaluation: reconstruction scorer (Chapter 3, Section 3.7.2; Algorithm 4.4; function F19).

The scorer reads a finished run folder (events.csv, links.csv, paths.json) and the documented steps.
It is the only code, apart from the unknown-step list in the export, that reads the documented steps (R5).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from . import groundtruth
from .config import resolve
from .timeutil import parse_ms


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_run(run_dir: Path):
    events = _read_csv(run_dir / "events.csv")
    for e in events:
        e["t_start"] = parse_ms(e["t_start"])
    links = _read_csv(run_dir / "links.csv")
    paths = json.loads((run_dir / "paths.json").read_text(encoding="utf-8"))
    return events, links, paths


def score_linker(name: str, links: list[dict], top_path: dict | None, step: dict, truth: dict) -> dict:
    accepted = [l for l in links if l["linker"] == name and l["decision"] == "accepted"]
    ref = set(truth["scorable_links"])
    order = truth["order"]

    def correct(l):
        a, b = step[l["from_event"]], step[l["to_event"]]
        return a is not None and b is not None and (a == b or (a, b) in ref)

    n_correct = sum(1 for l in accepted if correct(l))
    recovered = sorted({(step[l["from_event"]], step[l["to_event"]]) for l in accepted} & ref)
    out = {
        "linker": name,
        "candidate_links": sum(1 for l in links if l["linker"] == name),
        "accepted_links": len(accepted), "correct_links": n_correct,
        "link_precision": n_correct / len(accepted) if accepted else None,
        "expected_links_recovered": [f"{a}->{b}" for a, b in recovered],
        "link_recall": len(recovered) / len(ref) if ref else None,
        "wrong_links": [f"{l['from_event']}->{l['to_event']}" for l in accepted if not correct(l)],
    }
    evaluable = truth["evaluable_steps"]
    if top_path is None:
        out.update(step_coverage=0.0, step_order=[], pairs_right=None, pairs_total=0, pairs_right_share=None, kendall_tau=None,
                   observed_links_top_path=None)
        return out
    seen = []
    for ev in top_path["events"]:
        s = step[ev]
        if s is not None and s in evaluable and s not in seen:
            seen.append(s)                                           # order of first appearance
    conc = disc = 0
    for i in range(len(seen)):
        for j in range(i + 1, len(seen)):
            if order.index(seen[i]) < order.index(seen[j]):
                conc += 1
            else:
                disc += 1
    defined = len(seen) >= 2                                         # ordering is undefined below two steps
    out.update(
        step_coverage=len(seen) / len(evaluable), step_order=seen,
        pairs_right=conc if defined else None, pairs_total=conc + disc,
        pairs_right_share=conc / (conc + disc) if defined else None,
        kendall_tau=(conc - disc) / (conc + disc) if defined else None,
        observed_links_top_path=f"{top_path['observed_links']}/{len(top_path['links'])}",
    )
    return out


def success_rule(cg: dict, t: dict) -> dict:
    """Section 3.7.2: precision higher, coverage equal or higher, Kendall's tau not lower."""
    def ok(a, b, strict):
        if a is None or b is None:
            return False
        return a > b if strict else a >= b
    checks = {
        "precision_higher": ok(cg["link_precision"], t["link_precision"], True),
        "coverage_equal_or_higher": ok(cg["step_coverage"], t["step_coverage"], False),
        "tau_not_lower": ok(cg["kendall_tau"], t["kendall_tau"], False),
    }
    return {**checks, "holds": all(checks.values())}


def score(run_dir, cfg: dict, log=print) -> dict:
    run_dir = Path(run_dir)
    events, links, paths = load_run(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("config_sha256") != cfg["_config_sha256"]:
        log("WARNING: this configuration file is not the one that made the run (hash differs).")
    truth = groundtruth.load(resolve(cfg, cfg["dataset"]["documented_steps"]), resolve(cfg, cfg["dataset"]["reference_links"]),
                             paths_fixed_sha256=manifest["paths_fixed_sha256"])
    tol = float(cfg["scoring"]["tolerance_s"])
    step = groundtruth.assign(events, truth, tol)
    results = {}
    for lk in cfg["linkers"]:
        top = next((p for p in paths if p["linker"] == lk["name"] and p["rank"] == 1), None)
        results[lk["name"]] = score_linker(lk["name"], links, top, step, truth)
    out = {"tolerance_s": tol, "scorable_links": [f"{a}->{b}" for a, b in truth["scorable_links"]],
           "evaluable_steps": truth["evaluable_steps"], "step_assignment": step, "linkers": results}
    names = [lk["name"] for lk in cfg["linkers"]]
    primary = cfg["scoring"].get("success_rule", {})
    a, b = primary.get("framework", "causalguard"), primary.get("baseline", "temporal")
    if a in names and b in names:
        out["success_rule"] = success_rule(results[a], results[b])
    (run_dir / "scores.json").write_text(json.dumps(out, indent=2), encoding="utf-8", newline="\n")
    with open(run_dir / "step_assignment.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["event_id", "step"])
        w.writerows([(k, v or "") for k, v in step.items()])
    lines = []
    for n, r in results.items():
        f3 = lambda x: "n/a" if x is None else f"{x:.3f}"
        lines.append(f"{n}: accepted {r['accepted_links']}, correct {r['correct_links']}, precision {f3(r['link_precision'])}, "
                     f"recall {f3(r['link_recall'])}, coverage {f3(r['step_coverage'])}, order {','.join(r['step_order'])}, tau {f3(r['kendall_tau'])}")
    if "success_rule" in out:
        s = out["success_rule"]
        lines.append(f"success rule: precision higher={s['precision_higher']}; coverage equal or higher={s['coverage_equal_or_higher']}; "
                     f"tau not lower={s['tau_not_lower']} -> {'PASS' if s['holds'] else 'FAIL'}")
    (run_dir / "score_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    for ln in lines:
        log(ln)
    return out
