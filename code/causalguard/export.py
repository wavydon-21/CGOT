"""Module 6, explanation export (Chapter 3, Section 3.5.6; functions F13, F15, F16).

Writes events.csv, links.csv, paths.json, unknown_steps.csv, checklist.json and report.html.
The documented steps are read here only AFTER the paths are fixed, and only to list the steps that have
no event in a path ("unknown"). They cannot change any event, link, path or score (decision D9).
"""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from . import groundtruth, recheck
from .config import resolve
from .timeutil import clock, fmt_ms

EVENT_FIELDS = ["event_id", "t_start", "t_end", "source_kind", "source", "hosts", "stage", "event_type",
                "value_or_change", "detail", "source_file", "record_ref", "detector_score"]
LINK_FIELDS = ["link_id", "linker", "from_event", "to_event", "dt_s", "decision", "link_types", "rule_id",
               "reason_text", "evidence_ref", "status", "score", "long_window"]
TYPE_LABEL = {"abrupt_change": "Abrupt change", "actuator_state_change": "Actuator state change",
              "new_connection": "New connection", "unusual_volume": "Unusual data volume",
              "undocumented_host": "Connection to an undocumented host", "cip_write": "CIP control write"}


def _event_row(e: dict) -> dict:
    row = {k: e.get(k, "") for k in EVENT_FIELDS}
    row["t_start"], row["t_end"] = fmt_ms(e["t_start"]), fmt_ms(e["t_end"])
    row["hosts"] = "; ".join(e["hosts"])
    return row


def _link_row(l: dict) -> dict:
    row = {k: l.get(k, "") for k in LINK_FIELDS}
    row["link_types"] = "; ".join(l["link_types"])
    row["long_window"] = "true" if l["long_window"] else "false"
    return row


def _write_csv(path: Path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def write_all(run_dir: Path, cfg: dict, data: dict, events: list[dict], links: list[dict], paths: list[dict], fixed_sha256: str) -> dict:
    gaps = [{"t_start": fmt_ms(g["t_start"]), "t_end": fmt_ms(g["t_end"]),
             "note": f"no capture between {g['after_file']} and {g['before_file']}"} for g in data["data_gaps"]]

    # ---- the only use of the documented steps outside the scorer (after the paths are fixed) ----
    truth = groundtruth.load(resolve(cfg, cfg["dataset"]["documented_steps"]), resolve(cfg, cfg["dataset"]["reference_links"]),
                             paths_fixed_sha256=fixed_sha256)
    step_of = groundtruth.assign(events, truth, float(cfg["scoring"]["tolerance_s"]))
    step_desc = {s["step_id"]: s["description"] for s in truth["steps"]}
    out_paths = []
    for p in paths:
        present = {step_of[e] for e in p["events"]}
        out_paths.append({**p, "data_gaps": gaps,
                          "unknown_steps": [s for s in truth["order"] if s not in present]})

    _write_csv(run_dir / "events.csv", EVENT_FIELDS, [_event_row(e) for e in events])
    _write_csv(run_dir / "links.csv", LINK_FIELDS, [_link_row(l) for l in links])
    (run_dir / "paths.json").write_text(json.dumps(out_paths, indent=2), encoding="utf-8", newline="\n")
    limits = []                                      # knowledge limits as a CSV as well (TC9)
    for p in out_paths:
        limits += [{"linker": p["linker"], "rank": p["rank"], "kind": "unknown_step", "item": s, "note": step_desc[s]} for s in p["unknown_steps"]]
        limits += [{"linker": p["linker"], "rank": p["rank"], "kind": "data_gap", "item": f"{g['t_start']} to {g['t_end']}", "note": g["note"]} for g in gaps]
    _write_csv(run_dir / "unknown_steps.csv", ["linker", "rank", "kind", "item", "note"], limits)

    ds = {k: resolve(cfg, cfg["dataset"][k]) for k in ("flows", "layout_table", "statistical_table")}
    checklist = recheck.checklist(run_dir, cfg, out_paths, ds)
    (run_dir / "checklist.json").write_text(json.dumps(checklist, indent=2), encoding="utf-8", newline="\n")
    (run_dir / "report.html").write_text(
        render_html(run_dir.name, cfg, events, links, out_paths, gaps, step_desc, checklist), encoding="utf-8", newline="\n")
    return checklist


# ---------------------------------------------------------------------------------------------------
# HTML report (Figure 4.7)
# ---------------------------------------------------------------------------------------------------
CSS = """
:root{--ink:#111;--mute:#555;--line:#c9c9c9;--soft:#f4f5f7;--blue:#1f4e9c;--bluebg:#e8eef9}
*{box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;color:var(--ink);margin:0;background:#fff;font-size:14px;line-height:1.45}
main{max-width:1080px;margin:0 auto;padding:24px 28px 48px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:30px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
h3{font-size:15px;margin:0}
.sub{color:var(--mute);margin:0 0 14px}
.banner{border:1.5px solid var(--blue);background:var(--bluebg);color:var(--blue);padding:8px 12px;font-weight:bold;margin:12px 0 16px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 6px}
.stat{border:1px solid var(--line);padding:8px 12px;min-width:150px;flex:1}
.stat b{display:block;font-size:19px}
.stat span{color:var(--mute);font-size:12px}
.legend{display:flex;gap:16px;flex-wrap:wrap;align-items:center;color:var(--mute);font-size:12.5px;margin:10px 0 0}
.badge{display:inline-block;font-size:11.5px;font-weight:bold;padding:2px 8px;border-radius:10px;border:1.5px solid var(--ink);white-space:nowrap}
.observed{background:var(--ink);color:#fff}
.inferred{background:#fff;color:var(--ink);border-style:dashed}
.chip{display:inline-block;font-size:11.5px;padding:2px 7px;border:1px solid var(--blue);color:var(--blue);background:var(--bluebg);margin-right:4px;white-space:nowrap}
.path{border:1.5px solid var(--ink);margin:0 0 14px}
.path>summary{cursor:pointer;padding:10px 14px;background:var(--soft);display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;list-style:none}
.path>summary::-webkit-details-marker{display:none}
.path>summary .rank{font-weight:bold;font-size:15px}
.path>summary .meta{color:var(--mute)}
.path .body{padding:12px 14px 14px}
.chain{font-family:Consolas,"Courier New",monospace;font-size:13px;margin:0 0 10px;word-spacing:1px}
.unknown{border-left:4px solid var(--blue);background:var(--bluebg);padding:7px 10px;margin:0 0 10px}
.unknown b{color:var(--blue)}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--soft);font-size:12.5px}
tr.ev td{background:#fff}
tr.ev td.id{font-weight:bold;white-space:nowrap}
tr.lk td{background:#fafafa;color:#222;font-size:13px}
tr.lk td.arrow{text-align:center;color:var(--blue);font-weight:bold}
td.t{white-space:nowrap;font-family:Consolas,"Courier New",monospace;font-size:12.5px}
td.ref{font-family:Consolas,"Courier New",monospace;font-size:12.5px}
.yes{font-weight:bold}.no{font-weight:bold;color:#b00020}
details.more{margin:10px 0}
details.more>summary{cursor:pointer;font-weight:bold;padding:6px 0}
footer{color:var(--mute);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:10px}
@media print{.path{break-inside:avoid}}
"""


def _h(x) -> str:
    return html.escape(str(x))


def _badge(status: str) -> str:
    return f'<span class="badge {status}">{status.capitalize()}</span>' if status else ""


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _path_block(p: dict, ev: dict, lk: dict, step_desc: dict, open_: bool) -> str:
    chain = " → ".join(p["events"])
    n = len(p["links"])
    unknown = "".join(f"<div><b>{_h(s)}</b>: unknown &mdash; no event in this path matches this documented step ({_h(step_desc.get(s, ''))})</div>"
                      for s in p["unknown_steps"]) or "<div>None: every documented step has an event in this path.</div>"
    gaps = "".join(f"<div>Data gap: {_h(g['t_start'][11:19])}&ndash;{_h(g['t_end'][11:19])} ({_h(g['note'])})</div>" for g in p["data_gaps"])
    rows = []
    for i, eid in enumerate(p["events"]):
        e = ev[eid]
        t = clock(e["t_start"]) + ("" if e["t_end"] == e["t_start"] else "–" + clock(e["t_end"]))
        rows.append(f'<tr class="ev"><td class="id">{_h(eid)}</td><td class="t">{_h(t)}</td>'
                    f'<td>{_h(TYPE_LABEL.get(e["event_type"], e["event_type"]))}</td><td>{_h(e["source"])}</td>'
                    f'<td>{_h(e["value_or_change"])}</td><td class="ref">{_h(e["source_file"])}, {_h(e["record_ref"])}</td></tr>')
        if i < n:
            l = lk[p["links"][i]]
            chips = "".join(f'<span class="chip">{_h(t.capitalize())}</span>' for t in l["link_types"])
            rows.append(f'<tr class="lk"><td class="arrow">↓</td><td class="t">+{_h(l["dt_s"])} s</td>'
                        f'<td>{chips}</td><td colspan="2"><b>Why:</b> {_h(l["reason_text"])}</td>'
                        f'<td class="ref">{_badge(l["status"])} score {_h(l["score"])}<br>evidence: {_h(l["evidence_ref"])}</td></tr>')
    return (f'<details class="path"{" open" if open_ else ""}><summary><span class="rank">Path {p["rank"]}</span>'
            f'<span>score <b>{_h(p["score"])}</b></span><span class="meta">{len(p["events"])} events, {n} links</span>'
            f'<span class="meta">observed links {p["observed_links"]}/{n} ({_pct(p["observed_share"])})</span>'
            f'<span class="meta">unknown steps: {_h(", ".join(p["unknown_steps"]) or "none")}</span></summary>'
            f'<div class="body"><p class="chain">{_h(chain)}</p><div class="unknown">{unknown}{gaps}</div>'
            f'<table><tr><th>Event / link</th><th>Time</th><th>Type</th><th>Source</th><th>Value or change</th><th>Record (evidence)</th></tr>'
            f'{"".join(rows)}</table></div></details>')


def render_html(run_name: str, cfg: dict, events, links, paths, gaps, step_desc, checklist) -> str:
    ev = {e["event_id"]: e for e in events}
    parts = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>CausalGuard-OT report: {_h(run_name)}</title>"
             f"<meta name='viewport' content='width=device-width, initial-scale=1'><style>{CSS}</style></head><body><main>"]
    parts.append("<h1>CausalGuard-OT: reconstructed attack paths</h1>")
    parts.append(f"<p class='sub'>Run {_h(run_name)} &middot; configuration SHA-256 {_h(cfg['_config_sha256'][:16])}&hellip; &middot; "
                 f"linking window {_h(cfg['linking']['window_s'])} s &middot; merge gap {_h(cfg['thresholds']['merge_gap_s'])} s &middot; top {_h(cfg['paths']['k'])} paths</p>")
    if cfg["stage"] == "synthetic":
        parts.append("<div class='banner'>MADE-UP DATA: synthetic campaign (1 January 2000) used to test the prototype. Not SWaT data and not a research result.</div>")
    stats = [(len(events), f"events ({sum(e['source_kind'] == 'network' for e in events)} network, {sum(e['source_kind'] == 'process' for e in events)} process)")]
    for lkr in cfg["linkers"]:
        mine = [l for l in links if l["linker"] == lkr["name"]]
        stats.append((f"{sum(l['decision'] == 'accepted' for l in mine)} / {len(mine)}", f"links accepted / candidates: {lkr['name']}"))
    stats.append((len(gaps), "data gap(s): " + (", ".join(f"{g['t_start'][11:19]}–{g['t_end'][11:19]}" for g in gaps) or "none")))
    parts.append("<div class='stats'>" + "".join(f"<div class='stat'><b>{_h(a)}</b><span>{_h(b)}</span></div>" for a, b in stats) + "</div>")
    parts.append("<div class='legend'><span><span class='badge observed'>Observed</span> a network record connects the two events (provenance)</span>"
                 "<span><span class='badge inferred'>Inferred</span> rests on plant design or a measured dependency</span>"
                 "<span><b>Unknown</b>: a documented step with no event in the path</span></div>")

    for n, lkr in enumerate(cfg["linkers"]):
        mine = [p for p in paths if p["linker"] == lkr["name"]]
        lk = {l["link_id"]: l for l in links if l["linker"] == lkr["name"]}
        title = "CausalGuard-OT typed linker" if lkr["mode"] == "causalguard" and lkr["name"] == "causalguard" else (
            "Temporal-only linker (baseline)" if lkr["mode"] == "temporal" else f"Variant: {lkr['name']}")
        parts.append(f"<h2>{_h(title)}: top {len(mine)} paths</h2>")
        if not mine:
            parts.append("<p>No path: no link was accepted.</p>")
        for p in mine:
            parts.append(_path_block(p, ev, lk, step_desc, open_=(n == 0 and p["rank"] == 1)))

    parts.append("<h2>Explanation checklist (four principles, Section 3.7.3)</h2><table><tr><th>Linker</th><th>Path</th>"
                 "<th>1 Explanation: every link has a type and a reason</th><th>2 Meaningful: every event named by host or tag and time</th>"
                 "<th>3 Accuracy: every reason holds when re-checked against its record</th><th>4 Knowledge limits: unknown steps, gaps and inferred links marked</th></tr>")
    yn = lambda b: "<span class='yes'>Pass</span>" if b else "<span class='no'>Fail</span>"
    for r in checklist["paths"]:
        parts.append(f"<tr><td>{_h(r['linker'])}</td><td>{r['rank']}</td><td>{yn(r['explanation'])}</td><td>{yn(r['meaningful'])}</td>"
                     f"<td>{yn(r['explanation_accuracy'])}</td><td>{yn(r['knowledge_limits'])}</td></tr>")
    parts.append("</table><p class='sub' style='margin-top:6px'>Reasons that hold on re-check, all accepted links: "
                 + "; ".join(f"{_h(k)} {v['reasons_hold']}/{v['accepted']}" for k, v in checklist["links"].items()) + "</p>")

    parts.append("<h2>All events</h2><table><tr><th>ID</th><th>Start</th><th>End</th><th>Type</th><th>Source</th><th>Value or change</th><th>Detail</th><th>Record</th></tr>")
    for e in events:
        parts.append(f"<tr><td class='id'><b>{_h(e['event_id'])}</b></td><td class='t'>{_h(clock(e['t_start']))}</td><td class='t'>{_h(clock(e['t_end']))}</td>"
                     f"<td>{_h(TYPE_LABEL.get(e['event_type'], e['event_type']))}</td><td>{_h(e['source'])}</td><td>{_h(e['value_or_change'])}</td>"
                     f"<td>{_h(e['detail'])}</td><td class='ref'>{_h(e['source_file'])}, {_h(e['record_ref'])}</td></tr>")
    parts.append("</table>")

    for lkr in cfg["linkers"]:
        rej = [l for l in links if l["linker"] == lkr["name"] and l["decision"] == "rejected"]
        if rej:
            parts.append(f"<details class='more'><summary>Rejected candidate links: {_h(lkr['name'])} ({len(rej)})</summary>"
                         "<table><tr><th>From</th><th>To</th><th>Δt (s)</th><th>Why rejected</th></tr>"
                         + "".join(f"<tr><td>{_h(l['from_event'])}</td><td>{_h(l['to_event'])}</td><td>{_h(l['dt_s'])}</td><td>{_h(l['reason_text'])}</td></tr>" for l in rej)
                         + "</table></details>")
    parts.append("<footer>Files in this run folder: events.csv, links.csv, paths.json, unknown_steps.csv, checklist.json, timings.csv, manifest.json. "
                 "The score is a rank, not a probability. Measures against the documented steps are written separately by "
                 "<code>python -m causalguard score</code> (scores.json), because the paths are built without them.</footer>")
    parts.append("</main></body></html>")
    return "\n".join(parts)
