"""Four-principle checklist for each exported path (Chapter 3, Section 3.7.3; Phillips et al., 2021; TC13).

Principle 3 (explanation accuracy) is checked from the FILES the run wrote plus the supporting records
(flow table, layout table, statistical table), with its own small rule checks, not by calling the linker again.
"""
from __future__ import annotations

import csv
import re

from .timeutil import parse_ms


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _holds(link: dict, ev: dict, events: list[dict], flows: dict, layout: dict, stat: dict, cfg: dict):
    """Does every stored reason of this link still hold against its record? Returns (bool, note)."""
    a, b = ev[link["from_event"]], ev[link["to_event"]]
    dt = parse_ms(b["t_start"]) - parse_ms(a["t_start"])
    window = int(round(float(cfg["linking"]["window_s"]) * 1000))
    block = float(cfg["linking"].get("stat_lag_block_s", 5))
    is_long = str(link["long_window"]).lower() == "true"
    if dt <= 0:
        return False, "not in time order"
    if (dt > window) != is_long:
        return False, "window flag does not match the time difference"
    types = [t for t in link["link_types"].split("; ") if t]
    rules = [r for r in link["rule_id"].split("; ") if r]
    if len(types) != len(rules) or not types:
        return False, "types and rule IDs do not line up"
    if (link["status"] == "observed") != ("provenance" in types):
        return False, "observed/inferred status does not match the link types"
    for t, rule in zip(types, rules):
        if t == "temporal":
            continue
        if t == "provenance":
            fa, fb = flows.get(a["record_ref"]), flows.get(b["record_ref"])
            if fa is None or fb is None:
                return False, "provenance without two flow records"
            shared = {fa["src"], fa["dst"]} & {fb["src"], fb["dst"]}
            if not shared:
                return False, "the two flows share no host"
            if is_long:
                between = [e for e in events if e["source_kind"] == "network"
                           and parse_ms(a["t_start"]) < parse_ms(e["t_start"]) < parse_ms(b["t_start"])
                           and any(h in e["hosts"].split("; ") for h in shared)]
                if between:
                    return False, f"{between[0]['event_id']} is an earlier later event on the shared host"
        elif t == "domain":
            row = layout.get(rule)
            if row is None:
                return False, f"layout row {rule} not found"
            if row["relation"] == "controls stage":
                fa = flows.get(a["record_ref"])
                if not (fa and fa["protocol"].upper() == "CIP" and fa["cip_service"].lower() == "write" and fa["dst"] == row["from_address"]
                        and b["source"] in row["stage_tags"].split(";")):
                    return False, f"{rule} does not connect the CIP write and the tag"
            elif not (row["from"] == a["source"] and row["to"] == b["source"]):
                return False, f"{rule} does not connect {a['source']} to {b['source']}"
        elif t == "statistical":
            row = stat.get(rule)
            if row is None or row["from_tag"] != a["source"] or row["to_tag"] != b["source"]:
                return False, f"statistical row {rule} does not connect the two tags"
            lo, hi = max(0.0, float(row["lag_min_s"]) - block), float(row["lag_max_s"]) + block
            if not (lo * 1000 <= dt <= hi * 1000):
                return False, f"lag {dt / 1000:g} s outside {lo:g}-{hi:g} s"
        else:
            return False, f"unknown link type {t}"
    return True, ""


def checklist(run_dir, cfg: dict, paths: list[dict], dataset_paths: dict) -> dict:
    events = _read_csv(run_dir / "events.csv")
    links = _read_csv(run_dir / "links.csv")
    ev = {e["event_id"]: e for e in events}
    by_id = {(l["linker"], l["link_id"]): l for l in links}
    flows = {f["flow_id"]: f for f in _read_csv(dataset_paths["flows"])}
    layout = {r["row_id"]: r for r in _read_csv(dataset_paths["layout_table"])}
    stat = {r["row_id"]: r for r in _read_csv(dataset_paths["statistical_table"])}

    accepted = [l for l in links if l["decision"] == "accepted"]
    link_ok = {(l["linker"], l["link_id"]): _holds(l, ev, events, flows, layout, stat, cfg) for l in accepted}
    per_linker = {}
    for l in accepted:
        d = per_linker.setdefault(l["linker"], {"accepted": 0, "reasons_hold": 0, "failed": []})
        d["accepted"] += 1
        ok, note = link_ok[(l["linker"], l["link_id"])]
        d["reasons_hold"] += ok
        if not ok:
            d["failed"].append(f"{l['from_event']}->{l['to_event']}: {note}")

    rows = []
    for p in paths:
        pl = [by_id[(p["linker"], lid)] for lid in p["links"]]
        p1 = all(l["link_types"].strip() and l["reason_text"].strip() for l in pl)
        p2 = all(ev[e]["source"].strip() and re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", ev[e]["t_start"]) for e in p["events"])
        p3 = all(link_ok[(p["linker"], lid)][0] for lid in p["links"])
        p4 = (isinstance(p.get("unknown_steps"), list) and isinstance(p.get("data_gaps"), list)
              and all(l["status"] in ("observed", "inferred") for l in pl))
        rows.append({"linker": p["linker"], "rank": p["rank"], "explanation": bool(p1), "meaningful": bool(p2),
                     "explanation_accuracy": bool(p3), "knowledge_limits": bool(p4)})
    return {"paths": rows, "links": per_linker}
