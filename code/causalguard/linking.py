"""Module 4, typed linking (Chapter 3, Section 3.5.4, Table 3.4; Algorithm 4.2; functions F11-F13).

Both linkers are this one module. The temporal-only linker is the same candidate loop with the rules
switched off and every link scored 1 (Section 3.6, Table 4.5).
"""
from __future__ import annotations

from .timeutil import seconds


def _layout_index(layout: list[dict]):
    tag_rows, plc_rows = {}, {}
    for row in layout:
        if row["relation"] == "controls stage":
            plc_rows[row["from_address"]] = row
        else:
            tag_rows[(row["from"], row["to"])] = row
    return tag_rows, plc_rows


def _domain(a: dict, b: dict, tag_rows: dict, plc_rows: dict):
    """DOMAIN(a, b, L) of Algorithm 4.2; scope as in Part B, B9 item 3. Returns (support or None, why not)."""
    if a["source_kind"] == "process" and b["source_kind"] == "process":
        row = tag_rows.get((a["tag"], b["tag"]))                     # one layout row, one step (no chains)
        if row:
            return {"rule_id": row["row_id"], "reason": f"{row['row_id']}: {row['from']} {row['relation']} {row['to']}",
                    "evidence": f"layout:{row['row_id']}"}, ""
        return None, ("same tag; no layout row" if a["tag"] == b["tag"] else f"no layout row {a['tag']} -> {b['tag']}")
    if a["source_kind"] == "network" and b["source_kind"] == "process":
        if not a["is_cip_write"]:
            return None, f"network -> process needs a CIP write; {a['flow_id']} is not a CIP write"
        row = plc_rows.get(a["dst"])
        if row is None:
            return None, f"{a['flow_id']} is a CIP write, but {a['dst']} is not a PLC in the layout table"
        if b["tag"] in row["stage_tags"].split(";"):
            return {"rule_id": row["row_id"], "reason": f"{row['row_id']}: {row['from']} controls stage {row['to']} ({b['tag']})",
                    "evidence": f"layout:{row['row_id']}; {a['flow_id']}"}, ""
        return None, f"{a['flow_id']} writes to {row['from']} (stage {row['to']}); {b['tag']} is not in that stage"
    if a["source_kind"] == "process" and b["source_kind"] == "network":
        return None, "process -> network: no domain rule"
    return None, "network -> network: no domain rule"


def _statistical(a: dict, b: dict, dt_ms: int, table: list[dict], block_s: float):
    """STAT(a, b, S): a confirmed row tag(a) -> tag(b) whose lag range, widened by one block on each side,
    contains the start-time difference (Part B, B9 item 5; the sign is not checked)."""
    if not (a["source_kind"] == "process" and b["source_kind"] == "process"):
        return None, ""
    for row in table:
        if row["from_tag"] == a["tag"] and row["to_tag"] == b["tag"]:
            lo, hi = max(0.0, row["lag_min_s"] - block_s), row["lag_max_s"] + block_s
            if lo * 1000 <= dt_ms <= hi * 1000:
                return {"rule_id": row["row_id"],
                        "reason": f"{row['row_id']}: {a['tag']} -> {b['tag']} at {seconds(dt_ms):g} s (table lags {row['lag_min_s']:g}-{row['lag_max_s']:g} s)",
                        "evidence": f"stat:{row['row_id']}"}, ""
            return None, f"{row['row_id']} lag {seconds(dt_ms):g} s outside {lo:g}-{hi:g} s"
    return None, ""


def _provenance(a: dict, b: dict, long: bool):
    """Table 3.4: a network record connects A and B directly. Algorithm 4.2 line 12: shared host."""
    if not (a["source_kind"] == "network" and b["source_kind"] == "network"):
        return None, ""
    shared = sorted(set(a["hosts"]) & set(b["hosts"]))
    if not shared:
        return None, "no shared host"
    flows = f"{a['flow_id']}, {b['flow_id']}"
    if long:
        return {"rule_id": "P-host-long", "reason": f"next later event on host {shared[0]} ({flows})", "evidence": f"{a['flow_id']}; {b['flow_id']}"}, ""
    if len(shared) == 2 and a["source"] == b["source"]:
        return {"rule_id": "P-conn", "reason": f"same connection {a['source']} ({flows})", "evidence": f"{a['flow_id']}; {b['flow_id']}"}, ""
    return {"rule_id": "P-host", "reason": f"same host {shared[0]} ({flows})", "evidence": f"{a['flow_id']}; {b['flow_id']}"}, ""


def link(events: list[dict], linker: dict, cfg: dict, layout: list[dict], stat_table: list[dict]) -> list[dict]:
    """Returns the link records of one linker: accepted, and (causalguard mode) rejected with the reason."""
    L = cfg["linking"]
    window_ms = int(round(float(L["window_s"]) * 1000))
    block_s = float(L.get("stat_lag_block_s", 5))
    weights = L["weights"]
    mode = linker["mode"]
    rules = set(linker.get("rules", [])) if mode == "causalguard" else set()
    long_on = mode == "causalguard" and "provenance" in rules and linker.get("long_provenance", True)
    tag_rows, plc_rows = _layout_index(layout)
    out: list[dict] = []
    done = set()

    def check(a: dict, b: dict, long: bool):
        if (a["event_id"], b["event_id"]) in done:
            return
        done.add((a["event_id"], b["event_id"]))
        dt_ms = b["t_start"] - a["t_start"]
        rec = {"linker": linker["name"], "from_event": a["event_id"], "to_event": b["event_id"],
               "dt_s": seconds(dt_ms), "long_window": long}
        if mode == "temporal":
            rec.update(decision="accepted", link_types=["temporal"], rule_id="T", status="inferred", score=1,
                       reason_text=f"{b['event_id']} starts {seconds(dt_ms):g} s after {a['event_id']}, inside the window",
                       evidence_ref="time order")
            out.append(rec)
            return
        support, why_not = [], []
        if "provenance" in rules:
            s, why = _provenance(a, b, long)
            if s:
                support.append(("provenance", s))
            elif why:
                why_not.append(why)
        if not long and "domain" in rules:
            s, why = _domain(a, b, tag_rows, plc_rows)
            if s:
                support.append(("domain", s))
            elif why:
                why_not.append(why)
        if not long and "statistical" in rules:
            s, why = _statistical(a, b, dt_ms, stat_table, block_s)
            if s:
                support.append(("statistical", s))
            elif why:
                why_not.append(why)
        if not support:
            rec.update(decision="rejected", link_types=[], rule_id="", status="", score=0,
                       reason_text="no rule held: " + ("; ".join(why_not) if why_not else "no rule type applies"), evidence_ref="")
        else:
            types = [t for t, _ in support]
            rec.update(decision="accepted", link_types=types, rule_id="; ".join(s["rule_id"] for _, s in support),
                       status="observed" if "provenance" in types else "inferred",
                       score=sum(weights[t] for t in types),
                       reason_text="; ".join(s["reason"] for _, s in support),
                       evidence_ref="; ".join(s["evidence"] for _, s in support))
        out.append(rec)

    # Candidates inside the window (lines 1-5): sorted sliding window, strict time order.
    n = len(events)
    for i in range(n):
        k = i + 1
        while k < n and events[k]["t_start"] - events[i]["t_start"] <= window_ms:
            if events[k]["t_start"] > events[i]["t_start"]:
                check(events[i], events[k], long=False)
            k += 1
    # Long same-host provenance (lines 6-8): beyond the window, only the next later event on that host.
    if long_on:
        hosts = sorted({h for e in events for h in e["hosts"]})
        for h in hosts:
            on_host = [e for e in events if h in e["hosts"]]
            for a, b in zip(on_host, on_host[1:]):
                if b["t_start"] - a["t_start"] > window_ms:
                    check(a, b, long=True)

    out.sort(key=lambda r: (r["from_event"], r["to_event"]))
    prefix = "cg" if mode == "causalguard" and linker["name"] == "causalguard" else linker["name"][:3]
    for i, r in enumerate(out, start=1):
        r["link_id"] = f"{prefix}-L{i:03d}"
    return out
