"""Module 3, event abstraction (Chapter 3, Section 3.5.3; Algorithm 4.1 lines 10-25; functions F8, F9).

Minimal prototype (Part B, Section B2.5): the bands are FIXED values from the configuration. Learning and
calibrating them (Algorithm 4.1 lines 1-9), the frozen-value check and the dependency-violation check are
FYP2 work and are switched off here.
"""
from __future__ import annotations

from .timeutil import parse_ms, seconds

NETWORK_TYPE_ORDER = ("cip_write", "undocumented_host", "new_connection", "unusual_volume")   # Part B, B9 item 4


def _merge(flagged: list[dict], gap_ms: int) -> list[list[dict]]:
    """Flagged rows of one tag -> groups; a row joins the group if it is at most `gap` after the previous one."""
    groups: list[list[dict]] = []
    for r in flagged:
        if groups and r["t"] - groups[-1][-1]["t"] <= gap_ms:
            groups[-1].append(r)
        else:
            groups.append([r])
    return groups


def _stage_of_tag(layout: list[dict]) -> dict:
    out = {}
    for row in layout:
        if row["relation"] == "controls stage":
            for tag in filter(None, row["stage_tags"].split(";")):
                out[tag] = row["to"]
    return out


def _stage_of_plc(layout: list[dict]) -> dict:
    return {row["from_address"]: row["to"] for row in layout if row["relation"] == "controls stage"}


def process_events(historian: dict, thresholds: dict, layout: list[dict]) -> list[dict]:
    rows, src_file = historian["rows"], historian["source_file"]
    gap_ms = int(round(float(thresholds["merge_gap_s"]) * 1000))
    stage = _stage_of_tag(layout)
    events = []

    # Abrupt change (Algorithm 4.1 line 11): the value OR its 1-s change is outside the band.
    for tag, band in thresholds["bands"].items():
        vlo, vhi = band["value"]
        clo, chi = band["change"]
        flagged = []
        for i, r in enumerate(rows):
            v = r["values"][tag]
            d = None if i == 0 else v - rows[i - 1]["values"][tag]       # the first row has no 1-s change
            out_v = v < vlo or v > vhi
            out_d = d is not None and (d < clo or d > chi)
            if out_v or out_d:
                excess = max(max(vlo - v, v - vhi, 0) / (vhi - vlo),
                             0 if d is None else max(clo - d, d - chi, 0) / (chi - clo))
                flagged.append({"i": i, "t": r["t"], "row": r["row"], "value": v, "change": d, "excess": excess})
        for g in _merge(flagged, gap_ms):
            first = g[0]
            before = rows[first["i"] - 1]["values"][tag] if first["i"] > 0 else None
            ref = f"row {g[0]['row']}" if len(g) == 1 and g[0]["row"] == g[-1]["row"] else f"rows {g[0]['row']}-{g[-1]['row']}"
            events.append({
                "t_start": g[0]["t"], "t_end": g[-1]["t"], "source_kind": "process", "source": tag, "hosts": [],
                "stage": stage.get(tag, ""), "event_type": "abrupt_change",
                "value_or_change": (f"{before:g} -> {first['value']:g}" if before is not None else f"{first['value']:g}"),
                "detail": f"{len(g)} flagged second(s)", "source_file": src_file, "record_ref": ref,
                "detector_score": round(max(x["excess"] for x in g), 4), "flow_id": "", "tag": tag,
            })

    # Actuator state change (line 14): each change is one event, t_start = t_end.
    for tag in thresholds.get("actuators", []):
        for i in range(1, len(rows)):
            a, b = rows[i - 1]["values"][tag], rows[i]["values"][tag]
            if a != b:
                events.append({
                    "t_start": rows[i]["t"], "t_end": rows[i]["t"], "source_kind": "process", "source": tag, "hosts": [],
                    "stage": stage.get(tag, ""), "event_type": "actuator_state_change", "value_or_change": f"{a:g} -> {b:g}",
                    "detail": "", "source_file": src_file, "record_ref": f"row {rows[i]['row']}",
                    "detector_score": "", "flow_id": "", "tag": tag,
                })
    return events


def _rate(flow: dict):
    dur_ms = flow["t_end"] - flow["t_start"]
    return None if dur_ms <= 0 else flow["bytes"] * 1000 / dur_ms


def _pair_port(flow: dict):
    return (frozenset((flow["src"], flow["dst"])), flow["dst_port"])


def network_events(flows: list[dict], cfg: dict, host_roles: list[dict], layout: list[dict]) -> list[dict]:
    """One event per flow (Algorithm 4.1 lines 18-24). Flows that start in the pre-attack window are the
    reference set F0 and never become events."""
    pre0, pre1 = parse_ms(cfg["pre_attack_window"]["start"]), parse_ms(cfg["pre_attack_window"]["end"])
    workstation = cfg["network"]["scada_workstation"]
    factor = float(cfg["thresholds"]["volume_factor"])
    documented = {h["address"] for h in host_roles if h["in_component_list"].strip().lower() == "yes"}
    plc_stage = _stage_of_plc(layout)

    reference = [f for f in flows if pre0 <= f["t_start"] < pre1]
    seen = {_pair_port(f) for f in reference}
    max_rate: dict = {}
    for f in reference:
        r = _rate(f)
        if r is not None:
            max_rate[_pair_port(f)] = max(max_rate.get(_pair_port(f), 0.0), r)

    events = []
    for f in flows:
        if pre0 <= f["t_start"] < pre1:
            continue
        key, rate = _pair_port(f), _rate(f)
        is_cip_write = f["protocol"].upper() == "CIP" and f["cip_service"] == "write"
        matches, notes = [], []
        if is_cip_write and f["src"] == workstation:
            matches.append("cip_write")
        if f["src"] == workstation and f["dst"] not in documented:
            matches.append("undocumented_host")
        if key not in seen:
            matches.append("new_connection")
        # Unusual volume needs a pre-attack flow of the same host pair and port to compare with.
        if key in max_rate and rate is not None:
            limit = factor * max_rate[key]
            if rate > limit:
                matches.append("unusual_volume")
                notes.append(f"{rate:,.0f} B/s vs limit {limit:,.0f} B/s")
            else:
                notes.append(f"{rate:,.0f} B/s, limit {limit:,.0f} B/s")
        else:
            notes.append("volume not checked: no pre-attack flow of this host pair and port")
        if not matches:
            continue
        etype = next(t for t in NETWORK_TYPE_ORDER if t in matches)
        others = [t for t in NETWORK_TYPE_ORDER if t in matches and t != etype]
        detail = "; ".join(([f"also {', '.join(others)}"] if others else []) + notes)
        service = f"{f['protocol']} {f['cip_service']}".strip()
        events.append({
            "t_start": f["t_start"], "t_end": f["t_end"], "source_kind": "network",
            "source": f"{f['src']} -> {f['dst']}:{f['dst_port']}", "hosts": [f["src"], f["dst"]],
            "stage": plc_stage.get(f["dst"], "") if is_cip_write else "", "event_type": etype,
            "value_or_change": f"{service}, {f['bytes']:,} B", "detail": detail,
            "source_file": f["capture_file"], "record_ref": f["flow_id"], "detector_score": "",
            "flow_id": f["flow_id"], "tag": "",
            "is_cip_write": is_cip_write, "dst": f["dst"], "matches": matches,
        })
    return events


def extract(data: dict, cfg: dict) -> list[dict]:
    """All events, sorted by (t_start, source) and numbered ev01, ev02, ... (Algorithm 4.1 line 25)."""
    ev = process_events(data["historian"], cfg["thresholds"], data["layout"])
    ev += network_events(data["flows"], cfg, data["host_roles"], data["layout"])
    ev.sort(key=lambda e: (e["t_start"], e["source"]))
    width = max(2, len(str(len(ev))))
    for i, e in enumerate(ev, start=1):
        e["event_id"] = f"ev{i:0{width}d}"
        e["t_start_s"] = seconds(e["t_start"])
    return ev
