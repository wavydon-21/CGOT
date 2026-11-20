"""The documented steps (the made-up "event log") and the event-to-step assignment.

Decision D9 / requirement R5: this file is used ONLY by
  - explanation export, after the paths are fixed, to list documented steps with no event in a path; and
  - the scorer.
Modules 1-5 (ingest, events, linking, paths) never import it and never receive the file names.
`load` therefore needs the hash that paths.fix() returns: no fixed paths, no ground truth.
"""
from __future__ import annotations

import csv
import re

from .timeutil import parse_ms


class GroundTruthError(Exception):
    pass


def load(steps_path, links_path, *, paths_fixed_sha256: str) -> dict:
    if not (isinstance(paths_fixed_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", paths_fixed_sha256)):
        raise GroundTruthError("The documented steps may be read only after the paths are fixed (decision D9).")
    with open(steps_path, newline="", encoding="utf-8") as f:
        steps = [{
            "step_id": r["step_id"], "start": parse_ms(r["logged_start"]), "end": parse_ms(r["logged_end"]),
            "scored": r["scored"].strip().lower() == "yes", "description": r["description"],
            "connection": ((frozenset((r["conn_host_a"], r["conn_host_b"])), int(r["conn_port"])) if r["conn_host_a"] else None),
        } for r in csv.DictReader(f)]
    with open(links_path, newline="", encoding="utf-8") as f:
        ref = [(r["from_step"], r["to_step"]) for r in csv.DictReader(f) if r["scorable"].strip().lower() == "yes"]
    return {"steps": steps, "order": [s["step_id"] for s in steps], "scorable_links": ref,
            "evaluable_steps": [s["step_id"] for s in steps if s["scored"]]}


def _in_connection(event: dict, connection) -> bool:
    if event["source_kind"] != "network" or connection is None:
        return False
    pair, port = connection
    m = re.fullmatch(r"(\S+) -> (\S+):(\d+)", event["source"])
    return bool(m) and frozenset((m.group(1), m.group(2))) == pair and int(m.group(3)) == port


def assign(events: list[dict], truth: dict, tolerance_s: float) -> dict:
    """Algorithm 4.4 lines 1-6 (Chapter 3, Section 3.4.3). Returns {event_id: step_id or None}.
    An event is assigned by its START time."""
    tol = int(round(tolerance_s * 1000))
    out = {}
    for e in events:
        cand = [s for s in truth["steps"] if s["start"] - tol <= e["t_start"] <= s["end"] + tol]
        if not cand:
            out[e["event_id"]] = None
        elif len(cand) == 1:
            out[e["event_id"]] = cand[0]["step_id"]
        else:
            own = [s for s in cand if _in_connection(e, s["connection"])]
            if len(own) == 1:
                out[e["event_id"]] = own[0]["step_id"]
                continue
            rest = [s for s in cand if s["connection"] is None]
            if len(own) == 0 and len(rest) == 1:
                out[e["event_id"]] = rest[0]["step_id"]
            else:   # the written rule does not cover this case; stop instead of guessing
                raise GroundTruthError(f"{e['event_id']} falls in {[s['step_id'] for s in cand]} and Section 3.4.3 gives no rule for it")
    return out
