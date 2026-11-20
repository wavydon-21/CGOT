"""Module 5, path scoring (Chapter 3, Section 3.5.5; Algorithm 4.3; function F14).

Top-k search on the event graph. Every accepted link points forward in time, so events in start-time
order are a topological order. Each event keeps its k best paths that end there.
"""
from __future__ import annotations

import hashlib
import json


def _rank_key(path: dict):
    """RANK: (1) higher score; (2) earlier start of the first event; (3) earlier start at the first position
    where the two paths differ. Comparing the start-time lists in order gives (2) and (3) together.
    Event IDs come last only so that the order is fully fixed if two events start in the same millisecond."""
    return (-path["score"], tuple(path["starts"]), tuple(path["events"]))


def top_k(events: list[dict], links: list[dict], k: int) -> list[dict]:
    order = sorted(events, key=lambda e: (e["t_start"], e["event_id"]))
    start = {e["event_id"]: e["t_start"] for e in events}
    incoming: dict = {}
    for l in links:
        if l["decision"] == "accepted":
            incoming.setdefault(l["to_event"], []).append(l)
    best: dict = {e["event_id"]: [] for e in events}
    for v in order:
        vid = v["event_id"]
        cands = []
        for l in incoming.get(vid, []):
            u = l["from_event"]
            cands.append({"events": [u, vid], "links": [l["link_id"]], "score": l["score"], "starts": [start[u], start[vid]]})
            for p in best[u]:
                cands.append({"events": p["events"] + [vid], "links": p["links"] + [l["link_id"]],
                              "score": p["score"] + l["score"], "starts": p["starts"] + [start[vid]]})
        best[vid] = sorted(cands, key=_rank_key)[:k]
    every = [p for ps in best.values() for p in ps]
    return sorted(every, key=_rank_key)[:k]


def build(events: list[dict], links: list[dict], linker_name: str, k: int) -> list[dict]:
    status = {l["link_id"]: l["status"] for l in links}
    out = []
    for rank, p in enumerate(top_k(events, links, k), start=1):
        observed = sum(1 for lid in p["links"] if status[lid] == "observed")
        out.append({"linker": linker_name, "rank": rank, "events": p["events"], "links": p["links"], "score": p["score"],
                    "observed_links": observed, "observed_share": round(observed / len(p["links"]), 4)})
    return out


def fix(all_paths: list[dict]) -> str:
    """Hash of the path results. After this point the paths may not change; only then may the export step
    read the documented steps (decision D9)."""
    core = [{k: p[k] for k in ("linker", "rank", "events", "links", "score")} for p in all_paths]
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode("utf-8")).hexdigest()
