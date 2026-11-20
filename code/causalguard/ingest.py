"""Module 1, data ingestion (Chapter 3, Section 3.5.1; functions F1, F2).

Reads the files named in the configuration, records their SHA-256 hashes, and keeps the source file and
row number (historian) or flow ID (network) on every record. It never reads the documented-steps file.

Minimal prototype: the made-up workbook is small, so it is read directly; the one-off conversion to a
columnar file is already shown by the pilot code (pilot/ingest.py) and is reused in FYP2.
"""
from __future__ import annotations

import csv
from pathlib import Path

from openpyxl import load_workbook

from .config import resolve, sha256_file
from .timeutil import parse_ms


class IngestError(Exception):
    pass


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_historian(path: Path) -> dict:
    wb = load_workbook(path, read_only=True, data_only=True)
    ws = wb.worksheets[0]
    it = ws.iter_rows(values_only=True)
    header = [str(h).strip() for h in next(it)]
    if header[0].lower() != "timestamp":
        raise IngestError(f"{path.name}: first column must be Timestamp, got {header[0]!r}")
    tags = header[1:]
    rows = []
    for n, values in enumerate(it, start=2):                        # workbook row number; row 1 is the header
        if values[0] is None:
            continue
        rows.append({"row": n, "t": parse_ms(values[0]), "values": dict(zip(tags, values[1:]))})
    wb.close()
    for a, b in zip(rows, rows[1:]):
        if b["t"] <= a["t"]:
            raise IngestError(f"{path.name}: rows {a['row']} and {b['row']} are not in time order")
    return {"source_file": path.name, "tags": tags, "rows": rows}


def read_flows(path: Path) -> list[dict]:
    flows = []
    for r in _read_csv(path):
        flows.append({
            "flow_id": r["flow_id"], "capture_file": r["capture_file"],
            "t_start": parse_ms(r["t_start"]), "t_end": parse_ms(r["t_end"]),
            "src": r["src"], "dst": r["dst"], "dst_port": int(r["dst_port"]),
            "protocol": r["protocol"], "cip_service": r["cip_service"].strip().lower(), "bytes": int(r["bytes"]),
        })
    ids = [f["flow_id"] for f in flows]
    if len(set(ids)) != len(ids):
        raise IngestError(f"{path.name}: flow IDs are not unique")
    return flows


def capture_gaps(coverage: list[dict], min_gap_ms: int) -> list[dict]:
    """Gaps between consecutive capture files, found from the capture times alone (needs no ground truth)."""
    cov = sorted(coverage, key=lambda c: c["t_start"])
    gaps = []
    for a, b in zip(cov, cov[1:]):
        if b["t_start"] - a["t_end"] >= min_gap_ms:
            gaps.append({"t_start": a["t_end"], "t_end": b["t_start"], "after_file": a["capture_file"], "before_file": b["capture_file"]})
    return gaps


def ingest(cfg: dict) -> dict:
    ds = cfg["dataset"]
    paths = {k: resolve(cfg, ds[k]) for k in ("historian", "flows", "capture_coverage", "host_roles", "layout_table", "statistical_table")}
    for k, p in paths.items():
        if not p.exists():
            raise IngestError(f"dataset.{k} not found: {p}\nRun:  python -m causalguard make-synthetic")
    coverage = [{"capture_file": r["capture_file"], "t_start": parse_ms(r["t_start"]), "t_end": parse_ms(r["t_end"])}
                for r in _read_csv(paths["capture_coverage"])]
    min_gap_ms = int(round(float(cfg.get("ingestion", {}).get("min_capture_gap_s", 1)) * 1000))
    return {
        "historian": read_historian(paths["historian"]),
        "flows": read_flows(paths["flows"]),
        "coverage": coverage,
        "data_gaps": capture_gaps(coverage, min_gap_ms),
        "host_roles": _read_csv(paths["host_roles"]),
        "layout": _read_csv(paths["layout_table"]),
        "statistical": [dict(r, lag_min_s=float(r["lag_min_s"]), lag_max_s=float(r["lag_max_s"])) for r in _read_csv(paths["statistical_table"])],
        "input_hashes": {k: {"file": p.name, "sha256": sha256_file(p)} for k, p in paths.items()},
    }
