"""Fixture generator for the made-up campaign (Expected Outcomes Part B, Section B2).

Every value, time and flow here is invented (date 1 January 2000). Nothing is taken from SWaT data.
The numbers are copied from Part B Section B2 only; Sections B3-B8 (the answer key) are not used here.
"""
from __future__ import annotations

import csv
from pathlib import Path

from openpyxl import Workbook

DAY = "2000-01-01"
N_SECONDS = 2700                       # 09:00:00 .. 09:44:59, one row per second (B2.3)


def _t(sec: float) -> str:
    """Seconds after 09:00:00 -> '2000-01-01 HH:MM:SS.mmm'."""
    ms = round(sec * 1000)
    total = 9 * 3600 * 1000 + ms
    h, rem = divmod(total, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, milli = divmod(rem, 1000)
    return f"{DAY} {h:02d}:{m:02d}:{s:02d}.{milli:03d}"


def _hms(text: str) -> float:
    """'09:41:05' or '09:39:50.2' -> seconds after 09:00:00."""
    h, m, s = text.split(":")
    return (int(h) - 9) * 3600 + int(m) * 60 + float(s)


# ---- B2.3 historian --------------------------------------------------------------------------------
def historian_rows():
    rows = []
    for s in range(N_SECONDS):
        mv = 2 if s < 2467 else 1                                   # closed from 09:41:07
        if s in (1800, 1801, 1806) or s >= 2469:                    # noise glitch; then no flow
            fit = 0.0
        else:
            fit = 2.50 if s % 2 == 0 else 2.51
        if s <= 2468:
            lit = 600.0 if s % 2 == 0 else 600.2
        elif s <= 2489:
            lit = 600.0 - 0.5 * (s - 2468)                          # 589.5 at s = 2489
        else:
            lit = 588.0 - 1.5 * (s - 2490)                          # 588.0 at s = 2490, 274.5 at s = 2699
        rows.append((_t(s)[:19], mv, fit, round(lit, 1)))
    return rows


# ---- B2.4 flows ------------------------------------------------------------------------------------
HOSTS = [  # B2.2: address, role, in the testbed component list
    ("192.168.1.10", "PLC-1 (stage 1)", "yes"),
    ("192.168.1.20", "PLC-2 (stage 2)", "yes"),
    ("192.168.1.200", "Historian (HIST)", "yes"),
    ("192.168.1.201", "SCADA workstation (WS)", "yes"),
    ("192.168.1.99", "Undocumented poller", "no"),
    ("192.168.1.219", "Exfiltration server (EXF)", "no"),
    ("192.168.1.181", "Malware server (MAL)", "no"),
    ("8.8.8.8", "Public DNS server", "no"),
]
PLC1, PLC2, HIST, WS = "192.168.1.10", "192.168.1.20", "192.168.1.200", "192.168.1.201"
P99, EXF, MAL, DNS = "192.168.1.99", "192.168.1.219", "192.168.1.181", "8.8.8.8"

FLOWS = [  # flow, start, end, src, dst, port, protocol, CIP service, bytes, note
    ("f01", "09:00:10", "09:04:50", HIST, PLC1, 44818, "CIP", "read", 120_000, "pre-attack routine polling"),
    ("f02", "09:00:12", "09:04:52", HIST, PLC2, 44818, "CIP", "read", 118_000, "pre-attack routine polling"),
    ("f03", "09:01:00", "09:01:05", WS, HIST, 1433, "TCP", "", 40_000, "pre-attack routine query"),
    ("f04", "09:02:00", "09:02:01", PLC1, PLC2, 44818, "CIP", "write", 600, "pre-attack routine PLC-to-PLC write"),
    ("f05", "09:08:00", "09:44:50", HIST, PLC1, 44818, "CIP", "read", 1_000_000, "routine polling continues"),
    ("f06", "09:10:05", "09:14:30", WS, HIST, 1433, "TCP", "", 52_000_000, "historian data pulled to WS"),
    ("f07", "09:10:20", "09:14:55", WS, EXF, 443, "TCP", "", 51_000_000, "data sent out"),
    ("f08", "09:22:00", "09:22:01", P99, PLC2, 44818, "CIP", "read", 900, "noise: new poller"),
    ("f09", "09:41:00", "09:41:01", PLC1, PLC2, 44818, "CIP", "write", 600, "routine PLC-to-PLC write"),
    ("f10", "09:39:50.0", "09:39:50.2", WS, DNS, 53, "UDP", "", 150, "lookup just before the download"),
    ("f11", "09:40:10.0", "09:40:12.0", WS, MAL, 6001, "TCP", "", 10_000_000, "second-malware download (defines B)"),
    ("f12", "09:41:05", "09:41:06", WS, PLC1, 44818, "CIP", "write", 700, "attack command"),
]
CAPTURES = [("syn_00000", "09:00:00", "09:05:00"), ("syn_00001", "09:07:00", "09:45:00")]

# ---- B2.5 fixed inputs -----------------------------------------------------------------------------
LAYOUT = [  # row, from kind, from, from address, relation, to kind, to, tags of the stage
    ("D-1", "plc", "PLC-1", PLC1, "controls stage", "stage", "1", "MV101;FIT101;LIT101"),
    ("D-2", "plc", "PLC-2", PLC2, "controls stage", "stage", "2", "FIT201"),
    ("D-3", "tag", "MV101", "", "sets flow at", "tag", "FIT101", ""),
    ("D-4", "tag", "MV101", "", "feeds", "tag", "LIT101", ""),
    ("D-5", "tag", "FIT101", "", "feeds", "tag", "LIT101", ""),
]
STATISTICAL = [("S-1", "FIT101", "LIT101", 5, 30, "positive")]

# ---- B2.1 documented steps (ground truth: read only by export after the paths are fixed, and by the scorer) ----
STEPS = [  # step, start, end, scored, defining connection (host a, host b, port), what happens
    ("S0", "09:05:00", "09:05:00", "no", "", "", "", "Malware put on the SCADA workstation (WS) by USB"),
    ("A", "09:10:00", "09:15:00", "yes", "", "", "", "Historian data copied to WS and sent to the exfiltration server"),
    ("B", "09:40:10.0", "09:40:12.0", "yes", WS, MAL, "6001", "Second malware downloaded from the malware server"),
    ("C", "09:40:00", "09:43:00", "yes", "", "", "", "WS sends a CIP write to PLC-1 that closes valve MV-101"),
]
REFERENCE_LINKS = [("S0", "A", "no"), ("A", "B", "yes"), ("B", "C", "yes")]


def _write_csv(path: Path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def make(out_dir) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    wb = Workbook()
    ws = wb.active
    ws.title = "historian"
    ws.append(["Timestamp", "MV101", "FIT101", "LIT101"])            # workbook row 1; second s is row s + 2
    for row in historian_rows():
        ws.append(list(row))
    wb.save(out / "syn_historian.xlsx")

    cap_of = lambda start: next(c for c, a, b in CAPTURES if _hms(a) <= _hms(start) < _hms(b))
    _write_csv(out / "syn_flows.csv",
               ["flow_id", "capture_file", "t_start", "t_end", "src", "dst", "dst_port", "protocol", "cip_service", "bytes", "note"],
               [(fid, cap_of(a), _t(_hms(a)), _t(_hms(b)), src, dst, port, proto, svc, nbytes, note)
                for fid, a, b, src, dst, port, proto, svc, nbytes, note in FLOWS])
    _write_csv(out / "syn_capture_coverage.csv", ["capture_file", "t_start", "t_end"],
               [(c, _t(_hms(a)), _t(_hms(b))) for c, a, b in CAPTURES])
    _write_csv(out / "syn_host_roles.csv", ["address", "role", "in_component_list"], HOSTS)
    _write_csv(out / "syn_plant_layout.csv",
               ["row_id", "from_kind", "from", "from_address", "relation", "to_kind", "to", "stage_tags"], LAYOUT)
    _write_csv(out / "syn_statistical_table.csv", ["row_id", "from_tag", "to_tag", "lag_min_s", "lag_max_s", "sign"], STATISTICAL)
    _write_csv(out / "syn_documented_steps.csv",
               ["step_id", "logged_start", "logged_end", "scored", "conn_host_a", "conn_host_b", "conn_port", "description"],
               [(sid, _t(_hms(a)), _t(_hms(b)), scored, ha, hb, port, desc) for sid, a, b, scored, ha, hb, port, desc in STEPS])
    _write_csv(out / "syn_reference_links.csv", ["from_step", "to_step", "scorable"], REFERENCE_LINKS)
    (out / "README.txt").write_text(
        "MADE-UP DATA. Synthetic campaign from Expected Outcomes Part B, Section B2 (date 1 January 2000).\n"
        "Not SWaT data. Written by: python -m causalguard make-synthetic\n", encoding="utf-8")
    return out
