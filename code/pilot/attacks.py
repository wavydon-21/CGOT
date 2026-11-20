"""Read the supplied attack list (List_of_attacks_Final.xlsx) for the per-attack recall.

Known data problems (Chapter 3, Section 3.4.1) are handled in the open, not silently:
 - entries 37-41 give January 2015 instead of January 2016 -> the year is corrected and flagged
 - entries with 'No Physical Impact Attack' have no end time -> listed but not scored per attack
The end time is a time of day; it is joined to the start date (next day if earlier than the start).
"""
from __future__ import annotations

from datetime import datetime, time, timedelta
from pathlib import Path

import pandas as pd


def load_attack_list(path: Path, first_ts: pd.Timestamp, last_ts: pd.Timestamp, log=print) -> tuple[list[dict], list[dict]]:
    import openpyxl

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb[wb.sheetnames[0]]
    scored, unscored = [], []
    for row in ws.iter_rows(min_row=2, values_only=True):
        aid, start, end, point = row[0], row[1], row[2], row[3]
        if not isinstance(aid, (int, float)) or not isinstance(start, datetime):
            continue
        start = pd.Timestamp(start)
        corrected = False
        # a start date more than a day before the attack file begins is the January-2015 typo
        if start < first_ts - pd.Timedelta(days=1):
            start = start + pd.DateOffset(years=1)
            corrected = True
        if end is None:
            unscored.append({"id": int(aid), "start": start, "point": str(point), "year_corrected": corrected,
                             "reason": "no end time in the list"})
            continue
        if isinstance(end, datetime):
            end_ts = pd.Timestamp(end)
        elif isinstance(end, time):
            end_ts = pd.Timestamp(datetime.combine(start.date(), end))
        else:
            unscored.append({"id": int(aid), "start": start, "point": str(point), "year_corrected": corrected,
                             "reason": f"unreadable end time {end!r}"})
            continue
        if end_ts < start:
            end_ts += timedelta(days=1)
        scored.append({"id": int(aid), "start": start, "end": end_ts, "point": str(point), "year_corrected": corrected})
    wb.close()
    out_of_range = [a["id"] for a in scored if a["start"] < first_ts or a["end"] > last_ts]
    if out_of_range:
        log(f"  WARNING: attacks {out_of_range} fall outside the attack file's time range")
    return scored, unscored
