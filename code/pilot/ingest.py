"""Module 1: data ingestion (Chapter 3, Section 3.5.1; Chapter 4 design F1, F2).

Each source workbook is converted once to a Parquet file. The SHA-256 of the source and of
the converted file are written to a manifest. A later run recomputes the source hash and
stops if it differs from the manifest. Every row keeps its Excel row number (src_row) so any
later result can be traced back to a record (R2).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .config import sha256_file

TS_NAMES = {"timestamp"}
LABEL_NAMES = {"normal/attack"}


class IngestError(Exception):
    pass


def _find_header(first_rows):
    """Header row = the first of the first 10 rows that holds the tag name FIT101."""
    for i, row in enumerate(first_rows, start=1):
        if any(str(v).strip() == "FIT101" for v in row if v is not None):
            return i, [str(v).strip() if v is not None else "" for v in row]
    raise IngestError("Could not find the header row (a row containing FIT101) in the first 10 rows")


def convert_workbook(src: Path, dst: Path, progress_every: int = 50_000, log=print) -> dict:
    """Read one 2015 workbook and write Parquet. Returns the manifest entry (without hashes of dst)."""
    import openpyxl

    t0 = time.perf_counter()
    log(f"  reading {src.name} (this takes several minutes for the real files) ...")
    wb = openpyxl.load_workbook(src, read_only=True, data_only=True)
    ws = wb[wb.sheetnames[0]]
    rows_iter = ws.iter_rows(values_only=True)
    head = []
    for _ in range(10):
        head.append(next(rows_iter))
    header_row, header = _find_header(head)
    ts_col = next(i for i, h in enumerate(header) if h.lower() in TS_NAMES)
    lab_col = next(i for i, h in enumerate(header) if h.lower() in LABEL_NAMES)
    tag_cols = [i for i in range(len(header)) if i not in (ts_col, lab_col) and header[i] != ""]
    tags = [header[i] for i in tag_cols]

    # data rows start right after the header; Excel row number of the first data row:
    first_data_row = header_row + 1
    pending = head[header_row:]  # rows already read after the header
    chunks, n_rows, nonnumeric = [], 0, 0

    def flush(buf, start_row):
        nonlocal nonnumeric
        df = pd.DataFrame(buf)
        out = pd.DataFrame({"src_row": np.arange(start_row, start_row + len(df), dtype=np.int64)})
        out["timestamp_raw"] = df[ts_col].astype(str)
        vals = df[tag_cols]
        num = vals.apply(pd.to_numeric, errors="coerce")
        nonnumeric += int(num.isna().sum().sum() - vals.isna().sum().sum())
        num.columns = tags
        out = pd.concat([out, num.astype("float64")], axis=1)
        out["label_raw"] = df[lab_col].astype(str)
        return out

    buf = list(pending)
    start_row = first_data_row
    for row in rows_iter:
        buf.append(row)
        if len(buf) >= progress_every:
            chunks.append(flush(buf, start_row))
            start_row += len(buf)
            n_rows += len(buf)
            buf = []
            log(f"    {n_rows:,} rows read ({time.perf_counter() - t0:.0f} s)")
    if buf:
        # drop fully empty trailing rows (None everywhere)
        while buf and all(v is None for v in buf[-1]):
            buf.pop()
        if buf:
            chunks.append(flush(buf, start_row))
            n_rows += len(buf)
    wb.close()
    df = pd.concat(chunks, ignore_index=True)
    df = df[df["timestamp_raw"].str.strip().ne("None")].reset_index(drop=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(dst, index=False)
    return {
        "rows": int(len(df)),
        "columns": list(df.columns),
        "tag_columns": tags,
        "header_excel_row": header_row,
        "first_data_excel_row": first_data_row,
        "n_cells_not_numeric_after_coercion": int(nonnumeric),
        "convert_seconds": round(time.perf_counter() - t0, 1),
    }


def _manifest_path(cache_dir: Path) -> Path:
    return cache_dir / "manifest.json"


def load_manifest(cache_dir: Path) -> dict:
    p = _manifest_path(cache_dir)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"sources": {}}


def save_manifest(cache_dir: Path, manifest: dict) -> None:
    _manifest_path(cache_dir).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def ingest(key: str, src: Path, cache_dir: Path, log=print) -> tuple[pd.DataFrame, dict]:
    """Return (dataframe, manifest entry) for one source workbook.

    Converts on first use. On later runs the source hash is re-computed and compared with the
    manifest; a difference stops the run (design edge case, Chapter 4 Section 4.4.1).
    """
    src = Path(src)
    if not src.exists():
        raise IngestError(f"Source file not found: {src}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(cache_dir)
    entry = manifest["sources"].get(key)
    dst = cache_dir / f"{src.stem}.parquet"
    src_hash = sha256_file(src)
    if entry is not None and dst.exists():
        if entry["source_sha256"] != src_hash:
            raise IngestError(
                f"STOP: the hash of {src.name} differs from the manifest.\n"
                f"  manifest: {entry['source_sha256']}\n  now:      {src_hash}\n"
                "The source file has changed since it was first converted. Do not continue "
                "until you know why. (To start again deliberately, delete the cache folder.)")
        if entry["parquet_sha256"] != sha256_file(dst):
            raise IngestError(f"STOP: {dst.name} no longer matches the manifest hash. Delete the cache folder to rebuild.")
        log(f"  {src.name}: hash matches manifest, using {dst.name}")
        reused = True
    else:
        info = convert_workbook(src, dst, log=log)
        entry = {
            "source_path": str(src),
            "source_bytes": src.stat().st_size,
            "source_sha256": src_hash,
            "parquet_path": str(dst),
            "parquet_sha256": sha256_file(dst),
            "converted_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **info,
        }
        manifest["sources"][key] = entry
        save_manifest(cache_dir, manifest)
        log(f"  {src.name}: converted {entry['rows']:,} rows in {entry['convert_seconds']} s; SHA-256 recorded")
        reused = False
    df = pd.read_parquet(dst)
    entry = dict(entry, reused_cache=reused)
    return df, entry
