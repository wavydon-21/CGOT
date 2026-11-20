"""Command line:   python -m pilot run --config configs/pilot_2015.yaml"""
from __future__ import annotations

import argparse
import sys

from .config import ConfigError, load_config
from .detectors import DetectorError
from .ingest import IngestError
from .prep import PrepError


def main(argv=None) -> int:
    try:  # keep the console from failing on non-ASCII characters (Windows)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="pilot", description="CausalGuard-OT FYP1 2015 detection pilot")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the whole pilot with one configuration file")
    r.add_argument("--config", required=True)
    s = sub.add_parser("make-smoke-data", help="write the made-up smoke-test files under tests/data")
    s.add_argument("--out", default="tests/data")
    s.add_argument("--tag-mapping", default=None, help="path to tag_mapping_2015_2019.csv (copied into the smoke folder)")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "run":
            from .pipeline import run
            cfg = load_config(a.config)
            run(cfg)
        elif a.cmd == "make-smoke-data":
            from .smoke_data import make
            make(a.out, a.tag_mapping)
    except (ConfigError, IngestError, PrepError, DetectorError) as e:
        print(f"\n{e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
