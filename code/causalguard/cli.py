"""Command line.

  python -m causalguard make-synthetic                          write the made-up campaign under tests/data_synthetic
  python -m causalguard run     --config configs/synthetic.yaml modules 1-6, writes runs/<id>/
  python -m causalguard score   --run runs/<id>                 reconstruction scorer (reads the documented steps)
  python -m causalguard compare --run runs/<id>                 check the run against the frozen Part B answer key
  python -m causalguard all     --config configs/synthetic.yaml run + score + compare
  python -m causalguard freeze  --config configs/synthetic.yaml print the config SHA-256 and date for the logbook
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .config import ConfigError, load_config
from .groundtruth import GroundTruthError
from .ingest import IngestError


def _cfg_of_run(run_dir: Path, config):
    # A run folder sits in <code>/runs/<id>/; the config that made it is named in the same code folder.
    return load_config(config) if config else load_config(run_dir.resolve().parent.parent / "configs" / "synthetic.yaml")


def main(argv=None) -> int:
    try:  # keep the console from failing on non-ASCII characters (Windows)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="causalguard", description="CausalGuard-OT minimal prototype (made-up campaign)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make-synthetic", help="write the made-up campaign files")
    m.add_argument("--out", default="tests/data_synthetic")
    for name, text in (("run", "modules 1-6"), ("all", "run + score + compare"), ("freeze", "print the config hash")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--config", required=True)
    for name, text in (("score", "reconstruction scorer"), ("compare", "check against Part B")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--run", required=True)
        p.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "make-synthetic":
            from .synthetic import make
            print(f"Made-up campaign written to {make(a.out).resolve()}")
        elif a.cmd == "freeze":
            cfg = load_config(a.config)
            print(f"Config: {cfg['_config_path']}\nSHA-256: {cfg['_config_sha256'].upper()}\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        elif a.cmd in ("run", "all"):
            from .pipeline import run
            cfg = load_config(a.config)
            run_dir = run(cfg)
            if a.cmd == "all":
                from .compare import compare
                from .scorer import score
                score(run_dir, cfg)
                compare(run_dir, cfg)
        elif a.cmd == "score":
            from .scorer import score
            score(Path(a.run), _cfg_of_run(Path(a.run), a.config))
        elif a.cmd == "compare":
            from .compare import compare
            compare(Path(a.run), _cfg_of_run(Path(a.run), a.config))
    except (ConfigError, IngestError, GroundTruthError) as e:
        print(f"\n{e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
