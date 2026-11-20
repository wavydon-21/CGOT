"""One run: ingest -> events -> links (each linker) -> top-k paths -> export. The scorer is a separate command."""
from __future__ import annotations

import json
import platform
import shutil
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from . import events as events_mod
from . import export, linking, paths as paths_mod
from .config import check_gate, modules_view, resolve, sha256_file
from .ingest import ingest


def _log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


class Timer:
    def __init__(self):
        self.rows = []

    @contextmanager
    def step(self, name):
        t = time.perf_counter()
        yield
        self.rows.append({"step": name, "seconds": round(time.perf_counter() - t, 4)})


def run(cfg: dict, log=_log) -> Path:
    gate = check_gate(cfg, log)
    runs_dir = resolve(cfg, cfg["dataset"]["runs_dir"])
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = runs_dir / f"{stamp}_{cfg['_config_sha256'][:8]}_{cfg['stage']}"
    n = 1
    while run_dir.exists():                                          # two runs in the same second
        n += 1
        run_dir = runs_dir / f"{stamp}-{n}_{cfg['_config_sha256'][:8]}_{cfg['stage']}"
    run_dir.mkdir(parents=True)
    shutil.copy(cfg["_config_path"], run_dir / "config_used.yaml")
    log(f"Run folder: {run_dir}")
    timer = Timer()
    mcfg = modules_view(cfg)            # modules 1-5 do not get the ground-truth file names (D9)

    with timer.step("1_ingestion"):
        data = ingest(mcfg)
    log(f"Ingestion: {len(data['historian']['rows'])} historian rows, {len(data['flows'])} flows, {len(data['data_gaps'])} capture gap(s)")
    with timer.step("3_event_abstraction"):
        events = events_mod.extract(data, mcfg)
    log(f"Events: {len(events)} ({sum(e['source_kind'] == 'network' for e in events)} network, {sum(e['source_kind'] == 'process' for e in events)} process)")

    links, all_paths = [], []
    for lk in mcfg["linkers"]:
        with timer.step(f"4_typed_linking[{lk['name']}]"):
            lk_links = linking.link(events, lk, mcfg, data["layout"], data["statistical"])
        with timer.step(f"5_path_scoring[{lk['name']}]"):
            lk_paths = paths_mod.build(events, lk_links, lk["name"], int(mcfg["paths"]["k"]))
        links += lk_links
        all_paths += lk_paths
        acc = sum(l["decision"] == "accepted" for l in lk_links)
        log(f"Linker {lk['name']}: {len(lk_links)} candidates, {acc} accepted, top path score {lk_paths[0]['score'] if lk_paths else 'none'}")

    fixed = paths_mod.fix(all_paths)    # from here on the paths cannot change
    with timer.step("6_explanation_export"):
        checklist = export.write_all(run_dir, cfg, data, events, links, all_paths, fixed)
    if paths_mod.fix(all_paths) != fixed:
        raise RuntimeError("The paths changed after they were fixed (decision D9 broken).")

    with open(run_dir / "timings.csv", "w", encoding="utf-8", newline="") as f:
        f.write("step,seconds\n" + "".join(f"{r['step']},{r['seconds']}\n" for r in timer.rows))
    outputs = {p.name: sha256_file(p) for p in sorted(run_dir.iterdir()) if p.name in ("events.csv", "links.csv", "paths.json", "report.html", "checklist.json", "unknown_steps.csv")}
    manifest = {
        "run_dir": run_dir.name, "stage": cfg["stage"], "made_up_data": True,
        "config_sha256": cfg["_config_sha256"], "gate": gate, "inputs": data["input_hashes"],
        "paths_fixed_sha256": fixed, "outputs": outputs,
        "counts": {"events": len(events), "links": {lk["name"]: {"candidates": sum(l["linker"] == lk["name"] for l in links),
                                                                  "accepted": sum(l["linker"] == lk["name"] and l["decision"] == "accepted" for l in links)}
                                                    for lk in cfg["linkers"]}},
        "checklist": checklist,
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    log("Done. Open report.html in the run folder.")
    return run_dir
