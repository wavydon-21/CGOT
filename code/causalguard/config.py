"""Configuration loading. One YAML file holds every setting (Chapter 3, Table 3.5; Listing 4.1)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

STAGES = ("synthetic",)          # FYP1 step 10: made-up data only. The 2019 stage is added in FYP2.
RULE_FAMILIES = ("statistical", "domain", "provenance")
GROUND_TRUTH_KEYS = ("documented_steps", "reference_links")


class ConfigError(Exception):
    pass


class GateError(ConfigError):
    pass


def sha256_file(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_config(path) -> dict:
    p = Path(path).resolve()
    if not p.exists():
        raise ConfigError(f"Config file not found: {p}")
    raw = p.read_bytes()
    cfg = yaml.safe_load(raw)
    cfg["_config_path"] = str(p)
    cfg["_config_sha256"] = hashlib.sha256(raw).hexdigest()
    cfg["_root"] = str(p.parent.parent)   # paths in the YAML are relative to the code folder
    validate(cfg)
    return cfg


def resolve(cfg: dict, rel) -> Path:
    p = Path(str(rel))
    if not p.is_absolute():
        p = Path(cfg["_root"]) / p
    return p.resolve()


def validate(cfg: dict) -> None:
    if cfg.get("stage") not in STAGES:
        raise ConfigError(f"stage must be one of {STAGES}, got {cfg.get('stage')!r}")
    for key in ("historian", "flows", "capture_coverage", "host_roles", "layout_table",
                "statistical_table", "runs_dir") + GROUND_TRUTH_KEYS:
        if key not in cfg["dataset"]:
            raise ConfigError(f"dataset.{key} missing")
    th = cfg["thresholds"]
    if th["merge_gap_s"] < 0 or th["volume_factor"] <= 0:
        raise ConfigError("thresholds.merge_gap_s must be >= 0 and thresholds.volume_factor > 0")
    if cfg["linking"]["window_s"] <= 0:
        raise ConfigError("linking.window_s must be positive")
    names = set()
    for lk in cfg["linkers"]:
        if lk["mode"] not in ("causalguard", "temporal"):
            raise ConfigError(f"linker mode must be causalguard or temporal, got {lk['mode']!r}")
        for r in lk.get("rules", []):
            if r not in RULE_FAMILIES:
                raise ConfigError(f"unknown rule family {r!r} in linker {lk['name']}")
        if lk["name"] in names:
            raise ConfigError(f"linker name used twice: {lk['name']}")
        names.add(lk["name"])
    if cfg["paths"]["k"] < 1:
        raise ConfigError("paths.k must be at least 1")


def modules_view(cfg: dict) -> dict:
    """The configuration that modules 1-5 receive: the ground-truth file names are removed (decision D9, R5)."""
    view = {k: v for k, v in cfg.items()}
    view["dataset"] = {k: v for k, v in cfg["dataset"].items() if k not in GROUND_TRUTH_KEYS}
    return view


def check_gate(cfg: dict, log=print) -> dict:
    """Freeze rule (Chapter 4 Plan, Section 8a): the synthetic stage reads only the made-up files, and it
    refuses to run unless the frozen Expected Outcomes Part B is present with the hash written in the config."""
    data_dir = (Path(cfg["_root"]) / "tests" / "data_synthetic").resolve()
    for key, rel in cfg["dataset"].items():
        if key == "runs_dir":
            continue
        p = resolve(cfg, rel)
        if data_dir not in p.parents:
            raise GateError(f"synthetic stage may only read made-up files under {data_dir}; dataset.{key} points to {p}")
    eo = cfg.get("expected_outcomes") or {}
    path = resolve(cfg, eo["path"]) if eo.get("path") else None
    if path is None or not path.exists():
        raise GateError(f"STOP: the frozen Expected Outcomes Part B was not found at {path}.")
    want = str(eo.get("sha256") or "")
    actual = sha256_file(path)
    if not want:
        raise GateError("STOP: expected_outcomes.sha256 is empty in the config.")
    if actual.lower() != want.lower():
        raise GateError(
            "STOP: Expected_Outcomes_Part_B.md has changed since it was frozen.\n"
            f"  hash in config: {want}\n  hash of file:   {actual}\n"
            "A later note must be a dated addendum; the file is then re-hashed and the new hash recorded.")
    log(f"Freeze gate passed: Part B SHA-256 {actual[:16].upper()}... matches the config")
    return {"stage": cfg["stage"], "expected_outcomes_path": str(path), "expected_outcomes_sha256": actual}
