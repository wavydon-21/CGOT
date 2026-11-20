"""Configuration loading. One YAML file holds every setting (Chapter 3, Table 3.5)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

STAGES = ("dev", "pilot", "smoke")


class ConfigError(Exception):
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
    # Paths in the YAML are relative to the code root (the folder that holds configs/).
    cfg["_root"] = str(p.parent.parent)
    validate(cfg)
    return cfg


def resolve(cfg: dict, rel) -> Path:
    """Resolve a path from the config against the code root."""
    p = Path(str(rel))
    if not p.is_absolute():
        p = Path(cfg["_root"]) / p
    return p.resolve()


def validate(cfg: dict) -> None:
    if cfg.get("stage") not in STAGES:
        raise ConfigError(f"stage must be one of {STAGES}, got {cfg.get('stage')!r}")
    s = cfg["split"]
    if abs(s["train"] + s["calibration"] + s["holdout"] - 1.0) > 1e-9:
        raise ConfigError("split fractions must sum to 1")
    if not (0 < cfg["detection_budget"] < 1):
        raise ConfigError("detection_budget must be between 0 and 1")
    if not cfg["isolation_forest"]["seeds"]:
        raise ConfigError("isolation_forest.seeds must not be empty")
    for key in ("normal_xlsx", "tag_mapping_csv", "cache_dir", "runs_dir"):
        if key not in cfg["data"]:
            raise ConfigError(f"data.{key} missing")
    if cfg["stage"] != "dev":
        for key in ("attack_xlsx", "attack_list_xlsx"):
            if key not in cfg["data"]:
                raise ConfigError(f"data.{key} missing (needed outside the dev stage)")
