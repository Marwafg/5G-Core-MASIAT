from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
PAYLOADS_DIR = BASE_DIR / "payloads"
PROFILES_DIR = BASE_DIR / "config" / "profiles"


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
      data = yaml.safe_load(handle) or {}
    return data


def load_payload_set(name: str) -> dict[str, Any]:
    return load_yaml(PAYLOADS_DIR / f"{name}.yaml")


def load_profile(name: str) -> dict[str, Any]:
    return load_yaml(PROFILES_DIR / f"{name}.yaml")
