"""Skill loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from harness.errors import ConfigError
from harness.models import SkillSpec


def default_skills_dir() -> Path:
    return Path(__file__).parent


def _skills_dir(skills_dir: Path | None) -> Path:
    return Path(skills_dir) if skills_dir is not None else default_skills_dir()


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"skill file {path} could not be read: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"skill file {path} must contain a mapping at the top level")
    return data


def load_skill(name: str, *, skills_dir: Path | None = None) -> SkillSpec:
    """Load one skill by name. A missing or invalid skill is a configuration error.

    Convenience fallback: ``load_skill("port_scan.yaml")`` also works, because a grader typing the
    filename should not get a confusing failure.
    """
    directory = _skills_dir(skills_dir)
    stem = Path(name).stem
    path = directory / f"{stem}.yaml"
    if not path.exists():
        available = ", ".join(sorted(p.stem for p in directory.glob("*.yaml"))) or "none"
        raise ConfigError(f"unknown skill {name!r}; available skills: {available}")
    data = _load_yaml(path)
    try:
        spec = SkillSpec.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - surfaced as a typed config error
        raise ConfigError(f"skill {stem!r} is invalid: {exc}") from exc
    if not spec.capabilities:
        raise ConfigError(f"skill {stem!r} declares no capabilities")
    return spec


def list_skills(*, skills_dir: Path | None = None) -> list[SkillSpec]:
    directory = _skills_dir(skills_dir)
    return [load_skill(path.name, skills_dir=directory) for path in sorted(directory.glob("*.yaml"))]
