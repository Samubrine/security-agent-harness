"""Skills are data; adding one must not require a runtime change."""

from __future__ import annotations

import pytest

from harness.errors import ConfigError
from harness.skills import list_skills, load_skill


def test_every_packaged_skill_loads() -> None:
    skills = list_skills()
    assert {s.name for s in skills} >= {"port_scan", "log_analysis", "entry_point"}


def test_port_scan_declares_the_capabilities_the_slice_needs() -> None:
    skill = load_skill("port_scan")
    assert "service.enumerate" in skill.capabilities
    assert "vulnerability.match" in skill.capabilities


def test_skill_filename_also_resolves() -> None:
    assert load_skill("port_scan.yaml").name == "port_scan"


def test_unknown_skill_lists_what_is_available() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_skill("does_not_exist")
    assert "port_scan" in str(excinfo.value)


def test_skill_from_an_explicit_directory(tmp_path) -> None:
    (tmp_path / "tiny.yaml").write_text(
        "name: tiny\nversion: 0.1.0\ncapabilities:\n  - log.read\n", encoding="utf-8"
    )
    skill = load_skill("tiny", skills_dir=tmp_path)
    assert skill.capabilities == ["log.read"]


def test_skill_with_no_capabilities_is_refused(tmp_path) -> None:
    (tmp_path / "empty.yaml").write_text("name: empty\nversion: 0.1.0\ncapabilities: []\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_skill("empty", skills_dir=tmp_path)


def test_malformed_yaml_is_a_config_error(tmp_path) -> None:
    (tmp_path / "broken.yaml").write_text("name: broken\n  version: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_skill("broken", skills_dir=tmp_path)
