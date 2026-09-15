"""Shared pytest fixtures.

Tests never touch the network, a model endpoint, or docker. Everything they need is either a
file under ``tests/fixtures`` or something built in a ``tmp_path``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]

# Allow running the suite without an editable install (e.g. a bare checkout).
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def nmap_01_xml(fixtures_dir: Path) -> bytes:
    return (fixtures_dir / "nmap" / "lab_web_01.xml").read_bytes()


@pytest.fixture(scope="session")
def nmap_02_xml(fixtures_dir: Path) -> bytes:
    return (fixtures_dir / "nmap" / "lab_web_02.xml").read_bytes()


@pytest.fixture(scope="session")
def auth_log_bytes(fixtures_dir: Path) -> bytes:
    return (fixtures_dir / "logs" / "auth.log").read_bytes()


@pytest.fixture(scope="session")
def nginx_log_bytes(fixtures_dir: Path) -> bytes:
    return (fixtures_dir / "logs" / "nginx_access.log").read_bytes()


@pytest.fixture(scope="session")
def vuln_snapshot_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vuln" / "snapshot_2026-09.json"


@pytest.fixture(scope="session")
def unsigned_scope_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "scope" / "lab_scope.json"


@pytest.fixture
def run_id() -> str:
    return "run-test-0001"
