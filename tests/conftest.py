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


@pytest.fixture(scope="session")
def recorded_run_dir(fixtures_dir: Path) -> Path:
    """A frozen, tracked copy of a real recorded run directory.

    Deliberately under ``tests/fixtures`` and not ``eval/results``. That directory is gitignored - it
    is the local output of ``make eval`` - so a test reading it would pass on the machine that
    generated it and fail on a fresh clone, which is the worst of both worlds: a green suite that
    proves nothing about the repository.

    The directory is frozen rather than produced per test because grant, execution, decision and
    observation ids come from ``new_id`` and are random, so a regenerated run cannot satisfy a test
    that asserts a specific id. Tests that need a *fresh* run build one in ``tmp_path`` through the
    spine instead.
    """
    path = fixtures_dir / "run" / "port_scan"
    assert path.is_dir(), f"the frozen recorded run is missing at {path}"
    assert (path / "executions.json").is_file(), f"{path} is not a recorded run directory"
    return path


# ---------------------------------------------------------------------------------------------
# Scenario support
#
# A run needs a verifiable scope record, a workspace whose memory files exist, and a source of
# package and vulnerability data. Building that per test file would let the three scenario suites
# drift into three slightly different ideas of what a run is, so it is built once here.
# ---------------------------------------------------------------------------------------------


class LabEnvironment:
    """A signed scope, a workspace and the fixture paths, ready to hand to execute_run."""

    def __init__(self, base: Path, fixtures: Path) -> None:
        from datetime import timedelta

        from harness.models import ScopeFile, ScopeNetwork, ScopeWindow
        from harness.policy.scope import generate_keypair, sign_scope
        from harness.util import atomic_write_json, utcnow

        self.base = base
        self.fixtures = fixtures
        self.root = base / "workspace"
        self.root.mkdir(parents=True)
        (self.root / "memory").mkdir()
        (self.root / "MEMORY.md").write_text(
            "# Active Harness Memory\n\n- no active goals yet\n", encoding="utf-8"
        )
        (self.root / "memory" / "BASELINE.md").write_text(
            "# Baseline Memory\n\n## Invariants\n\n- Local inference is the default.\n", encoding="utf-8"
        )

        self.private_key = base / "keys" / "scope.key"
        self.public_key = base / "keys" / "scope.pub"
        generate_keypair(self.private_key, self.public_key)

        scope = ScopeFile(
            scope_id="lab-scenario",
            authorized_by="pytest",
            networks=[ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11", "10.77.0.12"])],
            filesystem=["/lab/logs"],
            aliases={
                "lab-web-01": "net:10.77.0.11",
                "lab-web-02": "net:10.77.0.12",
                "lab-logs": "fs:/lab/logs",
            },
            window=ScopeWindow(
                **{"from": utcnow() - timedelta(days=1), "to": utcnow() + timedelta(days=1)}
            ),
        )
        signed = sign_scope(scope, self.private_key)
        self.scope_path = base / "scope.json"
        atomic_write_json(self.scope_path, signed.model_dump(mode="json"))
        self.runs_root = base / "runs"

    def request(self, *, objective: str, skill: str, run_id: str, **overrides):
        """Build a RunRequest wired to this environment's scope, workspace and fixtures."""
        from harness.runtime.runner import RunRequest

        kwargs = dict(
            objective=objective,
            skill=skill,
            scope_path=self.scope_path,
            public_key_path=self.public_key,
            root=self.root,
            runs_root=self.runs_root,
            model_backend="scripted",
            model_id="scripted-planner",
            fixture_root=self.fixtures,
            log_root=self.fixtures / "logs",
            snapshot_path=self.fixtures / "vuln" / "snapshot_2026-09.json",
            run_id=run_id,
            enable_memory_curation=False,
        )
        kwargs.update(overrides)
        return RunRequest(**kwargs)


@pytest.fixture
def lab_environment(tmp_path: Path) -> LabEnvironment:
    return LabEnvironment(tmp_path, FIXTURES)
