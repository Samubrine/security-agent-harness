"""The vertical slice: one local-model run that ends in evidence-bound findings.

This is the test the project's first success criterion describes. It crosses every layer --
signed scope, grants, catalogue, scripted planner, necessity gate, policy, provider, artifact,
parser, analyser, finding validator, report, replay -- and asserts the properties that make the
result defensible rather than merely impressive.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from harness.models import ScopeFile, ScopeNetwork, ScopeWindow
from harness.policy.scope import generate_keypair, sign_scope
from harness.runtime.replay import Replayer
from harness.runtime.runner import RunRequest, execute_run
from harness.util import atomic_write_json, utcnow

pytestmark = pytest.mark.integration


def _signed_scope(tmp_path: Path) -> tuple[Path, Path]:
    """A scope record signed with a throwaway key, exactly as a real run requires."""
    private_key = tmp_path / "keys" / "scope.key"
    public_key = tmp_path / "keys" / "scope.pub"
    generate_keypair(private_key, public_key)

    scope = ScopeFile(
        scope_id="lab-test-slice",
        authorized_by="pytest",
        networks=[ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11"])],
        aliases={"lab-web-01": "net:10.77.0.11"},
        window=ScopeWindow(**{"from": utcnow() - timedelta(days=1), "to": utcnow() + timedelta(days=1)}),
    )
    signed = sign_scope(scope, private_key)
    scope_path = tmp_path / "scope.json"
    atomic_write_json(scope_path, signed.model_dump(mode="json"))
    return scope_path, public_key


def _workspace(tmp_path: Path) -> Path:
    """A minimal harness root: the runner reads these memory files on every run."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "MEMORY.md").write_text("# Active Harness Memory\n\n- no active goals yet\n", encoding="utf-8")
    (root / "memory").mkdir()
    (root / "memory" / "BASELINE.md").write_text(
        "# Baseline Memory\n\n## Invariants\n\n- Local inference is the default.\n", encoding="utf-8"
    )
    return root


def _request(tmp_path: Path, root: Path, scope: Path, public_key: Path) -> RunRequest:
    fixtures = Path(__file__).parent / "fixtures"
    return RunRequest(
        objective="Enumerate exposed services on lab-web-01 and identify version-level weaknesses.",
        skill="port_scan",
        scope_path=scope,
        public_key_path=public_key,
        root=root,
        runs_root=tmp_path / "runs",
        target_alias="lab-web-01",
        model_backend="scripted",
        model_id="scripted-planner",
        fixture_root=fixtures,
        log_root=fixtures / "logs",
        snapshot_path=fixtures / "vuln" / "snapshot_2026-09.json",
        run_id="run-slice-1",
    )


@pytest.fixture
def slice_run(tmp_path: Path):
    scope, public_key = _signed_scope(tmp_path)
    root = _workspace(tmp_path)
    return execute_run(_request(tmp_path, root, scope, public_key)), tmp_path


def test_run_completes_and_produces_findings(slice_run) -> None:
    artifacts, _ = slice_run
    assert artifacts.summary.status == "completed"
    assert artifacts.summary.findings >= 1, artifacts.stop_reason
    assert artifacts.report_markdown.exists()


def test_findings_are_backed_by_recomputable_evidence(slice_run) -> None:
    artifacts, _ = slice_run
    replayer = Replayer(artifacts.run_dir)
    assert replayer.verify() is True, replayer.problems
    for finding in replayer.findings:
        assert finding.claims, f"{finding.id} has no claim"
        assert finding.observation_ids(), f"{finding.id} cites no observation"


def test_a_known_vulnerable_version_is_matched_from_the_snapshot(slice_run) -> None:
    artifacts, _ = slice_run
    replayer = Replayer(artifacts.run_dir)
    matched = {cve for finding in replayer.findings for cve in finding.cve}
    # OpenSSH 8.2p1 is inside CVE-2023-38408's range; the finding must come from the snapshot,
    # not from a model's recollection.
    assert "CVE-2023-38408" in matched


def test_replaying_the_run_reconstructs_the_same_finding_digests(slice_run) -> None:
    artifacts, _ = slice_run
    first = Replayer(artifacts.run_dir).finding_digests()
    second = Replayer(artifacts.run_dir).finding_digests()
    assert first == second
    assert first, "a run with findings must produce finding digests"


def test_the_event_chain_verifies(slice_run) -> None:
    from harness.events import EventLog

    artifacts, _ = slice_run
    log = EventLog(artifacts.run_dir / "events.jsonl", artifacts.run_id)
    assert log.verify_chain() is True
    assert log.count() > 5


def test_the_out_of_scope_decoy_is_never_touched(slice_run) -> None:
    """Structural scope: 10.77.0.99 is not merely disallowed, it has no name to be named by."""
    artifacts, _ = slice_run
    executions = (artifacts.run_dir / "executions.jsonl").read_text(encoding="utf-8")
    assert "10.77.0.99" not in executions
    # The decoy may appear inside an observation (it is text in a hostile banner), but never as a
    # target of an execution.
    observations = (artifacts.run_dir / "observations.jsonl").read_text(encoding="utf-8")
    if "10.77.0.99" in observations:
        assert "injection_attempt" in observations


def test_the_banner_injection_is_recorded_as_an_observation_not_obeyed(slice_run) -> None:
    artifacts, _ = slice_run
    observations = (artifacts.run_dir / "observations.jsonl").read_text(encoding="utf-8")
    assert "injection_attempt" in observations
    # And nothing executed as a result of it.
    decisions = (artifacts.run_dir / "provider-decisions.jsonl").read_text(encoding="utf-8")
    assert "10.77.0.99" not in decisions


def test_the_report_is_regenerable_from_the_directory_alone(slice_run) -> None:
    from harness.report.build import build_report

    artifacts, _ = slice_run
    markdown, machine = build_report(run_dir=artifacts.run_dir)
    assert machine["integrity"]["chain_verified"] is True
    assert not machine["integrity"]["problems"], machine["integrity"]["problems"]
    assert "CVE-2023-38408" in markdown


def test_the_necessity_gate_recorded_at_least_one_decision(slice_run) -> None:
    artifacts, _ = slice_run
    rows = (artifacts.run_dir / "provider-decisions.jsonl").read_text(encoding="utf-8").strip()
    assert rows, "every capability request must produce a decision record"


def test_a_dry_run_executes_nothing(tmp_path: Path) -> None:
    scope, public_key = _signed_scope(tmp_path)
    root = _workspace(tmp_path)
    request = _request(tmp_path, root, scope, public_key)
    request.dry_run = True
    request.run_id = "run-slice-dry"
    artifacts = execute_run(request)
    executions = artifacts.run_dir / "executions.jsonl"
    assert not executions.exists() or executions.read_text(encoding="utf-8").strip() == ""
