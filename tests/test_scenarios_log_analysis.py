"""Milestone M2 end to end: detect hostile activity in a log corpus with bounded context.

The interesting assertion here is not that a rule fires. It is that the harness read *both* corpora
from one filesystem grant, and that a success following a burst is reported as its own claim rather
than folded into the burst that preceded it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.runtime.replay import Replayer
from harness.runtime.runner import execute_run

pytestmark = pytest.mark.integration


@pytest.fixture
def log_run(lab_environment) -> tuple[object, Path]:
    artifacts = execute_run(
        lab_environment.request(
            objective="Detect suspicious authentication and HTTP activity in lab-logs.",
            skill="log_analysis",
            target_alias="lab-logs",
            run_id="run-scenario-logs",
        )
    )
    return artifacts, artifacts.run_dir


def _observations(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))


def _kinds(run_dir: Path) -> set[str]:
    return {row["kind"] for row in _observations(run_dir)}


def _findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))


def _attempts(run_dir: Path) -> list[dict]:
    rows = (run_dir / "executions.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(row) for row in rows if row.strip()]


def test_the_run_completes_and_reads_both_corpora(log_run) -> None:
    """One filesystem grant, two files: the second must still be read.

    The planner keys its progress on the call's arguments, not on the grant, because reading
    auth.log and then nginx_access.log is one grant and two invocations. If that regressed, this
    run would silently analyse authentication logs and never look at the access log.
    """
    artifacts, run_dir = log_run
    assert artifacts.summary.status == "completed"
    kinds = _kinds(run_dir)
    assert {"auth_event", "auth_summary"} <= kinds
    assert {"http_event", "http_summary"} <= kinds
    assert len(_attempts(run_dir)) == 2


def test_the_brute_force_burst_is_found(lab_environment, log_run) -> None:
    _, run_dir = log_run
    titles = " | ".join(finding["title"].lower() for finding in _findings(run_dir))
    assert "brute force" in titles
    summary = next(row for row in _observations(run_dir) if row["kind"] == "auth_summary")
    assert summary["value"]["burst_detected"] is True
    assert summary["value"]["top_source"] == "10.77.0.44"
    assert summary["value"]["top_source_failures"] >= 8


def test_a_success_after_a_burst_is_a_separate_lower_confidence_claim(log_run) -> None:
    """Folding the two together would assert a compromise the evidence does not support."""
    _, run_dir = log_run
    findings = _findings(run_dir)
    burst = next(f for f in findings if "brute force" in f["title"].lower())
    aftermath = next(f for f in findings if "following a credential burst" in f["title"].lower())
    assert burst["status"] == "confirmed"
    assert aftermath["status"] == "possible"
    assert aftermath["id"] != burst["id"]
    assert any("caveat" in claim or claim["caveats"] for claim in aftermath["claims"])


def test_the_access_log_probes_are_found(log_run) -> None:
    _, run_dir = log_run
    summary = next(row for row in _observations(run_dir) if row["kind"] == "http_summary")
    reasons = summary["value"]["reason_counts"]
    assert summary["value"]["campaign_detected"] is True
    assert reasons.get("path_traversal", 0) >= 1
    assert reasons.get("injection_syntax", 0) >= 1
    assert reasons.get("scanner_user_agent", 0) >= 1


def test_a_rejected_probe_is_not_reported_as_a_compromise(log_run) -> None:
    """The fixture's traversal returns 400 and its injection returns 403; neither succeeded."""
    _, run_dir = log_run
    summary = next(row for row in _observations(run_dir) if row["kind"] == "http_summary")
    assert summary["value"]["successful_suspicious"] == []
    for finding in _findings(run_dir):
        assert finding["status"] in {"possible", "confirmed", "inconclusive", "not_affected"}


def test_every_finding_survives_replay(log_run) -> None:
    _, run_dir = log_run
    replayer = Replayer(run_dir)
    assert replayer.verify() is True, replayer.problems
    assert replayer.findings, "a corpus with a burst and probes must produce findings"


def test_the_log_evidence_never_enters_the_prompt_wholesale(log_run) -> None:
    """C5 is never sent to a model (design 02 section 10): only bounded rollups are."""
    _, run_dir = log_run
    trace = (run_dir / "trace.jsonl").read_text(encoding="utf-8")
    replay = (run_dir / "replay.json").read_text(encoding="utf-8")
    assert "Failed password for" not in trace
    assert "Failed password for" not in replay
