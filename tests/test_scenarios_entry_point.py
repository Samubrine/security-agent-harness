"""Milestone M3 end to end: a hypothesis that needs two independent sources.

The point of this scenario is the shape of the reasoning, not the finding itself. A cross-source
hypothesis must cite evidence from both sources, must stay below the confirmation bar that only
active verification could clear, and must not be reachable from memory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.runtime.replay import Replayer
from harness.runtime.runner import execute_run

pytestmark = pytest.mark.integration


@pytest.fixture
def entry_run(lab_environment) -> tuple[object, Path]:
    artifacts = execute_run(
        lab_environment.request(
            objective="Correlate scan and log evidence into a supported entry-point hypothesis.",
            skill="entry_point",
            run_id="run-scenario-entry",
        )
    )
    return artifacts, artifacts.run_dir


def _observations(run_dir: Path) -> dict[str, dict]:
    rows = json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in rows}


def _events(run_dir: Path, event_type: str) -> list[dict]:
    rows = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return [row for row in rows if row["type"] == event_type]


def _findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))


def test_the_run_exercises_both_sources(entry_run) -> None:
    artifacts, run_dir = entry_run
    assert artifacts.summary.status == "completed"
    kinds = {row["kind"] for row in _observations(run_dir).values()}
    assert "service" in kinds, "the scan half of the hypothesis must have run"
    assert {"auth_summary", "http_summary"} & kinds, "the log half must have run"


def test_the_hypothesis_cites_both_sources(entry_run) -> None:
    """A claim that rests on one source twice is not a correlation."""
    _, run_dir = entry_run
    observations = _observations(run_dir)
    findings = _findings(run_dir)
    hypothesis = next((f for f in findings if "hypothesis" in f["title"].lower()), None)
    assert hypothesis is not None, [f["title"] for f in findings]

    cited = [oid for claim in hypothesis["claims"] for oid in claim["supports"]]
    cited_kinds = {observations[oid]["kind"] for oid in cited if oid in observations}
    assert cited_kinds & {"service", "host_state", "scan_meta"}, cited_kinds
    assert cited_kinds & {"auth_summary", "http_summary", "auth_event", "http_event"}, cited_kinds


def test_the_hypothesis_is_possible_never_confirmed(entry_run) -> None:
    """Co-occurrence is not exploitation, and only active verification may say otherwise (D9)."""
    _, run_dir = entry_run
    hypothesis = next(f for f in _findings(run_dir) if "hypothesis" in f["title"].lower())
    assert hypothesis["status"] == "possible"
    assert any(claim["caveats"] for claim in hypothesis["claims"])


def test_the_hypothesis_survives_replay(entry_run) -> None:
    _, run_dir = entry_run
    replayer = Replayer(run_dir)
    assert replayer.verify() is True, replayer.problems


def test_the_skills_request_for_corroboration_reaches_the_gate(entry_run) -> None:
    """`verification.independent_for` is read, not decoration.

    The skill asks for it, the gate has a `trust_diversity_required` parameter for exactly this
    answer, and until WS-07 nothing passed one to the other - so the gate's second-provider path was
    unreachable and the skill's request had no effect whatsoever (K3, K5, R2-24).
    """
    _, run_dir = entry_run
    expansions = _events(run_dir, "PROVIDER_EXPANSION")
    assert expansions, "the skill asked for corroboration and no call was expanded"
    assert [row["data"]["expansion_reason"] for row in expansions] == ["trust_diversity"]
    # Two sources, and the capability that has two of them: entry_point's other capabilities are
    # served by a single provider each, and a demand for corroboration there would have refused a
    # call rather than strengthened it.
    assert expansions[0]["data"]["capability"] == "service.enumerate"
    assert len(expansions[0]["data"]["selected"]) == 2


def test_a_skill_that_does_not_ask_for_corroboration_is_unchanged(lab_environment) -> None:
    """The negative control: port_scan declares `independent_for: []` and asks for nothing."""
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-scenario-entry-single",
        )
    )
    assert _events(artifacts.run_dir, "PROVIDER_EXPANSION") == []
    assert artifacts.summary.provider_calls > 0, "a run that called nothing proves nothing here"


def test_an_uncorroborated_run_produces_no_hypothesis(lab_environment) -> None:
    """With only one source available, the cross-source rule must not fire at all.

    This is the negative control for the rule: if it fired on a scan alone, every port scan would
    end in an "entry point" finding, and the claim would be worth nothing.
    """
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate services only.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-scenario-entry-negative",
        )
    )
    titles = [f["title"].lower() for f in _findings(artifacts.run_dir)]
    assert not any("hypothesis" in title for title in titles)
