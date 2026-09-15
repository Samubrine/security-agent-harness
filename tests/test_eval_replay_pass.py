"""Tests for the replay pass and the memory metrics.

The replay pass is the one place where an evaluation step can destroy the artefact it is measuring.
The regression test that matters most is therefore not that the digest maps are produced, but that
producing them leaves the run's recorded model/provider trace byte-identical: that trace is what
``ReplayModelClient.from_path` reads to make a run offline-replayable, and an earlier version of this
pass wrote its report over it, which turned every subsequent offline replay into a JSONDecodeError.

The second test that matters is the adversarial one. A metric that compares two digest maps is only
worth having if it reports a mismatch when the thing it measures is broken, so one test tampers a
single recorded claim and asserts the maps stop agreeing.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from eval.metrics import (
    METRIC_NAMES,
    RunBundle,
    load_ground_truth,
    load_run_bundle,
    measured,
    memory_evidence_isolation,
    memory_persistence,
    memory_retrieval_cost,
    replay_fidelity,
)
from eval.replay_pass import REPLAY_REPORT, augment_replay_json, rederive_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The frozen recorded run. Under tests/fixtures and not eval/results, which is gitignored: a test
#: reading a directory that only exists on the machine that ran 'make eval' passes there and fails
#: on a clone, which is a green suite that proves nothing about the repository.
RECORDED_RUN = Path(__file__).resolve().parent / "fixtures" / "run" / "port_scan"


@pytest.fixture
def run_copy(tmp_path: Path) -> Path:
    """A real recorded run, copied so a test cannot corrupt the committed evidence."""
    destination = tmp_path / "run"
    shutil.copytree(RECORDED_RUN, destination)
    return destination


def _truth():
    return load_ground_truth(REPO_ROOT / "eval" / "ground_truth.json")


# ----------------------------------------------------------------------------------------------
# Re-derivation
# ----------------------------------------------------------------------------------------------


def test_a_clean_run_re_derives_its_own_findings(run_copy: Path) -> None:
    """The run's recorded observations imply the findings it recorded. That is the property."""
    result = rederive_findings(run_copy)
    assert result.live_finding_digests, "the frozen recorded run records findings"
    assert result.replayed_finding_digests
    assert result.live_finding_digests == result.replayed_finding_digests
    assert result.observations_used > 0
    assert result.rederived == len(result.live_finding_digests)


def test_a_tampered_claim_breaks_the_digest_maps(run_copy: Path) -> None:
    """THE adversarial case. Without this the metric could be measuring nothing at all.

    One character added to one recorded claim must stop the recorded findings from agreeing with
    what the run's own observations imply, and it must change exactly one digest rather than
    invalidating the whole comparison.
    """
    before = rederive_findings(run_copy)
    assert before.live_finding_digests == before.replayed_finding_digests

    findings_path = run_copy / "findings.json"
    rows = json.loads(findings_path.read_text(encoding="utf-8"))
    original = rows[0]["claims"][0]["statement"]
    rows[0]["claims"][0]["statement"] = original + " TAMPERED"
    findings_path.write_text(json.dumps(rows), encoding="utf-8")

    after = rederive_findings(run_copy)
    assert after.live_finding_digests != after.replayed_finding_digests
    changed = {
        key
        for key in before.live_finding_digests
        if before.live_finding_digests.get(key) != after.live_finding_digests.get(key)
    }
    assert len(changed) == 1, changed
    # The re-derived side is computed from observations, so tampering the recorded findings must
    # not move it. If it did, the pass would be reading the thing it is supposed to derive.
    assert after.replayed_finding_digests == before.replayed_finding_digests


def test_the_replay_report_does_not_touch_the_recorded_trace(run_copy: Path) -> None:
    """The regression that made this file necessary.

    ``replay.json`` is the JSONL trace of model and provider interactions and is what makes a run
    offline-replayable. Writing the digest document over it broke that; the report now has its own
    file and the trace must come out byte-identical.
    """
    trace = run_copy / "replay.json"
    assert trace.is_file()
    before = trace.read_bytes()
    # The recorded trace is JSONL records, which is exactly what from_path parses.
    first = json.loads(before.decode("utf-8").splitlines()[0])
    assert first.get("kind") in {"model", "provider"}

    augment_replay_json(run_copy)

    assert trace.read_bytes() == before, "the replay trace must not be rewritten"
    assert (run_copy / REPLAY_REPORT).is_file()
    document = json.loads((run_copy / REPLAY_REPORT).read_text(encoding="utf-8"))
    assert document["finding_digests"]
    assert document["replayed_finding_digests"]


def test_the_report_file_name_is_not_the_trace_file_name() -> None:
    """A one-line guard: the two names must never converge again."""
    assert REPLAY_REPORT != "replay.json"


def test_augmenting_twice_is_idempotent(run_copy: Path) -> None:
    first = augment_replay_json(run_copy)
    document_one = (run_copy / REPLAY_REPORT).read_text(encoding="utf-8")
    second = augment_replay_json(run_copy)
    assert second.replayed_finding_digests == first.replayed_finding_digests
    assert (run_copy / REPLAY_REPORT).read_text(encoding="utf-8") == document_one


# ----------------------------------------------------------------------------------------------
# replay_fidelity, before and after
# ----------------------------------------------------------------------------------------------


def test_replay_fidelity_is_not_measured_until_the_pass_runs(run_copy: Path) -> None:
    """A run that was never replayed must not be flattered with a 1.0."""
    metric = replay_fidelity(load_run_bundle(run_copy), _truth())
    assert metric.status == "not_measured"


def test_replay_fidelity_becomes_measured_after_the_pass(run_copy: Path) -> None:
    augment_replay_json(run_copy)
    metric = replay_fidelity(load_run_bundle(run_copy), _truth())
    assert metric.status == "measured"
    assert metric.value == 1.0


def test_replay_fidelity_reports_the_mismatch(run_copy: Path) -> None:
    augment_replay_json(run_copy)
    findings_path = run_copy / "findings.json"
    rows = json.loads(findings_path.read_text(encoding="utf-8"))
    rows[0]["claims"][0]["statement"] += " TAMPERED"
    findings_path.write_text(json.dumps(rows), encoding="utf-8")
    augment_replay_json(run_copy)
    metric = replay_fidelity(load_run_bundle(run_copy), _truth())
    assert metric.status == "measured"
    assert metric.value is not None and metric.value < 1.0
    assert metric.inputs["mismatched"]


# ----------------------------------------------------------------------------------------------
# Memory metrics
# ----------------------------------------------------------------------------------------------


def test_the_memory_metrics_are_registered() -> None:
    for name in ("memory_persistence", "memory_evidence_isolation", "memory_retrieval_cost"):
        assert name in METRIC_NAMES


def test_memory_isolation_holds_on_a_real_run(run_copy: Path) -> None:
    """Memory is context and can never support a finding. A real run must score 1.0."""
    metric = memory_evidence_isolation(load_run_bundle(run_copy))
    assert metric.status == "measured"
    assert metric.value == 1.0


def test_memory_isolation_catches_a_memory_reference_in_a_claim(tmp_path: Path) -> None:
    """The negative case: if a claim ever cites a memory entry, the metric must move."""
    bundle = RunBundle(
        run_dir=tmp_path,
        findings=[
            {"id": "f-1", "claims": [{"id": "c-1", "supports": ["o-1"]}]},
            {"id": "f-2", "claims": [{"id": "c-2", "supports": ["mem-deadbeef"]}]},
        ],
    )
    metric = memory_evidence_isolation(bundle)
    assert metric.status == "measured"
    assert metric.value == 0.5
    assert "f-2" in metric.inputs["offending"]
    assert metric.inputs["offending"]["f-2"] == ["mem-deadbeef"]


def test_memory_isolation_is_not_measured_without_findings(tmp_path: Path) -> None:
    assert memory_evidence_isolation(RunBundle(run_dir=tmp_path)).status == "not_measured"
    assert (
        memory_evidence_isolation(RunBundle(run_dir=tmp_path, findings=[])).status
        == "not_measured"
    )


def test_memory_persistence_reads_the_event_trail(tmp_path: Path) -> None:
    """A promotion that names no run is unattributable, and one naming another run is worse."""
    from harness.util import append_jsonl

    events = tmp_path / "events.jsonl"
    append_jsonl(events, {"type": "LONG_TERM_MEMORY_WRITTEN", "data": {"entry": "mem-a", "run": "run-1"}})
    append_jsonl(events, {"type": "LONG_TERM_MEMORY_WRITTEN", "data": {"entry": "mem-b", "run": "run-1"}})
    append_jsonl(events, {"type": "LONG_TERM_MEMORY_WRITTEN", "data": {"entry": "mem-c", "run": "run-OTHER"}})
    append_jsonl(events, {"type": "LONG_TERM_MEMORY_WRITTEN", "data": {"entry": "mem-d"}})
    bundle = RunBundle(run_dir=tmp_path, summary={"run_id": "run-1"})

    metric = memory_persistence(bundle)
    assert metric.status == "measured"
    assert metric.value == 0.5
    assert metric.inputs["promoted"] == 4
    assert len(metric.inputs["unattributed"]) == 2


def test_memory_persistence_is_not_measured_when_nothing_was_promoted(tmp_path: Path) -> None:
    """Not curating is a different fact from curating badly, and only the second is a finding."""
    from harness.util import append_jsonl

    append_jsonl(tmp_path / "events.jsonl", {"type": "RUN_STARTED", "data": {}})
    metric = memory_persistence(RunBundle(run_dir=tmp_path))
    assert metric.status == "not_measured"


def test_memory_retrieval_cost_prefers_measured_tokens(tmp_path: Path) -> None:
    from harness.util import append_jsonl

    events = tmp_path / "events.jsonl"
    append_jsonl(events, {"type": "MEMORY_RETRIEVED", "data": {"entries": ["mem-a", "mem-b"]}})
    append_jsonl(
        events,
        {"type": "CONTEXT_ASSEMBLED", "data": {"memory": {"total_tokens": 1217}}},
    )
    metric = memory_retrieval_cost(RunBundle(run_dir=tmp_path))
    assert metric.status == "measured"
    assert metric.inputs["unit"] == "tokens"
    assert metric.value == 1217
    assert metric.inputs["retrieved_entries"] == 2


def test_memory_retrieval_cost_falls_back_to_entry_count(tmp_path: Path) -> None:
    """A v1 run recorded retrieval but not token cost, so the unit has to be named."""
    from harness.util import append_jsonl

    append_jsonl(
        tmp_path / "events.jsonl",
        {"type": "MEMORY_RETRIEVED", "data": {"entries": ["mem-a", "mem-b", "mem-c"]}},
    )
    metric = memory_retrieval_cost(RunBundle(run_dir=tmp_path))
    assert metric.status == "measured"
    assert metric.inputs["unit"] == "entries"
    assert metric.value == 3


def test_memory_retrieval_cost_is_not_measured_without_events(tmp_path: Path) -> None:
    assert memory_retrieval_cost(RunBundle(run_dir=tmp_path)).status == "not_measured"


def test_measured_is_the_constructor_these_metrics_use() -> None:
    """Guards against a metric silently returning a bare number instead of a Metric."""
    assert measured("x", 1.0).status == "measured"
