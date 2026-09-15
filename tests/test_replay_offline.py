"""Offline replay (decision D24): a recorded run must be re-derivable with no live calls.

Replay is what makes a finding checkable after the fact. These tests pin the two halves of that
promise: the recorded file carries enough to reproduce the model's contribution, and the verifier
recomputes the run's integrity claims instead of trusting them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.errors import EventChainError, ReplayError
from harness.llm.prompts import parse_agent_turn
from harness.llm.replay import ReplayModelClient, request_digest
from harness.models import ReplayRecord
from harness.runtime.replay import Replayer
from harness.runtime.runner import execute_run

pytestmark = pytest.mark.integration


@pytest.fixture
def finished_run(lab_environment) -> tuple[object, Path]:
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-replay-offline",
        )
    )
    return artifacts, artifacts.run_dir


def _records(run_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (run_dir / "replay.json").read_text(encoding="utf-8").splitlines() if line.strip()]


def test_the_run_records_both_model_turns_and_provider_calls(finished_run) -> None:
    _, run_dir = finished_run
    records = _records(run_dir)
    kinds = {record["kind"] for record in records}
    assert kinds == {"model", "provider"}
    assert all(record["request_sha256"] for record in records)


def test_a_recorded_model_turn_can_be_reproduced_without_a_server(finished_run) -> None:
    """The decisive offline test: feed the recorded prompt back and get the same turn.

    The prompt is recorded verbatim, so this needs no live endpoint, no network and no re-rendering
    of context that may have changed since.
    """
    _, run_dir = finished_run
    model_records = [r for r in _records(run_dir) if r["kind"] == "model"]
    assert model_records

    client = ReplayModelClient([ReplayRecord.model_validate(record) for record in model_records])
    versions = {}
    for record in model_records:
        prompt = record["request_text"]
        assert prompt, "a model record without its prompt cannot be replayed or diagnosed"
        system, _, user = prompt.partition("\x00")
        assert request_digest(system, user) == record["request_sha256"]
        response = client.complete(system=system, user=user, step=record["step"])
        turn = parse_agent_turn(response.text)
        versions[record["step"]] = turn.next_action.kind

    # The recorded sequence is the one the run actually followed: enumerate, then match, then stop.
    assert versions[1] == "capability"
    assert len(versions) >= 2


def test_replay_returns_byte_identical_responses(finished_run) -> None:
    _, run_dir = finished_run
    model_records = [r for r in _records(run_dir) if r["kind"] == "model"]
    client = ReplayModelClient([ReplayRecord.model_validate(record) for record in model_records])
    record = model_records[0]
    system, _, user = record["request_text"].partition("\x00")
    first = client.complete(system=system, user=user, step=record["step"])
    replay_text = record["response"]["text"]
    assert first.text == replay_text


def test_replay_refuses_a_prompt_that_was_never_recorded() -> None:
    """Divergence must be loud: a run that silently replays the wrong turn is not a replay."""
    client = ReplayModelClient(
        [
            ReplayRecord(
                kind="model",
                key="model:step-1",
                step=1,
                request_sha256="0" * 64,
                response={"text": "{}"},
                recorded_at="2026-09-15T00:00:00Z",
                request_text="original",
            )
        ]
    )
    with pytest.raises(ReplayError):
        client.complete(system="changed", user="prompt", step=7)


def test_an_empty_replay_file_is_refused() -> None:
    with pytest.raises(ReplayError):
        ReplayModelClient([])


def test_verify_recomputes_evidence_and_findings(finished_run) -> None:
    _, run_dir = finished_run
    replayer = Replayer(run_dir)
    assert replayer.verify() is True, replayer.problems
    assert replayer.finding_digests()


def test_verify_detects_a_tampered_artifact(finished_run) -> None:
    """A stored artifact whose bytes no longer hash to its address must fail verification.

    Appending bytes leaves any span inside the original content intact, so a verifier that only
    recomputed spans would call this run healthy. Content addressing is checked directly instead.
    """
    _, run_dir = finished_run
    artifact = next(
        path for path in (run_dir / "artifacts").rglob("*") if path.is_file() and not path.name.endswith(".json")
    )
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    replayer = Replayer(run_dir)
    assert replayer.verify() is False
    assert any("does not hash to" in problem for problem in replayer.problems)


def test_verify_detects_an_edited_event_chain(finished_run) -> None:
    _, run_dir = finished_run
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(events[1])
    tampered["data"] = {**tampered.get("data", {}), "injected": True}
    events[1] = json.dumps(tampered)
    (run_dir / "events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")

    replayer = Replayer(run_dir)
    assert replayer.verify() is False
    assert any("event chain" in problem for problem in replayer.problems)


def test_the_event_log_itself_still_raises_on_a_broken_chain(finished_run) -> None:
    from harness.events import EventLog

    artifacts, run_dir = finished_run
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    events[0] = events[0].replace('"seq":1', '"seq":2', 1)
    (run_dir / "events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")
    with pytest.raises(EventChainError):
        EventLog(run_dir / "events.jsonl", artifacts.run_id).verify_chain()
