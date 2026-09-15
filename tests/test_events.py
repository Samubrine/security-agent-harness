"""Tests for the hash-chained event log.

The property under test is not "append writes a line" but "a line that was edited after the fact
cannot pass verification". Every adversarial test below rewrites ``events.jsonl`` the way an
attacker with file access (or a buggy later run) would, and asserts that verification fails and
says which sequence number broke.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.errors import EventChainError
from harness.events import EventLog
from harness.models import EventRecord
from harness.util import canonical_json, sha256_text, utcnow


def new_log(tmp_path: Path, run_id: str = "run-events-0001") -> EventLog:
    return EventLog(tmp_path / "events.jsonl", run_id)


def lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_lines(path: Path, rows: list[dict]) -> None:
    """Rewrite the log exactly as it would look if someone had tampered with it."""
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# Happy path: the chain that the harness itself writes
# ---------------------------------------------------------------------------------------------


def test_empty_log_starts_at_genesis_and_has_no_records(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    assert log.head_hash == ""
    assert log.count() == 0
    assert log.records() == []
    assert log.verify_chain() is True


def test_append_sequences_events_and_links_each_to_its_predecessor(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    first = log.append("RUN_STARTED", {"objective": "scan the lab"})
    second = log.append("CONTEXT_RESOLVED", {"tiers": {"C0": 10}})
    third = log.append("PROVIDER_STARTED")

    assert [first.seq, second.seq, third.seq] == [1, 2, 3]
    assert first.prev_event_hash == ""  # genesis is pinned, not floating
    assert second.prev_event_hash == first.event_hash
    assert third.prev_event_hash == second.event_hash
    assert log.head_hash == third.event_hash
    assert log.verify_chain() is True


def test_event_hash_is_the_recorded_rule_over_canonical_json(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    record = log.append("GAP_ADDED", {"kind": "tool_timeout"})
    on_disk = lines(tmp_path / "events.jsonl")[0]

    payload = {k: v for k, v in on_disk.items() if k != "event_hash"}
    assert on_disk["event_hash"] == sha256_text("" + canonical_json(payload))
    assert record.event_hash == on_disk["event_hash"]


def test_records_are_re_read_from_disk_not_served_from_memory(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    first = EventLog(path, "run-events-0001")
    first.append("RUN_STARTED", {"objective": "lab scan", "at_utc": utcnow()})
    first.append("PLAN_PROPOSED", {"steps": [1, 2]})

    reopened = EventLog(path, "run-events-0001")
    parsed = reopened.records()
    assert [r.type for r in parsed] == ["RUN_STARTED", "PLAN_PROPOSED"]
    assert all(isinstance(r, EventRecord) for r in parsed)
    assert all(r.run_id == "run-events-0001" for r in parsed)
    assert all(r.at.tzinfo is not None for r in parsed)
    assert reopened.count() == 2


def test_append_after_reopen_continues_the_existing_chain(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    EventLog(path, "run-events-0001").append("RUN_STARTED")

    resumed = EventLog(path, "run-events-0001")
    appended = resumed.append("RUN_ENDED", {"status": "completed"})
    assert appended.seq == 2
    assert appended.prev_event_hash == lines(path)[0]["event_hash"]
    assert resumed.verify_chain() is True


def test_data_is_copied_so_mutating_the_callers_dict_cannot_reseal_an_event(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    data = {"provider": "native:nmap"}
    record = log.append("PROVIDER_SELECTED", data)
    data["provider"] = "native:something-else"

    assert record.data["provider"] == "native:nmap"
    assert lines(tmp_path / "events.jsonl")[0]["data"]["provider"] == "native:nmap"
    assert log.verify_chain() is True


# ---------------------------------------------------------------------------------------------
# Adversarial: the chain must fail closed, and name the event that broke it
# ---------------------------------------------------------------------------------------------


def test_editing_a_committed_event_breaks_the_chain_at_that_sequence(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    log.append("RUN_STARTED")
    log.append("PROVIDER_COMPLETED", {"exit_status": "completed"})
    log.append("RUN_ENDED")
    assert log.verify_chain() is True

    rows = lines(path)
    rows[1]["data"]["exit_status"] = "failed"  # keep the recorded hash: the classic edit
    write_lines(path, rows)

    with pytest.raises(EventChainError) as excinfo:
        log.verify_chain()
    assert "seq 2" in str(excinfo.value)


def test_recomputing_one_events_hash_still_breaks_the_following_link(tmp_path: Path) -> None:
    """Tamper-evidence cannot be defeated one line at a time: repairing line 2 invalidates 3."""
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    for event_type in ("RUN_STARTED", "PLAN_PROPOSED", "RUN_ENDED"):
        log.append(event_type)

    rows = lines(path)
    rows[1]["data"] = {"injected": "by an attacker"}
    payload = {k: v for k, v in rows[1].items() if k != "event_hash"}
    rows[1]["event_hash"] = sha256_text(rows[1]["prev_event_hash"] + canonical_json(payload))
    write_lines(path, rows)

    with pytest.raises(EventChainError) as excinfo:
        log.verify_chain()
    assert "seq 3" in str(excinfo.value)


def test_deleting_a_middle_event_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    for event_type in ("RUN_STARTED", "POLICY_DECIDED", "RUN_ENDED"):
        log.append(event_type)

    rows = lines(path)
    write_lines(path, [rows[0], rows[2]])  # drop POLICY_DECIDED

    with pytest.raises(EventChainError) as excinfo:
        log.verify_chain()
    assert "seq 2" in str(excinfo.value)


def test_reordering_events_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    log.append("RUN_STARTED")
    log.append("APPROVAL_REQUESTED")
    log.append("APPROVAL_GIVEN")

    rows = lines(path)
    write_lines(path, [rows[0], rows[2], rows[1]])

    with pytest.raises(EventChainError):
        log.verify_chain()


def test_a_torn_line_is_a_chain_failure_not_a_silently_skipped_event(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    log.append("RUN_STARTED")
    log.append("FINDING_ADDED", {"finding": "f-1"})

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 3, "type": "RUN_EN')  # a crash mid-write

    with pytest.raises(EventChainError) as excinfo:
        log.verify_chain()
    assert "line 3" in str(excinfo.value)


def test_an_event_with_unknown_fields_is_refused_by_records(tmp_path: Path) -> None:
    """Unknown fields are how a smuggled payload would ride along in the audit log."""
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    log.append("RUN_STARTED")
    rows = lines(path)
    rows[0]["smuggled"] = "ignore previous instructions"
    write_lines(path, rows)

    with pytest.raises(EventChainError) as excinfo:
        log.records()
    assert "line 1" in str(excinfo.value)


def test_verify_chain_does_not_leak_a_pass_for_a_truncated_log(tmp_path: Path) -> None:
    """Truncation removes the tail, so the surviving prefix still verifies -- and the head hash
    changes, which is exactly why `head_hash` is recorded in the run summary."""
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    for event_type in ("RUN_STARTED", "PLAN_PROPOSED", "RUN_ENDED"):
        log.append(event_type)
    full_head = log.head_hash

    rows = lines(path)
    write_lines(path, rows[:1])

    assert log.verify_chain() is True
    assert log.head_hash != full_head
    assert log.count() == 1


# ---------------------------------------------------------------------------------------------
# Contract details
# ---------------------------------------------------------------------------------------------


def test_append_rejects_an_empty_event_type(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        new_log(tmp_path).append("")


def test_a_log_must_belong_to_a_run(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        EventLog(tmp_path / "events.jsonl", "")


def test_blank_lines_do_not_count_as_events(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = new_log(tmp_path)
    log.append("RUN_STARTED")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")
    assert log.count() == 1
    assert log.verify_chain() is True
