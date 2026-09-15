"""Tests for ``harness.runtime.verify`` - audit invariant 6, referential integrity.

The property under test is *negative* by nature: a run's report may only claim a call was
necessary and authorised if the ids it cites resolve to real records. So every test here either
(a) proves a broken reference is caught, or (b) proves a legitimate shape is not falsely accused.
A test that merely executes the audit would miss exactly the failure mode the module exists for.

The directory tests run against a byte copy of a real recorded run (``eval/results/port_scan``);
the copy is tampered with one specific defect at a time and the expected issue code asserted. The
committed bytes are never modified.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from harness.models import (
    Claim,
    EvidenceGap,
    Finding,
    Grant,
    Observation,
    PolicyDecision,
    ProviderDecision,
    ProviderExecution,
)
from harness.runtime.verify import audit_provenance, audit_run_dir
from harness.util import atomic_write_json, atomic_write_text, read_json

# Ids taken from the committed run. Asserted to exist by ``test_recorded_run_is_the_fixture`` so
# that a regenerated fixture fails loudly instead of quietly testing nothing.
RUN_ID = "eval-port-scan-01"
EXEC_A = "x-4041f0f0e878"
EXEC_B = "x-5081ebabb355"
NECESSITY_A = "d-8f1af2d33084"
NECESSITY_B = "d-a081bed88f0d"
POLICY_A = "pd-98cec9e2eaaa"
GRANT_A = "g-50c3fd8d5cbe"
OBS_A = "o-16128d8f6404"

_NOW = datetime(2026, 9, 15, 6, 0, 0, tzinfo=UTC)


@pytest.fixture
def run(repo_root: Path, tmp_path: Path) -> Path:
    """A writable copy of a real recorded run directory."""
    dst = tmp_path / "run"
    shutil.copytree(repo_root / "eval" / "results" / "port_scan" / "run", dst)
    return dst


def _mutate_json(path: Path, mutate: Callable[[Any], None]) -> None:
    raw = read_json(path)
    mutate(raw)
    atomic_write_json(path, raw)


def _write_jsonl(path: Path, records: Sequence[dict[str, Any]]) -> None:
    atomic_write_text(path, "".join(json.dumps(r, sort_keys=True) + "\n" for r in records))


# ---------------------------------------------------------------------------------------------
# In-memory graph builders for audit_provenance
# ---------------------------------------------------------------------------------------------


def _execution(**over: Any) -> ProviderExecution:
    fields: dict[str, Any] = dict(
        id=EXEC_A,
        run_id=RUN_ID,
        provider="native:synthetic",
        capability="service.enumerate",
        grant="g-1",
        policy_decision=POLICY_A,
        necessity_decision=NECESSITY_A,
        started_at=_NOW,
        ended_at=_NOW,
        exit_status="completed",
    )
    fields.update(over)
    return ProviderExecution(**fields)


def _decision(**over: Any) -> ProviderDecision:
    fields: dict[str, Any] = dict(id=NECESSITY_A, capability="service.enumerate", verdict="single", reason="r")
    fields.update(over)
    return ProviderDecision(**fields)


def _policy(**over: Any) -> PolicyDecision:
    fields: dict[str, Any] = dict(
        id=POLICY_A,
        provider="native:synthetic",
        capability="service.enumerate",
        grant="g-1",
        verdict="allow",
        risk="LOW",
    )
    fields.update(over)
    return PolicyDecision(**fields)


def _observation(**over: Any) -> Observation:
    fields: dict[str, Any] = dict(
        id="o-1",
        run_id=RUN_ID,
        kind="service",
        value={"port": 80},
        parser="nmap_xml",
        parser_version="0.1.0",
        provider="native:synthetic",
        execution_id=EXEC_A,
    )
    fields.update(over)
    return Observation(**fields)


def _finding(*, supports: Sequence[str] = ("o-1",), contradicts: Sequence[str] = (), **over: Any) -> Finding:
    fields: dict[str, Any] = dict(
        id="f-1",
        run_id=RUN_ID,
        title="t",
        claims=[
            Claim(id="c-1", statement="s", assertion="observed", supports=list(supports), contradicts=list(contradicts))
        ],
    )
    fields.update(over)
    return Finding(**fields)


def _grant(**over: Any) -> Grant:
    fields: dict[str, Any] = dict(
        id="g-1",
        resource="net:10.77.0.11",
        alias="lab-web-01",
        capabilities=["service.enumerate"],
        expires_at=_NOW + timedelta(days=1),
        origin="test",
    )
    fields.update(over)
    return Grant(**fields)


def _audit(**over: Any):
    fields: dict[str, Any] = dict(
        run_id=RUN_ID,
        executions=[_execution()],
        decisions=[_decision()],
        policy_decisions=[_policy()],
        observations=[_observation()],
        findings=[_finding()],
    )
    fields.update(over)
    return audit_provenance(**fields)


# ---------------------------------------------------------------------------------------------
# audit_provenance: the happy path and the values it must not invent
# ---------------------------------------------------------------------------------------------


def test_clean_graph_has_no_issues() -> None:
    audit = _audit()
    assert audit.ok is True
    assert audit.issues == []
    assert audit.checked["executions"] == 1
    assert audit.checked["known_policy_decision_ids"] == 1
    assert audit.checked["issues_error"] == 0


def test_empty_graph_is_ok_and_not_a_crash() -> None:
    audit = audit_provenance(
        run_id=RUN_ID,
        executions=[],
        decisions=[],
        policy_decisions=[],
        observations=[],
        findings=[],
    )
    assert audit.ok is True
    assert audit.issues == []
    assert audit.checked["executions"] == 0


def test_fabricated_necessity_decision_id_is_caught() -> None:
    audit = _audit(executions=[_execution(necessity_decision="d-fabricated")])
    assert audit.ok is False
    issue = next(i for i in audit.issues if i.code == "execution_necessity_decision_missing")
    assert issue.subject == EXEC_A
    assert issue.severity == "error"
    assert "d-fabricated" in issue.detail


def test_fabricated_policy_decision_id_is_caught() -> None:
    audit = _audit(executions=[_execution(policy_decision="pd-fabricated")])
    assert audit.ok is False
    issue = next(i for i in audit.issues if i.code == "execution_policy_decision_missing")
    assert issue.subject == EXEC_A
    assert "pd-fabricated" in issue.detail


def test_known_policy_decision_ids_stand_in_for_missing_records() -> None:
    """A v1 run has no PolicyDecision records; ids recovered out of band must still satisfy the
    check, and their absence must still be an error."""
    assert _audit(policy_decisions=[], known_policy_decision_ids=[POLICY_A]).issues == []
    without = _audit(policy_decisions=[], known_policy_decision_ids=[])
    assert without.codes() == ["execution_policy_decision_missing"]


def test_policy_decision_without_execution_id_is_not_a_mismatch() -> None:
    audit = _audit(policy_decisions=[_policy(execution_id=None)])
    assert audit.issues == []


def test_grant_check_only_applies_when_grants_were_supplied() -> None:
    """An empty grant sequence means "scope was not read", so accusing every execution of an
    unknown grant would make the audit lie about the strong case."""
    unknown = _execution(grant="g-unknown")
    assert _audit(executions=[unknown], grants=[]).issues == []
    with_grants = _audit(executions=[unknown], grants=[_grant(id="g-1")])
    assert with_grants.codes() == ["execution_grant_unknown"]
    assert with_grants.issues[0].subject == EXEC_A


def test_run_id_mismatch_is_reported_for_every_kind() -> None:
    audit = _audit(
        executions=[_execution(run_id="other-run")],
        observations=[_observation(run_id="other-run")],
        findings=[_finding(run_id="other-run")],
    )
    assert audit.codes() == [
        "execution_run_id_mismatch",
        "finding_run_id_mismatch",
        "observation_run_id_mismatch",
    ]


def test_memory_reference_is_not_a_missing_observation() -> None:
    """Memory is context, never evidence - but the audit must use the same "is this a memory
    reference" test as the live validator, or a finding it rejects would pass the audit."""
    audit = _audit(findings=[_finding(supports=["mem-abc123"], contradicts=["memory:lessons"])])
    assert audit.issues == []


def test_claim_reference_to_nothing_is_caught_in_both_directions() -> None:
    audit = _audit(findings=[_finding(supports=["o-ghost"], contradicts=["o-phantom"])])
    assert audit.codes() == ["finding_claim_observation_missing"]
    assert {i.subject for i in audit.issues} == {"f-1/c-1"}
    assert {i.detail.split("cites ")[1].split(",")[0] for i in audit.issues} == {"'o-ghost'", "'o-phantom'"}


def test_satisfied_by_unknown_observation_is_caught() -> None:
    assert _audit(decisions=[_decision(satisfied_by=["o-1"])]).issues == []
    audit = _audit(decisions=[_decision(satisfied_by=["o-ghost"])])
    assert audit.codes() == ["decision_satisfied_by_unknown_observation"]
    assert audit.issues[0].subject == NECESSITY_A


def test_expand_without_reason_is_unreachable_through_the_validator() -> None:
    """The check is only meaningful because the model forbids the shape it looks for: a hit can
    only come from bytes that bypassed pydantic, i.e. from tampering."""
    with pytest.raises(ValidationError):
        ProviderDecision(id="d-x", capability="c", verdict="expand", reason="r", selected=["a", "b"])
    tampered = ProviderDecision.model_construct(
        id="d-tampered", capability="c", verdict="expand", expansion_reason=None, satisfied_by=[]
    )
    audit = _audit(decisions=[_decision(), tampered])
    assert audit.codes() == ["decision_expand_without_reason"]
    assert audit.issues[0].subject == "d-tampered"


def test_policy_decision_linked_to_an_execution_that_cites_it_back_is_clean() -> None:
    assert _audit(policy_decisions=[_policy(execution_id=EXEC_A)]).issues == []


def test_policy_decision_mismatch_is_a_warning_not_a_failure() -> None:
    audit = _audit(
        policy_decisions=[
            _policy(execution_id=EXEC_A),
            _policy(id="pd-orphan", execution_id="x-ghost"),
            _policy(id="pd-elsewhere", execution_id=EXEC_A),
        ]
    )
    assert audit.codes() == ["policy_decision_execution_mismatch"]
    assert {i.subject for i in audit.issues} == {"pd-orphan", "pd-elsewhere"}
    assert all(i.severity == "warning" for i in audit.issues)
    # A one-way link is evidence of a wiring bug, not of an unbacked claim, so it must not fail
    # the run it is reported against.
    assert audit.ok is True
    assert audit.checked["issues_warning"] == 2


def test_duplicate_ids_are_reported_per_kind() -> None:
    audit = audit_provenance(
        run_id=RUN_ID,
        executions=[_execution(), _execution()],
        decisions=[_decision(), _decision()],
        policy_decisions=[],
        observations=[_observation(), _observation()],
        findings=[_finding(), _finding()],
        gaps=[EvidenceGap(id="g-1", run_id=RUN_ID, kind="empty_result")] * 2,
        grants=[_grant(), _grant()],
        known_policy_decision_ids=[POLICY_A],
    )
    duplicates = [i for i in audit.issues if i.code == "duplicate_record_id"]
    assert {(i.subject, i.detail.split(" records")[0]) for i in duplicates} == {
        (EXEC_A, "2 execution"),
        (NECESSITY_A, "2 provider decision"),
        ("o-1", "2 observation"),
        ("f-1", "2 finding"),
        ("g-1", "2 gap"),
        ("g-1", "2 grant"),
    }
    assert audit.ok is False


def test_identical_issues_are_deduplicated() -> None:
    """Two copies of one broken reference are one problem; a report that lists it twice invites the
    reader to think two things are wrong."""
    audit = _audit(findings=[_finding(supports=["o-ghost"]), _finding(supports=["o-ghost"])])
    assert [i.code for i in audit.issues] == ["duplicate_record_id", "finding_claim_observation_missing"]


def test_issue_order_is_independent_of_input_order() -> None:
    forward = _audit(executions=[_execution(necessity_decision="d-x"), _execution(id=EXEC_B, necessity_decision="d-y")])
    reverse = _audit(executions=[_execution(id=EXEC_B, necessity_decision="d-y"), _execution(necessity_decision="d-x")])
    assert [(i.code, i.subject, i.detail) for i in forward.issues] == [
        (i.code, i.subject, i.detail) for i in reverse.issues
    ]


# ---------------------------------------------------------------------------------------------
# audit_run_dir: the recorded run, clean and tampered
# ---------------------------------------------------------------------------------------------


def test_recorded_run_is_the_fixture() -> None:
    """Guard: if the fixture data is regenerated with different ids, fail loudly here rather than
    let every test below assert on ids it never found."""
    ids = {e["id"] for e in read_json(Path(__file__).resolve().parents[1] / "eval/results/port_scan/run/executions.json")}
    assert ids == {EXEC_A, EXEC_B}


def test_clean_recorded_run_is_ok_with_only_the_policy_warning(run: Path) -> None:
    audit = audit_run_dir(run)
    # v1 ships no policy-decisions.jsonl, so exactly one warning about the weaker check.
    assert [(i.code, i.severity) for i in audit.issues] == [("policy_decision_record_absent", "warning")]
    assert audit.ok is True
    assert audit.run_id == RUN_ID
    assert audit.checked["executions"] == 2
    assert audit.checked["provider_decisions"] == 2
    assert audit.checked["observations"] == 16
    # 10 policy ids recovered from provenance.jsonl governed_by triples, including both cited ones.
    assert audit.checked["known_policy_decision_ids"] >= 2


def test_tampered_necessity_decision_id_is_caught(run: Path) -> None:
    _mutate_json(run / "executions.json", lambda raw: raw[0].__setitem__("necessity_decision", "d-fabricated"))
    audit = audit_run_dir(run)
    assert audit.ok is False
    assert "execution_necessity_decision_missing" in audit.codes()
    assert any(i.subject == EXEC_A for i in audit.issues if i.code == "execution_necessity_decision_missing")


def test_tampered_policy_decision_id_is_caught(run: Path) -> None:
    _mutate_json(run / "executions.json", lambda raw: raw[0].__setitem__("policy_decision", "pd-fabricated"))
    audit = audit_run_dir(run)
    assert audit.ok is False
    assert "execution_policy_decision_missing" in audit.codes()


def test_deleting_provider_decisions_marks_the_dir_incomplete(run: Path) -> None:
    (run / "provider-decisions.jsonl").unlink()
    audit = audit_run_dir(run)
    assert "run_dir_incomplete" in audit.codes()
    assert any(i.subject == "provider-decisions.jsonl" for i in audit.issues)
    assert audit.ok is False


def test_garbage_observations_is_unreadable_not_a_crash(run: Path) -> None:
    (run / "observations.json").write_bytes(b"\x00\xff\xfe not json at all {{{")
    audit = audit_run_dir(run)
    assert "run_dir_unreadable" in audit.codes()
    assert audit.ok is False
    assert any(i.code == "run_dir_unreadable" and i.subject == "observations.json" for i in audit.issues)


def test_corrupt_observations_is_not_shadowed_by_the_jsonl_fallback(run: Path) -> None:
    """An attacker who can truncate the canonical file must not thereby choose which file is
    audited: a silent fallback would let stale bytes be pronounced clean."""
    assert (run / "observations.jsonl").exists()
    (run / "observations.json").write_bytes(b"{")
    audit = audit_run_dir(run)
    assert audit.checked["observations"] == 0
    assert any(i.code == "run_dir_unreadable" and i.subject == "observations.json" for i in audit.issues)


def test_fallback_file_is_read_when_the_canonical_one_is_absent(run: Path) -> None:
    (run / "observations.json").unlink()
    audit = audit_run_dir(run)
    assert audit.checked["observations"] == 16
    assert not [i for i in audit.issues if i.code == "run_dir_incomplete" and i.subject == "observations.json"]


def test_duplicate_execution_id_is_caught(run: Path) -> None:
    _mutate_json(run / "executions.json", lambda raw: raw.append(dict(raw[0])))
    audit = audit_run_dir(run)
    assert "duplicate_record_id" in audit.codes()
    issue = next(i for i in audit.issues if i.code == "duplicate_record_id")
    assert issue.subject == EXEC_A
    assert "execution" in issue.detail
    assert audit.ok is False


def test_run_directory_with_no_policy_file_derives_ids_from_governed_by(run: Path) -> None:
    """The v1 fallback: subject is the policy id, object the necessity id. Reading the triple
    backwards would produce a set nothing cites and silently pass every execution."""
    audit = audit_run_dir(run)
    assert POLICY_A in {
        json.loads(line)["subject"] for line in (run / "provenance.jsonl").read_text().splitlines() if line
    }
    assert "execution_policy_decision_missing" not in audit.codes()
    assert audit.checked["policy_decision_ids_derived"] == 10


def test_governed_by_derivation_fails_when_the_ids_are_removed(run: Path) -> None:
    """Negative control for the fallback: strip the governed_by triples and the policy check, which
    has no other source of ids, must now report both executions as unbacked."""
    kept = [line for line in (run / "provenance.jsonl").read_text().splitlines() if "governed_by" not in line]
    atomic_write_text(run / "provenance.jsonl", "\n".join(kept) + "\n")
    audit = audit_run_dir(run)
    assert audit.checked["policy_decision_ids_derived"] == 0
    assert audit.codes() == ["execution_policy_decision_missing", "policy_decision_record_absent"]


_PD_TEMPLATE = {
    "provider": "native:synthetic",
    "capability": "service.enumerate",
    "grant": GRANT_A,
    "verdict": "allow",
    "reasons": [],
    "risk": "LOW",
}


def test_policy_decisions_file_is_authoritative_when_present(run: Path) -> None:
    """A v1.1 run has real PolicyDecision records; a stray provenance triple naming a policy id that
    no record backs must not be accepted."""
    _write_jsonl(
        run / "policy-decisions.jsonl",
        [_PD_TEMPLATE | {"id": "pd-ac3c9b3acb03", "execution_id": EXEC_B}],
    )
    audit = audit_run_dir(run)
    assert "policy_decision_record_absent" not in audit.codes()
    assert audit.checked["policy_decisions"] == 1
    assert audit.codes() == ["execution_policy_decision_missing"]
    assert [i.subject for i in audit.issues] == [EXEC_A]


def test_present_policy_records_for_both_executions_are_clean(run: Path) -> None:
    _write_jsonl(
        run / "policy-decisions.jsonl",
        [
            _PD_TEMPLATE | {"id": POLICY_A, "execution_id": EXEC_A},
            _PD_TEMPLATE | {"id": "pd-ac3c9b3acb03", "execution_id": EXEC_B},
        ],
    )
    audit = audit_run_dir(run)
    assert audit.ok is True
    assert audit.issues == []


def test_policy_record_pointing_at_a_non_citing_execution_warns(run: Path) -> None:
    _write_jsonl(
        run / "policy-decisions.jsonl",
        [
            _PD_TEMPLATE | {"id": POLICY_A, "execution_id": EXEC_A},
            _PD_TEMPLATE | {"id": "pd-ac3c9b3acb03", "execution_id": EXEC_B},
            _PD_TEMPLATE | {"id": "pd-late", "execution_id": EXEC_A},
        ],
    )
    audit = audit_run_dir(run)
    assert audit.codes() == ["policy_decision_execution_mismatch"]
    assert audit.issues[0].subject == "pd-late"
    assert audit.ok is True


def test_unknown_grant_is_caught_when_scope_carries_grants(run: Path) -> None:
    scope = read_json(run / "scope.json")
    assert "grants" not in scope  # the committed scope has none, hence the clean run above
    scope["grants"] = [
        {
            "id": "g-not-ours",
            "resource": "net:10.77.0.11",
            "alias": "lab-web-01",
            "capabilities": ["service.enumerate"],
            "expires_at": "2027-01-01T00:00:00Z",
            "origin": "test",
            "kind": "net",
        }
    ]
    atomic_write_json(run / "scope.json", scope)
    audit = audit_run_dir(run)
    assert audit.codes() == ["execution_grant_unknown", "policy_decision_record_absent"]
    assert {i.subject for i in audit.issues if i.code == "execution_grant_unknown"} == {EXEC_A, EXEC_B}


def test_unknown_field_in_a_record_is_unreadable_and_does_not_invent_more(run: Path) -> None:
    """Strict models (``extra="forbid"``) mean altered bytes stop reconstructing. The record is
    still checked with the fields it does carry, so the audit reports the tampering once instead of
    inventing a second, unrelated error out of the missing shape."""

    def tamper(raw: list[dict[str, Any]]) -> None:
        raw[0]["injected"] = True

    _mutate_json(run / "executions.json", tamper)
    audit = audit_run_dir(run)
    assert audit.codes() == ["policy_decision_record_absent", "run_dir_unreadable"]
    assert any(i.subject == "executions.json" for i in audit.issues)


def test_record_that_fails_validation_but_carries_its_ids_is_still_audited(run: Path) -> None:
    """Tampering that breaks validation *and* fabricates a reference must not let the reference
    hide behind the parse failure: the lenient path keeps the id checks live."""

    def tamper(raw: list[dict[str, Any]]) -> None:
        raw[0]["necessity_decision"] = "d-fabricated"
        raw[0]["injected"] = True

    _mutate_json(run / "executions.json", tamper)
    audit = audit_run_dir(run)
    assert audit.codes() == [
        "execution_necessity_decision_missing",
        "policy_decision_record_absent",
        "run_dir_unreadable",
    ]
    assert any(i.code == "execution_necessity_decision_missing" and i.subject == EXEC_A for i in audit.issues)


def test_record_missing_a_checked_field_is_reported_but_not_guessed(run: Path) -> None:
    """Drop the id from an observation no finding cites, so the only possible code is the parse
    failure; a record whose *checked* field is absent must not be guessed at."""
    cited = {
        ref
        for finding in read_json(run / "findings.json")
        for claim in finding.get("claims", [])
        for ref in claim.get("supports", []) + claim.get("contradicts", [])
    }

    def tamper(raw: list[dict[str, Any]]) -> None:
        victim = next(record for record in raw if record["id"] not in cited)
        victim.pop("id")

    _mutate_json(run / "observations.json", tamper)
    audit = audit_run_dir(run)
    assert audit.codes() == ["policy_decision_record_absent", "run_dir_unreadable"]
    assert not [i for i in audit.issues if i.code == "observation_run_id_mismatch"]


def test_garbage_line_in_gaps_jsonl_is_unreadable(run: Path) -> None:
    with (run / "gaps.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("}{ not json\n")
    audit = audit_run_dir(run)
    assert any(i.code == "run_dir_unreadable" and i.subject == "gaps.jsonl" for i in audit.issues)


def test_unreadable_run_json_falls_back_to_the_directory_name(run: Path) -> None:
    (run / "run.json").write_bytes(b"{ truncated")
    audit = audit_run_dir(run)
    assert any(i.code == "run_dir_unreadable" and i.subject == "run.json" for i in audit.issues)
    assert audit.run_id == "run"
    # The copied run_id can no longer be agreed with, and every record that carries one is flagged.
    assert {"execution_run_id_mismatch", "finding_run_id_mismatch", "observation_run_id_mismatch"} <= set(audit.codes())


def test_nonexistent_directory_does_not_raise(tmp_path: Path) -> None:
    audit = audit_run_dir(tmp_path / "does-not-exist")
    assert audit.ok is False
    assert "run_dir_incomplete" in audit.codes()
    assert audit.run_id == "does-not-exist"
    assert not [i for i in audit.issues if i.code == "run_dir_unreadable"]


def test_empty_directory_does_not_raise(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    audit = audit_run_dir(empty)
    assert "run_dir_incomplete" in audit.codes()
    assert audit.checked["executions"] == 0
    assert audit.run_id == "empty"


def test_a_path_that_is_a_file_does_not_raise(run: Path) -> None:
    audit = audit_run_dir(run / "run.json")
    assert "run_dir_incomplete" in audit.codes()


def test_deleted_required_file_does_not_raise_and_is_reported(run: Path) -> None:
    for name in (
        "run.json",
        "executions.json",
        "executions.jsonl",
        "observations.json",
        "observations.jsonl",
        "findings.json",
        "scope.json",
    ):
        (run / name).unlink()
    audit = audit_run_dir(run)
    assert set(audit.codes()) == {"run_dir_incomplete", "policy_decision_record_absent"}
    assert {i.subject for i in audit.issues if i.code == "run_dir_incomplete"} == {
        "run.json",
        "executions.json",
        "observations.json",
        "findings.json",
        "scope.json",
    }


def test_absent_gaps_file_is_not_incompleteness(run: Path) -> None:
    """A run that recorded no gap writes no gaps.jsonl (as in eval/results/log_analysis/run);
    calling that incomplete would be a false accusation."""
    (run / "gaps.jsonl").unlink()
    audit = audit_run_dir(run)
    assert audit.ok is True
    assert audit.checked["gaps"] == 0
