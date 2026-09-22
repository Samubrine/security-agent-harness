"""Integrity of the committed run: its bytes, and its records against its event chain.

Two failures the suite did not catch (R2-03, R2-31), and the reason each stayed invisible:

* An artifact is filed under the SHA-256 of its own bytes, and the frozen run in
  ``tests/fixtures/run/port_scan`` is evidence for every claim the audits make about replay. On a
  stock Windows checkout (``core.autocrlf=true``) git rewrote line endings in the worktree, so the
  repository's own evidence no longer hashed to the address it is filed under and replay reported
  the committed run as tampered. Nothing re-hashed that directory, so the suite stayed green while
  the guarantee was gone.
* ``Replayer.verify`` re-hashes artifacts and re-validates findings, and both of those read the same
  files the run wrote. Editing ``observations.jsonl`` therefore replayed clean as long as the spans
  it cites still recomputed.

Both are byte-level properties of the committed tree, so these tests read the frozen run directly
instead of building one; the tampering cases work on a copy in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from harness.runtime.replay import Replayer
from harness.util import sha256_text

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED_RUN = FIXTURES / "run" / "port_scan"

#: Files whose contents are addressed by their own name, and which therefore must not be rewritten
#: by a checkout. Matches the ``-text`` rule in ``.gitattributes``.
ARTIFACT_FILES = sorted(
    path
    for path in FIXTURES.glob("**/artifacts/*/*")
    if path.is_file() and not path.name.endswith(".meta.json")
)


@pytest.fixture
def mutable_run(tmp_path: Path) -> Path:
    """A writable copy of the frozen run, so a test can edit what it records."""
    destination = tmp_path / "run"
    shutil.copytree(RECORDED_RUN, destination)
    return destination


def _observations(run_dir: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (run_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_observations(run_dir: Path, rows: list[dict]) -> None:
    (run_dir / "observations.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def _findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))


def _write_findings(run_dir: Path, rows: list[dict]) -> None:
    (run_dir / "findings.json").write_text(json.dumps(rows), encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# The bytes on disk
# ---------------------------------------------------------------------------------------------


def test_the_frozen_run_carries_artifacts() -> None:
    """A guard for the test below: an empty artifact set would make it pass vacuously."""
    assert ARTIFACT_FILES, f"no content-addressed artifact found under {FIXTURES}"


@pytest.mark.parametrize("path", ARTIFACT_FILES, ids=lambda path: f"{path.parent.name}/{path.name[:12]}")
def test_an_artifact_hashes_to_the_name_it_is_filed_under(path: Path) -> None:
    """The whole point of content addressing, checked against the worktree rather than the index.

    Fails on a checkout that rewrote line endings, which is exactly the state the harness would
    otherwise report as tampering with its own frozen run.
    """
    assert hashlib.sha256(path.read_bytes()).hexdigest() == path.name


def test_the_frozen_run_verifies() -> None:
    replayer = Replayer(RECORDED_RUN)
    assert replayer.verify() is True, replayer.problems


def test_a_rewritten_line_ending_breaks_the_content_address(mutable_run: Path) -> None:
    """Negative control: the check above only means something if rewriting bytes fails it.

    Reproduces the Windows checkout condition inside the test instead of depending on the platform,
    so the failure mode stays demonstrated on a machine where it cannot happen by accident.
    """
    artifact = next((path for path in ARTIFACT_FILES if b"\n" in path.read_bytes()), None)
    assert artifact is not None, "no artifact carries a line ending, so this control proves nothing"
    target = mutable_run / "artifacts" / artifact.parent.name / artifact.name
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any("does not hash to the address" in problem for problem in replayer.problems)


# ---------------------------------------------------------------------------------------------
# The records against the chain
# ---------------------------------------------------------------------------------------------


def test_a_clean_copy_still_verifies(mutable_run: Path) -> None:
    """Negative control for every tampering case below: the comparison is not simply always false."""
    replayer = Replayer(mutable_run)
    assert replayer.verify() is True, replayer.problems


def test_a_deleted_observation_is_reported(mutable_run: Path) -> None:
    rows = _observations(mutable_run)
    removed = rows.pop(0)
    _write_observations(mutable_run, rows)

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any(
        f"the event chain witnesses observation {removed['id']}" in problem for problem in replayer.problems
    ), replayer.problems


def test_an_observation_that_no_event_witnesses_is_reported(mutable_run: Path) -> None:
    """The other direction: a record the run never produced must not pass as recorded evidence."""
    rows = _observations(mutable_run)
    rows.append({**rows[0], "id": "o-fabricated"})
    _write_observations(mutable_run, rows)

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any(
        "observations.jsonl records o-fabricated, which no OBSERVATION_ADDED event" in problem
        for problem in replayer.problems
    ), replayer.problems


def test_an_edited_observation_is_reported_with_the_field(mutable_run: Path) -> None:
    """An edited value is the case the span check cannot see: the cited bytes still recompute."""
    rows = _observations(mutable_run)
    rows[0]["provider"] = "mcp:evil-scanner"
    _write_observations(mutable_run, rows)

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any(
        f"observation {rows[0]['id']} was recorded with provider='mcp:evil-scanner'" in problem
        for problem in replayer.problems
    ), replayer.problems


def test_an_edited_finding_is_reported_with_the_field(mutable_run: Path) -> None:
    rows = _findings(mutable_run)
    rows[0]["title"] = rows[0]["title"] + " (rewritten)"
    _write_findings(mutable_run, rows)

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any(
        f"finding {rows[0]['id']} was recorded with title=" in problem for problem in replayer.problems
    ), replayer.problems


def test_a_deleted_finding_is_reported(mutable_run: Path) -> None:
    """A finding can legitimately stop being reported, so the count the run closed with is the
    witness for a deletion rather than the set of FINDING_ADDED events."""
    rows = _findings(mutable_run)
    recorded = len(rows)
    rows.pop()
    _write_findings(mutable_run, rows)

    replayer = Replayer(mutable_run)
    assert replayer.verify() is False
    assert any(
        f"the final RUN_ENDED event records {recorded} findings, but findings.json records "
        f"{recorded - 1}" in problem
        for problem in replayer.problems
    ), replayer.problems


def test_the_frozen_prompts_are_internally_consistent() -> None:
    """Every recorded prompt hashes to the digest recorded beside it.

    The prompts in the fixture were rendered by the v1.1 build, before untrusted values were wrapped
    (R2-02, WS-02). They are a *record* of what that code sent, so the honest check is that the record
    is self-consistent, not that it matches what today's renderer would produce - re-rendering it
    without re-running the run would be a fabricated prompt, and re-running would change every pinned
    id (rule 0.1.4). What the current renderer produces is pinned by
    `tests/test_integration_vertical_slice.py::test_the_recorded_prompts_carry_the_banner_payload_inside_the_wrapper`.
    """
    rows = [
        json.loads(line)
        for line in (RECORDED_RUN / "replay.json").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows, "the frozen run recorded no replay trace"
    checked = 0
    for row in rows:
        text = row.get("request_text")
        if text is None:
            continue
        assert row["request_sha256"] == sha256_text(text), row["key"]
        checked += 1
    assert checked, "no model turn in the fixture carried its prompt, so nothing was checked"
