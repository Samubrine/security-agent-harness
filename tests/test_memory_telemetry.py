"""The two memory wirings v1.2 left inert (R2-26).

`_curate_memory` was called with `provider_calls=[]`, so the curator's call-order lesson could
never fire, and `LongTermIndex.mark_used` had no caller under `src/`, so `last_used_at` was never
written. Both are asserted against a real `execute_run`, because the defect was the wiring and not
the derivation: the curator and the index are already covered directly in `tests/test_memory.py`.
"""

from __future__ import annotations

from harness.memory.index import LongTermIndex
from harness.models import MemoryEntry
from harness.runtime.runner import execute_run
from harness.util import utcnow

OBJECTIVE = "Enumerate exposed services on lab-web-01."


def test_curation_derives_a_lesson_from_the_runs_own_provider_calls(lab_environment) -> None:
    """A port_scan run calls two capabilities; that order is a lesson only if it is passed on."""
    execute_run(
        lab_environment.request(
            objective=OBJECTIVE,
            skill="port_scan",
            run_id="run-curation-telemetry-01",
            enable_memory_curation=True,
        )
    )
    index = LongTermIndex(lab_environment.root / "memory" / "long_term" / "index.sqlite")
    patterns = [entry for entry in index.all() if entry.kind == "investigation_pattern"]
    index.close()
    assert patterns, (
        "the run made two provider calls for two capabilities, so the curator's order lesson "
        "applies; an empty provider_calls list is why it never appeared"
    )
    assert "service.enumerate" in patterns[0].summary


def test_a_run_records_the_long_term_entries_it_consulted(lab_environment) -> None:
    """`last_used_at` is what a later curator prefers over an entry that merely exists."""
    db_path = lab_environment.root / "memory" / "long_term" / "index.sqlite"
    index = LongTermIndex(db_path)
    index.add(
        MemoryEntry(
            id="mem-ffff0001",
            created_at=utcnow(),
            kind="lesson",
            summary="lab-web-01 exposes nginx and ssh; port_scan is the capability that finds them",
            source_runs=["run-earlier"],
        )
    )
    index.close()

    execute_run(
        lab_environment.request(objective=OBJECTIVE, skill="port_scan", run_id="run-mark-used-01")
    )

    reopened = LongTermIndex(db_path)
    entry = reopened.get("mem-ffff0001")
    reopened.close()
    assert entry is not None
    assert entry.last_used_at is not None, (
        "the entry matched the run's objective and was surfaced into its context, so it must be "
        "marked used"
    )
