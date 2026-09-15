"""Tests for the token ledger and the hard budget guard.

The guard is the only component allowed to end a run for spending too much, so the tests below pin
the exact boundary behaviour rather than "a limit exists": each budget permits its stated maximum
and refuses the next unit. A guard that raises one call early silently shrinks every run budget; a
guard that raises one call late lets a run exceed the limit it claims to enforce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.errors import BudgetExhausted
from harness.models import Budget, ModelMetadata, TokenLedgerEntry
from harness.tokens import BudgetGuard, TokenLedger

MODEL = ModelMetadata(backend="scripted", model_id="qwen3-4b-instruct", tokenizer_id="heuristic-4chars")


def new_ledger(tmp_path: Path, model: ModelMetadata = MODEL) -> TokenLedger:
    return TokenLedger(tmp_path / "trace.jsonl", model)


def raw_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------------------------
# TokenLedger: measure only, never enforce
# ---------------------------------------------------------------------------------------------


def test_ledger_appends_one_entry_per_record_and_totals_are_the_sum_of_entries(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    ledger = new_ledger(tmp_path)
    first = ledger.record(1, input_tokens=1200, output_tokens=90, tiers={"C0": 400, "C2": 800}, memory_tokens=60)
    ledger.record(2, input_tokens=300, output_tokens=10, evidence_tokens=25)

    assert isinstance(first, TokenLedgerEntry)
    entries = ledger.entries()
    assert [entry.step for entry in entries] == [1, 2]
    assert ledger.total_input() == sum(entry.input_tokens for entry in entries) == 1500
    assert ledger.total_output() == sum(entry.output_tokens for entry in entries) == 100
    assert len(raw_lines(path)) == 2
    assert entries[0].context_tokens_by_tier == {"C0": 400, "C2": 800}
    assert entries[0].memory_tokens == 60
    assert entries[1].evidence_tokens == 25


def test_ledger_stamps_the_frozen_model_identity_on_every_entry(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ledger.record(1, input_tokens=1, output_tokens=1)
    ledger.record(2, input_tokens=1, output_tokens=1)

    assert {entry.model_id for entry in ledger.entries()} == {"qwen3-4b-instruct"}
    assert {entry.tokenizer_id for entry in ledger.entries()} == {"heuristic-4chars"}


def test_ledger_is_append_only_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    new_ledger(tmp_path).record(1, input_tokens=10, output_tokens=2)
    reopened = TokenLedger(path, MODEL)
    reopened.record(2, input_tokens=20, output_tokens=4)

    assert [entry.step for entry in reopened.entries()] == [1, 2]
    assert reopened.total_input() == 30
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_an_empty_ledger_totals_zero_without_creating_a_file(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    assert ledger.entries() == []
    assert ledger.total_input() == 0
    assert ledger.total_output() == 0


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens", "memory_tokens", "evidence_tokens"])
def test_a_negative_token_count_is_refused_because_it_would_refund_the_ledger(tmp_path: Path, field: str) -> None:
    path = tmp_path / "trace.jsonl"
    ledger = new_ledger(tmp_path)
    ledger.record(1, input_tokens=100, output_tokens=10)

    counts = {"input_tokens": 0, "output_tokens": 0, "memory_tokens": 0, "evidence_tokens": 0}
    counts[field] = -1
    with pytest.raises(ValueError):
        ledger.record(2, **counts)

    assert ledger.total_input() == 100
    assert len(raw_lines(path)) == 1


def test_a_negative_context_tier_count_is_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    with pytest.raises(ValueError):
        ledger.record(1, input_tokens=10, output_tokens=1, tiers={"C4": -5})
    assert ledger.entries() == []


# ---------------------------------------------------------------------------------------------
# BudgetGuard: capacity budgets permit exactly the stated maximum
# ---------------------------------------------------------------------------------------------


def test_step_budget_permits_exactly_max_steps(tmp_path: Path) -> None:
    guard = BudgetGuard(Budget(max_steps=3))
    for _ in range(3):
        guard.step()

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.step()
    assert "max_steps" in str(excinfo.value)
    assert guard.snapshot()["steps"] == 3  # the refused step is not counted


def test_provider_call_budget_permits_exactly_max_calls_and_counts_in_batches(tmp_path: Path) -> None:
    guard = BudgetGuard(Budget(max_provider_calls=2))
    guard.provider_call()
    guard.provider_call()

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.provider_call()
    assert "max_provider_calls" in str(excinfo.value)
    assert guard.snapshot()["provider_calls"] == 2

    batched = BudgetGuard(Budget(max_provider_calls=2))
    batched.provider_call(2)
    with pytest.raises(BudgetExhausted) as excinfo:
        batched.provider_call(1)
    assert "max_provider_calls" in str(excinfo.value)
    assert batched.snapshot()["provider_calls"] == 2


def test_a_batched_provider_call_beyond_the_budget_is_refused_atomically() -> None:
    guard = BudgetGuard(Budget(max_provider_calls=2))
    guard.provider_call(1)
    with pytest.raises(BudgetExhausted):
        guard.provider_call(2)  # would reach three
    assert guard.snapshot()["provider_calls"] == 1


def test_provider_call_rejects_a_non_positive_batch() -> None:
    guard = BudgetGuard(Budget(max_provider_calls=2))
    for n in (0, -1):
        with pytest.raises(ValueError):
            guard.provider_call(n)


def test_prompt_token_budget_permits_exactly_max_prompt_tokens() -> None:
    guard = BudgetGuard(Budget(max_prompt_tokens=1000, max_completion_tokens=100))
    guard.add_tokens(600, 10)
    guard.add_tokens(400, 90)

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.add_tokens(1, 0)
    assert "max_prompt_tokens" in str(excinfo.value)
    assert guard.snapshot()["prompt_tokens"] == 1000


def test_completion_token_budget_permits_exactly_max_completion_tokens() -> None:
    guard = BudgetGuard(Budget(max_prompt_tokens=10_000, max_completion_tokens=150))
    guard.add_tokens(200, 150)

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.add_tokens(1, 1)
    assert "max_completion_tokens" in str(excinfo.value)
    assert guard.snapshot()["completion_tokens"] == 150


def test_a_refused_token_accounting_leaves_both_counters_untouched() -> None:
    """Half-recorded cost is worse than none: the prompt counter must not absorb a call whose
    completion half was refused."""
    guard = BudgetGuard(Budget(max_prompt_tokens=1000, max_completion_tokens=100))
    with pytest.raises(BudgetExhausted):
        guard.add_tokens(10, 500)
    assert guard.snapshot()["prompt_tokens"] == 0
    assert guard.snapshot()["completion_tokens"] == 0


def test_negative_token_accounting_is_refused() -> None:
    guard = BudgetGuard(Budget())
    with pytest.raises(ValueError):
        guard.add_tokens(-1, 0)
    with pytest.raises(ValueError):
        guard.add_tokens(0, -1)


def test_artifact_byte_budget_permits_exactly_max_artifact_bytes() -> None:
    guard = BudgetGuard(Budget(max_artifact_bytes=2048))
    guard.add_artifact_bytes(1024)
    guard.add_artifact_bytes(1024)

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.add_artifact_bytes(1)
    assert "max_artifact_bytes" in str(excinfo.value)
    assert guard.snapshot()["artifact_bytes"] == 2048


def test_artifact_byte_accounting_rejects_negative_and_oversized_single_requests() -> None:
    guard = BudgetGuard(Budget(max_artifact_bytes=16))
    with pytest.raises(ValueError):
        guard.add_artifact_bytes(-1)
    with pytest.raises(BudgetExhausted) as excinfo:
        guard.add_artifact_bytes(17)
    assert "max_artifact_bytes" in str(excinfo.value)
    assert guard.snapshot()["artifact_bytes"] == 0


# ---------------------------------------------------------------------------------------------
# Failure trip wire and wall clock
# ---------------------------------------------------------------------------------------------


def test_consecutive_failures_trip_the_failure_budget_when_the_limit_is_reached() -> None:
    guard = BudgetGuard(Budget(max_consecutive_failures=3))
    guard.failure()
    guard.failure()

    with pytest.raises(BudgetExhausted) as excinfo:
        guard.failure()
    assert "max_consecutive_failures" in str(excinfo.value)


def test_success_clears_the_consecutive_failure_counter() -> None:
    guard = BudgetGuard(Budget(max_consecutive_failures=3))
    guard.failure()
    guard.failure()
    guard.success()
    assert guard.snapshot()["consecutive_failures"] == 0

    # Progress resets the trip wire, so two more failures must not end the run.
    guard.failure()
    guard.failure()
    assert guard.snapshot()["consecutive_failures"] == 2


def test_success_does_not_refund_any_capacity_budget() -> None:
    guard = BudgetGuard(Budget(max_steps=1, max_provider_calls=1))
    guard.step()
    guard.provider_call()
    guard.success()

    with pytest.raises(BudgetExhausted):
        guard.step()
    with pytest.raises(BudgetExhausted):
        guard.provider_call()


def test_wall_clock_budget_fires_once_the_limit_is_passed() -> None:
    """The clock is advanced by rewriting the guard's monotonic start, because a test that slept for
    its budget would be slow and flaky; no sleep is involved anywhere in this suite."""
    guard = BudgetGuard(Budget(max_wall_clock_s=30))
    guard.check_wall_clock()  # a fresh run is inside its window

    guard._started_at -= 31  # noqa: SLF001 - the only way to test a wall clock without sleeping
    with pytest.raises(BudgetExhausted) as excinfo:
        guard.check_wall_clock()
    assert "max_wall_clock_s" in str(excinfo.value)


# ---------------------------------------------------------------------------------------------
# Snapshot: what a ProviderDecision records
# ---------------------------------------------------------------------------------------------


def test_snapshot_reports_every_counter_as_an_int() -> None:
    guard = BudgetGuard(Budget())
    expected = {
        "steps",
        "provider_calls",
        "prompt_tokens",
        "completion_tokens",
        "artifact_bytes",
        "consecutive_failures",
        "wall_clock_s",
    }
    snapshot = guard.snapshot()
    assert set(snapshot) == expected
    assert all(isinstance(value, int) and not isinstance(value, bool) for value in snapshot.values())
    assert set(snapshot.values()) == {0}

    guard.step()
    guard.provider_call(2)
    guard.add_tokens(100, 20)
    guard.add_artifact_bytes(4096)
    guard.failure()

    snapshot = guard.snapshot()
    assert snapshot["steps"] == 1
    assert snapshot["provider_calls"] == 2
    assert snapshot["prompt_tokens"] == 100
    assert snapshot["completion_tokens"] == 20
    assert snapshot["artifact_bytes"] == 4096
    assert snapshot["consecutive_failures"] == 1
    assert all(isinstance(value, int) and not isinstance(value, bool) for value in snapshot.values())
    assert json.dumps(snapshot)  # a ProviderDecision stores it as JSON
