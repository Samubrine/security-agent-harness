"""Per-run token ledger and the hard budget guard (design 01 section 9, design 08 section 7).

Two jobs that are deliberately kept apart:

* :class:`TokenLedger` *measures*. It appends one line per model call so a run can be costed and
  so the v2 Token Optimizer can later be trained on real traces instead of guesses. It enforces
  nothing.
* :class:`BudgetGuard` *enforces*. It holds the counters the model cannot raise, and it is the only
  thing that can end a run because it spent too much. Every limit it checks fails closed and names
  the specific budget that ran out, because "budget exceeded" during an incident is not actionable.

The guard is in-process state on purpose: budgets are per run, and a run is one process. It is not
persisted, unlike the ledger, which is the audit trail.
"""

from __future__ import annotations

import time
from pathlib import Path

from harness.errors import BudgetExhausted
from harness.models import Budget, ModelMetadata, TokenLedgerEntry
from harness.util import append_jsonl, read_jsonl


class TokenLedger:
    """Append-only JSONL ledger of model token usage, stamped with the frozen model identity."""

    def __init__(self, path: Path, model: ModelMetadata) -> None:
        self._path = Path(path)
        self._model = model

    def record(
        self,
        step: int,
        *,
        input_tokens: int,
        output_tokens: int,
        tiers: dict[str, int] | None = None,
        memory_tokens: int = 0,
        evidence_tokens: int = 0,
    ) -> TokenLedgerEntry:
        """Append one entry. Counts are validated non-negative because a negative delta would let a
        caller *refund* the ledger and quietly hide an overrun."""
        for name, value in (
            ("input_tokens", input_tokens),
            ("output_tokens", output_tokens),
            ("memory_tokens", memory_tokens),
            ("evidence_tokens", evidence_tokens),
        ):
            if int(value) < 0:
                raise ValueError(f"{name} may not be negative")
        tier_counts = {str(k): int(v) for k, v in (tiers or {}).items()}
        if any(v < 0 for v in tier_counts.values()):
            raise ValueError("context tier token counts may not be negative")

        entry = TokenLedgerEntry(
            step=step,
            model_id=self._model.model_id,
            tokenizer_id=self._model.tokenizer_id,
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            context_tokens_by_tier=tier_counts,
            memory_tokens=int(memory_tokens),
            evidence_tokens=int(evidence_tokens),
        )
        append_jsonl(self._path, entry.model_dump(mode="json"))
        return entry

    def entries(self) -> list[TokenLedgerEntry]:
        return [TokenLedgerEntry.model_validate(row) for row in read_jsonl(self._path)]

    def total_input(self) -> int:
        return sum(entry.input_tokens for entry in self.entries())

    def total_output(self) -> int:
        return sum(entry.output_tokens for entry in self.entries())


class BudgetGuard:
    """Hard limits for one run. All limits are absolute; none may be raised by the model.

    Two different questions are answered here, and they behave differently on purpose:

    * capacity budgets -- steps, provider calls, tokens, artifact bytes -- bound *how much work*
      is permitted. A call that would push a counter past its maximum is refused, so
      ``max_provider_calls=8`` really does allow eight calls.
    * the consecutive-failure budget is a *trip wire*, not a capacity: it answers "has this run
      stopped making progress?". It fires when the count reaches the maximum, because
      ``max_consecutive_failures=3`` means "three failures in a row and we stop", not "four".
    """

    def __init__(self, budgets: Budget) -> None:
        self._budgets = budgets
        self._steps = 0
        self._provider_calls = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._artifact_bytes = 0
        self._consecutive_failures = 0
        # Monotonic, so a wall-clock budget cannot be fooled by an NTP step or a clock change.
        self._started_at = time.monotonic()

    # -- capacity budgets ------------------------------------------------------------

    def step(self) -> None:
        if self._steps + 1 > self._budgets.max_steps:
            raise BudgetExhausted(
                f"budget exhausted: max_steps={self._budgets.max_steps} already used {self._steps}"
            )
        self._steps += 1

    def provider_call(self, n: int = 1) -> None:
        if n < 1:
            raise ValueError("a provider call consumes at least one call of budget")
        if self._provider_calls + n > self._budgets.max_provider_calls:
            raise BudgetExhausted(
                f"budget exhausted: max_provider_calls={self._budgets.max_provider_calls} "
                f"already used {self._provider_calls}, requested {n}"
            )
        self._provider_calls += n

    def add_tokens(self, prompt: int, completion: int) -> None:
        """Account a model call's tokens. Both limits are checked before either counter moves, so
        a rejected call cannot leave a half-recorded cost behind."""
        if prompt < 0 or completion < 0:
            raise ValueError("token counts may not be negative")
        if self._prompt_tokens + prompt > self._budgets.max_prompt_tokens:
            raise BudgetExhausted(
                f"budget exhausted: max_prompt_tokens={self._budgets.max_prompt_tokens} "
                f"already used {self._prompt_tokens}, requested {prompt}"
            )
        if self._completion_tokens + completion > self._budgets.max_completion_tokens:
            raise BudgetExhausted(
                f"budget exhausted: max_completion_tokens={self._budgets.max_completion_tokens} "
                f"already used {self._completion_tokens}, requested {completion}"
            )
        self._prompt_tokens += prompt
        self._completion_tokens += completion

    def add_artifact_bytes(self, n: int) -> None:
        if n < 0:
            raise ValueError("artifact byte counts may not be negative")
        if self._artifact_bytes + n > self._budgets.max_artifact_bytes:
            raise BudgetExhausted(
                f"budget exhausted: max_artifact_bytes={self._budgets.max_artifact_bytes} "
                f"already used {self._artifact_bytes}, requested {n}"
            )
        self._artifact_bytes += n

    def check_wall_clock(self) -> None:
        elapsed = self._elapsed_s()
        if elapsed > self._budgets.max_wall_clock_s:
            raise BudgetExhausted(
                f"budget exhausted: max_wall_clock_s={self._budgets.max_wall_clock_s} "
                f"elapsed {elapsed}"
            )

    # -- failure trip wire -----------------------------------------------------------

    def failure(self) -> None:
        """Record a failed attempt. Reaching the limit ends the run."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._budgets.max_consecutive_failures:
            raise BudgetExhausted(
                f"budget exhausted: max_consecutive_failures="
                f"{self._budgets.max_consecutive_failures} reached ({self._consecutive_failures} in a row)"
            )

    def success(self) -> None:
        """Clear the consecutive-failure counter. Progress resets the trip wire; it does not
        refund any capacity budget."""
        self._consecutive_failures = 0

    # -- reporting -------------------------------------------------------------------

    def snapshot(self) -> dict[str, int]:
        """Every counter, as integers, so a ``ProviderDecision`` can record the budget state that
        produced it -- this is what lets the report answer "why was another tool not run?" from
        recorded data instead of a reconstruction."""
        return {
            "steps": self._steps,
            "provider_calls": self._provider_calls,
            "prompt_tokens": self._prompt_tokens,
            "completion_tokens": self._completion_tokens,
            "artifact_bytes": self._artifact_bytes,
            "consecutive_failures": self._consecutive_failures,
            "wall_clock_s": self._elapsed_s(),
        }

    def _elapsed_s(self) -> int:
        return int(max(0.0, time.monotonic() - self._started_at))
