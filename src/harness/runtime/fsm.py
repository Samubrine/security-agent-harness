"""Explicit run state.

Decision D15 keeps this hand-written rather than delegating it to an agent framework, for the
same reason the policy engine is small: the control flow of a security investigation should be
readable in one sitting and assertable in a unit test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from harness.models import (
    Claim,
    Correlation,
    EvidenceGap,
    FollowUpNeed,
    Finding,
    Observation,
    ProviderCallTelemetry,
    ProviderDecision,
    ProviderExecution,
)


class State(StrEnum):
    INIT = "init"
    CONTEXT_RESOLVED = "context_resolved"
    PLANNING = "planning"
    VALIDATING = "validating"
    NECESSITY = "necessity"
    POLICY = "policy"
    EXECUTING = "executing"
    PARSING = "parsing"
    CORRELATING = "correlating"
    FINDINGS = "findings"
    TERMINATING = "terminating"
    DONE = "done"
    FAILED = "failed"


#: Legal transitions. Anything else is a bug in the loop, not a runtime condition, so the loop
#: asserts against this table instead of quietly continuing from an unreachable state.
# Nothing forces a run to keep going: a budget breach, a wall-clock breach or an unrecoverable
# error must be able to end the run from wherever it currently stands.
TERMINAL = {State.TERMINATING, State.DONE, State.FAILED}

TRANSITIONS: dict[State, set[State]] = {
    State.INIT: {State.CONTEXT_RESOLVED} | TERMINAL,
    State.CONTEXT_RESOLVED: {State.PLANNING} | TERMINAL,
    State.PLANNING: {State.VALIDATING} | TERMINAL,
    State.VALIDATING: {State.NECESSITY, State.PLANNING} | TERMINAL,
    State.NECESSITY: {State.POLICY, State.PLANNING, State.FINDINGS} | TERMINAL,
    State.POLICY: {State.EXECUTING, State.FINDINGS, State.PLANNING} | TERMINAL,
    State.EXECUTING: {State.PARSING, State.FINDINGS, State.PLANNING} | TERMINAL,
    State.PARSING: {State.CORRELATING, State.FINDINGS} | TERMINAL,
    State.CORRELATING: {State.FINDINGS} | TERMINAL,
    # FINDINGS -> POLICY is legal because one necessity decision can select more than one provider
    # (conflict_resolution, trust_diversity). `_run_provider` leaves the machine here, and `_pursue`
    # then gates the next execution of the *same* decision - which is a policy step, not a new
    # planning cycle: necessity has already been decided and must not be re-derived per provider.
    State.FINDINGS: {State.PLANNING, State.POLICY} | TERMINAL,
    State.TERMINATING: {State.DONE, State.FAILED},
    State.DONE: set(),
    State.FAILED: set(),
}


@dataclass
class RunState:
    run_id: str
    state: State = State.INIT
    step: int = 0
    observations: dict[str, Observation] = field(default_factory=dict)
    claims: list[Claim] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    gaps: list[EvidenceGap] = field(default_factory=list)
    executions: list[ProviderExecution] = field(default_factory=list)
    decisions: list[ProviderDecision] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    cache: dict[str, Any] = field(default_factory=dict)
    failed_providers: set[str] = field(default_factory=set)
    consecutive_failures: int = 0
    stop_reason: str | None = None
    #: Capabilities the model asked for that the runtime refused, with the reason. Kept so the
    #: report can show what was attempted, including attempts that looked like scope escapes.
    rejected_proposals: list[dict[str, Any]] = field(default_factory=list)
    #: Per-provider-call telemetry, recorded so the v2 Token Optimizer can be evaluated against
    #: measured traces instead of an architectural guess (design 08 section 9).
    telemetry: list[ProviderCallTelemetry] = field(default_factory=list)
    #: Evidence needs a conflict created on its own, without a model turn. Kept so the report can
    #: show that a second call was driven by a detected disagreement rather than by the planner.
    follow_ups: list[FollowUpNeed] = field(default_factory=list)

    def transition(self, new_state: State) -> None:
        if new_state is self.state:
            return
        allowed = TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise AssertionError(f"illegal transition {self.state} -> {new_state}")
        self.state = new_state

    def can_transition(self, new_state: State) -> bool:
        return new_state in TRANSITIONS.get(self.state, set())

    def observation_kinds(self) -> set[str]:
        return {obs.kind for obs in self.observations.values()}

    def observations_by_kind(self, kind: str) -> list[Observation]:
        return [obs for obs in self.observations.values() if obs.kind == kind]

    def has_cves(self) -> bool:
        return any(obs.kind == "vulnerability_match" for obs in self.observations.values())
