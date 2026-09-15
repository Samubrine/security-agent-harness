"""The necessity gate: the difference between a provider being available and it being needed.

These are the tests for design decision D22. Each one pins a rule that, if it silently changed,
would turn this project back into an agent that calls every tool it can reach.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from harness.models import Budget, Correlation, ModelMetadata, Observation, ProviderSpec, SkillSpec, SkillVerification
from harness.providers.base import ProviderResult
from harness.providers.necessity import CAPABILITY_OUTPUT_KINDS, NecessityGate, cache_key, output_kinds
from harness.providers.registry import ProviderRegistry
from harness.tokens import BudgetGuard


def spec(
    provider_id: str,
    *,
    capabilities: tuple[str, ...] = ("service.enumerate",),
    kind: str = "native",
    trust_class: str = "local_tool",
    risk: str = "LOW",
    latency_ms: int | None = None,
    egress: bool = False,
) -> ProviderSpec:
    return ProviderSpec(
        id=provider_id,
        kind=kind,  # type: ignore[arg-type]
        capabilities=list(capabilities),
        output_media_type="application/nmap+xml",
        parser="nmap_xml",
        risk=risk,  # type: ignore[arg-type]
        trust_class=trust_class,  # type: ignore[arg-type]
        requires_network_egress=egress,
        estimated_cost={"latency_ms": latency_ms} if latency_ms is not None else {},
    )


@dataclass
class FakeProvider:
    spec: ProviderSpec

    def invoke(self, request):  # pragma: no cover
        return ProviderResult(provider=self.spec.id, capability=request.capability, exit_status="completed")


def observation(kind: str, obs_id: str) -> Observation:
    return Observation(
        id=obs_id,
        run_id="run-necessity",
        kind=kind,
        value={},
        parser="test",
        parser_version="0.1.0",
        provider="native:synthetic",
        execution_id="x-1",
        trust_class="local_tool",
        taint="T2",
        evidence=[],
    )


def gate(*specs: ProviderSpec, skill: SkillSpec | None = None, guard: BudgetGuard | None = None) -> NecessityGate:
    registry = ProviderRegistry([FakeProvider(s) for s in specs])
    return NecessityGate(registry, Budget(), skill=skill, budgets_guard=guard)


def decide(engine: NecessityGate, **overrides):
    kwargs = dict(
        capability="service.enumerate",
        evidence_needed="No current-run service observations exist.",
        expects="service, product and version per open port",
        existing_observations=[],
    )
    kwargs.update(overrides)
    return engine.decide(**kwargs)


# -- rule 1: existing evidence removes the need entirely --------------------------------------


def test_missing_evidence_selects_exactly_one_provider() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")))
    assert decision.verdict == "single"
    assert decision.selected == ["native:a"]
    # The other candidate is recorded as rejected with a reason, which is how the report can answer
    # "why was the other available tool not run?".
    assert "native:b" in decision.rejected
    assert decision.rejected["native:b"]


def test_satisfied_evidence_skips_the_call_entirely() -> None:
    present = [observation(kind, "o-" + kind) for kind in sorted(CAPABILITY_OUTPUT_KINDS["service.enumerate"])]
    decision = decide(gate(spec("native:a")), existing_observations=present)
    assert decision.verdict == "satisfied"
    assert decision.selected == []
    assert set(decision.satisfied_by) == {o.id for o in present}


def test_partial_evidence_does_not_count_as_satisfied() -> None:
    """Half the declared output is still a gap; treating it as satisfied would hide it."""
    decision = decide(gate(spec("native:a")), existing_observations=[observation("service", "o-1")])
    assert decision.verdict == "single"


# -- rule 2: ranking -------------------------------------------------------------------------


def test_native_is_preferred_over_mcp_at_equal_cost() -> None:
    decision = decide(gate(spec("mcp:b", kind="mcp", trust_class="local_mcp"), spec("native:a")))
    assert decision.selected == ["native:a"]


def test_lower_risk_wins_over_lower_latency() -> None:
    decision = decide(
        gate(spec("native:fast-high", risk="HIGH", latency_ms=10), spec("native:slow-low", risk="LOW", latency_ms=900))
    )
    assert decision.selected == ["native:slow-low"]


def test_prefer_overrides_the_ranking_for_this_decision_only() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")), prefer="native:b")
    assert decision.selected == ["native:b"]


# -- rule 3: a failure is a replacement, not an expansion ------------------------------------


def test_failed_preferred_provider_is_replaced_by_the_next_candidate() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")), failed_providers={"native:a"})
    assert decision.verdict == "single"
    assert decision.selected == ["native:b"]
    assert decision.expansion_reason == "provider_failure"
    assert "native:a" in decision.rejected


def test_a_failure_further_down_the_ranking_is_not_an_expansion() -> None:
    """Only losing the provider that would have been chosen justifies a second call."""
    decision = decide(gate(spec("native:a"), spec("native:b")), failed_providers={"native:b"})
    assert decision.selected == ["native:a"]
    assert decision.expansion_reason is None


def test_all_candidates_failed_is_denied_not_retried() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")), failed_providers={"native:a", "native:b"})
    assert decision.verdict == "deny"
    assert decision.selected == []


# -- rules 4 and 5: the two reasons that justify two providers at once -----------------------


def conflict() -> Correlation:
    return Correlation(
        id="cor-1",
        run_id="run-necessity",
        key="service|lab-web-01|22|tcp",
        observation_ids=["o-1", "o-2"],
        relation="conflict",
        detail="providers disagree on version",
    )


def test_an_unresolved_conflict_expands_to_two_providers() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")), conflicts=[conflict()])
    assert decision.verdict == "expand"
    assert decision.expansion_reason == "conflict_resolution"
    assert len(decision.selected) == 2


def test_trust_diversity_expands_to_two_providers() -> None:
    decision = decide(gate(spec("native:a"), spec("native:b")), trust_diversity_required=True)
    assert decision.verdict == "expand"
    assert decision.expansion_reason == "trust_diversity"


def test_an_expansion_is_denied_when_the_skill_allows_only_one_provider() -> None:
    """A skill that caps a need at one provider is the run's stated verification policy."""
    skill = SkillSpec(
        name="tight",
        version="0.1.0",
        capabilities=["service.enumerate"],
        verification=SkillVerification(max_providers_per_need=1),
    )
    decision = decide(gate(spec("native:a"), spec("native:b"), skill=skill), trust_diversity_required=True)
    assert decision.verdict == "deny"
    assert decision.selected == []


def test_a_skill_may_raise_the_cap_but_never_past_the_hard_ceiling() -> None:
    skill = SkillSpec(
        name="wide",
        version="0.1.0",
        capabilities=["service.enumerate"],
        verification=SkillVerification(max_providers_per_need=9),
    )
    engine = gate(spec("native:a"), spec("native:b"), spec("native:c"), spec("native:d"), skill=skill)
    decision = decide(engine, trust_diversity_required=True)
    assert len(decision.selected) <= 3


# -- rule 6: nothing eligible -----------------------------------------------------------------


def test_an_unknown_capability_is_denied() -> None:
    decision = decide(gate(spec("native:a")), capability="teleport.host")
    assert decision.verdict == "deny"
    assert "no registered provider" in decision.reason


# -- rule 7: budget pressure defers rather than pretends ------------------------------------


def test_an_exhausted_provider_budget_defers_instead_of_calling() -> None:
    budgets = Budget(max_provider_calls=1)
    guard = BudgetGuard(budgets)
    guard.provider_call()  # the only call this run is allowed is already spent
    engine = NecessityGate(
        ProviderRegistry([FakeProvider(spec("native:a"))]), budgets, budgets_guard=guard
    )
    decision = decide(engine)
    assert decision.verdict == "defer"
    assert decision.selected == []
    # The decision records the budget state that produced it, so the report can explain the gap
    # from stored data rather than from a reconstruction.
    assert decision.budget_snapshot["provider_calls"] == 1


def test_an_expansion_is_deferred_when_only_one_call_remains() -> None:
    budgets = Budget(max_provider_calls=3)
    guard = BudgetGuard(budgets)
    guard.provider_call(2)
    engine = NecessityGate(
        ProviderRegistry([FakeProvider(spec("native:a")), FakeProvider(spec("native:b"))]),
        budgets,
        budgets_guard=guard,
    )
    decision = decide(engine, trust_diversity_required=True)
    assert decision.verdict == "defer"


# -- coverage gap: a provider ran and the declared output is still missing -------------------


def test_a_provider_that_ran_without_closing_the_need_justifies_a_second() -> None:
    engine = gate(spec("native:a"), spec("native:b"))
    cache = {cache_key("native:a", "service.enumerate"): ProviderResult(provider="native:a", capability="service.enumerate", exit_status="completed")}
    decision = decide(engine, cache=cache, existing_observations=[observation("service", "o-1")])
    assert decision.verdict == "expand"
    assert decision.expansion_reason == "coverage_gap"


# -- small surface checks --------------------------------------------------------------------


def test_output_kinds_are_sorted_for_stable_prompts() -> None:
    assert output_kinds("service.enumerate") == sorted(CAPABILITY_OUTPUT_KINDS["service.enumerate"])
    assert output_kinds("nothing.known") == []
