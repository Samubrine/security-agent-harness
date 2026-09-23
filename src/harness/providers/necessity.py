"""The provider necessity gate.

Availability is not necessity, and this module is the code that makes that distinction real. It is
deliberately rule-based and small (decision D22, and design 06's definition of done): a policy a
grader can read, whose every decision is recorded with the candidates it rejected and why.

The gate answers four questions in order, and the order is the design:

1. does current-run evidence already satisfy the need? If so, nothing runs. This is the only answer
   that saves a call outright, and it is the reason the report can say "this tool was not needed"
   rather than only "this tool was not run";
2. which single provider is the minimum sufficient one? Local before remote, lower risk before
   higher, cheaper before costlier, with the id as a stable tie-break;
3. is a second provider actually justified? Only for one of the five enumerated reasons, never
   because another provider happens to exist;
4. can the budget support it? If not, the honest verdict is ``defer`` plus a gap, never a quieter
   alternative like running it anyway or pretending the evidence exists.

One nuance worth naming: a provider *failure* is a replacement, not an expansion. When the first
provider dies, the run still wants exactly one answer, so the verdict is ``single`` with a recorded
``expansion_reason="provider_failure"``. ``expand`` is reserved for genuinely wanting two sources at
once, which is what conflict resolution and trust diversity are.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any

from harness.models import (
    Budget,
    Correlation,
    Observation,
    ProviderDecision,
    ProviderSpec,
    SkillSpec,
)
from harness.providers.base import ProviderResult
from harness.providers.registry import MAX_PROVIDERS_PER_NEED_HARD_CAP, ProviderRegistry
from harness.util import new_id

#: What each logical capability is declared to produce, and therefore what "this need is already
#: met" means. It lives next to the gate rather than in the loop so that the gate's notion of
#: satisfaction and any other component's notion cannot drift apart; the loop reads this table to
#: tell the model what a capability is for.
CAPABILITY_OUTPUT_KINDS: dict[str, set[str]] = {
    "service.enumerate": {"scan_meta", "host_state", "service"},
    "vulnerability.match": {"vulnerability_match"},
    "log.read": {"auth_event", "auth_summary", "http_event", "http_summary"},
    "log.query": {"log_query"},
    "http.probe": {"http_probe"},
}

KIND_ORDER: dict[str, int] = {"native": 0, "mcp": 1}
TRUST_ORDER: dict[str, int] = {"local_tool": 0, "local_mcp": 1, "external_provider": 2}
RISK_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

#: Reasoning strings are recorded on every rejection, so the report can answer "why was the other
#: available tool not run?" from stored data rather than from a reconstruction.
REASON_RANK = "available but not the minimum sufficient provider"
REASON_FAILED = "this provider failed earlier in the run"
REASON_EXCLUDED = "this provider declares it cannot serve the capability"
REASON_BUDGET = "the remaining provider-call budget cannot support this call"


def cache_key(provider_id: str, capability: str) -> str:
    """Convention for the run's result cache.

    Exported so the loop and any future provider share one spelling: a cache the gate cannot find
    is a cache that silently makes every call look necessary.
    """
    return f"{provider_id}:{capability}"


class NecessityGate:
    def __init__(
        self,
        registry: ProviderRegistry,
        budgets: Budget,
        *,
        skill: SkillSpec | None = None,
        budgets_guard: Any | None = None,
    ) -> None:
        self._registry = registry
        self._budgets = budgets
        self._skill = skill
        self._guard = budgets_guard

    # -- public surface -----------------------------------------------------------------

    def decide(
        self,
        *,
        capability: str,
        evidence_needed: str,
        expects: str,
        existing_observations: Sequence[Observation],
        cache: Mapping[str, ProviderResult] | None = None,
        failed_providers: Collection[str] = (),
        conflicts: Sequence[Correlation] = (),
        trust_diversity_required: bool = False,
        prefer: str | None = None,
    ) -> ProviderDecision:
        eligible = self._registry.by_capability(capability)
        specs = [provider.spec for provider in eligible]
        failed = set(failed_providers)
        snapshot = self._budget_snapshot()

        base = dict(
            capability=capability,
            considered=[spec.id for spec in specs],
            budget_snapshot=snapshot,
        )

        if not specs:
            return ProviderDecision(
                id=new_id("d"),
                verdict="deny",
                selected=[],
                rejected={},
                reason=(
                    f"no registered provider advertises {capability!r}; a capability without a "
                    "provider cannot be satisfied by policy"
                ),
                **base,
            )

        covered = self._satisfying_observations(capability, existing_observations)
        if covered is not None:
            return ProviderDecision(
                id=new_id("d"),
                verdict="satisfied",
                selected=[],
                rejected={spec.id: "not needed: current evidence already satisfies the request" for spec in specs},
                reason=(
                    f"current-run evidence already provides every output "
                    f"{capability!r} is declared to produce"
                ),
                satisfied_by=covered,
                **base,
            )

        ranked = self._rank(specs, prefer=prefer)
        viable = [spec for spec in ranked if spec.id not in failed]
        rejected = {
            spec.id: REASON_FAILED for spec in ranked if spec.id in failed
        }
        rejected.update({
            spec.id: REASON_RANK for spec in viable[1:] if spec.id not in rejected
        })

        if not viable:
            return ProviderDecision(
                id=new_id("d"),
                verdict="deny",
                selected=[],
                rejected=rejected,
                reason="every provider that advertises this capability has already failed",
                **base,
            )

        replacement = self._replacement_selection(ranked, viable, failed, rejected)
        if replacement is not None:
            selected, reason, expansion = replacement
            return self._budget_checked(
                selected=selected,
                expansion_reason=expansion,
                reason=reason,
                rejected=rejected,
                base=base,
            )

        conflict = self._conflict_for(capability, conflicts)
        if conflict is not None or trust_diversity_required:
            limit = self._provider_cap()
            if limit < 2 or len(viable) < 2:
                return ProviderDecision(
                    id=new_id("d"),
                    verdict="deny",
                    selected=[],
                    rejected=rejected,
                    reason=(
                        "a second provider is warranted but the skill or budget allows one "
                        "provider per need"
                    ),
                    **base,
                )
            reason_kind = "conflict_resolution" if conflict is not None else "trust_diversity"
            explanation = (
                f"existing providers disagree about {conflict.key}" if conflict is not None
                else "this conclusion must not rest on a single source"
            )
            # `limit` is the cap the skill/budget actually asked for, clamped to the hard
            # ceiling. Selecting a fixed two made `max_providers_per_need > 2` an inert field
            # (R2-30): a skill could not ask for three-way verification even though the model
            # and the hard ceiling both allow it.
            selected = [spec.id for spec in viable[:limit]]
            for spec in viable[limit:]:
                rejected.setdefault(spec.id, f"beyond the {reason_kind} selection")
            return self._budget_checked(
                selected=selected,
                expansion_reason=reason_kind,  # type: ignore[arg-type]
                reason=f"{len(selected)} providers are necessary because {explanation}",
                rejected=rejected,
                base=base,
            )

        coverage = self._coverage_gap(capability, viable, cache or {}, existing_observations)
        if coverage is not None:
            limit = self._provider_cap()
            if limit >= 2 and len(viable) >= 2:
                selected = [spec.id for spec in viable[:limit]]
                for spec in viable[limit:]:
                    rejected.setdefault(spec.id, "beyond the coverage-gap selection")
                return self._budget_checked(
                    selected=selected,
                    expansion_reason="coverage_gap",
                    reason=(
                        f"a provider already ran for {capability!r} and its output did not include "
                        f"every declared output kind ({coverage})"
                    ),
                    rejected=rejected,
                    base=base,
                )

        return self._budget_checked(
            selected=[viable[0].id],
            expansion_reason=None,
            reason=(
                f"one provider is the minimum sufficient answer: lowest-ranked eligible candidate "
                f"is {viable[0].id!r}"
            ),
            rejected=rejected,
            base=base,
        )

    # -- internals ----------------------------------------------------------------------

    def _budget_snapshot(self) -> dict[str, int]:
        if self._guard is None or not hasattr(self._guard, "snapshot"):
            return {}
        raw = self._guard.snapshot()
        return {str(key): int(value) for key, value in dict(raw).items()}

    def _provider_cap(self) -> int:
        cap = self._budgets.max_providers_per_need
        if self._skill is not None and self._skill.verification.max_providers_per_need is not None:
            cap = self._skill.verification.max_providers_per_need
        return max(1, min(cap, self._budgets.hard_max_providers_per_need, MAX_PROVIDERS_PER_NEED_HARD_CAP))

    def _remaining_provider_calls(self) -> int | None:
        used = self._budget_snapshot().get("provider_calls")
        if used is None:
            return None
        return max(0, self._budgets.max_provider_calls - used)

    def _budget_checked(
        self,
        *,
        selected: list[str],
        expansion_reason: str | None,
        reason: str,
        rejected: dict[str, str],
        base: dict[str, Any],
    ) -> ProviderDecision:
        remaining = self._remaining_provider_calls()
        if remaining is not None and remaining < len(selected):
            return ProviderDecision(
                id=new_id("d"),
                verdict="defer",
                selected=[],
                rejected={**rejected, **{pid: REASON_BUDGET for pid in selected}},
                reason=(
                    f"{REASON_BUDGET}: {len(selected)} call(s) needed, {remaining} remaining"
                ),
                **base,
            )
        verdict = "expand" if len(selected) > 1 else "single"
        return ProviderDecision(
            id=new_id("d"),
            verdict=verdict,  # type: ignore[arg-type]
            selected=selected,
            rejected=rejected,
            reason=reason,
            expansion_reason=expansion_reason,  # type: ignore[arg-type]
            **base,
        )

    def _satisfying_observations(
        self, capability: str, observations: Sequence[Observation]
    ) -> list[str] | None:
        required = CAPABILITY_OUTPUT_KINDS.get(capability)
        if not required:
            # An unknown capability has no declared output, so nothing can satisfy it. Saying
            # "not satisfied" keeps the gate from inventing coverage for a capability it does not
            # understand.
            return None
        present: dict[str, list[str]] = {}
        for observation in observations:
            present.setdefault(observation.kind, []).append(observation.id)
        for kind in required:
            if not present.get(kind):
                return None
        return sorted({obs_id for kind in required for obs_id in present[kind]})

    def _rank(
        self,
        specs: Sequence[ProviderSpec],
        *,
        prefer: str | None,
    ) -> list[ProviderSpec]:
        def key(spec: ProviderSpec) -> tuple[int, int, int, int]:
            latency = spec.estimated_cost.latency_ms
            return (
                0 if spec.id == prefer else 1,
                KIND_ORDER.get(spec.kind, 9),
                TRUST_ORDER.get(spec.trust_class, 9),
                RISK_ORDER.get(spec.risk, 9) * 1_000_000 + (latency if latency is not None else 10**6),
            )

        return sorted(specs, key=lambda spec: (key(spec), spec.id))

    def _replacement_selection(
        self,
        ranked: Sequence[ProviderSpec],
        viable: Sequence[ProviderSpec],
        failed: Collection[str],
        rejected: dict[str, str],
    ) -> tuple[list[str], str, str] | None:
        """A failed provider is replaced, not accompanied.

        The run still wants one answer to its question, so the verdict is ``single`` while the
        ``expansion_reason`` records why a second call happened at all. That keeps the
        multi-provider metric honest: a retry is visible without being counted as corroboration.

        This only applies when the provider that *would* have been chosen is the one that failed.
        A failure further down the ranking changes nothing about the minimum sufficient set, and
        reporting it as a replacement would inflate the expansion count with retries that never
        happened.
        """
        if not failed or not viable:
            return None
        if ranked and ranked[0].id not in failed:
            return None
        return (
            [viable[0].id],
            f"the previously selected provider failed; {viable[0].id!r} is the next eligible candidate",
            "provider_failure",
        )

    def _conflict_for(self, capability: str, conflicts: Sequence[Correlation]) -> Correlation | None:
        """The first unresolved conflict whose subject is something this capability produces.

        A correlation key begins with the observation kind it groups, so the test is membership in
        the capability's declared output kinds rather than a single chosen prefix: picking one kind
        (say the alphabetically first) would miss a conflict about any of the others.
        """
        kinds = CAPABILITY_OUTPUT_KINDS.get(capability) or {capability}
        for correlation in conflicts:
            if correlation.relation != "conflict":
                continue
            if correlation.key.split("|", 1)[0] in kinds:
                return correlation
        return None

    def _coverage_gap(
        self,
        capability: str,
        viable: Sequence[ProviderSpec],
        cache: Mapping[str, ProviderResult],
        observations: Sequence[Observation],
    ) -> str | None:
        """Did a provider already run for this capability and leave declared output missing?

        This is the honest definition of a coverage gap available to a deterministic gate: not a
        guess about what a provider might fail to return, but the recorded fact that one ran and the
        evidence set is still incomplete.

        The lookup is the exact ``cache_key(provider, capability)`` and nothing else. An earlier
        version also matched a bare provider id, which is what the run's cache holds when it records
        a completion without its capability - so a provider that had answered *this* capability could
        make a different capability look like it had already run, and the gate would expand for a
        coverage gap that did not exist (R2-29).
        """
        ran = [pid for pid in (spec.id for spec in viable) if cache_key(pid, capability) in cache]
        if not ran:
            return None
        required = CAPABILITY_OUTPUT_KINDS.get(capability) or set()
        present = {observation.kind for observation in observations}
        missing = sorted(required - present)
        if not missing:
            return None
        return ", ".join(missing)


def output_kinds(capability: str) -> list[str]:
    """Sorted output kinds for a capability, for prompt rendering and catalogue building."""
    return sorted(CAPABILITY_OUTPUT_KINDS.get(capability) or set())
