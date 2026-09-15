"""Routing: turn a necessity decision into the concrete providers that will run.

The router re-checks the decision rather than executing it. A decision is a record that may have
been written by an earlier step, replayed from disk, or edited while producing a report;
re-validating that each named provider exists and still advertises the capability costs a couple
of comparisons and closes the gap between "the decision said so" and "this provider may be
called".
"""

from __future__ import annotations

from harness.errors import NecessityDenied
from harness.models import ProviderDecision, ProviderSpec
from harness.providers.base import Provider
from harness.providers.registry import MAX_PROVIDERS_PER_NEED_HARD_CAP, ProviderRegistry

#: Verdicts that legitimately select nothing. A decision claiming one of these while also naming
#: providers is internally inconsistent, and executing it would run providers the gate never
#: justified.
_EMPTY_SELECTION_VERDICTS = frozenset({"satisfied", "deny", "defer"})


class Router:
    def __init__(self, registry: ProviderRegistry) -> None:
        self._registry = registry

    def eligible(self, capability: str) -> list[ProviderSpec]:
        return [provider.spec for provider in self._registry.by_capability(capability)]

    def resolve(self, decision: ProviderDecision) -> list[Provider]:
        """Return the providers a decision authorises, in the decision's own order."""
        if decision.verdict in _EMPTY_SELECTION_VERDICTS:
            if decision.selected:
                raise NecessityDenied(
                    f"decision {decision.id} verdict {decision.verdict!r} must not select providers"
                )
            return []
        if not decision.selected:
            raise NecessityDenied(
                f"decision {decision.id} verdict {decision.verdict!r} selected nothing"
            )
        if len(decision.selected) > MAX_PROVIDERS_PER_NEED_HARD_CAP:
            raise NecessityDenied(
                f"decision {decision.id} selects {len(decision.selected)} providers, above the "
                f"hard cap of {MAX_PROVIDERS_PER_NEED_HARD_CAP}"
            )
        seen: set[str] = set()
        resolved: list[Provider] = []
        for provider_id in decision.selected:
            if provider_id in seen:
                raise NecessityDenied(f"decision {decision.id} selects {provider_id!r} twice")
            seen.add(provider_id)
            try:
                provider = self._registry.get(provider_id)
            except KeyError as exc:
                raise NecessityDenied(
                    f"decision {decision.id} selected unknown provider {provider_id!r}"
                ) from exc
            if not provider.spec.supports(decision.capability):
                raise NecessityDenied(
                    f"provider {provider_id!r} does not advertise capability "
                    f"{decision.capability!r}"
                )
            resolved.append(provider)
        return resolved
