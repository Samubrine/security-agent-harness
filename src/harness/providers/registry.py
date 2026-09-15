"""The capability catalogue: capability -> providers, never the other way round.

The registry is deliberately dumb. It answers "who could serve this capability" and nothing
about whether anyone should run. That split is what makes "registration is not usage" checkable:
the router and the necessity gate are the only code that turns availability into a call.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from harness.models import ProviderSpec
from harness.providers.base import Provider

#: Mirrors Budget.hard_max_providers_per_need. Kept as a constant rather than read from a
#: constructed Budget so the router can refuse an over-wide decision even when no run config is
#: in hand; the frozen vocabulary remains the single source of the number.
MAX_PROVIDERS_PER_NEED_HARD_CAP = 3


class ProviderRegistry:
    def __init__(self, providers: Iterable[Provider] = ()) -> None:
        self._by_id: dict[str, Provider] = {}
        self._by_capability: dict[str, list[str]] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: Provider) -> None:
        """Add one provider.

        A duplicate id is an error rather than a silent replacement: shadowing an existing
        provider would let a later registration change the meaning of an already-decided call,
        which is exactly the ambiguity that hides a routing bug from an audit.
        """
        spec = provider.spec
        if not spec.id:
            raise ValueError("a provider must have a non-empty spec.id")
        if spec.id in self._by_id:
            raise ValueError(f"provider id {spec.id!r} is already registered")
        self._by_id[spec.id] = provider
        for capability in sorted(set(spec.capabilities)):
            # A capability the provider declares as excluded never enters the index, so
            # by_capability cannot hand back a provider that already said it cannot serve it.
            if capability in spec.excludes:
                continue
            self._by_capability.setdefault(capability, []).append(spec.id)

    def get(self, provider_id: str) -> Provider:
        return self._by_id[provider_id]

    def by_capability(self, capability: str) -> list[Provider]:
        ids = self._by_capability.get(capability, [])
        return [self._by_id[pid] for pid in sorted(ids)]

    def specs(self) -> list[ProviderSpec]:
        return [self._by_id[pid].spec for pid in sorted(self._by_id)]

    def capabilities(self) -> list[str]:
        return sorted(self._by_capability)

    def __iter__(self) -> Iterator[Provider]:
        return iter([self._by_id[pid] for pid in sorted(self._by_id)])

    def __len__(self) -> int:
        return len(self._by_id)
