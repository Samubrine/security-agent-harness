"""Registry behaviour: availability is not usage, and a claim must be honest."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from harness.models import ProviderSpec
from harness.providers.base import ProviderResult
from harness.providers.registry import MAX_PROVIDERS_PER_NEED_HARD_CAP, ProviderRegistry


def make_spec(
    provider_id: str,
    *,
    capabilities: tuple[str, ...] = ("service.enumerate",),
    kind: str = "native",
    trust_class: str = "local_tool",
    risk: str = "LOW",
    excludes: tuple[str, ...] = (),
    latency_ms: int | None = None,
    egress: bool = False,
) -> ProviderSpec:
    return ProviderSpec(
        id=provider_id,
        kind=kind,  # type: ignore[arg-type]
        capabilities=list(capabilities),
        output_media_type="application/octet-stream",
        parser="none",
        risk=risk,  # type: ignore[arg-type]
        trust_class=trust_class,  # type: ignore[arg-type]
        requires_network_egress=egress,
        excludes=list(excludes),
        estimated_cost={"latency_ms": latency_ms} if latency_ms is not None else {},
    )


@dataclass
class FakeProvider:
    spec: ProviderSpec

    def invoke(self, request):  # pragma: no cover - the registry never invokes anything
        return ProviderResult(provider=self.spec.id, capability=request.capability, exit_status="completed")


def test_an_excluded_capability_never_reaches_the_catalogue() -> None:
    """A provider that says it cannot serve a capability must not be a candidate for it.

    nmap declares http.probe and excludes it. If the exclusion were ignored, the planner could ask
    for something no adapter implements, which is worse than the capability being unavailable.
    """
    registry = ProviderRegistry([FakeProvider(make_spec("native:nmap", capabilities=("service.enumerate", "http.probe"), excludes=("http.probe",)))])
    assert [p.spec.id for p in registry.by_capability("service.enumerate")] == ["native:nmap"]
    assert registry.by_capability("http.probe") == []


def test_a_duplicate_provider_id_is_refused() -> None:
    """Shadowing a provider would let a later registration change an already-decided call."""
    registry = ProviderRegistry([FakeProvider(make_spec("native:one"))])
    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeProvider(make_spec("native:one")))


def test_registration_does_not_imply_usage() -> None:
    registry = ProviderRegistry(
        [FakeProvider(make_spec("native:a")), FakeProvider(make_spec("mcp:b", kind="mcp"))]
    )
    # Two providers advertise one capability, and the registry's job ends at reporting that fact.
    assert len(registry.by_capability("service.enumerate")) == 2
    assert registry.capabilities() == ["service.enumerate"]


def test_lookups_are_sorted_and_stable() -> None:
    registry = ProviderRegistry(
        [
            FakeProvider(make_spec("native:zeta", capabilities=("service.enumerate", "http.probe"))),
            FakeProvider(make_spec("native:alpha", capabilities=("service.enumerate",))),
        ]
    )
    assert [p.spec.id for p in registry.by_capability("service.enumerate")] == [
        "native:alpha",
        "native:zeta",
    ]
    assert [spec.id for spec in registry.specs()] == ["native:alpha", "native:zeta"]


def test_an_empty_provider_id_is_refused() -> None:
    registry = ProviderRegistry()
    spec = make_spec("native:x").model_copy(update={"id": ""})
    with pytest.raises(ValueError, match="non-empty"):
        registry.register(FakeProvider(spec))


def test_hard_cap_is_three() -> None:
    """The design's ceiling is a constant, not a tunable, and every other layer agrees with it."""
    assert MAX_PROVIDERS_PER_NEED_HARD_CAP == 3
