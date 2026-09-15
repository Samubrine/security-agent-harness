"""Milestone M4 end to end: two providers for one capability, and only one of them runs.

The claim being tested is that provider plurality buys coverage without producing provider spam. The
assertions are therefore about what did *not* run, and about whether the run can explain the
decisions it made from its own records.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from harness.models import ProviderSpec
from harness.providers.base import ProviderRequest, ProviderResult, make_gap
from harness.runtime.runner import execute_run

pytestmark = pytest.mark.integration


@dataclass
class AlwaysFailingProvider:
    """A provider that advertises the capability, is cheapest, and never works.

    Deliberately the cheapest candidate: that is what makes the gate choose it first, which is the
    only way to exercise the failure-fallback path through the real loop rather than by calling the
    gate directly.
    """

    provider_id: str = "native:aaa-failing"

    @property
    def spec(self) -> ProviderSpec:
        return ProviderSpec(
            id=self.provider_id,
            kind="native",
            capabilities=["service.enumerate"],
            output_media_type="application/nmap+xml",
            parser="nmap_xml",
            risk="LOW",
            trust_class="local_tool",
            requires_network_egress=False,
            timeout_s=5,
            idempotent=True,
            estimated_cost={"latency_ms": 1},
            description="Test double: always fails, so the fallback path can be observed.",
        )

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        return ProviderResult(
            provider=self.provider_id,
            capability=request.capability,
            exit_status="failed",
            error="deliberate failure for the multi-provider scenario",
            gaps=[
                make_gap(
                    request=request,
                    kind="provider_failure",
                    impact="the injected provider failed on purpose, so its evidence is missing",
                )
            ],
        )


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _scan_run(lab_environment, run_id: str, **overrides):
    return execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id=run_id,
            **overrides,
        )
    )


def test_a_normal_run_uses_exactly_one_provider_per_need(lab_environment) -> None:
    """Two providers advertise service.enumerate; the minimum sufficient one runs."""
    artifacts = _scan_run(lab_environment, "run-m4-single")
    executions = _jsonl(artifacts.run_dir / "executions.jsonl")
    enumerate_calls = [row for row in executions if row["capability"] == "service.enumerate"]
    assert len(enumerate_calls) == 1, [r["provider"] for r in enumerate_calls]
    assert enumerate_calls[0]["provider"] == "native:synthetic"


def test_the_provider_that_did_not_run_is_still_explained(lab_environment) -> None:
    """The report must answer "why was the other available tool not run?", from stored data."""
    artifacts = _scan_run(lab_environment, "run-m4-rejected")
    decisions = _jsonl(artifacts.run_dir / "provider-decisions.jsonl")
    scan_decision = next(d for d in decisions if d["capability"] == "service.enumerate")
    assert scan_decision["verdict"] == "single"
    assert scan_decision["selected"] == ["native:synthetic"]
    assert "native:nmap" in scan_decision["considered"]
    assert scan_decision["rejected"].get("native:nmap")


def test_a_failing_provider_is_replaced_without_a_planner_change(lab_environment) -> None:
    """The escalation test M4 asks for: a provider dies, another covers the same need.

    The failing provider is deliberately the cheapest candidate, so the gate picks it first. Nothing
    about the planner changes between the two attempts; only the run's record of which providers have
    failed does.
    """
    artifacts = _scan_run(
        lab_environment, "run-m4-fallback", extra_providers=(AlwaysFailingProvider(),)
    )
    executions = _jsonl(artifacts.run_dir / "executions.jsonl")
    providers = [row["provider"] for row in executions if row["capability"] == "service.enumerate"]
    assert providers[0] == "native:aaa-failing"
    assert "native:synthetic" in providers
    assert any(row["exit_status"] == "failed" for row in executions)

    decisions = [d for d in _jsonl(artifacts.run_dir / "provider-decisions.jsonl") if d["capability"] == "service.enumerate"]
    fallback = [d for d in decisions if d.get("expansion_reason") == "provider_failure"]
    assert fallback, [d["verdict"] for d in decisions]
    assert fallback[0]["rejected"].get("native:aaa-failing")

    # And the failure is not hidden: it produced a gap the report carries.
    gaps = _jsonl(artifacts.run_dir / "gaps.jsonl")
    assert any(gap["kind"] == "provider_failure" for gap in gaps)


def test_the_fallback_run_still_produces_the_same_evidence(lab_environment) -> None:
    """Coverage is recovered, not merely attempted: the service observations still arrive."""
    artifacts = _scan_run(
        lab_environment, "run-m4-recovered", extra_providers=(AlwaysFailingProvider(),)
    )
    observations = json.loads((artifacts.run_dir / "observations.json").read_text(encoding="utf-8"))
    services = [obs for obs in observations if obs["kind"] == "service"]
    assert services
    assert all(obs["provider"] == "native:synthetic" for obs in services)


def test_no_expansion_happens_without_a_recorded_reason(lab_environment) -> None:
    """The invariant that keeps multi-provider routing auditable, checked over real run data."""
    artifacts = _scan_run(
        lab_environment, "run-m4-reasons", extra_providers=(AlwaysFailingProvider(),)
    )
    for decision in _jsonl(artifacts.run_dir / "provider-decisions.jsonl"):
        if decision["verdict"] == "expand":
            assert decision["expansion_reason"] in {
                "coverage_gap",
                "conflict_resolution",
                "independent_verification",
                "provider_failure",
                "trust_diversity",
            }
            assert len(decision["selected"]) >= 2


def test_a_need_already_satisfied_does_not_call_again(lab_environment) -> None:
    """Availability plus existing evidence must resolve to no call at all."""
    artifacts = _scan_run(lab_environment, "run-m4-satisfied")
    decisions = _jsonl(artifacts.run_dir / "provider-decisions.jsonl")
    by_capability = {}
    for decision in decisions:
        by_capability.setdefault(decision["capability"], []).append(decision["verdict"])
    assert by_capability["service.enumerate"][0] == "single"
    assert by_capability["vulnerability.match"][0] == "single"
    # The run stops because no authorised capability is still missing evidence, which is the gate
    # doing its job rather than the step budget running out.
    assert artifacts.stop_reason is not None
    assert "no capability" in artifacts.stop_reason
