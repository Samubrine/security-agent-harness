"""Phase 3 end-to-end checks for the v1.1 gap closures.

These are the seam tests. Each subsystem's own suite proves its module is internally correct; this
file proves the *call sites* the orchestrator added actually exist, agree on conventions, and move
the property the audit said was missing.

Two of these go through the real `execute_run`, because the audit finding they close was never
about a module being wrong - it was about nothing being wired up:

* `test_every_execution_resolves_to_a_persisted_policy_decision` closes audit invariant 6. Before
  v1.1 an execution's `policy_decision` field was required and unresolvable: policy decisions were
  never persisted, so only the id survived, inside a provenance triple.
* `test_every_provider_is_assessed_for_egress_before_the_loop_starts` closes invariant 12: the
  provider-side egress gate now keys off the transport rather than the provider's own claim.

One goes through a hand-assembled `InvestigationLoop`, because the re-planning path needs an
unresolved conflict to exist and - see
`test_with_the_shipped_planner_no_conflict_is_reachable` - the shipped planner cannot produce one.
That test documents the limit rather than hiding it: the wiring is real and tested, and the
scenario suite does not exercise it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from harness.analysers.correlate import Correlator
from harness.models import Observation, ProviderSpec
from harness.runtime.runner import execute_run

pytestmark = pytest.mark.integration


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _service(observation_id: str, run_id: str, provider: str, version: str) -> Observation:
    """A service observation for the same subject from a named provider.

    Same `(target, port, protocol)` key and a different `version`, which is exactly the shape the
    correlator calls a conflict: two sources disagreeing about a field they both filled.
    """
    return Observation(
        id=observation_id,
        run_id=run_id,
        kind="service",
        value={
            "target": "10.77.0.11",
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": version,
            "cpe": f"cpe:/a:nginx:nginx:{version}",
        },
        parser="nmap_xml",
        parser_version="0.1.0",
        provider=provider,
        execution_id=f"x-{provider}",
    )


def _real_conflict(run_id: str) -> tuple[object, list[Observation]]:
    """Build a conflict correlation with the real correlator, not a hand-made record.

    Using the real correlator matters: it is the component that decides whether two observations
    agree, complement or conflict, and a test that fabricated the `Correlation` would agree with
    itself about a judgement it never exercised.
    """
    correlator = Correlator(run_id)
    observations = [
        _service("o-aaaa0001", run_id, "native:synthetic", "1.18.0"),
        _service("o-aaaa0002", run_id, "native:rival", "1.19.0"),
    ]
    fresh = correlator.add(observations)
    conflicts = [c for c in fresh if c.relation == "conflict"]
    assert conflicts, [c.relation for c in fresh]
    return conflicts[0], observations


@dataclass
class RivalProvider:
    """A second source for `service.enumerate`, so the gate has two candidates to expand across.

    A conflict can only be resolved by a second provider, and the necessity gate refuses to expand
    when only one is registered - it returns `deny` with "a second provider is warranted but the
    skill or budget allows one provider per need". This double exists to make the two-candidate
    case reachable. It is never invoked: these tests assert the decision rather than the execution.
    """

    provider_id: str = "native:rival"

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
            # Deliberately more expensive than the synthetic provider, so it is the second-ranked
            # candidate and the expansion has to reach past the cheapest one.
            estimated_cost={"latency_ms": 50},
        )

    def invoke(self, request: object):  # pragma: no cover - the test asserts the decision only
        """Fail the way a real adapter fails: a typed result plus a gap, never an exception.

        A provider failure is a fact the report must carry, and the loop treats it as one. Raising
        here would test the test rather than the wiring, and would abort the run mid-expansion.
        """
        from harness.providers.base import failed_result

        return failed_result(
            request=request,
            provider=self.provider_id,
            error="the rival double declines to produce a second opinion",
            impact="the conflict stays unresolved and is reported as a gap",
        )


def _build_loop(env, tmp_path: Path, *, run_id: str):
    """Assemble the spine the way `execute_run` does, so the loop under test is the real one.

    Duplicating the wiring here rather than calling a private runner helper is deliberate: this test
    is about the loop's own call sites, and reaching through a private constructor would make the
    test pass if the runner stopped wiring something.
    """
    from harness.analysers.cve_match import VulnerabilitySnapshot
    from harness.artifacts import ArtifactStore, ProvenanceLog
    from harness.context.builder import ContextBuilder
    from harness.context.resolver import ContextResolver
    from harness.events import EventLog
    from harness.llm.client import build_client
    from harness.memory.index import LongTermIndex
    from harness.memory.manager import MemoryManager
    from harness.models import Budget, RunConfig
    from harness.parsers.registry import ParserRegistry
    from harness.policy.engine import AutoDenyGate, PolicyEngine
    from harness.policy.taint import TaintTracker
    from harness.providers.necessity import NecessityGate
    from harness.providers.native.synthetic import SyntheticProvider
    from harness.providers.registry import ProviderRegistry
    from harness.providers.router import Router
    from harness.runtime.capabilities import with_logical_capabilities
    from harness.runtime.loop import InvestigationLoop
    from harness.runtime.replay import ReplayWriter
    from harness.tokens import BudgetGuard, TokenLedger
    from harness.util import sha256_json, utcnow

    run_dir = tmp_path / "loop-run"
    run_dir.mkdir(parents=True, exist_ok=True)

    memory = MemoryManager(env.root)
    index = LongTermIndex(env.root / "memory" / "long_term" / "index.sqlite")
    resolved = ContextResolver(root=env.root, memory=memory, index=index).resolve(
        objective="Enumerate exposed services on lab-web-01.",
        skill_name="port_scan",
        scope_path=env.scope_path,
        public_key_path=env.public_key,
        run_id=run_id,
    )
    resolved.grants = with_logical_capabilities(resolved.grants)

    model = build_client(backend="scripted", model_id="scripted-planner")
    registry = ProviderRegistry([SyntheticProvider(fixture_root=env.fixtures), RivalProvider()])
    snapshot = VulnerabilitySnapshot.load(env.fixtures / "vuln" / "snapshot_2026-09.json")
    budgets = Budget()
    config = RunConfig(
        run_id=run_id,
        objective="Enumerate exposed services on lab-web-01.",
        skill="port_scan",
        scope_id=resolved.scope.scope_id,
        scope_sha256=sha256_json(resolved.scope.model_dump(mode="json")),
        model=model.metadata,
        budgets=budgets,
        memory=resolved.memory,
        harness_version="test",
        created_at=utcnow(),
    )
    parsers = ParserRegistry()
    from harness.runtime.runner import _register_parsers

    # The real parser set, so a provider that does run produces real observations rather than a
    # missing-parser gap. Reaching for the runner's private helper is deliberate: registering a
    # second, slightly different parser set here is how a test stops resembling production.
    _register_parsers(parsers)
    loop = InvestigationLoop(
        config=config,
        context=resolved,
        model=model,
        registry=registry,
        gate=NecessityGate(registry, budgets, skill=resolved.skill),
        policy=PolicyEngine(resolved.grants),
        approvals=AutoDenyGate(),
        store=ArtifactStore(run_dir, run_id, max_bytes=budgets.max_artifact_bytes),
        events=EventLog(run_dir / "events.jsonl", run_id),
        provenance=ProvenanceLog(run_dir / "provenance.jsonl"),
        ledger=TokenLedger(run_dir / "trace.jsonl", model.metadata),
        budgets=BudgetGuard(budgets),
        parsers=parsers,
        replay=ReplayWriter(run_dir / "replay.json"),
        rules=None,
        snapshot=snapshot,
        correlator=Correlator(run_id),
        builder=ContextBuilder(),
        taint=TaintTracker(),
        router=Router(registry),
    )
    return loop


def _advance_to_planning(loop) -> None:
    """Walk the FSM to PLANNING, which is where a real cycle starts.

    Following the legal transitions rather than assigning `state.state` keeps the FSM's own
    legality check in the loop: if the re-planning hook were reachable from a state the machine
    does not actually permit, this test would fail on the transition rather than on an assertion.
    """
    from harness.runtime.fsm import State

    loop._goto(State.CONTEXT_RESOLVED)
    loop._goto(State.PLANNING)


# ----------------------------------------------------------------------------------------------
# Invariant 6, end to end: every cited policy decision resolves
# ----------------------------------------------------------------------------------------------


def test_every_execution_resolves_to_a_persisted_policy_decision(lab_environment) -> None:
    """The audit's invariant 6, checked against a run the real spine produced."""
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-policy-refs",
        )
    )
    run_dir = artifacts.run_dir
    executions = json.loads((run_dir / "executions.json").read_text(encoding="utf-8"))
    assert executions, "the run produced no executions, so this test proves nothing"

    persisted = {row["id"] for row in _jsonl(run_dir / "policy-decisions.jsonl")}
    assert persisted, "policy-decisions.jsonl is the file that makes the reference resolvable"
    for execution in executions:
        assert execution["policy_decision"] in persisted, execution["policy_decision"]
        assert execution["necessity_decision"] in {
            row["id"] for row in _jsonl(run_dir / "provider-decisions.jsonl")
        }

    # And the events ledger can be joined the same way, so a reader of events.jsonl alone can
    # reach the governing policy record rather than stopping at a verdict string.
    decided = [e for e in _jsonl(run_dir / "events.jsonl") if e["type"] == "POLICY_DECIDED"]
    assert decided
    assert all(e["data"].get("policy_decision_id") in persisted for e in decided)


def test_a_fabricated_grant_is_caught_on_a_real_run(lab_environment) -> None:
    """The grant reference, end to end. Grant ids are randomly minted, so the run must record
    them: re-minting from the scope record on a later day yields different ids and every
    execution would look unknown."""
    from harness.runtime.verify import audit_run_dir

    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-grants",
        )
    )
    run_dir = artifacts.run_dir
    clean = audit_run_dir(run_dir)
    assert clean.ok, [f"{i.code}: {i.detail}" for i in clean.issues]
    assert clean.checked["grants"] > 0, "a v1.1 run records the grants it minted"

    executions_path = run_dir / "executions.json"
    rows = json.loads(executions_path.read_text(encoding="utf-8"))
    rows[0]["grant"] = "g-fabricated"
    executions_path.write_text(json.dumps(rows), encoding="utf-8")

    tampered = audit_run_dir(run_dir)
    assert not tampered.ok
    assert "execution_grant_unknown" in tampered.codes()


def test_a_v1_run_says_grants_could_not_be_checked(lab_environment) -> None:
    """A committed v1 run has no grants.json. The audit must say so rather than report a clean
    grant check over zero grants, which would be a stronger claim than it can support."""
    from harness.runtime.verify import audit_run_dir

    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-grants-absent",
        )
    )
    (artifacts.run_dir / "grants.json").unlink()
    audit = audit_run_dir(artifacts.run_dir)
    assert "grants_record_absent" in audit.codes()
    assert audit.checked["grants"] == 0
    # A warning, not an error: a v1 directory is still auditable, just less completely.
    assert audit.ok


def test_the_verifier_accepts_a_run_the_spine_produced(lab_environment) -> None:
    """The producer and the checker agree - the seam that a green unit suite cannot show."""
    from harness.runtime.verify import audit_run_dir

    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-audit-clean",
        )
    )
    audit = audit_run_dir(artifacts.run_dir)
    assert audit.ok, [f"{i.code}: {i.detail}" for i in audit.issues]
    # A v1.1 run persists policy decisions, so the verifier must not fall back to the weaker
    # provenance-derived check and must not emit its warning.
    assert "policy_decision_record_absent" not in audit.codes()


# ----------------------------------------------------------------------------------------------
# Invariant 12, end to end: the egress gate runs before the loop
# ----------------------------------------------------------------------------------------------


def test_every_provider_is_assessed_for_egress_before_the_loop_starts(lab_environment) -> None:
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-egress",
        )
    )
    assessments = json.loads((artifacts.run_dir / "egress.json").read_text(encoding="utf-8"))
    registered = {row["provider"] for row in _jsonl(artifacts.run_dir / "telemetry.jsonl")}
    assert assessments, "egress.json must record a verdict per provider"
    for assessment in assessments:
        assert assessment["permitted"] is True
        # Every shipped provider is a local process, so nothing may be flagged as a transport lie.
        assert assessment["declaration_mismatch"] is False, assessment
        assert assessment["endpoint_class"] == "loopback"
    assert registered <= {a["provider"] for a in assessments}

    # The assessment is on the event trail too, because a reader reconstructing the run from
    # events.jsonl should not have to know that a second file exists.
    events = [e for e in _jsonl(artifacts.run_dir / "events.jsonl") if e["type"] == "EGRESS_ASSESSED"]
    assert len(events) == len(assessments)


def test_a_remote_provider_is_refused_unless_egress_is_enabled(lab_environment) -> None:
    """The original audit bug, end to end: a provider must not be able to declare itself local.

    The provider below claims `requires_network_egress=False` while pointing at a public endpoint.
    Under the v1 design that claim was consulted and believed; here the endpoint decides.
    """
    from dataclasses import dataclass

    from harness.models import ProviderSpec
    from harness.providers.base import ProviderResult

    @dataclass
    class SelfDeclaredLocalProvider:
        provider_id: str = "native:self-declared-local"

        @property
        def spec(self) -> ProviderSpec:
            return ProviderSpec(
                id=self.provider_id,
                kind="mcp",
                capabilities=["service.enumerate"],
                output_media_type="application/nmap+xml",
                parser="nmap_xml",
                risk="LOW",
                trust_class="local_mcp",
                # The lie. The transport and endpoint say otherwise.
                requires_network_egress=False,
                transport="remote_service",
                endpoint="https://mcp.example.com/sse",
                timeout_s=5,
                estimated_cost={"latency_ms": 1},
            )

        def invoke(self, request) -> ProviderResult:  # pragma: no cover - never reached
            raise AssertionError("a refused provider must not be invoked")

    with pytest.raises(Exception) as caught:
        execute_run(
            lab_environment.request(
                objective="Enumerate exposed services on lab-web-01.",
                skill="port_scan",
                target_alias="lab-web-01",
                run_id="run-v11-egress-refused",
                extra_providers=(SelfDeclaredLocalProvider(),),
            )
        )
    assert type(caught.value).__name__ == "EgressViolation", caught.value
    assert "mcp.example.com" in str(caught.value)


# ----------------------------------------------------------------------------------------------
# Conflict-driven re-planning: the wiring
# ----------------------------------------------------------------------------------------------


def test_a_conflict_schedules_its_own_resolving_call(lab_environment, tmp_path) -> None:
    """A detected conflict produces a real expand/conflict_resolution decision, unasked.

    This is the audit's criterion 6 partial: conflicts were detected, stored and rendered, and
    nothing acted on them.
    """
    run_id = "run-v11-conflict"
    loop = _build_loop(lab_environment, tmp_path, run_id=run_id)
    conflict, observations = _real_conflict(run_id)
    # Seed the observations the conflict is about, not just the correlation. The re-planner maps a
    # conflicting observation kind to the capability that can serve it, so a conflict whose
    # observations are absent from state is a conflict nothing can act on - which is itself
    # asserted in test_a_correlation_citing_absent_observations_is_ignored.
    for observation in observations:
        loop.state.observations[observation.id] = observation
    loop.state.correlations.append(conflict)

    catalogue = loop.build_catalogue()
    assert "service.enumerate" in {e["capability"] for e in catalogue["capabilities"]}

    need = loop._scheduled_follow_up(catalogue)
    assert need is not None, "a conflict about a capability in the catalogue must schedule a call"
    assert need.reason == "conflict_resolution"
    assert need.correlation_id == conflict.id

    before = len(loop.state.decisions)
    _advance_to_planning(loop)
    loop._pursue_follow_up(need, catalogue)

    decisions = loop.state.decisions[before:]
    assert decisions, "the scheduled call must go through the necessity gate"
    expansion = [d for d in decisions if d.expansion_reason == "conflict_resolution"]
    assert expansion, [(d.verdict, d.expansion_reason) for d in decisions]
    # Two providers, because resolving a disagreement with one source is not a resolution.
    assert len(expansion[0].selected) >= 2
    assert loop.state.follow_ups == [need]

    scheduled = [e for e in loop.events.records() if e.type == "FOLLOW_UP_SCHEDULED"]
    assert len(scheduled) == 1
    assert scheduled[0].data["capability"] == "service.enumerate"


def test_a_conflict_about_an_unauthorised_capability_schedules_nothing(
    lab_environment, tmp_path
) -> None:
    """The catalogue filter is the structural guarantee, so it must be tested as one.

    A conflict about a capability no grant can serve must not produce a call. The filter is applied
    against the catalogue rather than against the gate, so an unservable conflict is dropped before
    it can become a proposal at all.
    """
    run_id = "run-v11-conflict-unauthorised"
    loop = _build_loop(lab_environment, tmp_path, run_id=run_id)
    conflict, observations = _real_conflict(run_id)
    for observation in observations:
        loop.state.observations[observation.id] = observation
    loop.state.correlations.append(conflict)

    # A catalogue that offers nothing for the conflicting kind.
    assert loop._scheduled_follow_up({"capabilities": []}) is None
    assert loop._scheduled_follow_up({"capabilities": [{"capability": "vulnerability.match"}]}) is None


def test_the_same_conflict_does_not_schedule_twice(lab_environment, tmp_path) -> None:
    """Without this the loop would re-detect the same conflict on every pass and never converge."""
    run_id = "run-v11-conflict-once"
    loop = _build_loop(lab_environment, tmp_path, run_id=run_id)
    conflict, observations = _real_conflict(run_id)
    for observation in observations:
        loop.state.observations[observation.id] = observation
    loop.state.correlations.append(conflict)
    catalogue = loop.build_catalogue()

    first = loop._scheduled_follow_up(catalogue)
    assert first is not None
    _advance_to_planning(loop)
    loop._pursue_follow_up(first, catalogue)

    assert loop._scheduled_follow_up(catalogue) is None
    assert len(loop.state.follow_ups) == 1


def test_with_the_shipped_planner_no_conflict_is_reachable(lab_environment) -> None:
    """Documents the limit of the re-planning path rather than letting a reader assume it runs.

    A conflict needs two providers to observe the same subject. Reaching a two-provider selection
    needs `coverage_gap` or `trust_diversity`, and the scripted planner re-requests a capability
    only after a *failed* attempt - a successful one is recorded as completed and skipped. So with
    the shipped skill, providers and planner, no conflict is ever produced, and the re-planning
    path is exercised by tests rather than by a scenario run.

    If this assertion ever starts failing, the re-planning path has become reachable and the
    scenario suite should be extended to cover it end to end.
    """
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-v11-no-conflict",
        )
    )
    assert _jsonl(artifacts.run_dir / "correlations.jsonl") == []
    assert _jsonl(artifacts.run_dir / "follow-ups.jsonl") == []
