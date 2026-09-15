"""Tests for the risk/taint policy engine and approval routing.

Two properties matter more than the individual branch behaviour:

* `decide` is total - hostile or malformed input produces a reasoned denial, never an
  exception, because a gate that crashes is a gate that is not enforcing anything;
* taint can only ever move a verdict towards `ask`. No combination of inputs may turn a
  taint-escalated call back into an allowed one.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from harness.models import Grant, PolicyDecision, ProviderSpec, Tainted
from harness.policy.engine import (
    DEFAULT_MAX_REJECTIONS,
    REASON_CAPABILITY_NOT_GRANTED,
    REASON_CAPABILITY_NOT_SUPPORTED,
    REASON_DRY_RUN,
    REASON_GRANT_EXPIRED,
    REASON_GRANT_UNKNOWN,
    REASON_RISK_HIGH,
    REASON_RISK_LOW,
    REASON_RISK_MEDIUM,
    REASON_RISK_MEDIUM_EGRESS,
    REASON_RUN_STRICT,
    REASON_TAINTED_ARGUMENTS,
    REASON_TAINTED_NOVEL_RESOURCE,
    AutoApproveGate,
    AutoDenyGate,
    PolicyEngine,
    RecordingGate,
    RejectionCounter,
    count_rejection,
    is_side_effectful,
)
from harness.policy.grants import GrantBook
from harness.util import utcnow

SCAN = "service.enumerate"
READ = "fs.read"


def provider(
    *,
    pid: str = "native:nmap",
    capability: str = SCAN,
    risk: str = "LOW",
    egress: bool = True,
    idempotent: bool = True,
    excludes: list[str] | None = None,
) -> ProviderSpec:
    return ProviderSpec(
        id=pid,
        kind="native",
        capabilities=[capability],
        output_media_type="application/nmap+xml",
        parser="nmap_xml",
        risk=risk,  # type: ignore[arg-type]
        trust_class="local_tool",
        requires_network_egress=egress,
        idempotent=idempotent,
        excludes=excludes or [],
    )


def grant(
    *,
    gid: str = "g-scan",
    capabilities: list[str] | None = None,
    ttl_s: int = 3600,
    alias: str = "lab-web-01",
) -> Grant:
    return Grant(
        id=gid,
        resource="net:10.77.0.11",
        alias=alias,
        capabilities=capabilities if capabilities is not None else [SCAN, READ],
        ports=None,
        expires_at=utcnow() + timedelta(seconds=ttl_s),
        origin="scope:lab-test:payload:sha256:x:sig:sha256:y:run:r1",
        kind="net",
    )


def engine(*grants: Grant, dry_run: bool = False, strict: bool = False) -> PolicyEngine:
    return PolicyEngine(GrantBook(list(grants) or [grant()]), dry_run=dry_run, strict=strict)


def decide(policy: PolicyEngine, prov: ProviderSpec | None = None, **kw) -> PolicyDecision:
    params = {
        "provider": prov or provider(),
        "capability": SCAN,
        "grant_id": "g-scan",
        "args": {},
    }
    params.update(kw)
    return policy.decide(**params)  # type: ignore[arg-type]


def test_low_risk_local_read_is_allowed() -> None:
    decision = decide(engine(), provider(pid="native:nmap", risk="LOW", egress=False))
    assert decision.verdict == "allow"
    assert decision.reasons == [REASON_RISK_LOW]
    assert decision.risk_downgraded_by_taint is False
    assert decision.decided_at is not None and decision.decided_at.tzinfo is not None
    assert decision.id.startswith("pd-")
    assert decision.taint_level == "T1"


def test_medium_risk_is_allowed_without_egress_and_asks_with_it() -> None:
    local = decide(engine(), provider(risk="MEDIUM", egress=False))
    assert local.verdict == "allow"
    assert local.reasons == [REASON_RISK_MEDIUM]

    remote = decide(engine(), provider(risk="MEDIUM", egress=True))
    assert remote.verdict == "ask"
    assert REASON_RISK_MEDIUM_EGRESS in remote.reasons


def test_a_strict_run_escalates_medium_risk_even_without_egress() -> None:
    decision = decide(engine(strict=True), provider(risk="MEDIUM", egress=False))
    assert decision.verdict == "ask"
    assert decision.reasons == [REASON_RUN_STRICT]


def test_high_risk_always_asks() -> None:
    for egress in (True, False):
        decision = decide(engine(), provider(risk="HIGH", egress=egress, idempotent=False))
        assert decision.verdict == "ask"
        assert REASON_RISK_HIGH in decision.reasons


def test_a_missing_grant_is_denied_rather_than_raised() -> None:
    decision = decide(engine(), grant_id="g-forged")
    assert decision.verdict == "deny"
    assert decision.reasons == [REASON_GRANT_UNKNOWN]
    assert decision.grant == "g-forged"


def test_a_non_string_grant_id_is_denied_without_stringifying_attack_input() -> None:
    decision = decide(engine(), grant_id={"$ne": None})  # type: ignore[arg-type]
    assert decision.verdict == "deny"
    assert decision.reasons == [REASON_GRANT_UNKNOWN]
    assert decision.grant == ""


def test_an_expired_grant_is_denied() -> None:
    policy = engine(grant(ttl_s=-1))
    decision = decide(policy)
    assert decision.verdict == "deny"
    assert REASON_GRANT_EXPIRED in decision.reasons


def test_a_capability_absent_from_the_grant_is_denied() -> None:
    policy = engine(grant(capabilities=[READ], alias="lab-logs"))
    decision = decide(
        policy, provider(capability=READ, pid="native:logfile", egress=False), capability=READ
    )
    # The grant is valid and the provider supports fs.read, so this must be an allow ...
    assert decision.verdict == "allow"
    # ... while asking the same grant for a network capability is denied.
    forged = decide(policy)
    assert forged.verdict == "deny"
    assert REASON_CAPABILITY_NOT_GRANTED in forged.reasons


def test_a_capability_the_provider_excludes_is_denied() -> None:
    nmap = provider(capability="http.probe", excludes=["http.probe"])
    decision = decide(engine(grant(capabilities=["http.probe"])), nmap, capability="http.probe")
    assert decision.verdict == "deny"
    assert REASON_CAPABILITY_NOT_SUPPORTED in decision.reasons


def test_dry_run_denies_side_effects_and_egress_but_allows_local_reads() -> None:
    policy = engine(dry_run=True)
    remote = decide(policy, provider(risk="LOW", egress=True))
    assert remote.verdict == "deny"
    assert remote.reasons == [REASON_DRY_RUN]

    intrusive = decide(policy, provider(risk="HIGH", egress=False, idempotent=False))
    assert intrusive.verdict == "deny"
    assert intrusive.reasons == [REASON_DRY_RUN]

    # A local read-only call is still "allowed" in a dry run, because the plan is rendered from
    # allowed intentions and nothing is executed either way.
    local = decide(policy, provider(risk="LOW", egress=False))
    assert local.verdict == "allow"


def test_complete_absence_of_authority_wins_over_dry_run() -> None:
    policy = engine(dry_run=True)
    decision = decide(policy, grant_id="")
    # The more actionable reason is recorded: authority is missing, not merely simulated.
    assert decision.verdict == "deny"
    assert decision.reasons == [REASON_GRANT_UNKNOWN]


def test_t3_tainted_arguments_force_ask_on_an_otherwise_low_provider() -> None:
    raw = decide(engine(), provider(risk="LOW", egress=True))
    assert raw.verdict == "allow"

    declared = decide(engine(), provider(risk="LOW", egress=True), taint="T3")
    assert declared.verdict == "ask"
    assert declared.reasons == [REASON_TAINTED_ARGUMENTS]
    assert declared.risk_downgraded_by_taint is True
    assert declared.taint_level == "T3"

    # The same escalation must happen when the taint rides inside the arguments and the caller
    # forgot to say so: args are the attacker-controlled part of a proposal.
    carried = decide(
        engine(),
        provider(risk="LOW", egress=True),
        args={"target": Tainted(value="lab-web-01", level="T3", origin="artifact:sha256:x#0-812")},
    )
    assert carried.verdict == "ask"
    assert REASON_TAINTED_ARGUMENTS in carried.reasons
    assert carried.taint_level == "T3"


def test_t2_tainted_arguments_do_not_force_ask() -> None:
    decision = decide(
        engine(),
        provider(risk="LOW", egress=True),
        args={"note": Tainted(value="lab log line", level="T2", origin="fs:/lab/logs")},
    )
    assert decision.verdict == "allow"
    assert decision.risk_downgraded_by_taint is False


def test_taint_does_not_escalate_a_passive_local_read() -> None:
    # Reading a hostile banner is the harness's job; only acting on it is the risk. A read-only,
    # idempotent, local provider stays allowed even with T3 arguments.
    decision = decide(
        engine(),
        provider(risk="LOW", egress=False, idempotent=True),
        args={"text": Tainted(value="banner", level="T3", origin="artifact:sha256:x#0-812")},
    )
    assert decision.verdict == "allow"


def test_a_proposal_authored_under_taint_that_names_a_new_resource_asks() -> None:
    decision = decide(
        engine(),
        provider(risk="LOW", egress=True),
        proposal_authored_under_taint=True,
        novel_resource=True,
    )
    assert decision.verdict == "ask"
    assert decision.reasons == [REASON_TAINTED_NOVEL_RESOURCE]
    assert decision.risk_downgraded_by_taint is True


def test_novel_resource_alone_does_not_escalate() -> None:
    # Without T3 in context there is nothing to escalate from: a new-but-authorised resource is
    # an ordinary discovery, not an injection attempt.
    decision = decide(engine(), provider(risk="LOW", egress=True), novel_resource=True)
    assert decision.verdict == "allow"
    assert decision.risk_downgraded_by_taint is False


def test_tainted_proposal_without_a_novel_resource_does_not_escalate() -> None:
    decision = decide(
        engine(), provider(risk="LOW", egress=True), proposal_authored_under_taint=True
    )
    assert decision.verdict == "allow"


def test_taint_escalation_never_softens_an_already_high_risk_call() -> None:
    decision = decide(engine(), provider(risk="HIGH", egress=False, idempotent=False), taint="T3")
    assert decision.verdict == "ask"
    assert REASON_TAINTED_ARGUMENTS in decision.reasons
    assert REASON_RISK_HIGH in decision.reasons


@pytest.mark.parametrize(
    "kwargs",
    [
        {"capability": "", "grant_id": ""},
        {"capability": "net.raw", "grant_id": "g-scan"},
        {"args": {"nested": [[[[Tainted(value="x", level="T3", origin="o")]]]]}},
        {"args": {"weird": {"level": "T9"}}},
        {"taint": "T3", "grant_id": "g-scan\x00injected"},
        {"taint": "T9"},
        {"taint": None},
    ],
)
def test_decide_never_raises_on_hostile_input(kwargs: dict) -> None:
    decision = decide(engine(), **kwargs)
    assert decision.verdict in {"allow", "ask", "deny"}
    assert decision.reasons


def test_an_unrecognised_taint_level_fails_closed() -> None:
    # A nonsense label must be read as "trusted"? No - as hostile. This keeps the engine's
    # no-exception promise without inventing a fourth trust state.
    decision = decide(engine(), provider(risk="LOW", egress=True), taint="T9")  # type: ignore[arg-type]
    assert decision.verdict == "ask"
    assert decision.taint_level == "T3"
    assert decision.risk_downgraded_by_taint is True


def test_side_effect_classification_matches_the_provider_spec() -> None:
    assert is_side_effectful(provider(risk="LOW", idempotent=True)) is False
    assert is_side_effectful(provider(risk="LOW", idempotent=False)) is True
    assert is_side_effectful(provider(risk="MEDIUM", idempotent=True)) is True
    assert is_side_effectful(provider(risk="HIGH", idempotent=True)) is True


def test_auto_deny_gate_fails_closed() -> None:
    policy = engine()
    decision = decide(policy, provider(risk="HIGH", egress=False, idempotent=False))
    response = policy.request_approval(decision, AutoDenyGate())
    assert response.approved is False
    assert response.request_id and response.answered_at.tzinfo is not None
    assert policy.rejections.rejections(decision.provider) == 1


def test_auto_approve_gate_approves_and_reports_the_request_verbatim() -> None:
    policy = engine()
    decision = decide(policy, provider(risk="HIGH", egress=False, idempotent=False))
    gate = RecordingGate([True])
    response = policy.request_approval(decision, gate, argv_preview=["nmap", "-sV", "10.77.0.11"])
    assert response.approved is True
    assert len(gate.requests) == 1
    request = gate.requests[0]
    assert request.policy_decision == decision.id
    assert request.provider == decision.provider
    assert request.capability == decision.capability
    assert request.grant == decision.grant
    assert request.argv_preview == ["nmap", "-sV", "10.77.0.11"]
    assert request.requested_at.tzinfo is not None
    assert policy.rejections.rejections(decision.provider) == 0


def test_recording_gate_consumes_answers_in_order_then_denies() -> None:
    gate = RecordingGate([True, False])
    policy = engine()
    decision = decide(policy, provider(risk="HIGH", egress=False, idempotent=False))
    assert policy.request_approval(decision, gate).approved is True
    assert policy.request_approval(decision, gate).approved is False
    assert gate.remaining == 0
    # Exhausted scripted answers must not approve: a test double that defaults to "yes" would
    # make every approval-routing assertion pass for the wrong reason.
    exhausted = policy.request_approval(decision, gate)
    assert exhausted.approved is False
    assert "exhausted" in exhausted.answer


def test_auto_approve_gate_approves_unconditionally() -> None:
    decision = decide(engine(), provider(risk="HIGH", egress=False, idempotent=False))
    assert engine().request_approval(decision, AutoApproveGate()).approved is True


def test_three_rejections_of_the_same_provider_stop_the_run() -> None:
    policy = engine()
    decision = decide(policy, provider(risk="HIGH", egress=False, idempotent=False))
    gate = RecordingGate([False, False, False, True])
    for _ in range(DEFAULT_MAX_REJECTIONS):
        policy.request_approval(decision, gate)
    assert policy.rejections.at_limit(decision.provider) is True
    assert policy.rejections.stop_reason(decision.provider) == "rejected by user 3 times"
    # A subsequent approval does not erase the count: the pattern worth stopping is repeated
    # interruption, not disagreement with one invocation.
    policy.request_approval(decision, gate)
    assert policy.rejections.rejections(decision.provider) == 3
    assert policy.rejections.snapshot() == {decision.provider: 3}


def test_rejections_are_counted_per_provider() -> None:
    counter = RejectionCounter()
    for _ in range(2):
        counter.record_rejection("native:nmap")
    counter.record_rejection("mcp:scanner-a")
    assert counter.rejections("native:nmap") == 2
    assert counter.at_limit("native:nmap") is False
    assert counter.rejections("mcp:scanner-a") == 1
    assert count_rejection(counter, "native:nmap") is True
    assert counter.stop_reason("mcp:scanner-a") is None
    counter.reset("native:nmap")
    assert counter.rejections("native:nmap") == 0


def test_rejection_counter_requires_a_sane_limit() -> None:
    with pytest.raises(ValueError):
        RejectionCounter(limit=0)
