"""The policy engine: risk classes, taint escalation, dry run, and approval routing.

Risk answers a different question from scope. Scope answers "may I touch this at all"; risk
answers "should a human be interrupted first". This module is where the second question is
decided, per concrete provider invocation, and it is deliberately total:

* `PolicyEngine.decide` never raises. A missing, expired, or insufficient grant becomes a
  `deny` verdict with reasons, because a crash in the gate would be an outage in the
  safety control, and an outage is not a safe failure mode - a reasoned denial is.
* `dry_run` never returns `allow` for a call that could change state or leave the
  machine. It returns `deny` with a `dry_run` reason so the plan is still rendered
  and the operator sees the same intentions the real run would have executed.
* Taint escalation (see `harness.policy.taint`) can only ever move a verdict towards
  `ask`. No input to this class can move a verdict from `ask` to `allow`.

Approval routing lives here too, because "ask" is only meaningful with a place to ask. The default
gate is non-interactive and denies; a run with no human attached must fail closed. Three rejections
of the same provider is the run-ending signal, and `RejectionCounter` is the counting helper
the runtime needs to notice it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from harness.errors import GrantError
from harness.models import (
    ApprovalRequest,
    ApprovalResponse,
    PolicyDecision,
    ProviderSpec,
    TaintLevel,
)
from harness.policy.grants import GrantBook

# Imported from the sibling taint module so that the engine's reading of "this argument is
# tainted" is the same reading the parsers register against; two implementations would be two
# definitions of the trust boundary.
from harness.policy.taint import arg_taint_level, coerce_level, higher, level_rank
from harness.util import new_id, utcnow

# Reason codes are part of the record, so they are named constants rather than inline strings:
# evaluation and replay assert on them, and a typo in a reason string would silently change what a
# report claims happened.
REASON_GRANT_UNKNOWN = "grant_unknown"
REASON_GRANT_EXPIRED = "grant_expired"
REASON_CAPABILITY_NOT_GRANTED = "capability_not_granted"
REASON_CAPABILITY_NOT_SUPPORTED = "capability_not_supported"
REASON_RISK_LOW = "risk_low"
REASON_RISK_MEDIUM = "risk_medium"
REASON_RISK_MEDIUM_EGRESS = "risk_medium_requires_egress"
REASON_RISK_HIGH = "risk_high"
REASON_RUN_STRICT = "run_strict"
REASON_DRY_RUN = "dry_run"
REASON_TAINTED_ARGUMENTS = "tainted_arguments_t3"
REASON_TAINTED_NOVEL_RESOURCE = "proposal_authored_under_taint_new_resource"

#: How many rejections of one provider a human has to give before the run should stop asking.
DEFAULT_MAX_REJECTIONS = 3


def is_side_effectful(provider: ProviderSpec) -> bool:
    """Whether a call can change state on the target.

    Read from the provider spec rather than from model prose: MEDIUM/HIGH are defined by the design
    as "touches the target meaningfully" / "intrusive", and a provider that declares itself
    non-idempotent is by definition capable of changing something.
    """
    return provider.risk != "LOW" or not provider.idempotent


class PolicyEngine:
    """Decides allow / ask / deny for one concrete provider invocation."""

    def __init__(self, grants: GrantBook, *, dry_run: bool = False, strict: bool = False) -> None:
        self._grants = grants
        self._dry_run = dry_run
        # "strict" is the explicit strictness the design mentions for MEDIUM risk. It is a
        # per-engine flag, not a per-request one, so a run cannot relax it mid-investigation.
        self._strict = strict
        self.rejections = RejectionCounter()
        #: Every verdict this engine produced, in order. Recorded here because the audit found
        #: that an execution's `policy_decision` id was a required field that nothing could
        #: resolve: policy decisions were never persisted, so only the id survived, inside a
        #: provenance triple. Without a record to check against, "the field is required" was the
        #: whole guarantee.
        self._decisions: list[PolicyDecision] = []

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def strict(self) -> bool:
        return self._strict

    def decide(
        self,
        *,
        provider: ProviderSpec,
        capability: str,
        grant_id: str,
        args: dict[str, Any],
        taint: TaintLevel = "T1",
        proposal_authored_under_taint: bool = False,
        novel_resource: bool = False,
    ) -> PolicyDecision:
        """Decide, and keep the verdict.

        Recording happens at this single public boundary rather than at each return site inside
        `_decide`, so a future early return cannot escape the record. The denied verdicts matter
        most: they produce no provider execution, so the decision record is the only place a
        reader can learn why an action did not happen.
        """
        decision = self._decide(
            provider=provider,
            capability=capability,
            grant_id=grant_id,
            args=args,
            taint=taint,
            proposal_authored_under_taint=proposal_authored_under_taint,
            novel_resource=novel_resource,
        )
        self._decisions.append(decision)
        return decision

    def decisions(self) -> list[PolicyDecision]:
        """The verdicts this engine produced, oldest first."""
        return list(self._decisions)

    def _decide(
        self,
        *,
        provider: ProviderSpec,
        capability: str,
        grant_id: str,
        args: dict[str, Any],
        taint: TaintLevel = "T1",
        proposal_authored_under_taint: bool = False,
        novel_resource: bool = False,
    ) -> PolicyDecision:
        """Return a verdict for this invocation. Never raises; failures become `deny`.

        Order matters. Authority is checked before anything else, because "you may not" is a better
        explanation than "this was dry-run". Dry run is checked before risk, because in a dry run
        nothing executes regardless of how intrusive the call would have been. Taint is checked
        before the risk table, because the whole point of taint escalation is to override a risk
        class that would otherwise have allowed the call.
        """
        now = utcnow()
        reasons: list[str] = []
        risk_downgraded_by_taint = False

        # The caller's declared taint and the taint actually carried by the arguments are both
        # considered. Taking the maximum means a forgotten keyword cannot silently de-escalate a
        # call whose arguments came out of a hostile banner.
        effective_taint = higher(coerce_level(taint), arg_taint_level(args))

        side_effectful = is_side_effectful(provider)
        acts_on_target = side_effectful or provider.requires_network_egress

        grant = None
        try:
            grant = self._grants.get(grant_id)
        except GrantError:
            reasons.append(REASON_GRANT_UNKNOWN)
        if grant is not None:
            if now > grant.expires_at:
                reasons.append(REASON_GRANT_EXPIRED)
            if capability not in grant.capabilities:
                reasons.append(REASON_CAPABILITY_NOT_GRANTED)
        if not provider.supports(capability):
            reasons.append(REASON_CAPABILITY_NOT_SUPPORTED)

        if reasons:
            verdict = "deny"
        elif self._dry_run and acts_on_target:
            verdict = "deny"
            reasons.append(REASON_DRY_RUN)
        elif acts_on_target and level_rank(effective_taint) >= level_rank("T3"):
            verdict = "ask"
            reasons.append(REASON_TAINTED_ARGUMENTS)
            risk_downgraded_by_taint = True
            if provider.risk == "HIGH":
                reasons.append(REASON_RISK_HIGH)
        elif acts_on_target and proposal_authored_under_taint and novel_resource:
            verdict = "ask"
            reasons.append(REASON_TAINTED_NOVEL_RESOURCE)
            risk_downgraded_by_taint = True
            if provider.risk == "HIGH":
                reasons.append(REASON_RISK_HIGH)
        elif provider.risk == "HIGH":
            verdict = "ask"
            reasons.append(REASON_RISK_HIGH)
        elif provider.risk == "MEDIUM":
            if provider.requires_network_egress:
                verdict = "ask"
                reasons.append(REASON_RISK_MEDIUM_EGRESS)
            elif self._strict:
                verdict = "ask"
                reasons.append(REASON_RUN_STRICT)
            else:
                verdict = "allow"
                reasons.append(REASON_RISK_MEDIUM)
        else:
            verdict = "allow"
            reasons.append(REASON_RISK_LOW)

        return PolicyDecision(
            id=new_id("pd"),
            execution_id=None,
            provider=provider.id,
            capability=capability,
            # A non-string grant id is a malformed proposal; recording it as empty keeps the
            # decision record honest instead of stringifying attacker input into a grant field.
            grant=grant_id if isinstance(grant_id, str) else "",
            verdict=verdict,
            reasons=reasons,
            risk=provider.risk,
            risk_downgraded_by_taint=risk_downgraded_by_taint,
            taint_level=effective_taint,
            decided_at=now,
        )

    def request_approval(
        self,
        decision: PolicyDecision,
        gate: ApprovalGate,
        *,
        question: str | None = None,
        argv_preview: Sequence[str] = (),
    ) -> ApprovalResponse:
        """Route an `ask` verdict through a gate and count the answer.

        A denial is recorded against the provider so the caller can stop a run where a human has
        said "stop" three times; an approval does not erase that count, because the pattern worth
        stopping is repeated interruption, not a disagreement with one invocation.
        """
        request = ApprovalRequest(
            id=new_id("ap"),
            policy_decision=decision.id,
            question=question
            or f"Approve {decision.capability} via {decision.provider} under grant {decision.grant}?",
            provider=decision.provider,
            capability=decision.capability,
            grant=decision.grant,
            argv_preview=[str(arg) for arg in argv_preview],
            requested_at=utcnow(),
        )
        response = gate.request(request)
        if response.approved:
            self.rejections.record_approval(decision.provider)
        else:
            self.rejections.record_rejection(decision.provider)
        return response


class ApprovalGate(Protocol):
    """How an `ask` verdict reaches a decision. Implementations must not raise."""

    def request(self, req: ApprovalRequest) -> ApprovalResponse: ...


class AutoDenyGate:
    """Non-interactive default: no human, no approval.

    The safe default for unattended runs and for any code path that has not explicitly opted into
    a human-in-the-loop gate.
    """

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request_id=req.id,
            approved=False,
            answered_at=utcnow(),
            answer="denied: no interactive approver is attached",
            answered_by="auto-deny",
        )


class AutoApproveGate:
    """Blanket approval, for `--yes` and for rendering a dry-run plan."""

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request_id=req.id,
            approved=True,
            answered_at=utcnow(),
            answer="approved: automatic approver",
            answered_by="auto-approve",
        )


class RecordingGate:
    """A gate driven by a fixed list of answers, for deterministic tests and replays.

    Once the answers run out the gate **denies**. A test double that ran out of answers and
    approved by default would make every approval-routing test pass for the wrong reason.
    """

    def __init__(self, answers: list[bool]) -> None:
        self._answers = list(answers)
        self.requests: list[ApprovalRequest] = []

    @property
    def remaining(self) -> int:
        return len(self._answers)

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        self.requests.append(req)
        if not self._answers:
            return ApprovalResponse(
                request_id=req.id,
                approved=False,
                answered_at=utcnow(),
                answer="denied: scripted answers exhausted",
                answered_by="recording-gate",
            )
        approved = bool(self._answers.pop(0))
        return ApprovalResponse(
            request_id=req.id,
            approved=approved,
            answered_at=utcnow(),
            answer="approved" if approved else "rejected",
            answered_by="recording-gate",
        )


class RejectionCounter:
    """Counts per-provider approval rejections so the run can stop being told "no"."""

    def __init__(self, limit: int = DEFAULT_MAX_REJECTIONS) -> None:
        if limit < 1:
            raise ValueError("rejection limit must be at least 1")
        self._limit = limit
        self._rejections: dict[str, int] = {}

    @property
    def limit(self) -> int:
        return self._limit

    def record_rejection(self, provider: str) -> int:
        """Count one rejection and return the provider's new total."""
        count = self._rejections.get(provider, 0) + 1
        self._rejections[provider] = count
        return count

    def record_approval(self, provider: str) -> None:
        """Note an approval. Deliberately does not reset the count (see the class docstring)."""
        return None

    def rejections(self, provider: str) -> int:
        return self._rejections.get(provider, 0)

    def at_limit(self, provider: str) -> bool:
        return self._rejections.get(provider, 0) >= self._limit

    def stop_reason(self, provider: str) -> str | None:
        """A stop reason for the FSM, or `None` while the provider may still be asked."""
        if self.at_limit(provider):
            return f"rejected by user {self._rejections[provider]} times"
        return None

    def reset(self, provider: str) -> None:
        """Forget a provider's rejections. Only a deliberate operator action should call this."""
        self._rejections.pop(provider, None)

    def snapshot(self) -> dict[str, int]:
        return dict(sorted(self._rejections.items()))


def count_rejection(counter: RejectionCounter, provider: str) -> bool:
    """Record a rejection and report whether the provider has now hit the limit.

    Kept as a function because the runtime's approval path reads better as "record this, should we
    stop?" than as three lines of counter bookkeeping.
    """
    counter.record_rejection(provider)
    return counter.at_limit(provider)
