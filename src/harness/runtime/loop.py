"""The investigation loop.

One pass through the design's appendix: resolve context, ask the local model for one typed
capability need, validate it, decide whether it is necessary, gate it through policy, execute it,
parse it, correlate it, derive findings, and repeat until the model stops or a budget does.

The loop is deliberately boring. Every interesting decision lives in a small, separately tested
component; this file wires them together and records what happened. If something here looks like
judgement rather than sequencing, it is in the wrong file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from harness.analysers.cve_match import CveCandidate, VulnerabilitySnapshot
from harness.context.cost import attribute_prompt_cost, memory_retrieval_cost
from harness.errors import (
    ApprovalRejected,
    BudgetExhausted,
    GrantError,
    HarnessError,
    ModelClientError,
    ParserError,
    ProposalValidationError,
    ProviderError,
)
from harness.findings.builder import build_findings
from harness.findings.validate import validate_all
from harness.llm.prompts import parse_agent_turn
from harness.models import (
    ApprovalRequest,
    CapabilityProposal,
    EvidenceGap,
    FollowUpNeed,
    Observation,
    ProviderCallTelemetry,
    ProviderDecision,
    ProviderExecution,
    RunConfig,
    RunStatus,
    RunSummary,
)
from harness.providers.base import ProviderRequest, ProviderResult
from harness.providers.necessity import CAPABILITY_OUTPUT_KINDS, cache_key
from harness.policy.ports import render_window
from harness.runtime.replan import follow_up_needs
from harness.runtime.fsm import RunState, State
from harness.util import canonical_json, iso, new_id, utcnow

#: Human-facing description and default arguments per capability. The *machine* definition of what
#: a capability produces lives in ``harness.providers.necessity.CAPABILITY_OUTPUT_KINDS`` and is
#: read from there, so the catalogue the model sees and the gate that judges it cannot disagree
#: about what "this need is already met" means.
CATALOGUE_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "service.enumerate": {
        "expects": "service, product, version and CPE observations for each open port",
        "args": {"profile": "service_detection"},
    },
    "vulnerability.match": {
        "expects": "candidate CVE observations derived from observed versions",
        "args": {},
    },
    "log.read": {
        "expects": "parsed authentication and HTTP events with a bounded rollup",
        "args": {"path": "auth.log"},
    },
    "http.probe": {
        "expects": "HTTP response headers and title observations",
        "args": {},
    },
}

#: Default log files offered when a filesystem grant is available. Two entries is what makes the
#: planner read both corpora: after the first read the HTTP kinds are still missing.
LOG_FILES = ("auth.log", "nginx_access.log")


@dataclass
class LoopOutcome:
    state: RunState
    summary: RunSummary


@dataclass
class _ParsedSummary:
    """What one parse contributed, measured against what the run already knew.

    Novelty is what makes a second provider's contribution distinguishable from a repeat of the
    first one's, and it is one of the signals the v2 Token Optimizer is meant to be trained on.
    """

    new_keys: list[str] = field(default_factory=list)
    duplicate_keys: list[str] = field(default_factory=list)
    duplicate_observations: int = 0
    observations: int = 0


class InvestigationLoop:
    def __init__(
        self,
        *,
        config: RunConfig,
        context: Any,
        model: Any,
        registry: Any,
        gate: Any,
        policy: Any,
        approvals: Any,
        store: Any,
        events: Any,
        provenance: Any,
        ledger: Any,
        budgets: Any,
        parsers: Any,
        replay: Any,
        rules: Any,
        snapshot: VulnerabilitySnapshot,
        correlator: Any,
        builder: Any | None = None,
        taint: Any | None = None,
        router: Any | None = None,
    ) -> None:
        self.config = config
        self.context = context
        self.model = model
        self.registry = registry
        self.gate = gate
        self.policy = policy
        self.approvals = approvals
        self.store = store
        self.events = events
        self.provenance = provenance
        self.ledger = ledger
        self.budgets = budgets
        self.parsers = parsers
        self.replay = replay
        self.rules = rules
        self.snapshot = snapshot
        self.correlator = correlator
        self.taint = taint
        self.router = router
        if builder is None:
            from harness.context.builder import ContextBuilder

            builder = ContextBuilder()
        self.builder = builder

        self.state = RunState(run_id=config.run_id)
        self._started_at: datetime = utcnow()
        # Aliased rather than duplicated: the telemetry belongs to the run state, so a caller that
        # holds the state holds the trace.
        self._telemetry = self.state.telemetry
        # One entry per attempted provider call, carrying the arguments that were proposed. A
        # planner needs the arguments to tell "I already read auth.log" from "I still have not read
        # nginx_access.log"; two calls can share one grant and differ only in their arguments.
        self._attempts: list[dict[str, Any]] = []
        self._seen_observation_keys: set[str] = set()
        self._last_gap_count = 0
        self._last_finding_ids: set[str] = set()
        #: Capabilities a conflict already scheduled a resolving call for. Without this the loop
        #: would detect the same unresolved conflict on the next pass and ask for the same
        #: expansion forever; one resolving call per capability is the ceiling.
        self._follow_ups_attempted: set[str] = set()
        #: Why the run is ending, recorded where the reason is decided (see `_end_run`). Left unset
        #: by a run that ends because the investigation finished, which is what makes the summary
        #: status a fact about the run rather than a constant written next to a stop reason.
        self._outcome: str | None = None

    # -- public entry point ----------------------------------------------------------------

    def run(self) -> RunState:
        self._log_run_start()
        try:
            self._planning_cycle()
        except BudgetExhausted as exc:
            self._goto(State.TERMINATING)
            self._end_run("budget_exhausted", str(exc), "RUN_BUDGET_EXHAUSTED")
        except HarnessError as exc:
            self._goto(State.TERMINATING)
            self._end_run(
                "failed",
                f"harness error: {exc}",
                "RUN_FAILED",
                error_type=type(exc).__name__,
            )

        self._finalise()
        return self.state

    def _end_run(
        self, status: RunStatus, stop_reason: str, event: str, *, error_type: str | None = None
    ) -> None:
        """Record why the run is ending, in one place, so the status cannot disagree with the log.

        The status is written where the cause is known instead of being inferred from the stop text
        afterwards. A budget-exhausted run and a run whose model died used to be finalised as
        `status="completed"` with a stop reason beside them, which is how memory curation -- which
        promotes lessons from runs that did *not* fail (`memory/curator.py`) -- could treat an
        abandoned investigation as a finished one. `status` is one of `RunSummary`'s vocabulary.
        """
        self.state.stop_reason = stop_reason
        self._outcome = status
        data: dict[str, Any] = {"reason": stop_reason}
        if error_type is not None:
            data["type"] = error_type
        self.events.append(event, data)

    # -- the cycle -------------------------------------------------------------------------

    def _planning_cycle(self) -> None:
        self._goto(State.CONTEXT_RESOLVED)
        self._log_context_resolved()

        while True:
            self.budgets.check_wall_clock()
            self._goto(State.PLANNING)
            self.budgets.step()
            self.state.step += 1

            catalogue = self.build_catalogue()
            if not catalogue["capabilities"]:
                self.state.stop_reason = self._nothing_left_to_ask()
                break

            # A conflict schedules its own resolving call, before the model is asked. The need is
            # already computable from run state, so asking the model to re-derive it would spend a
            # model turn on a question the harness has already answered. Design 08 says a conflict
            # may create a new evidence need; before v1.1 nothing turned that "may" into a call.
            need = self._scheduled_follow_up(catalogue)
            if need is not None:
                self._pursue_follow_up(need, catalogue)
                self._derive()
                self._goto(State.PLANNING)
                continue

            bundle = self.builder.build(
                resolved=self.context,
                catalogue=catalogue,
                run_digest=self.run_digest(catalogue),
                evidence_rollup="",
            )

            suggestion = self._ask_model(bundle)
            if suggestion is None:
                break

            if suggestion.get("stop"):
                self.state.stop_reason = suggestion.get("reason") or "model stopped"
                break

            proposal = suggestion["proposal"]
            if not self._validate(proposal, catalogue):
                continue

            if not self._pursue(proposal, catalogue):
                continue

            self._derive()
            self._goto(State.PLANNING)

    # -- model turn ------------------------------------------------------------------------

    def _ask_model(self, bundle: Any) -> dict[str, Any] | None:
        self.budgets.add_tokens(bundle.total_tokens, 0)
        self.ledger.record(
            self.state.step,
            input_tokens=bundle.total_tokens,
            output_tokens=0,
            tiers=bundle.tiers,
            memory_tokens=bundle.tiers.get("C1", 0) + bundle.tiers.get("C3", 0),
            evidence_tokens=bundle.tiers.get("C4", 0),
        )
        # What this prompt cost per tier, what a tier cap discarded, and what memory retrieval
        # cost. Recorded on the event trail rather than computed on demand because design 08's v2
        # Token Optimizer is meant to learn from measured traces, and a trace that was never
        # collected cannot be revisited later. dropped_tokens is the compression figure: it is the
        # cost of the tier caps rather than a saving, since a cap removes evidence the model would
        # otherwise have seen.
        cost = attribute_prompt_cost(
            tiers=bundle.tiers,
            tier_caps=self.builder.tier_caps,
            run_id=self.config.run_id,
            step=self.state.step,
        )
        memory_cost = memory_retrieval_cost(
            baseline_text=self.context.baseline_text,
            active_text=self.context.active_text,
            retrieved=self.context.retrieved,
        )
        self.events.append(
            "CONTEXT_ASSEMBLED",
            {
                "step": self.state.step,
                "tiers": cost.tiers,
                "total_tokens": cost.total_tokens,
                "dropped_tokens": cost.dropped_tokens,
                "over_cap_tiers": cost.over_cap_tiers,
                "memory": memory_cost.model_dump(mode="json"),
            },
        )
        request_text = bundle.system + "\x00" + bundle.user
        try:
            response = self.model.complete(system=bundle.system, user=bundle.user, step=self.state.step)
        except ModelClientError as exc:
            self._end_run(
                "failed",
                f"model client failed: {exc}",
                "RUN_FAILED",
                error_type="ModelClientError",
            )
            return None

        self.budgets.add_tokens(0, response.output_tokens)
        self.ledger.record(
            self.state.step,
            input_tokens=0,
            output_tokens=response.output_tokens,
            tiers={},
        )
        self.replay.model(
            key=f"model:step-{self.state.step}",
            step=self.state.step,
            request=request_text,
            response={
                "text": response.text,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "raw": response.raw,
            },
        )

        try:
            turn = parse_agent_turn(response.text)
        except ModelClientError as exc:
            # A malformed turn is a failure of this step, not of the run: the model gets another
            # chance, and the budget is what stops a model that never produces valid output.
            self.budgets.failure()
            self.state.consecutive_failures += 1
            self.events.append("VALIDATION_FAILED", {"scope": "agent_turn", "reason": str(exc)})
            return None if self._failures_exhausted() else {"stop": False, "retry": True, "proposal": None}

        self.events.append(
            "PLAN_PROPOSED",
            {"step": self.state.step, "plan": [p.model_dump(mode="json") for p in turn.plan]},
        )
        self._record_hypotheses(turn.hypotheses)
        self.budgets.success()
        self.state.consecutive_failures = 0

        action = turn.next_action
        if action.kind == "stop":
            return {"stop": True, "reason": action.reason}
        return {"stop": False, "proposal": action.proposal}

    def _record_hypotheses(self, hypotheses: Sequence[str]) -> None:
        """Keep what the model asserted, and give each statement an id a proposal can cite.

        The prompt asks the model for hypotheses and the run used to drop them, which left design
        D5's "the model may propose hypotheses only against existing ids" unimplementable: there were
        no ids to reference and nothing recorded to check a reference against (R2-24). Ids are
        assigned here rather than taken from the model, because a model-chosen id could collide with
        another turn's or be reused to point at a statement it never made; the id's only job is to be
        referenceable within this run. The statement is stored as prose the model wrote, which is
        what it is - it is never promoted to a claim or a finding (D5).
        """
        for statement in hypotheses:
            text = str(statement).strip()
            if not text:
                continue
            entry = {"id": new_id("h"), "statement": text, "step": self.state.step}
            self.state.hypotheses.append(entry)
            self.events.append(
                "HYPOTHESIS_RECORDED", {"hypothesis": entry["id"], "statement": text, "step": self.state.step}
            )

    def _hypothesis_reference_reason(self, proposal: CapabilityProposal) -> str | None:
        """Why a proposal's hypothesis reference is not usable, or ``None`` when it is.

        A reference to a hypothesis this run never recorded is refused rather than ignored: the field
        exists so a call can be attributed to the question it was made for, and an unresolvable id
        would make the attribution a fiction.
        """
        if not proposal.hypothesis_id:
            return None
        known = {str(entry["id"]) for entry in self.state.hypotheses}
        if proposal.hypothesis_id in known:
            return None
        return (
            f"hypothesis {proposal.hypothesis_id!r} was not recorded in this run; a proposal may "
            "cite only a hypothesis the model already stated"
        )

    def _failures_exhausted(self) -> bool:
        return self.state.consecutive_failures >= self.config.budgets.max_consecutive_failures

    # -- validation ------------------------------------------------------------------------

    def _validate(self, proposal: CapabilityProposal | None, catalogue: Mapping[str, Any]) -> bool:
        self._goto(State.VALIDATING)
        if proposal is None:
            return False
        self.events.append(
            "CAPABILITY_PROPOSED",
            {
                "capability": proposal.capability,
                "grant": proposal.grant,
                "expects": proposal.expects,
                "evidence_needed": proposal.evidence_needed,
            },
        )
        entry = next(
            (c for c in catalogue["capabilities"] if c["capability"] == proposal.capability), None
        )
        reason: str | None = None
        if entry is None:
            reason = (
                f"capability {proposal.capability!r} is not in the catalogue for this step; "
                "a capability that is not offered cannot be satisfied"
            )
        elif proposal.grant not in {g["grant"] for g in entry["grants"]}:
            # This is the structural scope guarantee in practice: an unknown grant id has no
            # meaning, and a resource the scope did not authorise has no alias to name.
            reason = (
                f"grant {proposal.grant!r} is not offered for capability {proposal.capability!r}"
            )
        else:
            reason = self._hypothesis_reference_reason(proposal)

        if reason is None:
            try:
                self.context.grants.require(proposal.grant, proposal.capability)
            except GrantError as exc:
                reason = str(exc)

        if reason is not None:
            self.state.rejected_proposals.append(
                {"capability": proposal.capability, "grant": proposal.grant, "reason": reason}
            )
            self.events.append(
                "VALIDATION_FAILED",
                {"scope": "capability_proposal", "capability": proposal.capability, "reason": reason},
            )
            self.budgets.failure()
            self.state.consecutive_failures += 1
            return False

        self.budgets.success()
        self.state.consecutive_failures = 0
        return True

    # -- necessity, policy, execution ------------------------------------------------------

    def _corroboration_required(self, capability: str) -> bool:
        """Whether this call must be corroborated by a second, independent source.

        A skill asks for it in one of two ways, and v1.1 read neither: ``allow_second_provider_by_default``
        asks on behalf of every need the skill has, and ``verification.independent_for`` names the
        conclusions that must not rest on a single source. Entries there are written
        ``<skill>.<conclusion>`` (see ``src/harness/skills/entry_point.yaml``), so the test is that the
        skill's own name appears before the dot - the structural reading of "this skill's conclusions
        need corroboration".

        Only asked where corroboration is *possible*: with one eligible provider the gate would
        refuse the call outright, which would trade stronger evidence for less evidence. A capability
        with a single source runs on that source, and the decision record says so.

        This is also what makes the conflict-driven re-planning behind the gate reachable by a real
        run (K3): a conflict needs two providers answering the same question, and before this the only
        way to get two was a coverage gap that the shipped providers do not produce.
        """
        skill = self.context.skill
        asked = skill.allow_second_provider_by_default or any(
            entry.split(".", 1)[0] == skill.name for entry in skill.verification.independent_for
        )
        return asked and len(self.registry.by_capability(capability)) >= 2

    def _pursue(self, proposal: CapabilityProposal, catalogue: Mapping[str, Any]) -> bool:
        self._goto(State.NECESSITY)
        decision = self.gate.decide(
            capability=proposal.capability,
            evidence_needed=proposal.evidence_needed,
            expects=proposal.expects,
            existing_observations=list(self.state.observations.values()),
            cache=self.state.cache,
            failed_providers=self.state.failed_providers,
            conflicts=self.state.correlations,
            trust_diversity_required=self._corroboration_required(proposal.capability),
        )
        self.state.decisions.append(decision)
        self.events.append(
            "NECESSITY_DECIDED",
            {
                "capability": decision.capability,
                "verdict": decision.verdict,
                "selected": decision.selected,
                "rejected": decision.rejected,
                "reason": decision.reason,
                "expansion_reason": decision.expansion_reason,
            },
        )

        if decision.verdict == "satisfied":
            self.events.append(
                "CALL_SKIPPED",
                {
                    "capability": decision.capability,
                    "reason": decision.reason,
                    "satisfied_by": decision.satisfied_by,
                },
            )
            return True

        if decision.verdict in {"defer", "deny"}:
            self._add_gap(
                kind="budget_exhausted" if decision.verdict == "defer" else "partial_coverage",
                capability=decision.capability,
                impact=decision.reason,
            )
            return True

        if decision.verdict == "expand" and decision.expansion_reason:
            self.events.append(
                "PROVIDER_EXPANSION",
                {
                    "capability": decision.capability,
                    "selected": decision.selected,
                    "expansion_reason": decision.expansion_reason,
                },
            )

        any_executed = False
        for provider in self.router.resolve(decision):
            if self._run_provider(provider, proposal, decision):
                any_executed = True
        self._goto(State.FINDINGS)
        # Reports what happened rather than a constant: with nothing executed there is nothing new
        # to derive, and the caller's next move is to ask the model again with the failure recorded.
        return any_executed

    # -- scheduled re-planning on conflict --------------------------------------------------

    def _scheduled_follow_up(self, catalogue: Mapping[str, Any]) -> FollowUpNeed | None:
        """A resolving provider call that an unresolved conflict justifies.

        The capability is filtered against the catalogue, which is the same structural guarantee
        the model's proposals get: a scheduled call can only ever be for something that is both
        registered and authorised. A conflict about a capability no grant can serve therefore
        produces no call rather than an unauthorised one.
        """
        needs = follow_up_needs(
            run_id=self.config.run_id,
            conflicts=self.state.correlations,
            observations=self.state.observations,
            decisions=self.state.decisions,
            already_attempted=self._follow_ups_attempted,
            max_needs=1,
        )
        offered = {entry["capability"] for entry in catalogue["capabilities"]}
        for need in needs:
            if need.capability in offered:
                return need
        return None

    def _pursue_follow_up(self, need: FollowUpNeed, catalogue: Mapping[str, Any]) -> bool:
        """Pursue a scheduled need through the ordinary validate/necessity/policy path.

        Deliberately not a shortcut around the gate. The need says *what* is wanted and *why*; the
        gate still decides whether a second provider is warranted and which one, so the expansion
        is recorded with expansion_reason=conflict_resolution like any other multi-provider call.
        Routing it any other way would make conflicts the one code path that can spend budget
        without a necessity decision behind it.
        """
        self._follow_ups_attempted.add(need.capability)
        self.state.follow_ups.append(need)
        self.events.append(
            "FOLLOW_UP_SCHEDULED",
            {
                "capability": need.capability,
                "reason": need.reason,
                "correlation": need.correlation_id,
                "observations": need.observation_ids,
                "detail": need.detail,
            },
        )
        entry = next(
            entry for entry in catalogue["capabilities"] if entry["capability"] == need.capability
        )
        grant = entry["grants"][0]
        proposal = CapabilityProposal(
            grant=grant["grant"],
            capability=need.capability,
            args=dict(grant["args"]),
            expects=need.expects,
            evidence_needed=need.detail,
        )
        if not self._validate(proposal, catalogue):
            return False
        return self._pursue(proposal, catalogue)

    def _run_provider(
        self, provider: Any, proposal: CapabilityProposal, decision: ProviderDecision
    ) -> bool:
        """Execute one selected provider.

        The provider arrives resolved rather than by id: `Router.resolve` is the step that re-checks
        a decision's selection against the registry before anything runs (the decision is a record
        that may have been replayed from disk), so looking the provider up again here would throw
        that check away (R2-25).
        """
        provider_id = provider.spec.id
        spec = provider.spec

        self._goto(State.POLICY)
        taint_level = self._current_taint()
        policy_decision = self.policy.decide(
            provider=spec,
            capability=proposal.capability,
            grant_id=proposal.grant,
            args=dict(proposal.args),
            taint=taint_level,
            proposal_authored_under_taint=taint_level == "T3",
            novel_resource=False,
        )
        self.provenance.add(
            policy_decision.id, "governed_by", decision.id, capability=proposal.capability
        )
        self.events.append(
            "POLICY_DECIDED",
            {
                "provider": provider_id,
                "capability": proposal.capability,
                "verdict": policy_decision.verdict,
                "reasons": policy_decision.reasons,
                "taint_downgrade": policy_decision.risk_downgraded_by_taint,
                # The id, not just the verdict. Without it a reader of events.jsonl cannot
                # join an execution back to the policy record that authorised it, which is
                # what audit invariant 6 asks for; before v1.1 the id existed only inside a
                # provenance triple.
                "policy_decision_id": policy_decision.id,
            },
        )

        approved = True
        if self.config.dry_run:
            # Dry run answers "what would happen?" without doing it. The policy verdict above is the
            # real verdict -- a local read-only call is genuinely permitted -- so the plan stays an
            # honest rendering rather than a table of everything denied. What dry run removes is the
            # invocation itself, and the rejection is recorded so the model moves on instead of
            # re-proposing the same capability until the step budget runs out.
            self.state.rejected_proposals.append(
                {
                    "capability": proposal.capability,
                    "grant": proposal.grant,
                    "reason": "dry run: the call was rendered and policy-checked but not executed",
                    "denied": True,
                }
            )
            self.events.append(
                "PROVIDER_REJECTED",
                {"provider": provider_id, "capability": proposal.capability, "reason": "dry_run"},
            )
            return False
        if policy_decision.verdict == "ask":
            approved = self._request_approval(provider_id, proposal, policy_decision)
        if policy_decision.verdict == "deny" or not approved:
            self._record_denied_execution(provider_id, proposal, policy_decision, approved)
            return False

        self._goto(State.EXECUTING)
        grant = self.context.grants.get(proposal.grant)
        request = ProviderRequest(
            run_id=self.config.run_id,
            execution_id=new_id("x"),
            capability=proposal.capability,
            args=dict(proposal.args),
            grant=grant,
            target_alias=grant.alias,
            timeout_s=spec.timeout_s,
        )
        started = utcnow()
        self.events.append(
            "PROVIDER_STARTED",
            {"provider": provider_id, "capability": proposal.capability, "alias": grant.alias},
        )
        try:
            result = provider.invoke(request)
        except ProviderError as exc:
            result = ProviderResult(
                provider=provider_id,
                capability=proposal.capability,
                exit_status="failed",
                error=str(exc),
            )
        ended = utcnow()

        metadata = self.store.put(
            (result.stdout or b""),
            media_type=result.media_type,
            producer=provider_id,
            execution_id=request.execution_id,
            taint="T3" if provider_id.startswith("mcp:") else "T2",
        )
        # The store enforces the byte ceiling itself, but it does not report what it spent, so
        # without this the guard's counter stays at zero and every recorded budget snapshot claims
        # no artifact bytes were used - a number a report renders as fact (R2-24). Same `Budget`
        # value, so the two cannot disagree about the limit.
        self.budgets.add_artifact_bytes(metadata.byte_length)
        execution = ProviderExecution(
            id=request.execution_id,
            run_id=self.config.run_id,
            provider=provider_id,
            capability=proposal.capability,
            provider_version=result.provider_version,
            grant=proposal.grant,
            # Both halves of what the grant authorises, so a run's own record answers "what was this
            # call allowed to reach?" without re-deriving it from grants.json (R2-11).
            alias=grant.alias,
            resource=grant.resource,
            policy_decision=policy_decision.id,
            necessity_decision=decision.id,
            started_at=started,
            ended_at=ended,
            exit_status=result.exit_status,
            argv=result.argv,
            stdout_sha256=metadata.digest if result.stdout else None,
            response_sha256=None,
            nondeterminism="live-network" if spec.requires_network_egress else "local-tool",
            artifacts=[metadata.digest],
        )
        self.state.executions.append(execution)
        # The reverse link from a policy decision to the execution it authorised. The field existed
        # and the run audit read it, but nothing ever wrote it, so the audit's "these two must name
        # each other" check could only ever compare two Nones (R2-24).
        policy_decision.execution_id = execution.id
        self.provenance.add(execution.id, "produced", metadata.digest, provider=provider_id)
        self.events.append(
            "ARTIFACT_CREATED",
            {
                "artifact": metadata.digest,
                "media_type": metadata.media_type,
                "bytes": metadata.byte_length,
                "execution": execution.id,
            },
        )
        self.replay.provider(
            key=execution.id,
            step=self.state.step,
            request={"provider": provider_id, "capability": proposal.capability, "alias": grant.alias},
            response={
                "exit_status": result.exit_status,
                "artifact": metadata.digest,
                "structured": result.structured,
            },
        )

        if result.exit_status != "completed":
            self.state.failed_providers.add(provider_id)
            self.budgets.failure()
            self.state.consecutive_failures += 1
            self.events.append(
                "PROVIDER_FAILED",
                {"provider": provider_id, "capability": proposal.capability, "error": result.error},
            )
            self._add_gap(
                kind="provider_failure",
                capability=proposal.capability,
                impact=result.error or "provider did not complete",
            )
            self._goto(State.FINDINGS)
            return False

        self.budgets.success()
        self.state.consecutive_failures = 0
        self.budgets.provider_call()
        cache_hit = cache_key(provider_id, proposal.capability) in self.state.cache
        # Recorded so the necessity gate can tell "a provider already ran for this capability"
        # from "nobody has tried yet", which is the difference between a real coverage gap and the
        # first call for a need.
        self.state.cache[cache_key(provider_id, proposal.capability)] = result
        self._attempts.append(
            {
                "capability": proposal.capability,
                "provider": provider_id,
                "grant": proposal.grant,
                "args": dict(proposal.args),
                "exit_status": result.exit_status,
            }
        )
        self.events.append(
            "PROVIDER_COMPLETED",
            {"provider": provider_id, "capability": proposal.capability, "execution": execution.id},
        )
        parsed = self._parse(result, execution, metadata.digest, spec, grant.alias)
        # The telemetry design 08 section 9 requires v1 to record. It is written now because the
        # v2 Token Optimizer is meant to be an optimisation over measured traces rather than an
        # architectural guess, and a trace that was never collected cannot be revisited.
        self._telemetry.append(
            ProviderCallTelemetry(
                execution_id=execution.id,
                provider=provider_id,
                capability=proposal.capability,
                step=self.state.step,
                payload_bytes=len(result.stdout or b""),
                normalized_observations=parsed.observations,
                duplicate_observations=parsed.duplicate_observations,
                new_observation_keys=sorted(parsed.new_keys),
                duplicate_keys=sorted(parsed.duplicate_keys),
                cache_hit=cache_hit,
                latency_ms=int((ended - started).total_seconds() * 1000),
                expansion_reason=decision.expansion_reason,
            )
        )
        self._goto(State.CORRELATING)
        self._correlate()
        self._goto(State.FINDINGS)
        return True

    def _record_unparsable_payload(self, execution: ProviderExecution, exc: ParserError) -> None:
        """Record a remote payload the harness could not read, and keep the run going (R2-18, R2-19).

        The execution is replaced with a failed one because the call contributed nothing: leaving it
        as `completed` would let the run report a successful call whose bytes produced no evidence,
        and the gate would keep selecting a provider whose output the harness cannot read.
        """
        failed = execution.model_copy(update={"exit_status": "failed"})
        self.state.executions = [failed if item.id == execution.id else item for item in self.state.executions]
        self.state.failed_providers.add(execution.provider)
        self.budgets.failure()
        self.state.consecutive_failures += 1
        self.events.append(
            "PROVIDER_FAILED",
            {
                "provider": execution.provider,
                "capability": execution.capability,
                "error": str(exc),
            },
        )
        self._add_gap(
            kind="provider_failure",
            capability=execution.capability,
            impact=f"the payload from {execution.provider} could not be read: {exc}",
        )

    def _parse(
        self,
        result: ProviderResult,
        execution: ProviderExecution,
        digest: str,
        spec: Any,
        target_alias: str,
    ) -> Any:
        self._goto(State.PARSING)
        if not result.stdout:
            self._add_gap(
                kind="empty_result",
                capability=execution.capability,
                impact="provider completed without producing output",
            )
            return _ParsedSummary()
        store = self.store

        def evidence_of(byte_start: int, byte_end: int) -> list[Any]:
            return [store.ref(digest, byte_start=byte_start, byte_end=byte_end)]

        try:
            parsed = self.parsers.parse(
                result.stdout,
                result.media_type,
                execution=execution,
                run_id=self.config.run_id,
                trust_class=spec.trust_class,
                artifact_digest=digest,
                evidence_of=evidence_of,
                # The alias, never the resource: it is the only target name the model is allowed to see,
                # and it is the only one an observation may carry into a prompt.
                target=target_alias,
            )
        except ParserError as exc:
            if spec.trust_class == "local_tool":
                # A native adapter's parser failing is a bug in *this* repository: the bytes came from
                # a tool the harness runs itself, against fixtures it also controls. It aborts the run
                # so it gets fixed, rather than being absorbed as an environment condition.
                raise
            # An untrusted producer's payload that will not parse is an outcome, not a crash: a
            # remote server can send anything, and a run that dies mid-investigation because of it
            # has let the server choose when the run ends. The call is recorded as failed, the
            # provider is marked failed so the gate replaces it, and the run continues with a gap.
            self._record_unparsable_payload(execution, exc)
            return _ParsedSummary()
        summary = _ParsedSummary(observations=len(parsed.observations))
        for observation in parsed.observations:
            # Novelty is measured against what the run already knew, which is what makes a second
            # provider's contribution distinguishable from a repeat of the first one's.
            key = observation.correlation_key()
            if key in self._seen_observation_keys:
                summary.duplicate_observations += 1
                summary.duplicate_keys.append(key)
            else:
                summary.new_keys.append(key)
            self._seen_observation_keys.add(key)
            self.state.observations[observation.id] = observation
            self.provenance.add(observation.id, "derived_from", digest, kind=observation.kind)
            self.events.append(
                "OBSERVATION_ADDED",
                {
                    "observation": observation.id,
                    "kind": observation.kind,
                    "provider": observation.provider,
                    "evidence": [r.artifact for r in observation.evidence],
                },
            )
        for gap in list(parsed.gaps) + list(result.gaps or []):
            self.state.gaps.append(gap)
            self.events.append("GAP_ADDED", {"gap": gap.id, "kind": gap.kind, "impact": gap.impact})
        return summary

    def _correlate(self) -> None:
        correlations = self.correlator.add(list(self.state.observations.values()))
        known = {c.key for c in self.state.correlations}
        for correlation in correlations:
            if correlation.key in known:
                continue
            known.add(correlation.key)
            self.state.correlations.append(correlation)
            self.events.append(
                "CORRELATION_ADDED",
                {
                    "correlation": correlation.id,
                    "relation": correlation.relation,
                    "key": correlation.key,
                    "observations": correlation.observation_ids,
                },
            )

    # -- derivation ------------------------------------------------------------------------

    def _derive(self) -> None:
        observations = list(self.state.observations.values())
        claims = list(self.rules.evaluate(observations))
        self.state.claims = claims
        # A rule whose template disagrees with the observation it matched is skipped rather than
        # crashing the run, but it is never silent: an analyser that quietly stops firing looks
        # exactly like an environment with nothing to report.
        for rule_id, problem in getattr(self.rules, "skipped", []):
            self.events.append(
                "ANALYSER_RULE_SKIPPED", {"rule": rule_id, "reason": problem}
            )
        for claim in claims:
            self.events.append(
                "CLAIM_ADDED",
                {"claim": claim.id, "rule": claim.rule_id, "assertion": claim.assertion},
            )

        candidates = self._candidates_from_observations(observations)
        findings = build_findings(
            run_id=self.config.run_id,
            observations=observations,
            claims=claims,
            candidates=candidates,
            correlations=self.state.correlations,
            skill=self.context.skill.name,
        )
        accepted, rejected = validate_all(
            findings, observations=self.state.observations, store=self.store
        )
        for bad in rejected:
            self.events.append(
                "VALIDATION_FAILED",
                {"scope": "finding", "finding": bad.id, "title": bad.title},
            )
        new_ids = {f.id for f in accepted}
        # Attributes the outcome of the derivation to the provider calls that made this step
        # possible, so "did that call change anything?" is answerable per call rather than per run.
        changed = new_ids != self._last_finding_ids
        closed_gap = len(self.state.gaps) < self._last_gap_count
        for entry in self._telemetry:
            if entry.step == self.state.step:
                entry.changed_finding = changed
                entry.closed_gap = closed_gap
        self._last_gap_count = len(self.state.gaps)
        for finding in accepted:
            if finding.id in self._last_finding_ids:
                continue
            self.events.append(
                "FINDING_ADDED",
                {
                    "finding": finding.id,
                    "title": finding.title,
                    "status": finding.status,
                    "cve": finding.cve,
                },
            )
            for claim in finding.claims:
                for observation_id in claim.supports:
                    self.provenance.add(finding.id, "supports", observation_id)
        self._last_finding_ids = new_ids
        self.state.findings = accepted

    @staticmethod
    def _candidates_from_observations(observations: Sequence[Observation]) -> list[CveCandidate]:
        services = {obs.value.get("cpe"): obs.id for obs in observations if obs.kind == "service"}
        out: list[CveCandidate] = []
        for obs in observations:
            if obs.kind != "vulnerability_match":
                continue
            value = obs.value
            out.append(
                CveCandidate(
                    cve=str(value.get("cve", "")),
                    cpe=str(value.get("cpe", "")),
                    product=str(value.get("product", "")),
                    version=str(value.get("version", "")),
                    cvss=float(value.get("cvss") or 0.0),
                    severity=str(value.get("severity", "unknown")),
                    summary=str(value.get("summary", "")),
                    matched_on=str(value.get("matched_on", "")),
                    # The matcher's own observation first, then the service observation it was
                    # derived from, so the finding builder can join claims to candidates through
                    # observation ids rather than through statement text.
                    observation_ids=(
                        [obs.id, services[value["cpe"]]]
                        if value.get("cpe") in services
                        else [obs.id]
                    ),
                )
            )
        return out

    # -- catalogue and digest --------------------------------------------------------------

    def build_catalogue(self) -> dict[str, Any]:
        """The complete set of legal requests for this step.

        A capability appears only when a registered provider can serve it *and* a grant authorises
        it. Everything else is invisible to the model, which is why an unregistered provider means
        an unavailable capability rather than a policy question.
        """
        grants_by_capability: dict[str, list[Any]] = {}
        for grant in self.context.grants.grants:
            for capability in grant.capabilities:
                grants_by_capability.setdefault(capability, []).append(grant)

        entries: list[dict[str, Any]] = []
        for capability in self.context.skill.capabilities:
            providers = self.registry.by_capability(capability)
            candidates = grants_by_capability.get(capability, [])
            if not providers or not candidates:
                continue
            expectation = CATALOGUE_EXPECTATIONS.get(capability, {})
            base_args = dict(expectation.get("args") or {})
            offered: list[dict[str, Any]] = []
            seen_keys: set[str] = set()
            for grant in candidates:
                variants = [base_args]
                if capability == "log.read" and grant.kind == "fs":
                    variants = [{"path": name} for name in LOG_FILES]
                for variant in variants:
                    # A net grant with a port window offers exactly that window: the plan the model
                    # writes is the plan that will be executed, so what it can propose has to be
                    # something the scope authorises. A grant without a window adds nothing, which
                    # keeps the prompts of every existing scope byte-identical (R2-05).
                    offered_args = dict(variant)
                    if grant.ports is not None and "ports" not in offered_args:
                        offered_args["ports"] = render_window(grant.ports)
                    key = canonical_json({"grant": grant.id, "args": offered_args})
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    offered.append({"grant": grant.id, "alias": grant.alias, "args": offered_args})
            if not offered:
                continue
            denied = {
                item["capability"] for item in self.state.rejected_proposals if item.get("denied")
            }
            if capability in denied:
                continue
            entries.append(
                {
                    "capability": capability,
                    "intent_hint": expectation.get("intent_hint", capability),
                    "expects": expectation.get("expects", ""),
                    "expected_kinds": sorted(CAPABILITY_OUTPUT_KINDS.get(capability) or set()),
                    "grants": offered,
                }
            )

        return {
            "skill": self.context.skill.name,
            "objective": self.context.objective,
            "capabilities": entries,
        }

    def run_digest(self, catalogue: Mapping[str, Any]) -> dict[str, Any]:
        """The C2 tier: deterministic harness state, never raw provider output."""
        return {
            "step": self.state.step,
            "objective_kind": self.context.skill.name,
            "observations": [
                {"id": obs.id, "kind": obs.kind, "value": obs.value}
                for obs in sorted(self.state.observations.values(), key=lambda o: o.id)
            ],
            "claims": [
                {"id": c.id, "statement": c.statement, "assertion": c.assertion}
                for c in self.state.claims
            ],
            "candidates": [
                {"cve": obs.value.get("cve"), "cpe": obs.value.get("cpe")}
                for obs in sorted(self.state.observations.values(), key=lambda o: o.id)
                if obs.kind == "vulnerability_match"
            ],
            "gaps": [{"id": g.id, "kind": g.kind, "impact": g.impact} for g in self.state.gaps],
            "executed": list(self._attempts),
            "denied": [item for item in self.state.rejected_proposals if item.get("denied")],
            "capabilities": [
                {
                    "capability": entry["capability"],
                    "expects": entry["expects"],
                    "expected_kinds": entry["expected_kinds"],
                    "grants": entry["grants"],
                }
                for entry in catalogue["capabilities"]
            ],
            "granted_aliases": sorted({g["alias"] for entry in catalogue["capabilities"] for g in entry["grants"]}),
        }

    # -- approvals and gaps ----------------------------------------------------------------

    def _request_approval(self, provider_id: str, proposal: CapabilityProposal, policy_decision: Any) -> bool:
        request = ApprovalRequest(
            id=new_id("ap"),
            policy_decision=policy_decision.id,
            question=(
                f"Approve {provider_id} for {proposal.capability} on grant {proposal.grant}? "
                "This call was routed to a human because of its risk class or its taint."
            ),
            provider=provider_id,
            capability=proposal.capability,
            grant=proposal.grant,
            argv_preview=list(proposal.args.get("argv") or []),
            requested_at=utcnow(),
        )
        self.events.append(
            "APPROVAL_REQUESTED",
            {"request": request.id, "provider": provider_id, "capability": proposal.capability},
        )
        response = self.approvals.request(request)
        self.events.append(
            "APPROVAL_GIVEN",
            {"request": request.id, "approved": response.approved, "answer": response.answer},
        )
        if not response.approved:
            self.state.rejected_proposals.append(
                {
                    "capability": proposal.capability,
                    "grant": proposal.grant,
                    "reason": "human rejected the approval request",
                    "denied": True,
                }
            )
            self._add_gap(
                kind="rejected_by_user",
                capability=proposal.capability,
                impact="a human declined this call, so the evidence it would have produced is missing",
            )
        return response.approved

    def _record_denied_execution(
        self, provider_id: str, proposal: CapabilityProposal, policy_decision: Any, approved: bool
    ) -> None:
        kind = "rejected_by_user" if not approved else "permission_denied"
        reason = policy_decision.reasons[0] if policy_decision.reasons else "policy denied"
        self.state.rejected_proposals.append(
            {
                "capability": proposal.capability,
                "grant": proposal.grant,
                "reason": reason,
                "denied": True,
            }
        )
        self.events.append(
            "PROVIDER_REJECTED",
            {"provider": provider_id, "capability": proposal.capability, "reason": reason},
        )
        if approved:
            self._add_gap(kind=kind, capability=proposal.capability, impact=reason)

    def _add_gap(self, *, kind: str, capability: str, impact: str, scope: dict[str, Any] | None = None) -> None:
        gap = EvidenceGap(
            id=new_id("g"),
            run_id=self.config.run_id,
            kind=kind,  # type: ignore[arg-type]
            scope=dict(scope or {}),
            impact=impact,
            capability=capability,
        )
        self.state.gaps.append(gap)
        self.events.append("GAP_ADDED", {"gap": gap.id, "kind": gap.kind, "impact": gap.impact})

    def _current_taint(self) -> str:
        levels = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}
        worst = "T1"
        for obs in self.state.observations.values():
            if levels.get(obs.taint, 0) > levels[worst]:
                worst = obs.taint
        return worst

    # -- lifecycle bookkeeping -------------------------------------------------------------

    def _goto(self, new_state: State) -> None:
        self.state.transition(new_state)

    def _log_run_start(self) -> None:
        self.events.append(
            "RUN_STARTED",
            {
                "objective": self.config.objective,
                "skill": self.config.skill,
                "scope_id": self.config.scope_id,
                "scope_sha256": self.config.scope_sha256,
                "model": self.config.model.model_dump(mode="json"),
                "budgets": self.config.budgets.model_dump(mode="json"),
                "grant_count": len(self.context.grants.grants),
                "dry_run": self.config.dry_run,
            },
        )
        # Which key the scope was verified against, recorded on the trail rather than only in the run
        # manifest: "the signature verified" is a weaker statement than "the operator's key verified
        # it", and a reader has to be able to tell which one this run had (R2-06).
        self.events.append(
            "AUTHORITY_VERIFIED",
            {
                "scope_id": self.config.scope_id,
                "authority": self.config.authority,
                "anchor_fingerprint": self.config.anchor_fingerprint,
            },
        )

    def _log_context_resolved(self) -> None:
        self.provenance.add(self.config.run_id, "authorised_by", self.config.scope_sha256)
        self.events.append(
            "CONTEXT_RESOLVED",
            {
                "grants": [
                    {
                        "grant": g.id,
                        "alias": g.alias,
                        "capabilities": list(g.capabilities),
                        "expires_at": iso(g.expires_at),
                    }
                    for g in self.context.grants.grants
                ],
                "baseline_sha256": self.context.memory.baseline_sha256,
                "active_sha256": self.context.memory.active_sha256,
            },
        )
        if self.context.retrieved:
            self.events.append(
                "MEMORY_RETRIEVED",
                {
                    "entries": [hit.entry.id for hit in self.context.retrieved],
                    "kinds": [hit.entry.kind for hit in self.context.retrieved],
                },
            )

    def _nothing_left_to_ask(self) -> str:
        """Why the catalogue is empty. The two causes are different and only one is about authority.

        A capability disappears from the catalogue when it has no registered provider with a grant
        *or* when it was denied. Reporting the first cause for a run that ended because authority
        refused every call would be the record telling the reader something that is not true, which
        is the failure this whole file exists to avoid (see `docs/dev/AUDIT-v12.md` R1-10).
        """
        denied = sorted(
            {str(item["capability"]) for item in self.state.rejected_proposals if item.get("denied")}
        )
        if denied:
            return (
                f"no capability is left: {', '.join(denied)} was denied, and nothing else in this "
                f"skill has both a registered provider and a grant"
            )
        return "no capability in this skill has both a registered provider and a grant"

    def _terminal_status(self) -> RunStatus:
        """Why the run ended, in the vocabulary ``RunSummary.status`` is typed on.

        A run that recorded no failure of its own and executed nothing because authority refused
        every call it made did not complete an investigation: it was denied one. A dry run is not
        that case -- its proposals are marked denied by the harness itself, since rendering the plan
        without executing it is exactly what the operator asked for.
        """
        if self._outcome is not None:
            return self._outcome
        if not self.config.dry_run and not self.state.executions:
            if any(item.get("denied") for item in self.state.rejected_proposals):
                return "denied"
        return "completed"

    def _finalise(self) -> None:
        status = self._terminal_status()
        summary = RunSummary(
            run_id=self.config.run_id,
            status=status,
            steps=self.state.step,
            provider_calls=len(self.state.executions),
            findings=len(self.state.findings),
            gaps=len(self.state.gaps),
            started_at=self._started_at,
            ended_at=utcnow(),
            event_count=len(self.events.records()) if hasattr(self.events, "records") else 0,
        )
        self.events.append(
            "RUN_ENDED",
            {
                "status": summary.status,
                "steps": summary.steps,
                "findings": summary.findings,
                "gaps": summary.gaps,
                "stop_reason": self.state.stop_reason,
            },
        )
        self._summary = summary
        self._goto(State.TERMINATING)
        self._goto(State.DONE if summary.status == "completed" else State.FAILED)

    @property
    def summary(self) -> RunSummary:
        return getattr(self, "_summary", RunSummary(run_id=self.config.run_id, status="failed"))
