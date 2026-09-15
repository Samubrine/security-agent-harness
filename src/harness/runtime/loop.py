"""The investigation loop.

One pass through the design's appendix: resolve context, ask the local model for one typed
capability need, validate it, decide whether it is necessary, gate it through policy, execute it,
parse it, correlate it, derive findings, and repeat until the model stops or a budget does.

The loop is deliberately boring. Every interesting decision lives in a small, separately tested
component; this file wires them together and records what happened. If something here looks like
judgement rather than sequencing, it is in the wrong file.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from harness.analysers.cve_match import CveCandidate, VulnerabilitySnapshot
from harness.errors import (
    ApprovalRejected,
    BudgetExhausted,
    GrantError,
    HarnessError,
    ModelClientError,
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
    Observation,
    ProviderDecision,
    ProviderExecution,
    RunConfig,
    RunSummary,
)
from harness.providers.base import ProviderRequest, ProviderResult
from harness.providers.necessity import CAPABILITY_OUTPUT_KINDS, cache_key
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
        self._telemetry: list[Any] = []
        self._last_gap_count = 0
        self._last_finding_ids: set[str] = set()

    # -- public entry point ----------------------------------------------------------------

    def run(self) -> RunState:
        self._log_run_start()
        try:
            self._planning_cycle()
        except BudgetExhausted as exc:
            self._goto(State.TERMINATING)
            self.state.stop_reason = str(exc)
            self.events.append("RUN_BUDGET_EXHAUSTED", {"reason": str(exc)})
        except HarnessError as exc:
            self._goto(State.TERMINATING)
            self.state.stop_reason = f"harness error: {exc}"
            self.events.append("RUN_FAILED", {"reason": str(exc), "type": type(exc).__name__})

        self._finalise()
        return self.state

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
                self.state.stop_reason = (
                    "no capability in this skill has both a registered provider and a grant"
                )
                break

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
        request_text = bundle.system + "\x00" + bundle.user
        try:
            response = self.model.complete(system=bundle.system, user=bundle.user, step=self.state.step)
        except ModelClientError as exc:
            self.state.stop_reason = f"model client failed: {exc}"
            self.events.append("RUN_FAILED", {"reason": str(exc), "type": "ModelClientError"})
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
        self.budgets.success()
        self.state.consecutive_failures = 0

        action = turn.next_action
        if action.kind == "stop":
            return {"stop": True, "reason": action.reason}
        return {"stop": False, "proposal": action.proposal}

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
        for provider_id in decision.selected:
            if self._run_provider(provider_id, proposal, decision):
                any_executed = True
        self._goto(State.FINDINGS)
        return any_executed or True

    def _run_provider(
        self, provider_id: str, proposal: CapabilityProposal, decision: ProviderDecision
    ) -> bool:
        provider = self.registry.get(provider_id)
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
        execution = ProviderExecution(
            id=request.execution_id,
            run_id=self.config.run_id,
            provider=provider_id,
            capability=proposal.capability,
            provider_version=result.provider_version,
            grant=proposal.grant,
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
        # Recorded so the necessity gate can tell "a provider already ran for this capability"
        # from "nobody has tried yet", which is the difference between a real coverage gap and the
        # first call for a need.
        self.state.cache[cache_key(provider_id, proposal.capability)] = result
        self.state.cache[provider_id] = result
        self.events.append(
            "PROVIDER_COMPLETED",
            {"provider": provider_id, "capability": proposal.capability, "execution": execution.id},
        )
        self._parse(result, execution, metadata.digest, spec, grant.alias)
        self._goto(State.CORRELATING)
        self._correlate()
        self._goto(State.FINDINGS)
        return True

    def _parse(
        self,
        result: ProviderResult,
        execution: ProviderExecution,
        digest: str,
        spec: Any,
        target_alias: str,
    ) -> None:
        self._goto(State.PARSING)
        if not result.stdout:
            self._add_gap(
                kind="empty_result",
                capability=execution.capability,
                impact="provider completed without producing output",
            )
            return
        store = self.store

        def evidence_of(byte_start: int, byte_end: int) -> list[Any]:
            return [store.ref(digest, byte_start=byte_start, byte_end=byte_end)]

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
        for observation in parsed.observations:
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
                    key = canonical_json({"grant": grant.id, "args": variant})
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    offered.append({"grant": grant.id, "alias": grant.alias, "args": variant})
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
            "executed": [
                {
                    "capability": execution.capability,
                    "provider": execution.provider,
                    "grant": execution.grant,
                    "exit_status": execution.exit_status,
                }
                for execution in self.state.executions
            ],
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

    def _finalise(self) -> None:
        summary = RunSummary(
            run_id=self.config.run_id,
            status="completed",
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
