"""The harness vocabulary: every typed record the spine moves between subsystems.

This module is the single source of truth for the data model described in
``docs/design/02-data-model.md`` and ``docs/design/03-policy-and-safety.md``. Subsystems
import from here rather than defining their own shapes, which is what keeps the
deterministic spine and the model proposal an actually-checked contract.

Two rules are encoded structurally, not by convention:

* ``CapabilityProposal`` has no target and no provider field. A model cannot name a host it
  was not granted, because there is no field in which to write one.
* ``Finding``/``Claim`` can only be built over ``Observation``s, and an ``Observation``
  can only be built over ``EvidenceRef``s, and an ``EvidenceRef`` can only point into an
  immutable artifact. There is no path from a memory entry into a finding.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from harness.util import iso, sha256_text

# --------------------------------------------------------------------------------------
# Enumerations (kept as Literals so they survive JSON round-trips and JSON Schema export)
# --------------------------------------------------------------------------------------

Risk = Literal["LOW", "MEDIUM", "HIGH"]
TrustClass = Literal["local_tool", "local_mcp", "external_provider"]
TaintLevel = Literal["T0", "T1", "T2", "T3"]
Nondeterminism = Literal["local-tool", "live-network", "external-provider"]
ExitStatus = Literal["completed", "failed", "timeout", "denied"]
PolicyVerdict = Literal["allow", "ask", "deny"]
NecessityVerdict = Literal["satisfied", "single", "expand", "defer", "deny"]
ExpansionReason = Literal[
    "coverage_gap",
    "conflict_resolution",
    "independent_verification",
    "provider_failure",
    "trust_diversity",
]
FindingStatus = Literal["possible", "confirmed", "not_affected", "inconclusive"]
Confidence = Literal["observed", "high", "medium", "low", "unknown"]
Assertion = Literal["observed", "rule_derived", "llm_hypothesis"]
CorrelationRelation = Literal["agreement", "complement", "conflict"]
MemoryKind = Literal[
    "tool_behavior",
    "investigation_pattern",
    "environment_fact",
    "user_convention",
    "lesson",
]
MemoryConfidence = Literal["stable", "provisional"]
GapKind = Literal[
    "tool_timeout",
    "provider_failure",
    "permission_denied",
    "empty_result",
    "partial_coverage",
    "provider_conflict",
    "no_cpe",
    "db_stale",
    "unreachable",
    "budget_exhausted",
    "rejected_by_user",
    "prompt_injection_attempt",
]


class _Base(BaseModel):
    """Strict by default: unknown fields are bugs, not tolerated input."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, arbitrary_types_allowed=False)


class _Frozen(_Base):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------------------
# Budgets and run identity
# --------------------------------------------------------------------------------------


class Budget(_Base):
    """Hard limits. The model cannot raise them; only a skill may override, within caps."""

    max_steps: int = 12
    max_provider_calls: int = 8
    max_prompt_tokens: int = 60_000
    max_completion_tokens: int = 8_000
    max_wall_clock_s: int = 600
    max_artifact_bytes: int = 32 * 1024 * 1024
    max_consecutive_failures: int = 3
    max_providers_per_need: int = 2
    hard_max_providers_per_need: int = 3

    @model_validator(mode="after")
    def _sane(self) -> Self:
        if self.max_providers_per_need > self.hard_max_providers_per_need:
            raise ValueError("max_providers_per_need may not exceed the hard cap")
        if self.hard_max_providers_per_need > 3:
            raise ValueError("no run may use more than three providers for one need")
        return self


class ModelMetadata(_Frozen):
    """Frozen at run start so token accounting and replay are interpretable."""

    backend: str
    model_id: str
    model_digest: str | None = None
    context_window: int = 8192
    tokenizer_id: str = "heuristic-4chars"
    temperature: float = 0.0
    top_p: float = 1.0
    seed: int | None = 0
    system_prompt_digest: str = ""
    is_local: bool = True


class ScopeWindow(_Base):
    from_at: datetime = Field(alias="from")
    to: datetime

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def covers(self, when: datetime) -> bool:
        return self.from_at <= when <= self.to


class ScopeNetwork(_Base):
    cidr: str
    include: list[str]


class ScopeFile(_Base):
    """The authorisation record. Unsigned or unverifiable scope means no run at all."""

    scope_id: str
    authorized_by: str
    networks: list[ScopeNetwork]
    filesystem: list[str] = Field(default_factory=list)
    # alias -> resource, e.g. {"lab-web-01": "net:10.77.0.11", "lab-logs": "fs:/lab/logs"}.
    # This mapping is the only bridge between what is authorised and what the model may name:
    # an alias whose resource is not covered by `networks`/`filesystem` is refused at load time,
    # so an out-of-scope host is unreachable rather than merely discouraged.
    aliases: dict[str, str] = Field(default_factory=dict)
    window: ScopeWindow
    dry_run: bool = False
    notes: str = ""
    signature: str | None = None
    signature_alg: str = "ed25519"
    signer_public_key: str | None = None

    def signing_payload(self) -> dict[str, Any]:
        """Everything except the signature itself, which is what gets signed."""
        data = self.model_dump(mode="json")
        data.pop("signature", None)
        return data


class Grant(_Frozen):
    """An opaque, bounded, expiring authority token. The only name the model ever sees is
    ``alias``; the real resource never appears in a proposal."""

    id: str
    resource: str
    alias: str
    capabilities: list[str]
    ports: list[int] | None = None
    expires_at: datetime
    origin: str
    kind: Literal["net", "fs"] = "net"

    def covers(self, capability: str, when: datetime) -> bool:
        return capability in self.capabilities and when <= self.expires_at


# --------------------------------------------------------------------------------------
# Skills
# --------------------------------------------------------------------------------------


class SkillVerification(_Base):
    max_providers_per_need: int | None = None
    independent_for: list[str] = Field(default_factory=list)


class SkillSpec(_Frozen):
    """Declarative skill: which capabilities exist, what the objective means, budgets."""

    name: str
    version: str
    description: str = ""
    objective_template: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str]
    completion_criteria: list[str] = Field(default_factory=list)
    verification: SkillVerification = Field(default_factory=SkillVerification)
    budget_override: dict[str, int] = Field(default_factory=dict)
    allow_second_provider_by_default: bool = False


# --------------------------------------------------------------------------------------
# Model-facing contracts
# --------------------------------------------------------------------------------------


class CapabilityProposal(_Base):
    """What the model may ask for. Note what is *absent*: target, provider, command."""

    grant: str
    capability: str
    args: dict[str, Any] = Field(default_factory=dict)
    expects: str
    evidence_needed: str
    hypothesis_id: str | None = None


class PlanStep(_Base):
    step: int
    capability: str
    intent: str


class StopAction(_Base):
    """The model is allowed to say "stop"; it is never allowed to say "done, trust me"."""

    kind: Literal["stop"] = "stop"
    reason: str


class CapabilityAction(_Base):
    kind: Literal["capability"] = "capability"
    proposal: CapabilityProposal


class AgentTurn(_Base):
    """One model turn: an advisory plan plus exactly one next action."""

    plan: list[PlanStep] = Field(default_factory=list)
    next_action: CapabilityAction | StopAction
    hypotheses: list[str] = Field(default_factory=list)
    narrative_hint: str | None = None


# --------------------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------------------


class EstimatedCost(_Base):
    latency_ms: int | None = None
    token_payload_hint: int | None = None


class ProviderSpec(_Frozen):
    """A provider advertises capabilities, never becomes planner vocabulary."""

    id: str
    kind: Literal["native", "mcp"]
    capabilities: list[str]
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_media_type: str
    parser: str
    risk: Risk
    trust_class: TrustClass
    requires_network_egress: bool
    timeout_s: int = 60
    idempotent: bool = True
    estimated_cost: EstimatedCost = Field(default_factory=EstimatedCost)
    description: str = ""
    # Capabilities the provider deliberately cannot serve (drives ``coverage_gap``).
    excludes: list[str] = Field(default_factory=list)

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities and capability not in self.excludes


class ProviderExecution(_Frozen):
    id: str
    run_id: str
    provider: str
    capability: str
    provider_version: str | None = None
    grant: str
    policy_decision: str
    necessity_decision: str
    started_at: datetime
    ended_at: datetime
    exit_status: ExitStatus
    argv: list[str] | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    response_sha256: str | None = None
    nondeterminism: Nondeterminism = "local-tool"
    artifacts: list[str] = Field(default_factory=list)


class ProviderDecision(_Base):
    """Emitted for *every* capability request, including ones that run nothing.

    This is what lets the report answer "why was another tool not run?".
    """

    id: str
    capability: str
    verdict: NecessityVerdict
    selected: list[str] = Field(default_factory=list)
    considered: list[str] = Field(default_factory=list)
    rejected: dict[str, str] = Field(default_factory=dict)
    reason: str
    expansion_reason: ExpansionReason | None = None
    budget_snapshot: dict[str, int] = Field(default_factory=dict)
    satisfied_by: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _expand_needs_reason(self) -> Self:
        if self.verdict == "expand" and self.expansion_reason is None:
            raise ValueError("an expand decision must carry an expansion_reason")
        if self.verdict == "expand" and len(self.selected) < 2:
            raise ValueError("an expand decision must select at least two providers")
        return self


# --------------------------------------------------------------------------------------
# Evidence graph
# --------------------------------------------------------------------------------------


class EvidenceRef(_Base):
    """A span inside an immutable artifact. ``span_sha256`` is recomputable, which is the
    whole point: a finding is defensible only if its span hashes back to real bytes."""

    artifact: str
    media_type: str
    byte_start: int
    byte_end: int
    line_start: int | None = None
    line_end: int | None = None
    locator: str | None = None
    span_sha256: str = ""
    taint: TaintLevel = "T3"

    def compute_span_sha256(self, raw: bytes) -> str:
        return sha256_text(raw[self.byte_start : self.byte_end].decode("utf-8", errors="replace"))


class Observation(_Base):
    id: str
    run_id: str
    kind: str
    value: dict[str, Any]
    parser: str
    parser_version: str
    provider: str
    execution_id: str
    freshness: datetime | None = None
    trust_class: TrustClass = "local_tool"
    taint: TaintLevel = "T2"
    evidence: list[EvidenceRef] = Field(default_factory=list)

    def correlation_key(self) -> str:
        """Identity used by the correlator to spot agreement/conflict across providers.

        Deliberately free of provider identity and of free-text fields, so two providers
        reporting the same fact on the same target compare equal.
        """
        return f"{self.kind}|{canonical_value(self.value)}"


def canonical_value(value: Any) -> str:
    from harness.util import canonical_json

    return canonical_json(value)


class Claim(_Base):
    id: str
    statement: str
    assertion: Assertion
    rule_id: str | None = None
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    confidence: Confidence = "medium"
    confidence_basis: str = ""
    caveats: list[str] = Field(default_factory=list)


class Finding(_Base):
    id: str
    run_id: str
    title: str
    status: FindingStatus = "possible"
    claims: list[Claim] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    cve: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    narrative: str | None = None
    gaps: list[str] = Field(default_factory=list)
    skill: str = ""
    created_at: datetime | None = None

    def observation_ids(self) -> list[str]:
        out: list[str] = []
        for claim in self.claims:
            out.extend(claim.supports)
        return out


class EvidenceGap(_Base):
    id: str
    run_id: str
    kind: GapKind
    scope: dict[str, Any] = Field(default_factory=dict)
    impact: str = ""
    capability: str | None = None


class Correlation(_Base):
    id: str
    run_id: str
    key: str
    observation_ids: list[str]
    relation: CorrelationRelation
    detail: str = ""


# --------------------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------------------


class MemoryEntry(_Base):
    id: str
    created_at: datetime
    kind: MemoryKind
    summary: str
    source_runs: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    confidence: MemoryConfidence = "provisional"
    last_used_at: datetime | None = None
    supersedes: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class MemoryCompaction(_Base):
    id: str
    run_id: str
    performed_at: datetime
    before_digest: str
    after_digest: str
    archived_snapshot: str
    promoted_entries: list[str] = Field(default_factory=list)
    removed_duplicates: int = 0
    local_model_used: bool = False


class RetrievedMemory(_Base):
    """A memory hit labelled for prompt inclusion. Carries provenance for explainability
    only — the label ``memory_context`` is how the validator knows it is not evidence."""

    entry: MemoryEntry
    score: float = 0.0
    retrieved_for: str = ""


# --------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------


class Tainted(_Base):
    value: str
    level: TaintLevel
    origin: str
    nonce: str | None = None


class PolicyDecision(_Base):
    id: str
    execution_id: str | None = None
    provider: str
    capability: str
    grant: str
    verdict: PolicyVerdict
    reasons: list[str] = Field(default_factory=list)
    risk: Risk
    risk_downgraded_by_taint: bool = False
    taint_level: TaintLevel | None = None
    decided_at: datetime | None = None


class ApprovalRequest(_Base):
    id: str
    policy_decision: str
    question: str
    provider: str
    capability: str
    grant: str
    argv_preview: list[str] = Field(default_factory=list)
    requested_at: datetime


class ApprovalResponse(_Base):
    request_id: str
    approved: bool
    answered_at: datetime
    answer: str = ""
    answered_by: str = "cli"


# --------------------------------------------------------------------------------------
# Telemetry
# --------------------------------------------------------------------------------------


class TokenLedgerEntry(_Base):
    step: int
    model_id: str
    tokenizer_id: str
    input_tokens: int = 0
    output_tokens: int = 0
    context_tokens_by_tier: dict[str, int] = Field(default_factory=dict)
    memory_tokens: int = 0
    evidence_tokens: int = 0


class ProviderCallTelemetry(_Base):
    """Recorded now so the v2 Token Optimizer is an optimisation over measured traces
    rather than an architectural guess."""

    execution_id: str
    provider: str
    capability: str
    step: int
    payload_bytes: int = 0
    normalized_observations: int = 0
    duplicate_observations: int = 0
    new_observation_keys: list[str] = Field(default_factory=list)
    duplicate_keys: list[str] = Field(default_factory=list)
    cache_hit: bool = False
    latency_ms: int = 0
    changed_finding: bool = False
    closed_gap: bool = False
    expansion_reason: ExpansionReason | None = None


# --------------------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------------------


class EventRecord(_Base):
    """One canonical JSON line in ``events.jsonl``. ``event_hash`` is computed over the
    canonical form of every other field plus ``prev_event_hash``."""

    seq: int
    run_id: str
    type: str
    at: datetime
    data: dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str = ""
    event_hash: str = ""

    def payload_without_hash(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data.pop("event_hash", None)
        return data

    def computed_hash(self) -> str:
        from harness.util import canonical_json

        return sha256_text(self.prev_event_hash + canonical_json(self.payload_without_hash()))


# --------------------------------------------------------------------------------------
# Run-level records
# --------------------------------------------------------------------------------------


class MemoryDigests(_Base):
    baseline_sha256: str = ""
    active_sha256: str = ""
    long_term_entries: list[str] = Field(default_factory=list)
    retrieved_sha256: str = ""


class RunConfig(_Frozen):
    """Frozen at run start. Later memory mutation cannot retroactively change a run."""

    run_id: str
    objective: str
    skill: str
    scope_id: str
    scope_sha256: str
    model: ModelMetadata
    budgets: Budget
    memory: MemoryDigests
    harness_version: str
    git_sha: str | None = None
    dry_run: bool = False
    created_at: datetime
    enable_remote_egress: bool = False
    seed: int = 0


class RunSummary(_Base):
    run_id: str
    status: Literal["completed", "budget_exhausted", "failed", "denied"]
    steps: int = 0
    provider_calls: int = 0
    findings: int = 0
    gaps: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None
    event_count: int = 0
    replay_verified: bool = False


class ArtifactMeta(_Base):
    digest: str
    media_type: str
    byte_length: int
    created_at: datetime
    producer: str
    execution_id: str | None = None
    run_id: str = ""
    taint: TaintLevel = "T2"
    redacted: bool = False


class ReplayRecord(_Frozen):
    """A recorded model or provider interaction. Replay never re-touches the network."""

    kind: Literal["model", "provider"]
    key: str
    step: int
    request_sha256: str
    response: Any
    recorded_at: datetime
    #: The exact request that produced the recorded response, for model turns. Kept alongside the
    #: digest because design 02 puts prompts in the trace: a replay that can only say "the digest
    #: does not match" cannot tell a reviewer what changed, and an evaluation of prompt quality
    #: needs the prompt itself. It is local content the run already held.
    request_text: str | None = None

    def to_jsonl(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def iso_now_str() -> str:
    from harness.util import utcnow

    return iso(utcnow())


def require_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# --------------------------------------------------------------------------------------
# v1.1 additions: one record per honesty gap named in docs/dev/AUDIT.md section 6.
#
# These are additive. Nothing here changes a v1 record's shape, so a run directory written
# by v1 still loads, and the four checks the audit found missing have somewhere to put
# their verdict instead of being reported as prose.
# --------------------------------------------------------------------------------------


class ProvenanceIssue(_Base):
    """One broken reference in a run's evidence graph.

    Audit invariant 6: ``ProviderExecution.necessity_decision`` and ``.policy_decision``
    are required fields, but nothing checked that the ids they name exist, so a record
    citing a fabricated decision id serialised happily.
    """

    code: str
    subject: str
    detail: str
    severity: Literal["error", "warning"] = "error"


class ProvenanceAudit(_Base):
    """The result of re-deriving a recorded run's reference graph from that run's own files."""

    run_id: str
    checked: dict[str, int] = Field(default_factory=dict)
    issues: list[ProvenanceIssue] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        """A warning is recorded but does not fail a run; only errors do."""
        return not any(issue.severity == "error" for issue in self.issues)

    def codes(self) -> list[str]:
        return sorted({issue.code for issue in self.issues})


class EgressAssessment(_Base):
    """Whether a provider call may leave the local network, decided from its endpoint
    rather than from the provider's own declaration.

    ``declared_by_provider`` is kept because a disagreement between it and
    ``egress_actually_required`` is itself the finding: the provider-side egress gap was
    that a component was allowed to grade itself.
    """

    provider: str
    endpoint: str | None = None
    endpoint_class: Literal["loopback", "private", "public", "unknown"] = "unknown"
    declared_by_provider: bool = False
    egress_actually_required: bool = False
    permitted: bool = True
    reasons: list[str] = Field(default_factory=list)

    @property
    def declaration_mismatch(self) -> bool:
        return self.declared_by_provider != self.egress_actually_required


class FollowUpNeed(_Base):
    """A concrete evidence need derived from run state rather than from the model.

    Design 08 says a conflict *may* create a new evidence need; the audit found nothing
    made that happen. This is the deterministic object the loop feeds back to the
    necessity gate so that a conflict schedules its own resolving call.
    """

    id: str
    run_id: str
    capability: str
    expects: str
    reason: ExpansionReason
    correlation_id: str | None = None
    observation_ids: list[str] = Field(default_factory=list)
    detail: str = ""


class TierCostReport(_Base):
    """Per-tier token attribution for one prompt, plus what the tier caps discarded."""

    run_id: str = ""
    step: int = 0
    tiers: dict[str, int] = Field(default_factory=dict)
    total_tokens: int = 0
    dropped_tokens: int = 0
    over_cap_tiers: list[str] = Field(default_factory=list)


class MemoryCostReport(_Base):
    """What memory cost one step, split by class, so retrieval cost is a number."""

    baseline_tokens: int = 0
    active_tokens: int = 0
    retrieved_tokens: int = 0
    retrieved_entries: int = 0
    total_tokens: int = 0
