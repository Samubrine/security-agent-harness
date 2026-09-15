"""Run orchestration: build the spine, run it, persist everything, report.

This module is the only place that knows how the parts are assembled. Keeping assembly here means
the loop stays testable with fakes and the CLI stays a thin argument parser.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.analysers.cve_match import VulnerabilitySnapshot
from harness.analysers.correlate import Correlator
from harness.analysers.rules import RuleEngine
from harness.artifacts import ArtifactStore, ProvenanceLog
from harness.context.builder import ContextBuilder
from harness.context.resolver import ContextResolver, ResolvedContext
from harness.errors import ConfigError
from harness.events import EventLog
from harness.llm.client import build_client
from harness.memory.index import LongTermIndex
from harness.memory.manager import MemoryManager
from harness.models import Budget, ModelMetadata, RunConfig, RunSummary
from harness.parsers.registry import ParserRegistry
from harness.policy.engine import AutoApproveGate, AutoDenyGate, PolicyEngine, RecordingGate
from harness.policy.grants import GrantBook
from harness.policy.taint import TaintTracker
from harness.providers.necessity import NecessityGate
from harness.providers.registry import ProviderRegistry
from harness.providers.router import Router
from harness.runtime.analysers import (
    MEDIA_TYPE as VULN_MEDIA_TYPE,
    PARSER_NAME as VULN_PARSER_NAME,
    CveMatcherProvider,
    parse_vulnerability_json,
)
from harness.runtime.capabilities import with_logical_capabilities
from harness.runtime.loop import InvestigationLoop
from harness.runtime.replay import ReplayWriter
from harness.tokens import BudgetGuard, TokenLedger
from harness.util import atomic_write_json, iso, new_id, sha256_json, utcnow


@dataclass
class RunRequest:
    """Everything a caller may vary. Anything not here is frozen by design."""

    objective: str
    skill: str
    scope_path: Path
    public_key_path: Path | None = None
    root: Path = field(default_factory=lambda: Path.cwd())
    runs_root: Path | None = None
    #: When set, the run is written exactly here instead of under ``runs_root``. The evaluation
    #: harness drives the CLI with ``--out`` and scores the directory it named, so the run id and
    #: the directory name are allowed to differ.
    run_dir: Path | None = None
    model_backend: str = "scripted"
    model_id: str = "scripted-planner"
    endpoint: str | None = None
    target_alias: str | None = None
    approval_mode: str = "deny"
    approval_answers: tuple[bool, ...] = ()
    dry_run: bool = False
    allow_remote: bool = False
    run_id: str | None = None
    snapshot_path: Path | None = None
    fixture_root: Path | None = None
    log_root: Path | None = None
    enable_memory_curation: bool = True
    extra_providers: tuple[Any, ...] = ()

    def resolved_runs_root(self) -> Path:
        return Path(self.runs_root) if self.runs_root else Path(self.root) / "runs"


@dataclass
class RunArtifacts:
    run_id: str
    run_dir: Path
    report_markdown: Path
    report_json: Path
    summary: RunSummary
    stop_reason: str | None = None


def _budgets_for(skill: Any) -> Budget:
    budgets = Budget()
    if not skill.budget_override:
        return budgets
    allowed = {name for name in Budget.model_fields if name in skill.budget_override}
    unknown = set(skill.budget_override) - allowed
    if unknown:
        raise ConfigError(f"skill {skill.name!r} overrides unknown budgets: {sorted(unknown)}")
    merged = budgets.model_dump()
    merged.update({k: int(v) for k, v in skill.budget_override.items() if k in allowed})
    return Budget.model_validate(merged)


def _approval_gate(mode: str, answers: tuple[bool, ...]) -> Any:
    if mode == "approve":
        return AutoApproveGate()
    if mode == "deny":
        return AutoDenyGate()
    if mode == "scripted":
        return RecordingGate(list(answers))
    raise ConfigError(f"unknown approval mode {mode!r}; expected deny, approve or scripted")


def _register_parsers(parsers: ParserRegistry) -> None:
    """Register the deterministic parsers. A missing implementation is a wiring bug, not a gap."""
    from harness.parsers import auth_log, nmap_xml, nginx_access
    from harness.parsers.mcp_json import MCP_MEDIA_TYPE, parse_mcp_json

    parsers.register("application/nmap+xml", "nmap_xml", nmap_xml.parse_nmap_xml)
    parsers.register("text/x-authlog", "auth_log", auth_log.parse_auth_log)
    parsers.register("text/x-nginx-access", "nginx_access", nginx_access.parse_nginx_access)
    parsers.register(MCP_MEDIA_TYPE, "mcp_json", parse_mcp_json)
    parsers.register(VULN_MEDIA_TYPE, VULN_PARSER_NAME, parse_vulnerability_json)


def _build_registry(
    request: RunRequest,
    snapshot: VulnerabilitySnapshot,
    observations: Any,
    run_id: str,
) -> ProviderRegistry:
    from harness.providers.native.logfile import LogFileProvider
    from harness.providers.native.nmap import NmapProvider
    from harness.providers.native.synthetic import SyntheticProvider

    fixture_root = Path(request.fixture_root) if request.fixture_root else Path(__file__).resolve().parents[3] / "tests" / "fixtures"
    log_root = Path(request.log_root) if request.log_root else fixture_root / "logs"

    registry = ProviderRegistry()
    # The synthetic provider is registered first for determinism in tests and CI; the real nmap
    # provider is registered alongside it, which is what makes this capability multi-provider
    # before any MCP server exists.
    registry.register(SyntheticProvider(fixture_root=fixture_root / "nmap"))
    registry.register(NmapProvider())
    registry.register(LogFileProvider(root=log_root))
    registry.register(CveMatcherProvider(snapshot=snapshot, observations=observations))
    for provider in request.extra_providers:
        registry.register(provider)
    return registry


def _persist(run_dir: Path, run_id: str, config: RunConfig, summary: RunSummary, state: Any) -> None:
    from harness.util import append_jsonl

    observations = [obs.model_dump(mode="json") for obs in sorted(state.observations.values(), key=lambda o: o.id)]
    _write_jsonl(run_dir / "observations.jsonl", observations)
    # The same records are written once as JSON arrays as well as once as JSONL. The JSONL files are
    # the append-only working form; the JSON arrays are what the evaluation harness and any external
    # reader consume, and keeping both means neither has to guess at the other's shape.
    atomic_write_json(run_dir / "observations.json", observations)
    _write_jsonl(run_dir / "claims.jsonl", [c.model_dump(mode="json") for c in state.claims])
    _write_jsonl(run_dir / "findings.jsonl", [])
    atomic_write_json(run_dir / "findings.json", [f.model_dump(mode="json") for f in state.findings])
    _write_jsonl(run_dir / "gaps.jsonl", [g.model_dump(mode="json") for g in state.gaps])
    _write_jsonl(
        run_dir / "provider-decisions.jsonl",
        [d.model_dump(mode="json") for d in state.decisions],
    )
    executions = [e.model_dump(mode="json") for e in state.executions]
    _write_jsonl(run_dir / "executions.jsonl", executions)
    atomic_write_json(run_dir / "executions.json", executions)
    _write_jsonl(
        run_dir / "correlations.jsonl", [c.model_dump(mode="json") for c in state.correlations]
    )
    # Provider-call telemetry (design 08 section 9). Written in the shape the evaluation harness
    # reads, so provider efficiency and necessity precision are measured rather than asserted.
    telemetry = [getattr(item, "model_dump", lambda **_: item)(mode="json") for item in getattr(state, "telemetry", [])]
    _write_jsonl(run_dir / "telemetry.jsonl", telemetry)
    # ``trace.jsonl`` is the run's single trace per the design's layout: prompts and provider
    # telemetry next to the token ledger. The ledger appended its own lines during the run, so the
    # provider records are appended to the same file rather than living only in telemetry.jsonl.
    if telemetry:
        for record in telemetry:
            append_jsonl(run_dir / "trace.jsonl", record)
    _write_jsonl(run_dir / "rejected-proposals.jsonl", list(state.rejected_proposals))

    manifest = json_safe(config.model_dump(mode="json"))
    manifest.update(
        {
            "run_id": run_id,
            "status": summary.status,
            "stop_reason": state.stop_reason,
            "summary": summary.model_dump(mode="json"),
        }
    )
    atomic_write_json(run_dir / "run.json", manifest)


def _write_jsonl(path: Path, rows: list[Any]) -> None:
    if path.exists():
        path.unlink()
    from harness.util import append_jsonl

    for row in rows:
        append_jsonl(path, row)


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    return value


def execute_run(request: RunRequest) -> RunArtifacts:
    root = Path(request.root)
    run_id = request.run_id or f"run-{utcnow().strftime('%Y%m%dT%H%M%S')}-{new_id('', 2)[1:]}"
    run_dir = Path(request.run_dir) if request.run_dir else request.resolved_runs_root() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    snapshot_path = (
        Path(request.snapshot_path)
        if request.snapshot_path
        else Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vuln" / "snapshot_2026-09.json"
    )
    snapshot = VulnerabilitySnapshot.load(snapshot_path)

    memory = MemoryManager(root)
    index = LongTermIndex(root / "memory" / "long_term" / "index.sqlite")
    resolver = ContextResolver(root=root, memory=memory, index=index)
    resolved: ResolvedContext = resolver.resolve(
        objective=request.objective,
        skill_name=request.skill,
        scope_path=Path(request.scope_path),
        public_key_path=request.public_key_path,
        run_id=run_id,
    )
    if request.target_alias:
        filtered = [g for g in resolved.grants.grants if g.alias == request.target_alias]
        if not filtered:
            raise ConfigError(
                f"alias {request.target_alias!r} is not in the scope; "
                f"authorised aliases: {resolved.aliases()}"
            )
        resolved.grants = GrantBook(filtered)
    # Compose the logical capability vocabulary onto the minted grants. The scope record speaks
    # about resources; skills speak about operations; this is the one place that says which
    # operation a resource kind can serve.
    resolved.grants = with_logical_capabilities(resolved.grants)

    budgets = _budgets_for(resolved.skill)
    model = build_client(
        backend=request.model_backend,
        model_id=request.model_id,
        endpoint=request.endpoint,
        allow_remote=request.allow_remote,
        script=Path(request.endpoint) if request.model_backend == "replay" and request.endpoint else None,
    )

    config = RunConfig(
        run_id=run_id,
        objective=request.objective,
        skill=resolved.skill.name,
        scope_id=resolved.scope.scope_id,
        scope_sha256=sha256_json(resolved.scope.model_dump(mode="json")),
        model=model.metadata,
        budgets=budgets,
        memory=resolved.memory,
        harness_version=__import__("harness").__version__,
        git_sha=_git_sha(root),
        dry_run=request.dry_run,
        created_at=utcnow(),
        enable_remote_egress=request.allow_remote,
    )

    store = ArtifactStore(run_dir, run_id, max_bytes=budgets.max_artifact_bytes)
    events = EventLog(run_dir / "events.jsonl", run_id)
    provenance = ProvenanceLog(run_dir / "provenance.jsonl")
    ledger = TokenLedger(run_dir / "trace.jsonl", model.metadata)
    guard = BudgetGuard(budgets)
    replay = ReplayWriter(run_dir / "replay.json")
    taint = TaintTracker()

    parsers = ParserRegistry()
    _register_parsers(parsers)

    loop_state: dict[str, Any] = {}
    registry = _build_registry(
        request, snapshot, observations=lambda: list(loop_state.get("observations", [])), run_id=run_id
    )

    rules = RuleEngine()
    correlator = Correlator(run_id)
    policy = PolicyEngine(resolved.grants, dry_run=request.dry_run)
    gate = NecessityGate(registry, budgets, skill=resolved.skill, budgets_guard=guard)
    router = Router(registry)
    approvals = _approval_gate(request.approval_mode, request.approval_answers)

    loop = InvestigationLoop(
        config=config,
        context=resolved,
        model=model,
        registry=registry,
        gate=gate,
        policy=policy,
        approvals=approvals,
        store=store,
        events=events,
        provenance=provenance,
        ledger=ledger,
        budgets=guard,
        parsers=parsers,
        replay=replay,
        rules=rules,
        snapshot=snapshot,
        correlator=correlator,
        builder=ContextBuilder(),
        taint=taint,
        router=router,
    )
    # The matcher reads the loop's live observation set, which is why this indirection exists:
    # the provider must never be handed model-supplied data about which evidence to read.
    registry.get("native:cve_matcher").observations = lambda: list(
        loop.state.observations.values()
    )  # type: ignore[attr-defined]

    state = loop.run()
    loop_state["observations"] = list(state.observations.values())
    summary = loop.summary

    if request.enable_memory_curation:
        _curate_memory(memory, index, state, events, run_id)

    _persist(run_dir, run_id, config, summary, state)
    # The run directory carries its own authorisation record. A run whose scope record only existed
    # on the machine that started it could not be audited later, and the scope is the artifact that
    # answers "under whose authority did this happen?".
    from harness.util import atomic_write_json as _write_json

    _write_json(run_dir / "scope.json", resolved.scope.model_dump(mode="json"))

    from harness.report.build import write_report

    report_md, report_json = write_report(run_dir=run_dir)
    return RunArtifacts(
        run_id=run_id,
        run_dir=run_dir,
        report_markdown=report_md,
        report_json=report_json,
        summary=summary,
        stop_reason=state.stop_reason,
    )


def _curate_memory(memory: MemoryManager, index: LongTermIndex, state: Any, events: EventLog, run_id: str) -> None:
    """Post-run memory curation (design 01, step 15).

    Memory writes happen after the investigation is over, which is what keeps the run's evidence
    graph independent of anything the harness learned while producing it.
    """
    from harness.memory.curator import MemoryCurator

    try:
        curator = MemoryCurator(memory, index)
        proposal = curator.propose(
            run_id=run_id,
            findings=list(state.findings),
            gaps=list(state.gaps),
            provider_calls=[],
            events=events.records(),
        )
    except Exception as exc:  # noqa: BLE001 - a curation failure must not invalidate a good run
        events.append("MEMORY_UPDATE_FAILED", {"reason": str(exc)})
        return
    events.append(
        "MEMORY_UPDATE_PROPOSED",
        {
            "active_sections": {k: v for k, v in proposal.active_sections.items()},
            "long_term_entries": [e.id for e in proposal.long_term_entries],
            "rationale": proposal.rationale,
        },
    )
    commit = curator.commit(proposal, run_id=run_id)
    for entry_id in commit.promoted:
        events.append("LONG_TERM_MEMORY_WRITTEN", {"entry": entry_id, "run": run_id})
    if commit.compaction is not None:
        events.append(
            "MEMORY_COMPACTED",
            {
                "before": commit.compaction.before_digest,
                "after": commit.compaction.after_digest,
                "archived": commit.compaction.archived_snapshot,
                "removed_duplicates": commit.compaction.removed_duplicates,
            },
        )


def _git_sha(root: Path) -> str | None:
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha or None
