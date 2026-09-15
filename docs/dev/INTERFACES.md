# Internal Interface Contract

Normative for implementation work. It exists so several subsystems can be built in parallel
against one frozen vocabulary instead of drifting into six private data models.

## 0. Ground rules

- Python 3.12+ (the dev venv is 3.14). Run everything through the project venv:
  `.venv/bin/python -m pytest tests -q`.
- Import shared records from `harness.models` and primitives from `harness.util`. Do not define
  a second model for something that already exists there. If a record is genuinely missing, add
  it to `harness/models.py` and say so in your final message.
- Errors come from `harness.errors`. Do not raise bare `Exception` in library code.
- Pydantic models are strict (`extra="forbid"`) and timezone-aware. Never construct a naive
  datetime; use `harness.util.utcnow()`.
- No `shell=True`, ever. Provider commands are argv arrays.
- No test may touch the network, the docker daemon, or a real model endpoint. Deterministic
  fixtures only.
- Every module must import in isolation: `python -c "import harness.<module>"` works.

## 1. Shared primitives (already written, do not redefine)

harness.util

| Function | Contract |
|---|---|
| `utcnow()` | aware UTC now |
| `iso(dt)` | canonical ISO-8601 with trailing Z; raises on naive input |
| `new_id(prefix, nbytes=6)` | opaque random id such as `o-9f2c31ab` |
| `canonical_json(obj)` | sorted keys, compact separators; the hashing form |
| `sha256_hex(bytes)`, `sha256_text(str)`, `sha256_json(obj)` | digests |
| `atomic_write_bytes`, `atomic_write_text`, `atomic_write_json`, `read_json`, `append_jsonl`, `read_jsonl` | durable IO |
| `estimate_tokens(text)` | about 4 chars per token fallback estimator |
| `clamp_text(text, limit)` | bounded text with an explicit truncation marker |
| `strip_control_chars(text)` | removes ANSI/control characters from untrusted text |
| `safe_relpath(root, candidate)` | resolve-or-raise path containment check |

## 2. Module-by-module public API

Every module below must expose exactly these names. Extra private helpers are fine.

### harness.events

```python
class EventLog:
    def __init__(self, path: Path, run_id: str) -> None
    def append(self, event_type: str, data: dict[str, Any] | None = None) -> EventRecord
    def records(self) -> list[EventRecord]
    @property
    def head_hash(self) -> str
    def verify_chain(self) -> bool          # raise EventChainError on a broken chain
    def count(self) -> int
```

Hash rule is exactly section 12 of `docs/design/02-data-model.md`: canonicalise the record
without `event_hash`, then `sha256(prev_event_hash + canonical_json(record))`.

### harness.artifacts

```python
class ArtifactStore:
    def __init__(self, root: Path, run_id: str, *, max_bytes: int = 32 * 1024 * 1024) -> None
    def put(self, data: bytes, *, media_type: str, producer: str,
            execution_id: str | None = None, taint: TaintLevel = "T2") -> ArtifactMeta
    def put_text(self, text: str, **kw) -> ArtifactMeta
    def get(self, digest: str) -> bytes
    def meta(self, digest: str) -> ArtifactMeta
    def exists(self, digest: str) -> bool
    def ref(self, digest: str, *, byte_start: int, byte_end: int, locator: str | None = None,
            line_start: int | None = None, line_end: int | None = None,
            taint: TaintLevel = "T3") -> EvidenceRef        # sets span_sha256
    def verify_ref(self, ref: EvidenceRef) -> bool            # recompute span hash from bytes

class ProvenanceLog:
    def __init__(self, path: Path) -> None
    def add(self, subject: str, relation: str, obj: str, **extra: Any) -> None
    def triples(self) -> list[dict[str, Any]]
```

Artifact layout: `root/artifacts/<aa>/<sha256>` plus `<sha256>.meta.json`, where `aa` is the
first two hex characters of the digest. Digest strings are `sha256:<hex>`.

### harness.tokens

```python
class TokenLedger:
    def __init__(self, path: Path, model: ModelMetadata) -> None
    def record(self, step: int, *, input_tokens: int, output_tokens: int,
               tiers: dict[str, int] | None = None, memory_tokens: int = 0,
               evidence_tokens: int = 0) -> TokenLedgerEntry
    def total_input(self) -> int
    def total_output(self) -> int
    def entries(self) -> list[TokenLedgerEntry]

class BudgetGuard:
    def __init__(self, budgets: Budget) -> None
    def step(self) -> None                                     # raises BudgetExhausted
    def provider_call(self, n: int = 1) -> None                # raises BudgetExhausted
    def add_tokens(self, prompt: int, completion: int) -> None # raises BudgetExhausted
    def add_artifact_bytes(self, n: int) -> None               # raises BudgetExhausted
    def failure(self) -> None                                  # raises BudgetExhausted
    def success(self) -> None                                  # clears consecutive failures
    def check_wall_clock(self) -> None                         # raises BudgetExhausted
    def snapshot(self) -> dict[str, int]
```

### harness.policy

Three modules: `policy/scope.py`, `policy/grants.py`, `policy/engine.py`, `policy/taint.py`,
plus `policy/__init__.py` re-exporting the public names below.

```python
# scoping: the authorisation record
def generate_keypair(private_path: Path, public_path: Path) -> None
def sign_scope(scope: ScopeFile, private_key_path: Path) -> ScopeFile
def verify_scope(scope: ScopeFile, public_key_path: Path | None) -> None   # raises ScopeError
def load_scope(path: Path, *, public_key_path: Path | None = None,
               allow_unsigned: bool = False, now: datetime | None = None) -> ScopeFile

# grants.py
class GrantBook:
    def __init__(self, grants: list[Grant]) -> None
    @property
    def grants(self) -> list[Grant]
    def by_alias(self, alias: str) -> list[Grant]
    def get(self, grant_id: str) -> Grant                      # raises GrantError
    def require(self, grant_id: str, capability: str, when: datetime | None = None) -> Grant
    def catalogue_for(self, capability: str) -> list[str]      # aliases that can serve it
    def digest(self) -> str

def mint_from_scope(scope: ScopeFile, *, run_id: str, ttl_s: int = 3600,
                    now: datetime | None = None) -> GrantBook

# engine.py
class PolicyEngine:
    def __init__(self, grants: GrantBook, *, dry_run: bool = False) -> None
    def decide(self, *, provider: ProviderSpec, capability: str, grant_id: str,
               args: dict[str, Any], taint: TaintLevel = "T1",
               proposal_authored_under_taint: bool = False,
               novel_resource: bool = False) -> PolicyDecision

class ApprovalGate(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalResponse: ...

class AutoDenyGate(ApprovalGate): ...      # non-interactive default
class AutoApproveGate(ApprovalGate): ...   # used by --yes and dry-run rendering paths
class RecordingGate(ApprovalGate):
    def __init__(self, answers: list[bool]) -> None

# taint.py
class TaintTracker:
    def __init__(self, *, nonce: str | None = None) -> None
    @property
    def nonce(self) -> str
    def register(self, level: TaintLevel, origin: str) -> None
    def level_of(self, origin: str) -> TaintLevel
    def max_level(self) -> TaintLevel
    def taint_gate_triggered(self, *, args: dict[str, Any], proposal_new_resource: bool,
                             side_effectful: bool) -> bool
    def spotlight(self, text: str, *, origin: str, level: TaintLevel = "T3") -> str
    def strip_nonce(self, text: str) -> str
    def detect_injection(self, text: str) -> list[str]         # matched injection patterns
```

Policy rules to implement (see `docs/design/03-policy-and-safety.md` sections 3, 4 and 7):

- `LOW` becomes `allow`; `MEDIUM` becomes `allow` unless the provider requires network egress
  or the run is strict, in which case `ask`; `HIGH` is always `ask`.
- Taint escalation: a side-effectful or egress call whose arguments derive from `T3`, or which
  was authored while `T3` was in context and references a novel resource, is forced to `ask`
  even when its risk class is `LOW`. Record `risk_downgraded_by_taint=True`.
- `dry_run` never returns `allow` for a side-effectful or egress provider; it returns `deny`
  with a `dry_run` reason so the plan is still rendered.
- A missing, expired or insufficient grant produces `deny`; `decide()` never raises.

### harness.providers

```python
# base.py
@dataclass
class ProviderRequest:
    run_id: str
    execution_id: str
    capability: str
    args: dict[str, Any]
    grant: Grant
    target_alias: str
    timeout_s: int

@dataclass
class ProviderResult:
    provider: str
    capability: str
    exit_status: ExitStatus
    stdout: bytes | None = None
    media_type: str = "application/octet-stream"
    structured: dict[str, Any] | None = None     # MCP-style structured response
    argv: list[str] | None = None
    provider_version: str | None = None
    error: str | None = None
    gaps: list[EvidenceGap] = field(default_factory=list)

class Provider(Protocol):
    spec: ProviderSpec
    def invoke(self, request: ProviderRequest) -> ProviderResult: ...

# registry.py
class ProviderRegistry:
    def __init__(self, providers: Iterable[Provider] = ()) -> None
    def register(self, provider: Provider) -> None
    def get(self, provider_id: str) -> Provider                 # raises KeyError
    def by_capability(self, capability: str) -> list[Provider]
    def specs(self) -> list[ProviderSpec]
    def capabilities(self) -> list[str]

# necessity.py
class NecessityGate:
    def __init__(self, registry: ProviderRegistry, budgets: Budget, *,
                 skill: SkillSpec | None = None, budgets_guard: BudgetGuard | None = None) -> None
    def decide(self, *, capability: str, evidence_needed: str, expects: str,
               existing_observations: Sequence[Observation],
               cache: dict[str, ProviderResult] | None = None,
               failed_providers: Collection[str] = (),
               conflicts: Sequence[Correlation] = (),
               trust_diversity_required: bool = False,
               prefer: str | None = None) -> ProviderDecision

# router.py
class Router:
    def __init__(self, registry: ProviderRegistry) -> None
    def resolve(self, decision: ProviderDecision) -> list[Provider]
    def eligible(self, capability: str) -> list[ProviderSpec]
```

Necessity rules, v1 and fully deterministic (section 4 of
`docs/design/08-local-first-memory-and-routing.md`):

1. If existing observations already cover the fields implied by `expects`, return `satisfied`
   with `selected=[]` and the satisfying observation ids in `satisfied_by`.
2. Otherwise rank eligible providers: native before mcp before external trust class; then lower
   risk; then lower `estimated_cost.latency_ms`; then provider id. Select exactly one, verdict
   `single`.
3. A provider in `failed_providers` is rejected with reason `provider_failure`, and the next
   eligible provider becomes the selection with verdict `expand` and reason `provider_failure`.
4. An unresolved `conflict` correlation for the same capability gives verdict `expand` with
   `conflict_resolution`.
5. `trust_diversity_required=True` gives verdict `expand` with `trust_diversity`.
6. No eligible provider gives `deny`.
7. A budget that cannot support the call gives `defer`, with `budget_snapshot` populated from
   `budgets_guard.snapshot()` when a guard was supplied.
8. Never select more than `skill.verification.max_providers_per_need` (falling back to
   `Budget.max_providers_per_need`, hard cap 3). Selecting three requires the skill to ask for it.

### harness.providers.native

```text
native/nmap.py       NmapProvider      capabilities: service.enumerate, http.probe (spec.excludes http.probe)
native/synthetic.py  SyntheticProvider capability: service.enumerate           (fixture-backed, deterministic)
native/logfile.py    LogFileProvider   capability: log.read
mcp/client.py        McpStdioClient    JSON-RPC 2.0 over stdio (initialize, tools/list, tools/call)
mcp/provider.py      McpProvider       wraps a client, advertises capabilities from its tool list
```

`NmapProvider.invoke` must build argv as a list, never a shell string, and it must resolve the
host from `request.grant.resource` rather than from model-supplied text. `SyntheticProvider`
returns the bytes of `tests/fixtures/nmap/lab_web_01.xml` for the alias `lab-web-01` and
`tests/fixtures/nmap/lab_web_02.xml` for `lab-web-02`, and reports `provider_failure` for any
other alias. Both declare `media_type="application/nmap+xml"` and `parser="nmap_xml"`.

### harness.parsers

```python
ParserFn = Callable[..., ParseResult]

@dataclass
class ParseResult:
    observations: list[Observation]
    gaps: list[EvidenceGap] = field(default_factory=list)

class ParserRegistry:
    def register(self, media_type: str, name: str, fn: ParserFn, *, version: str = "0.1.0") -> None
    def parse(self, data: bytes, media_type: str, *, execution: ProviderExecution,
              run_id: str, trust_class: TrustClass = "local_tool",
              artifact_digest: str | None = None,
              evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None) -> ParseResult
```

Media types: `application/nmap+xml`, `text/x-authlog`, `text/x-nginx-access`,
`application/vnd.harness.mcp+json`.

Observation kinds and their required `value` keys are fixed by the fixtures described in
section 4:

| kind | value keys |
|---|---|
| `service` | `target`, `port`, `protocol`, `state`, `service`, `product`, `version`, `cpe` |
| `host_state` | `target`, `state` |
| `scan_meta` | `scanner`, `scan_type`, `started_at` |
| `auth_event` | `target`, `event`, `src_ip`, `user`, `timestamp`, `outcome` |
| `auth_summary` | `target`, `window`, `failed_logins`, `successful_logins`, `distinct_sources`, `top_source`, `top_source_failures` |
| `http_event` | `target`, `src_ip`, `method`, `path`, `status`, `timestamp`, `suspicious` |
| `http_summary` | `target`, `total_requests`, `suspicious_requests`, `paths` |
| `banner` | `target`, `port`, `banner`, `product`, `version` |
| `injection_attempt` | `target`, `source`, `pattern`, `payload_excerpt` |

Every observation carries at least one `EvidenceRef` whose span hashes back to the artifact
bytes. Use `evidence_of(byte_start, byte_end)` when it is supplied; otherwise build refs against
`artifact_digest` using byte offsets into `data`.

The auth-log parser emits per-event observations plus one `auth_summary`; the nginx parser does
the same with `http_summary`. The nmap parser emits `scan_meta`, `host_state`, `service` per
open port, and a `banner` observation whenever the XML carries a service banner or extraports
text. An `injection_attempt` observation is emitted by whichever parser sees an injection
pattern, via `TaintTracker.detect_injection`.

### harness.analysers

```python
# rules.py
class RuleEngine:
    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None
    def evaluate(self, observations: Sequence[Observation]) -> list[Claim]

# cve_match.py
class VulnerabilitySnapshot:
    digest: str
    entries: list[dict[str, Any]]
    @classmethod
    def load(cls, path: Path) -> VulnerabilitySnapshot
    def match(self, cpes: Sequence[str], versions: dict[str, str] | None = None) -> list[dict[str, Any]]

@dataclass
class CveCandidate:
    cve: str
    cpe: str
    product: str
    version: str
    cvss: float
    severity: str
    summary: str
    matched_on: str
    observation_ids: list[str]

def cpe_from_observation(obs: Observation) -> str | None
def extract_cpes(observations: Sequence[Observation]) -> list[str]
def candidate_cves(observations: Sequence[Observation], snapshot: VulnerabilitySnapshot,
                   *, min_cvss: float = 0.0) -> tuple[list[CveCandidate], list[EvidenceGap]]

# correlate.py
class Correlator:
    def __init__(self, run_id: str = "") -> None
    def add(self, observations: Sequence[Observation]) -> list[Correlation]
    def correlations(self) -> list[Correlation]
```

The CVE matcher is deterministic and offline: normalise CPE 2.3 strings and compare the observed
version against the entry range (`version_start_including`, `version_end_excluding`) for the same
vendor and product. An unparsable or absent version yields no match and a `no_cpe` gap, never a
guess. A missing match is never rendered as safe.

### harness.findings

```python
# builder.py
def build_findings(*, run_id: str, observations: Sequence[Observation],
                   claims: Sequence[Claim], candidates: Sequence[CveCandidate],
                   correlations: Sequence[Correlation], skill: str) -> list[Finding]

# validate.py
@dataclass
class ValidationResult:
    ok: bool
    violations: list[str]

def validate_finding(finding: Finding, *, observations: Mapping[str, Observation],
                     store: ArtifactStore) -> ValidationResult
def validate_all(findings: Sequence[Finding], *, observations: Mapping[str, Observation],
                 store: ArtifactStore) -> tuple[list[Finding], list[Finding]]
```

`validate_all` returns `(accepted, rejected)` so the caller can log `VALIDATION_FAILED` for each
rejection. Invariants enforced: every finding has at least one claim; every claim is either a
supporting observation reference or a rule-derived/observed claim with real observation ids;
every referenced observation exists in the current run; every evidence span recomputes from its
artifact; every reported CVE appears in the recorded snapshot digest; severity is one of the
fixed rubric values and is never taken from model prose.

### harness.memory

```python
# manager.py
class MemoryManager:
    def __init__(self, root: Path, *, active_cap_bytes: int = 4096) -> None
    def load_baseline(self) -> str
    def load_active(self) -> str
    def digests(self) -> MemoryDigests
    def write_active(self, text: str) -> MemoryCompaction | None   # compacts when over the cap
    def append_active_section(self, title: str, bullets: Sequence[str]) -> None

# index.py
class LongTermIndex:
    def __init__(self, db_path: Path) -> None
    def add(self, entry: MemoryEntry) -> None
    def get(self, entry_id: str) -> MemoryEntry | None
    def all(self) -> list[MemoryEntry]
    def search(self, query: str, *, limit: int = 5, kinds: Sequence[MemoryKind] | None = None,
               include_superseded: bool = False) -> list[RetrievedMemory]
    def mark_used(self, entry_ids: Sequence[str], when: datetime) -> None

# curator.py
@dataclass
class CuratorProposal:
    active_sections: dict[str, list[str]]
    long_term_entries: list[MemoryEntry]
    rationale: str

@dataclass
class CuratorCommit:
    promoted: list[str]
    compaction: MemoryCompaction | None
    active_sha256: str

class MemoryCurator:
    def __init__(self, manager: MemoryManager, index: LongTermIndex) -> None
    def propose(self, *, run_id: str, findings: Sequence[Finding],
                gaps: Sequence[EvidenceGap], provider_calls: Sequence[ProviderCallTelemetry],
                events: Sequence[EventRecord]) -> CuratorProposal
    def commit(self, proposal: CuratorProposal, *, run_id: str) -> CuratorCommit
```

Rules: nothing from a single failed run is promoted as `stable`; every promoted entry lists
`run_id` in `source_runs`; the active-memory file never exceeds the cap after `write_active`; a
pre-compaction snapshot is written under `memory/archive/` before the rewrite. The index uses
SQLite FTS5 and no vector database.

### harness.llm

```python
# client.py
@dataclass
class ModelResponse:
    text: str
    input_tokens: int
    output_tokens: int
    raw: dict[str, Any] = field(default_factory=dict)

class ModelClient(Protocol):
    metadata: ModelMetadata
    def complete(self, *, system: str, user: str, step: int) -> ModelResponse: ...

def build_client(*, backend: str, model_id: str, endpoint: str | None = None,
                 temperature: float = 0.0, seed: int | None = 0,
                 context_window: int = 8192, script: Path | None = None) -> ModelClient

# scripted.py
class ScriptedModelClient:
    def __init__(self, metadata: ModelMetadata, *, plan: list[dict[str, Any]] | None = None) -> None

# replay.py
class ReplayModelClient:
    def __init__(self, records: Sequence[ReplayRecord]) -> None

# prompts.py
def system_prompt() -> str
def render_turn_prompt(*, objective: str, skill: SkillSpec, catalogue: dict[str, Any],
                       run_digest: str, memory_context: str, evidence_context: str) -> str
def parse_agent_turn(text: str) -> AgentTurn    # tolerant of fenced JSON; raises ModelClientError

# schemas.py
def agent_turn_schema() -> dict[str, Any]
def export_schemas(dest: Path) -> dict[str, Path]
```

Backends: `scripted` (deterministic, no server), `replay`, `ollama`, `openai` (any
OpenAI-compatible local server). `ollama` and `openai` are the only ones that touch the network,
and they only ever reach a configured local endpoint; a non-loopback endpoint requires
`enable_remote_egress`. `build_client` raises `ConfigError` for an unknown backend and
`EgressViolation` for a non-loopback endpoint without egress enabled.

`ScriptedModelClient` is a small deterministic policy, not a stub that returns constant text: it
inspects the run digest it is given and proposes, in order, `service.enumerate` then
`vulnerability.match` for a `port_scan` objective, then `stop`. It must produce byte-identical
turns for identical inputs, and it must never propose a capability that is absent from the
catalogue it was handed.

### harness.context

```python
# resolver.py
@dataclass
class ResolvedContext:
    run_id: str
    objective: str
    skill: SkillSpec
    scope: ScopeFile
    grants: GrantBook
    memory: MemoryDigests
    baseline_text: str
    active_text: str
    retrieved: list[RetrievedMemory]

class ContextResolver:
    def __init__(self, *, root: Path, memory: MemoryManager, index: LongTermIndex) -> None
    def resolve(self, *, objective: str, skill_name: str, scope_path: Path,
                public_key_path: Path | None, run_id: str,
                retrieved_limit: int = 3) -> ResolvedContext

# builder.py
@dataclass
class PromptBundle:
    system: str
    user: str
    tiers: dict[str, int]      # tier name -> token estimate

class ContextBuilder:
    def __init__(self, *, tier_caps: dict[str, int] | None = None) -> None
    def build(self, *, resolved: ResolvedContext, catalogue: dict[str, Any],
              run_digest: str, evidence_rollup: str = "") -> PromptBundle

# retrieval.py
def retrieve_for_plan(index: LongTermIndex, *, objective: str, skill: SkillSpec,
                      limit: int = 3) -> list[RetrievedMemory]

# spotlight.py
class Spotlight:
    def __init__(self, tracker: TaintTracker) -> None
    def wrap(self, text: str, *, origin: str, level: TaintLevel = "T3") -> str
    def unwrap(self, text: str) -> str
```

Context tiers follow section 10 of `docs/design/02-data-model.md`: `C0` system, policy and
capability schemas; `C1` baseline plus bounded active memory; `C2` deterministic run rollup;
`C3` retrieved long-term memory; `C4` bounded evidence spans. Raw artifacts (`C5`) never enter a
prompt.

### harness.runtime

```python
# fsm.py
class State(StrEnum):
    INIT = "init"
    CONTEXT_RESOLVED = "context_resolved"
    PLANNING = "planning"
    VALIDATING = "validating"
    NECESSITY = "necessity"
    POLICY = "policy"
    EXECUTING = "executing"
    PARSING = "parsing"
    CORRELATING = "correlating"
    FINDINGS = "findings"
    TERMINATING = "terminating"
    DONE = "done"
    FAILED = "failed"

@dataclass
class RunState:
    run_id: str
    state: State
    step: int = 0
    observations: dict[str, Observation]
    claims: list[Claim]
    findings: list[Finding]
    gaps: list[EvidenceGap]
    executions: list[ProviderExecution]
    decisions: list[ProviderDecision]
    correlations: list[Correlation]
    cache: dict[str, ProviderResult]
    failed_providers: set[str]
    consecutive_failures: int = 0
    stop_reason: str | None = None

# replay.py
class ReplayWriter:
    def __init__(self, path: Path) -> None
    def model(self, *, key: str, step: int, request: str, response: Any) -> None
    def provider(self, *, key: str, step: int, request: dict[str, Any], response: Any) -> None

class Replayer:
    def __init__(self, run_dir: Path) -> None
    def verify(self) -> bool
    def finding_digests(self) -> dict[str, str]
    def report(self) -> dict[str, Any]

# loop.py
class InvestigationLoop:
    def __init__(self, *, config: RunConfig, context: ResolvedContext,
                 model: ModelClient, registry: ProviderRegistry, gate: NecessityGate,
                 policy: PolicyEngine, approvals: ApprovalGate, store: ArtifactStore,
                 events: EventLog, provenance: ProvenanceLog, ledger: TokenLedger,
                 budgets: BudgetGuard, parsers: ParserRegistry, replay: ReplayWriter,
                 rules: RuleEngine, snapshot: VulnerabilitySnapshot,
                 correlator: Correlator) -> None
    def run(self) -> RunState
```

### harness.report

```python
def build_report(*, run_dir: Path) -> tuple[str, dict[str, Any]]   # markdown, json
def write_report(*, run_dir: Path) -> tuple[Path, Path]
```

### harness.skills

```python
def load_skill(name: str, *, skills_dir: Path | None = None) -> SkillSpec
def list_skills(*, skills_dir: Path | None = None) -> list[SkillSpec]
```

### harness.cli

Typer app with commands `run`, `replay`, `doctor`, `scope sign`, `scope verify`, `eval run` and
`memory show`. `harness run --help` must work with no model endpoint configured.

## 3. Determinism rules

- Run ids come from the CLI, but everything inside a run that is hashed must be reproducible:
  sort collections before hashing, never hash a `set`, never fold wall-clock time into a digest
  except as an explicitly recorded field.
- `ScriptedModelClient` produces identical turns for identical inputs so integration tests are
  stable.

## 4. Fixtures (already in `tests/fixtures/`, read-only for implementers)

| Path | Contents |
|---|---|
| `nmap/lab_web_01.xml` | ports 22, 80, 8080 open; OpenSSH 8.2p1 Ubuntu 20.04 with an injected instruction inside the banner; nginx 1.18.0; Apache Tomcat 9.0.30 |
| `nmap/lab_web_02.xml` | 443/tcp nginx 1.18.0 only |
| `logs/auth.log` | a failed-password burst from 10.77.0.44 followed by an accepted login |
| `logs/nginx_access.log` | normal traffic plus traversal and scanner probes |
| `vuln/snapshot_2026-09.json` | offline CVE snapshot with version ranges for OpenSSH, nginx and Tomcat |
| `scope/lab_scope.json` | unsigned scope record for the lab network |

## 5. Definition of done for a subsystem

1. `python -c "import harness.<pkg>"` succeeds.
2. Its tests pass: `.venv/bin/python -m pytest tests/<your files> -q`.
3. No import cycle. Importing a sibling subsystem needs a comment explaining why.
4. You report the exact files you created or changed, and anything you deliberately left out.
