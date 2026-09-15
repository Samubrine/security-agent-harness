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

`TaintTracker.detect_injection` must delegate to `harness.util.detect_injection` instead of
defining its own patterns: the parsers read attacker-controlled banners too, and two pattern
lists would be two definitions of "this payload is an injection". `harness.util` also provides
`out_of_scope_ips(text, authorised)` for showing that a payload tried to widen scope.

Policy rules to implement (see `docs/design/03-policy-and-safety.md` sections 3, 4 and 7):

- `LOW` becomes `allow`; `MEDIUM` becomes `allow` unless the provider requires network egress
  or the run is strict, in which case `ask`; `HIGH` is always `ask`.
- Taint escalation: a side-effectful or egress call whose arguments derive from `T3`, or which
  was authored while `T3` was in context and references a novel resource, is forced to `ask`
  even when its risk class is `LOW`. Record `risk_downgraded_by_taint=True`.
- `dry_run` never returns `allow` for a side-effectful or egress provider; it returns `deny`
  with a `dry_run` reason so the plan is still rendered.
- A missing, expired or insufficient grant produces `deny`; `decide()` never raises.

`mint_from_scope` derives one grant per entry in `ScopeFile.aliases`. The alias is the
model-facing name and `Grant.resource` is the real one. An alias whose resource is not covered by
the scope's `networks` or `filesystem` is a `ScopeError` at mint time, which is what makes an
out-of-scope host unreachable instead of merely discouraged. The scope's `window` is checked at
load time; an expired or not-yet-valid window is a `ScopeError` and the run never starts.

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

The gate needs a deterministic definition of "the evidence already satisfies this need". Use a
module-level `CAPABILITY_OUTPUT_KINDS: dict[str, set[str]]` mapping a capability to the
observation kinds it is declared to produce, for example `service.enumerate` to
`{service, host_state, scan_meta}`. A request is `satisfied` when every kind in that set is
already present in `existing_observations`, or when a successful `cache` entry exists for the
selected provider and its observations are already present. An unknown capability falls back to
"not satisfied".

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


## 6. v1.1 frozen contract - closing the gaps in `docs/dev/AUDIT.md` section 6

Sections 0-5 still hold. This section is normative for the v1.1 workstreams and was frozen
before any of them started. Four rules apply to all of them:

- **Do not edit `harness/models.py`.** The records you need already exist:
  `ProvenanceIssue`, `ProvenanceAudit`, `EgressAssessment`, `FollowUpNeed`,
  `TierCostReport`, `MemoryCostReport`. Use their existing field names.
- **Do not edit `harness/errors.py`.** `EgressViolation` already exists.
- **Do not edit `runtime/loop.py`, `runtime/runner.py`, `policy/engine.py`, `cli.py`.**
  The orchestrator owns the wiring. If you need a call site added there, report it.
- **Do not import a sibling v1.1 module.** `verify`, `egress`, `replan` and `cost` must
  each import standalone. Depend only on section 1-5 modules.

### 6.1 `harness.runtime.verify` - invariant 6, referential integrity

Audit finding: `ProviderExecution.necessity_decision` and `.policy_decision` are required
fields, but nothing checked that the ids they name exist. A record citing a fabricated decision
id serialised happily.

```python
def audit_provenance(
    *,
    run_id: str,
    executions: Sequence[ProviderExecution],
    decisions: Sequence[ProviderDecision],
    policy_decisions: Sequence[PolicyDecision],
    observations: Sequence[Observation],
    findings: Sequence[Finding],
    gaps: Sequence[EvidenceGap] = (),
    grants: Sequence[Grant] = (),
    known_policy_decision_ids: Collection[str] = (),
) -> ProvenanceAudit
def audit_run_dir(run_dir: Path) -> ProvenanceAudit
```

Each check emits a distinct `ProvenanceIssue.code`. Severity is `error` unless marked:

| code | condition |
|---|---|
| `execution_necessity_decision_missing` | an execution's `necessity_decision` is not the id of any supplied `ProviderDecision` |
| `execution_policy_decision_missing` | an execution's `policy_decision` is not a supplied policy decision id and not in `known_policy_decision_ids` |
| `policy_decision_execution_mismatch` | a `PolicyDecision` has `execution_id` set to an execution id that does not cite it back (warning) |
| `execution_grant_unknown` | `execution.grant` is not among the supplied grants, when grants were supplied |
| `execution_run_id_mismatch` | `execution.run_id != run_id` |
| `observation_run_id_mismatch` | `observation.run_id != run_id` |
| `finding_run_id_mismatch` | `finding.run_id != run_id` |
| `finding_claim_observation_missing` | a finding's claim cites an id that is neither a current-run observation nor a memory reference |
| `decision_expand_without_reason` | verdict `expand` with no `expansion_reason`. The model validator makes this unreachable, so a hit means tampered bytes on disk |
| `decision_satisfied_by_unknown_observation` | a `satisfied_by` id is not a current-run observation |
| `duplicate_record_id` | two records of the same kind share an id |
| `run_dir_incomplete` | (only from `audit_run_dir`) a required file is absent |
| `run_dir_unreadable` | (only from `audit_run_dir`) a file is present but does not parse |

`audit_run_dir(run_dir)` reads `run.json`, `executions.json` (fallback `executions.jsonl`),
`provider-decisions.jsonl`, `policy-decisions.jsonl` (absent in v1 - see below),
`observations.json` (fallback `.jsonl`), `findings.json`, `gaps.jsonl`, and `scope.json`
for grants. It reconstructs real pydantic records, which is the point: **a malformed record is an
issue, not a crash**. `audit_run_dir` must not raise for any input, including a nonexistent or
empty directory.

`run_id` for a directory audit comes from `run.json`; if that is absent, from the directory
name.

Two v1 facts to design around, both verified against `runs/doc-check`:

1. `policy-decisions.jsonl` **does not exist in a v1 run directory**. Policy decision ids are
   only recoverable from `provenance.jsonl` triples with `relation == "governed_by"`, whose
   `subject` is the policy decision id (`pd-...`) and whose `object` is the necessity
   decision id. When the file is absent, derive ids that way and emit a single
   `policy_decision_record_absent` **warning** (not an error) so the weaker check is visible.
   When the file is present it is authoritative.
2. `POLICY_DECIDED` events in v1 do not carry the decision id. v1.1 adds
   `policy_decision_id` to that event; read it when present but never require it.

Use `harness.util.read_json` / `read_jsonl`. Do not use `json.loads` on a file you have not
confirmed exists.

### 6.2 `harness.policy.egress` - provider-side egress, invariant 12

Audit finding: `ProviderSpec.requires_network_egress` is declared by the provider and trusted,
so a remote MCP server registered with `requires_network_egress=False` is treated as a local
source. The rest of the design never lets a component grade itself.

```python
def classify_endpoint(endpoint: str | None) -> Literal["loopback", "private", "public", "unknown"]
def assess_provider_egress(
    provider: str,
    *,
    endpoint: str | None = None,
    declared_requires_egress: bool = False,
    egress_enabled: bool = False,
) -> EgressAssessment
def require_permitted(assessment: EgressAssessment) -> None      # raises EgressViolation
def classify_prompt_content(text: str) -> list[str]              # egress-sensitive markers found
def redact_for_egress(text: str) -> tuple[str, int]              # redacted text, markers removed
```

Rules, all deterministic and all on the endpoint rather than the declaration:

- `classify_endpoint` accepts `host`, `host:port`, `scheme://host:port/path`. Bare
  `127.0.0.1`, `::1`, `localhost` and any `127.0.0.0/8` address are `loopback`.
  RFC1918 (`10/8`, `172.16/12`, `192.168/16`), `169.254/16`, `fc00::/7` and `fe80::/10`
  are `private`. A routable address, or a name that is not `localhost`, is `public`.
  `None`, empty and unparsable input is `unknown`. A name that is not an IP literal and is not
  `localhost` **is `public`** - a DNS name resolves somewhere, and assuming otherwise is the bug
  being fixed. Never resolve anything: no `socket`, no `getaddrinfo`.
- `egress_actually_required` is true only for `public`.
- `permitted` is `not egress_actually_required or egress_enabled`.
- `unknown` is **not** permitted unless `egress_enabled`: an endpoint the harness cannot
  classify must not be treated as local.
- `declared_by_provider` echoes `declared_requires_egress`; a disagreement with
  `egress_actually_required` is recorded in `reasons` as a `declaration_mismatch` entry even
  when the call is permitted, because policy's risk computation used the declaration.
- `require_permitted` raises `EgressViolation` whose message names the provider and the class.

`classify_prompt_content` returns the sorted, deduplicated set of markers that must not leave
the machine, one entry per marker class: `artifact_digest` (a `sha256:<64 hex>`),
`evidence_span` (`byte_start`/`byte_end` style span reference, or an `EvidenceRef` field
name), `memory_reference` (a `mem-<hex>` id), `memory_section` (a literal `MEMORY.md` or
`BASELINE.md`), `run_identifier` (a `run-...` id). An empty list means nothing sensitive was
recognised - it is not a certificate that the text is safe, and the docstring must say so.
`redact_for_egress` replaces each recognised marker with `[redacted:<class>]` and returns the
count of substitutions.

### 6.3 `harness.runtime.replan` - conflict-driven re-planning

Audit finding: a conflict is detected and displayed, but nothing schedules a resolving call. The
necessity gate *would* expand with `conflict_resolution` if the model asked again; nothing
forces it to ask.

```python
CAPABILITY_FOR_KIND: dict[str, str]        # observation kind -> logical capability

def follow_up_needs(
    *,
    run_id: str,
    conflicts: Sequence[Correlation],
    observations: Mapping[str, Observation],
    decisions: Sequence[ProviderDecision] = (),
    already_attempted: Collection[str] = (),
    max_needs: int = 2,
) -> list[FollowUpNeed]
```

- Only `relation == "conflict"` correlations produce a need. `agreement` and `complement`
  never do: turning agreement into another call is exactly the wasted provider call the necessity
  gate exists to prevent.
- `CAPABILITY_FOR_KIND` is derived at import time by inverting
  `harness.providers.necessity.CAPABILITY_OUTPUT_KINDS`. Import it; do not restate it.
- For each conflict, the capability is the one that serves the observation kinds of the
  observations named in the correlation. If neither observation's kind maps to a capability, the
  conflict produces no need.
- A capability that is already in `already_attempted` produces no need - one resolving call per
  capability, or the run loops. Also skip a capability that any earlier decision already expanded
  for `conflict_resolution`.
- Output is deterministic: sorted by `(capability, correlation_id)`, at most one need per
  capability, truncated to `max_needs`. Ids come from `new_id("fn")`.
- `reason` is always `"conflict_resolution"`; `observation_ids` is the correlation's
  observation ids, sorted; `detail` names the conflicting values in one line.

### 6.4 `harness.context.cost` - the telemetry the v2 optimizer would need

Audit finding: compression, cache and memory-retrieval telemetry are not recorded, so a future
optimizer would have less to learn from than design 08 section 9 implies.

```python
def attribute_prompt_cost(
    *, tiers: Mapping[str, int], tier_caps: Mapping[str, int] | None = None,
    run_id: str = "", step: int = 0,
) -> TierCostReport
def memory_retrieval_cost(
    *, baseline_text: str, active_text: str, retrieved: Sequence[RetrievedMemory]
) -> MemoryCostReport
def compression_savings(*, raw_text: str, clamped_text: str) -> int
```

- `attribute_prompt_cost` fills `tiers` (echoed, sorted by name), `total_tokens` as their sum,
  `over_cap_tiers` as the sorted tier names whose cap they exceed, and `dropped_tokens` as the
  sum of the overages. A tier with no cap in `tier_caps` is never over cap.
- `memory_retrieval_cost` uses `harness.util.estimate_tokens` on the baseline text, the active
  text and each retrieved entry's `summary`. `retrieved_entries` is the count of entries, not a
  token count.
- `compression_savings` returns `estimate_tokens(raw) - estimate_tokens(clamped)`, floored at 0.
  It measures what a tier cap discarded, and a negative result would mean the "clamped" text grew.

### 6.5 `eval/` - make the unmeasured metrics measured

Audit finding: `replay_fidelity` returns `not_measured` in every scenario because a scenario
run performs no replay pass; and the three memory metrics and the token metric are computed
nowhere. Everything needed is already on disk.

Write scope: `eval/replay_pass.py` (new), `eval/metrics.py`, `eval/runner.py`,
`eval/scenarios/*.json`, `eval/ground_truth.json`, `tests/test_eval_replay_pass.py`.

```python
# eval/replay_pass.py
@dataclass
class ReplayPass:
    run_id: str
    replayed_finding_digests: dict[str, str]
    live_finding_digests: dict[str, str]
    rederived: int
    observations_used: int
    problems: list[str]

def rederive_findings(run_dir: Path) -> ReplayPass
def augment_replay_json(run_dir: Path) -> ReplayPass          # writes, returns
```

`rederive_findings` is a genuine re-derivation, not a re-read: it loads the run's recorded
observations and re-runs the harness's own deterministic pipeline -
`harness.analysers.rules.RuleEngine`, `harness.analysers.cve_match.VulnerabilitySnapshot` +
`candidate_cves`, `harness.analysers.correlate.Correlator`, `harness.findings.builder.build_findings`
- then hashes the result with `harness.util.canonical_json` + `sha256_text`, keyed by finding id.
`live_finding_digests` are the same hashes over the recorded `findings.json`. If those two maps
disagree, the run's own observations do not imply its findings, which is precisely the property
worth measuring.

The vulnerability snapshot for the re-derivation comes from `tests/fixtures/vuln/snapshot_2026-09.json`.
That path is a *test fixture*, and using it from `eval/` is a deliberate, documented shortcut:
report it in your final message. Prefer accepting a `snapshot_path` argument with that default.

Required changes to `eval/metrics.py`:

- `RunBundle` gains `policy_decisions: list[dict] | None = None`,
  `memory_events: list[dict] | None = None` and `ledger: list[dict] | None = None`, each
  `None` when the underlying file is absent, so `not_measured` stays honest.
- `load_run_bundle` populates them from `policy-decisions.jsonl`, `events.jsonl` filtered to
  `LONG_TERM_MEMORY_WRITTEN`/`MEMORY_COMPACTED`, and `trace.jsonl` ledger lines.
- `replay_fidelity` is **unchanged** - it already reads `finding_digests` and
  `replayed_finding_digests` from `replay.json`. Once `augment_replay_json` runs, it measures.
- Three new metrics join `METRIC_NAMES` and `_METRIC_FUNCTIONS`, each returning
  `not_measured` with a reason when its input is absent:
  `memory_persistence` (share of curated runs that wrote at least one long-term entry and left the
  active memory under its cap), `memory_evidence_isolation` (share of findings whose claims cite no
  memory reference - must be 1.0), `memory_retrieval_cost` (tokens spent on retrieved memory,
  reported not targeted).
- Adding a metric to `METRIC_NAMES` fails `validate_scenario_references` unless every scenario
  in `eval/scenarios/` carries a target for it. Add `{"kind": "report"}` targets for the cost
  metric and `{"kind": "min", "value": 1.0}` for the isolation metric.

Required change to `eval/runner.py`: after a scenario's run completes and before metrics are
computed, call `augment_replay_json` on that scenario's run directory so the replay pass is part
of the measurement rather than a separate manual step.

Constraints: the eval harness shells out to the CLI, so tests must **not** invoke a real run. Test
`rederive_findings` against a committed run directory (`eval/results/port_scan/run`) copied into
`tmp_path`, and test that a *tampered* copy - one recorded finding's `statement` changed - produces
a digest mismatch. That adversarial case is the test that matters: without it the metric could be
measuring nothing.
