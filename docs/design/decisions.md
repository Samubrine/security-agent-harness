# Decision Log

Statuses: **accepted**, **provisional**, **open**, **rejected**. The earlier design conversation is
referred to as *the source design*.

## D1 — The model proposes; the spine executes
**Accepted.** The local model returns a typed capability proposal; runtime owns state, budgets,
provider selection, policy, invocation, memory writes and finding construction.

## D2 — The evidence graph is the current-run source of truth
**Accepted.** Artifacts, observations, claims, findings, gaps, executions and grants form the
investigation graph. Cross-run memory is separate and cannot validate findings.

## D3 — Plan-and-execute with bounded adaptation
**Accepted.** The model emits an advisory plan plus exactly one next capability request and
re-emits the plan as evidence changes.

## D4 — Capability grants, not checked target strings
**Accepted.** Context resolution mints scoped grants; providers resolve aliases against grants.
Out-of-scope resources have no valid representation in tool inputs.

## D5 — The model never authors a finding
**Accepted.** Parsers/rules/matchers construct claims and findings; the model may narrate and
propose hypotheses only against existing ids.

## D6 — Severity is never assigned by the model
**Accepted.** It derives from CVSS or a fixed rubric.

## D7 — Raw provider output is never injected wholesale into context
**Accepted.** Raw bytes become artifacts. Deterministic rollups and bounded, provenance-preserving
spans may enter context on demand.

## D8 — Vulnerability mapping is deterministic and snapshot-stamped
**Accepted.** CPE/version matching uses local snapshot data; absence of a match is never rendered
as proof of safety.

## D9 — Finding status and confidence are separate
**Accepted.** Finding status is `possible | confirmed | not_affected | inconclusive`. Confidence
is a separate claim property (`low | medium | high | observed | unknown`). Active verification
moves status; confidence alone does not.

## D10 — Sigma for log rules, Nuclei for active verification
**Accepted.** Reuse standards rather than inventing detection formats.

## D11 — One reasoning agent plus deterministic verification
**Accepted.** Multiple providers do not imply multiple agents. Re-probing, re-parsing and
cross-provider comparison are preferred to an LLM critic.

## D12 — Local-first memory has baseline, active and long-lived tiers
**Accepted.** `memory/BASELINE.md` is stable human-curated context; `MEMORY.md` is bounded active
memory; durable entries are stored/indexed locally and retrieved selectively.

Memory is advisory context, never finding evidence. v1 uses FTS5/keyword retrieval and does not
require a vector database.

*Supersedes:* the previous decision to remove memory entirely.

## D13 — MCP and native tools are providers behind a capability registry
**Accepted.** Multiple MCP servers may advertise overlapping capabilities. The planner requests a
logical capability; the harness chooses implementation.

Native providers remain preferred where the harness must control raw evidence bytes. MCP is a
protocol/provider boundary, not the owner of orchestration.

*Supersedes:* the previous "one MCP server only" demonstration decision.

## D14 — Append-only, hash-chained event log instead of an event bus
**Accepted.** Every event includes `prev_event_hash` and `event_hash` over canonicalized content.
Replay verifies the chain before reconstructing state.

## D15 — Hand-written FSM, not an agent framework
**Accepted.** The security-critical control flow remains inspectable and testable.

## D16 — Structured outputs everywhere
**Accepted.** Pydantic models define proposals, observations, findings, provider specs and memory
entry schemas; JSON Schema is exported from the same definitions.

## D17 — Taint tracking and spotlighting defend the model boundary
**Accepted.** Remote/provider-controlled strings are data-only, provenance-tagged, and cannot
widen scope. MCP output is treated as untrusted unless explicitly classified otherwise.

## D18 — Budgets terminate runs
**Accepted.** Steps, provider calls, prompt tokens, wall clock, artifact bytes and consecutive
failures are counted by the spine. The model cannot reset its own budget.

## D19 — Evaluation is scored against a scanner baseline
**Accepted.** Report precision/recall/evidence quality beside plain scanning; zero unsupported
findings remains the key invariant.

## D20 — Local, self-owned, egress-isolated security lab only
**Accepted.** No valid signed scope means no provider execution.

## D21 — Local inference is the default execution mode
**Accepted.** The primary model client targets a local endpoint. Remote model adapters are opt-in,
data-egress governed and separately labeled in evaluation.

A run records local model/backend/tokenizer metadata so token accounting and replay are
interpretable.

## D22 — Provider use is necessity-gated and minimum-sufficient
**Accepted.** Before every native/MCP invocation, the spine checks whether current evidence or a
valid cache already satisfies the requested need. One provider is selected by default.

Multiple providers require one of: `coverage_gap`, `conflict_resolution`,
`independent_verification`, `provider_failure`, or `trust_diversity`. The selected and rejected
candidates are logged.

This is primarily a cost/token control, but it is also an auditability rule: the harness can
answer not only "why did this tool run?" but "why was another available tool not run?"

## D23 — Token optimization is a version-two subsystem
**Accepted.** v1 implements only hard budgets, context tiers, caching/dedup, token telemetry and
the deterministic necessity gate.

v2 will introduce a `TokenOptimizer` with a model-specific cost estimator, marginal-utility
estimator, provider-portfolio planner, memory-retrieval planner, dynamic context allocator and
compression/cache strategy. The exact optimization algorithm remains **open** until v1 traces
exist.

## D24 — Replay and rerun are distinct
**Accepted.** `replay` reconstructs state from recorded model/provider responses and artifacts,
with no live network execution. `rerun` starts a fresh investigation and may differ.

## Open questions

| # | Question | Blocking? | Resolution point |
|---|---|---|---|
| O1 | Minimal Sigma evaluator versus `pysigma` | No | before M2 |
| O2 | Which local model/backend is the default reference implementation? | Yes for M0 | week 1 benchmark |
| O3 | Exact `MEMORY.md` size ceiling and compaction trigger | No | measured during M2 |
| O4 | Provider ranking when cost/risk are equal | No | M4 fixture results |
| O5 | Whether trust-diversity should be mandatory for specific high-impact finding classes | No | M4/M5 evaluation |
| O6 | v2 Token Optimizer objective/estimator | No for v1 | after v1 telemetry |
