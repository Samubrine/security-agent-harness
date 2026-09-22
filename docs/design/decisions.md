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

## D25 — Every declared field has a consumer, or a stated reason it does not (v1.2)
**Accepted.** The round-2 audit found eight settings and records the code writes and nothing reads
(`docs/dev/AUDIT-v12.md` R2-24, R2-25, R2-29). A field that nothing consumes is a promise the harness
does not keep: a reader takes it as a control that exists. Each was therefore honoured or removed,
with the disposition recorded here and enforced by
`tests/test_schemas_contract.py::test_every_skill_field_is_consumed_or_declared_display_only`.

| Field | Disposition | Where it is read now |
|---|---|---|
| `SkillVerification.independent_for` | **honoured** | `InvestigationLoop._corroboration_required` asks the gate for a second, independent source for a skill whose conclusions the entry names. This is also what makes the gate's second-provider path and the conflict-driven re-planning behind it reachable by a real run (K3, K5); O5's question about *mandating* diversity for specific finding classes stays open. |
| `SkillSpec.allow_second_provider_by_default` | **honoured** | Same helper: it is the skill-wide form of the same request. Applied only where a second provider exists, because demanding corroboration from a capability with one provider would make the gate refuse a call rather than strengthen it. |
| `SkillSpec.inputs` | **honoured** | `runner._require_skill_inputs` refuses a run whose required input kind no grant in the authorised scope provides, with the other authorisation failures and before the model is called. `entry_point` now declares the log corpus it also needs. |
| `SkillSpec.objective_template` | **deleted** | The objective is supplied by the caller and recorded in the run manifest; nothing rendered the template, and design 02 §13's skill contract does not include it. A template that no code reads drifts silently from the command lines people actually type. |
| `AgentTurn.hypotheses` | **honoured** | `InvestigationLoop._record_hypotheses` records each statement with a run-local id and emits `HYPOTHESIS_RECORDED`. The statement stays model prose and is never promoted to a claim (D5). |
| `CapabilityProposal.hypothesis_id` | **honoured** | `InvestigationLoop._hypothesis_reference_reason` refuses a proposal that cites a hypothesis this run never recorded. Design 02 §5 and D5 both require the field; the model-facing half — ids in the turn's `hypotheses` list, so a conforming planner can cite one — lands with the single prompt regeneration in WS-02.7, because it changes every recorded prompt digest. |
| `PolicyDecision.execution_id` | **honoured** | The loop fills it when the execution is created, so `harness.runtime.verify`'s check that a decision and an execution name each other has something to compare instead of two `None`s. |
| `Router` | **honoured** | `InvestigationLoop._pursue` executes through `Router.resolve`, which re-checks a decision's selection against the registry at the execution boundary. The decision is a record that may have been replayed or edited, and looking the provider up again in the loop threw that check away. |
| artifact-byte counter (`BudgetGuard.add_artifact_bytes`, recorded in `budget_snapshot`) | **honoured** | The loop charges each stored artifact's length to the guard, so the recorded snapshot states a real byte count instead of the constant zero a report renders as fact. The `ArtifactStore` remains the component that enforces the ceiling. |
| necessity cache bare-provider-id key | **deleted** | `_coverage_gap` matches only `cache_key(provider, capability)`, and the loop no longer writes a key nothing read. The bare id made a completion for one capability look like a completion for another (R2-29). |
| `Observation.freshness` | **deferred** | It is a recorded field, not a setting: an operator cannot set it and no decision should rest on a timestamp that is, for every shipped parser, the time the observation was recorded. Deleting it requires editing the frozen fixture, whose rows carry it and which is validated with `extra="forbid"`; §0.1.4 forbids that outside a deliberate re-record. Decision: delete it in the next deliberate re-record, not before. |
| `ProviderExecution.nondeterminism` | **deferred** | Same reason, plus a second one: the value echoes the *provider's* declaration about itself, and invariant 12 says the harness must judge by the transport it chose (`egress.json` already records that judgement). It is redundant with a record that is trusted, so it should go the same way as `freshness` — at the next deliberate re-record. |

## D26 — What the scope record authorises, and who it is verified against (v1.2)
**Accepted.** The round-2 audit found five authorisation claims that were signed but not enforced
(`docs/dev/AUDIT-v12.md` R2-05 … R2-09, R2-32). Each is now a check, and this is what each check
means:

* **Ports.** A `ScopeNetwork` may carry `ports`, the set of ports it authorises. The window is minted
  onto `Grant.ports`, offered to the planner as the only port specification it may propose for that
  grant, and enforced in `PolicyEngine.decide`: a call whose `args.ports` reaches outside the window
  is denied with `ports_not_granted`, and a call naming no ports at all is denied too, because the
  provider would otherwise choose its own default set. A network without the field says nothing about
  ports, which is the pre-v1.2 behaviour and is kept deliberately. The check is on the argument named
  `ports`, which is what the shipped adapters read: a provider whose port argument has another name
  is not covered, and an MCP tool that carries ports inside one of its own declared arguments is
  bounded only by that argument's declaration.
* **Payload versions.** `ScopeFile.payload_version` records the shape of the payload a record was
  signed under, so a field added to the model later does not make earlier signatures unverifiable -
  the run frozen in `tests/fixtures/run/port_scan` is signed with a key that no longer exists. A
  record may not carry a field its declared version did not have, so nothing in a record can sit
  outside its own signature. `sign_scope` always signs the current version.
* **Trust anchor.** A run verifies the scope against an operator-supplied public key. Without one it
  refuses: the embedded-key fallback proves the record agrees with itself, which anyone who can edit
  the file can arrange. `--dev-embedded-key` opts into that fallback explicitly, and both the run
  manifest and an `AUTHORITY_VERIFIED` event record `authority: anchored | self-signed` with the
  anchor's fingerprint, so a report can say which one a run had. `make run`, `make eval` and the
  scenario invocations pass the anchor; the README recipe does too.
* **`scope.dry_run`.** Effective dry run is `request.dry_run or scope.dry_run`. A scope signed for a
  rehearsal cannot execute, and the request can only add the restriction.
* **Grant lifetime.** `expires_at = min(now + ttl, scope.window.to)`, and minting under a window that
  has already closed is refused. The window is evaluated once, at load; this is what stops a grant
  outliving the authority it came from.
* **Argument schemas.** `ProviderSpec.input_schema` is enforced by `PolicyEngine.decide` through
  `harness.policy.arguments`, which implements the keywords the shipped adapters declare (`type`,
  `properties`, `required`, `additionalProperties`, `items`, `enum`) and ignores any other rather than
  guessing at it. A schema keyword nothing checks would be worse than none: it would let a provider
  author believe a constraint that is not there.

## D27 — What v1.2 does not close, and why
**Accepted.** The round-2 audit's ledger has rows that no v1.2 workstream owns. Recording them here
is what makes them *deferred* rather than forgotten, and it keeps the "deliberately not implemented"
table in `docs/dev/IMPLEMENTATION.md` for decisions rather than defects.

| Row | Disposition |
|---|---|
| K1 — prompt-content egress filtering is dead code | **Deferred.** `classify_prompt_content`/`redact_for_egress` exist and are tested; wiring them changes every prompt a remote run sends, and the v1.2 round had no way to measure that against a recorded run. The next step is a change that records what was redacted per turn (the ledger already records per-turn tiers), so the cost of redaction is visible rather than asserted. |
| K4 — v2 Token Optimizer absent | **Deferred by D23**, which is where it belongs. |
| K6 — `memory_persistence` measures attribution, not the byte cap | **Kept as-is.** The metric measures what it can see from the run directory (every promoted entry names its source run); the cap is enforced and tested by `MemoryManager`. Renaming the metric would break the design's table, so the limitation is stated in its docstring and in the ledger instead. |
| K7 — no active verification | **Deliberate** (design 00 section 5). Its stated reason in `IMPLEMENTATION.md` was wrong and is corrected: the grants do serve `http.probe`; the nmap adapter advertises and then excludes it. |
| K8, K9 — no live lab run, no third-party MCP server | **Environmental.** Neither was available on the machine this was built on; both are stated where they are measured. |
| R2-26, R2-28, R2-30, R2-30b | **Deferred**, listed as carried-forward defects in `IMPLEMENTATION.md`: inert curator inputs, an unbounded read in `logfile`, two tests that cannot fail as written, and two loose scenario assertions. |

## Open questions

| # | Question | Blocking? | Resolution point |
|---|---|---|---|
| O1 | Minimal Sigma evaluator versus `pysigma` | No | before M2 |
| O2 | Which local model/backend is the default reference implementation? | Yes for M0 | week 1 benchmark |
| O3 | Exact `MEMORY.md` size ceiling and compaction trigger | No | measured during M2 |
| O4 | Provider ranking when cost/risk are equal | No | M4 fixture results |
| O5 | Whether trust-diversity should be mandatory for specific high-impact finding classes | No | M4/M5 evaluation |
| O6 | v2 Token Optimizer objective/estimator | No for v1 | after v1 telemetry |
