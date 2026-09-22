# Implementation Notes

A map from the design to the code, and the recipes for extending it. Read
[docs/dev/INTERFACES.md](INTERFACES.md) for the frozen module contracts and
[docs/dev/AUDIT.md](AUDIT.md) for an independent account of what is and is not delivered.

## Design document to code

| Design | Implemented in |
|---|---|
| 00 vision and success criteria | split across `src/harness/runtime/loop.py` (the lifecycle), `src/harness/findings/validate.py` (the zero-unsupported-findings claim), `eval/metrics.py` (the measured criteria) |
| 01 architecture | `runtime/loop.py` and `runtime/fsm.py` are the deterministic spine; `llm/` is the probabilistic brain. `llm/client.py` is the model adapter boundary; `providers/necessity.py` is section 5; `context/builder.py` is the tier model of section 10; `tokens.py` is section 9 |
| 02 data model | `models.py` holds every record. `artifacts.py` is artifacts and evidence spans; `events.py` is the hash-chained log of section 12; `runtime/replay.py` is the replay of section 13 and `providers/necessity.py` the decision record of section 7 |
| 03 policy and safety | `policy/scope.py` (signed record), `policy/grants.py` (section 2), `policy/engine.py` (section 3), `policy/taint.py` (sections 4 and 5), `util.detect_injection` (the single pattern set), `lab/docker-compose.yml` (section 8) |
| 04 prior art | background only; no code |
| 05 alternatives | background only; no code |
| 06 roadmap | the milestones are the test suites: M1 `tests/test_integration_vertical_slice.py`, M2 `tests/test_scenarios_log_analysis.py`, M3 `tests/test_scenarios_entry_point.py`, M4 `tests/test_scenarios_multi_provider.py`. The layout in section 3 is the tree in the README |
| 07 evaluation | `eval/scenarios/`, `eval/ground_truth.json`, `eval/metrics.py`, `eval/runner.py` |
| 08 memory and routing | `memory/` (section 2), `providers/` (sections 3 and 4), `providers/necessity.py` (the section 4 rules), `runtime/capabilities.py` (the binding the model needs), the telemetry in `models.ProviderCallTelemetry` (section 9) |
| decisions.md | D1 `runtime/loop.py`; D2 `findings/validate.py`; D4 `policy/grants.py`; D5 `analysers/`; D8 `analysers/cve_match.py`; D12 `memory/`; D13 `providers/`; D14 `events.py`; D15 `runtime/fsm.py`; D16 `models.py` plus `llm/schemas.py`; D17 `policy/taint.py`; D18 `tokens.py`; D21 `llm/client.py` (loopback enforcement); D22 `providers/necessity.py` |

+## v1.1 - what the first audit's gap list turned into

`docs/dev/AUDIT.md` section 6 named eight places where the implementation was weaker than the prose
around it. Five of them were closed by the v1.1 work. The rest are still open and are listed below
`v1.1` rather than here, because a reader should not have to diff two documents to find out.

| Gap from AUDIT.md section 6 | What changed | Where |
|---|---|---|
| Invariant 6: a cited decision id was required but unresolvable | Policy decisions are persisted, the `POLICY_DECIDED` event carries `policy_decision_id`, and `runtime/verify.py` re-derives the reference graph from a run directory and reports every broken reference | `policy/engine.py`, `runtime/runner.py`, `runtime/verify.py` |
| Invariant 12: no provider-side egress gate | Egress is decided from the transport the harness chose, never from the provider's own declaration. A provider is assessed before the loop starts and a refused one stops the run | `policy/egress.py`, `runtime/runner.py` |
| Invariant 12 (grant references) | A run records the grants it minted. Grant ids come from `new_id`, so they cannot be re-derived from the scope record; without the file every execution reference would look unknown | `runtime/runner.py`, `runtime/verify.py` |
| Conflicts detected but never acted on | A conflict schedules its own resolving call, through the ordinary validate/necessity/policy path, before the model is asked | `runtime/replan.py`, `runtime/loop.py` |
| Compression, cache and memory-retrieval telemetry not recorded | `CONTEXT_ASSEMBLED` records per-tier cost, what the tier caps discarded, and what memory cost, on every model turn | `context/cost.py`, `runtime/loop.py` |
| Replay fidelity and the three memory metrics never measured | `replay_fidelity` performs a real re-derivation from recorded observations; three memory metrics joined the set | `eval/replay_pass.py`, `eval/metrics.py`, `eval/runner.py` |

### Run directory artifacts added in v1.1

| File | Contents | Why it exists |
|---|---|---|
| `policy-decisions.jsonl` | every policy verdict, including denies | an execution's `policy_decision` field was required but unresolvable, and a denied call produces no execution at all, so this was the only place to learn why an action did not happen |
| `grants.json` | the grants the run minted | grant ids are random, so they cannot be re-derived from `scope.json` |
| `follow-ups.jsonl` | evidence needs a conflict created without a model turn | distinguishes a call the harness scheduled from one the planner asked for |
| `egress.json` | one assessment per registered provider | evidence that each provider was judged on how the harness reached it, not on what it claimed |
| `replay-report.json` | the replay pass result, digest maps included | **not** `replay.json`: that file is the JSONL model/provider trace `ReplayModelClient` reads, and writing the report over it broke offline replay |

### Two integration bugs the v1.1 work exposed rather than introduced

- **`FINDINGS -> POLICY` was an illegal transition.** `_pursue` loops over every provider a
  necessity decision selected, and `_run_provider` leaves the machine at `FINDINGS`. The second
  provider's gate step therefore asserted `illegal transition findings -> policy`. It had never
  fired because the only two paths that select two providers - `conflict_resolution` and
  `trust_diversity` - had never executed. No committed run directory contains a single correlation.
- **`verify.py` reported a clean grant check over zero grants.** It read a top-level `grants` key
  from `scope.json`, which a `ScopeFile` does not have, so the check was silently dead. It now
  reports `grants_record_absent` as a warning rather than implying it checked something.

## The capability model, once

There are two capability vocabularies and conflating them is the mistake that makes a system either
uselessly rigid or silently unsafe.

A **grant capability** (`net.connect`, `net.raw`, `net.tls`, `fs.read`) describes what a *resource*
permits. It is derived from the signed scope in `policy/grants.py` and is never negotiated from model
output. This is the vocabulary in which "a read-only banner tool cannot inherit `net.raw`" is even
expressible, and it is what the policy engine's single membership check tests (`capability in
grant.capabilities`).

A **logical capability** (`service.enumerate`, `vulnerability.match`, `log.read`) is what a skill may
ask for. It is resource-independent by design, which is what lets a second provider satisfy it without
the planner changing.

`runtime/capabilities.py` is the binding between them: it says which resource kind can serve which
logical capability, and `with_logical_capabilities` composes the logical names onto the minted grants
so one membership check answers both questions. Transport-level enforcement stays with the provider
adapter, which is harness-authored and declares only the logical capabilities it serves.

Two consequences, both of which the tests rely on:

* adding a provider for an existing logical capability is a registration change and nothing else - no
  binding edit, no planner edit, no policy edit;
* a logical capability that no grant can serve is absent from the catalogue, so the model cannot ask
  for it at all. That is why `http.probe` appears in no run: no grant serves it.

## Recipes

### Add a provider for an existing capability

Write the adapter (`.spec` plus `.invoke`) in `src/harness/providers/native/` or
`src/harness/providers/mcp/`, then register it in `_build_registry` in
`src/harness/runtime/runner.py`. That is the whole change: the registry indexes it by capability,
the necessity gate ranks it by declared cost, risk and trust class, and the router will select it
only when it is the minimum sufficient answer. Nothing in `runtime/loop.py`, `llm/` or `policy/`
needs to know it exists. `tests/test_scenarios_multi_provider.py` demonstrates this by injecting a
provider through `RunRequest.extra_providers` without touching any of those modules.

Rules an adapter must honour, because the tests assert them:

* take the target from `request.grant.resource`, never from `request.args`;
* put only argv arrays into subprocesses, never a shell string;
* return a failed `ProviderResult` carrying an `EvidenceGap` for an ordinary failure rather than
  raising - "the tool could not answer" is itself a fact the report must carry;
* return raw bytes in `stdout` and let a parser decide what they mean.

### Add a skill

Drop a YAML file in `src/harness/skills/`. `SkillSpec` needs a name, a version, and the capabilities
the skill is allowed to use. A capability absent from the registry, or from the run's grants, simply
will not appear in the catalogue for that run, so a skill may list a capability optimistically and
the harness will only offer what it can actually serve. `verification.max_providers_per_need` is the
skill's stated verification policy and it caps the necessity gate.

### Add a parser

Write a function taking `(data, *, execution, run_id, trust_class, artifact_digest, evidence_of,
target)` and returning a `ParseResult`. Build observations with `ParseContext.observe`, which refuses
an evidence span outside the artifact and hashes the span from the real bytes. Register it in
`_register_parsers` in `src/harness/runtime/runner.py` against the media type the provider
advertises. Two rules the registry enforces: an observation without a recomputable evidence span is
rejected, and one attributed to a different run is rejected.

Attacker-reachable text (a banner, a user agent, a request path) goes through
`injection_observations`, which turns instruction-shaped payloads into `injection_attempt`
observations and a `prompt_injection_attempt` gap instead of anything the harness would act on.

### Add an analyser rule

Append an entry to `DEFAULT_RULES` in `src/harness/analysers/rules.py`. A rule is data: either
`kind` plus `requires`/`requires_contains` for one observation, or `requires_kinds` for a claim that
needs several sources. Claims are built by the engine and cite the observations they matched. A rule
whose template disagrees with the observation it matched is skipped and recorded as an
`ANALYSER_RULE_SKIPPED` event, so a dead analyser cannot pass for an environment with nothing to
report.

### Add a scenario

Add a JSON file to `eval/scenarios/` and, if it needs new expectations, an entry to
`eval/ground_truth.json`. `validate_scenario_references` will tell you if a scenario cites an
expectation that does not exist, if an expectation no scenario claims, or if a metric no scenario
feeds. `make eval` signs nothing and builds nothing, so run `make scope` once first.

## What is deliberately not implemented

Before trusting an entry in this table, read `docs/dev/AUDIT-v12.md`: it re-verified every row
below against `1275c14`, corrected the stated reason for two of them (the `http.probe` and
independent-verification rows), and records a second round of findings — including four
integrity defects — with the command that reproduces each one.

| Absent | Why |
|---|---|
| v2 Token Optimizer | Decision D23 defers it until v1 traces exist to tune against. Provider-call telemetry is recorded so those traces exist. |
| Conflict re-planning that a real run can reach | The wiring exists and is tested (`runtime/replan.py`, `runtime/loop.py`), but **no shipped run reaches it**: a conflict needs two providers to observe one subject, and the scripted planner re-requests a capability only after a *failed* attempt - a successful one is recorded as completed and skipped. No committed run directory contains a single correlation. `tests/test_integration_v11.py::test_with_the_shipped_planner_no_conflict_is_reachable` asserts that limit rather than leaving it to be discovered. |
| Prompt-content egress filtering | `policy/egress.py` provides `classify_prompt_content` and `redact_for_egress`, and they are tested, but **nothing calls them**. A run with remote inference enabled still sends whatever the context builder assembled. Provider-side egress is enforced; prompt-side is not. |
| Auditing a run from the CLI | `runtime/verify.py` re-derives a run's reference graph and reports every broken reference, but `audit_run_dir` is called only from tests. `harness replay` verifies the event chain and evidence spans; it does not call the provenance audit, so an operator has no command that reports a dangling decision or grant reference. |
| Skill-requested independent verification | The necessity gate supports `trust_diversity_required`, and design 08 lists `independent_verification` as a legal expansion reason, but the loop never sets the flag: no skill can ask for its conclusion to rest on two sources. This is also one of the two paths that would make a conflict reachable. |
| Memory persistence as a **cap** check | `memory_persistence` measures whether every promoted entry names its source run. It does not measure that `MEMORY.md` ended under its byte cap, because the active file lives in the workspace rather than in the run directory. The cap itself is still enforced and tested by `MemoryManager`. |
| Active verification (`nuclei`, `http.probe`, exploitation of any kind) | Out of scope by decision. It is also why no finding can reach status `confirmed` from a version match: only an observation of the thing itself does that. |
| A live lab run and a real `nmap` scan | Neither was possible in the environment this was built in. The lab is validated as configuration and the scanner adapter is tested for its degradation path. |
| Third-party MCP server interoperability | The client is exercised over a real pipe against a hand-written server, including a misbehaving one. A real external server was not available. |
| Production SIEM integration, exploitation, persistence, lateral movement | Non-goals in design 00 section 5. |
