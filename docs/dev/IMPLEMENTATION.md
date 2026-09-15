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

| Absent | Why |
|---|---|
| v2 Token Optimizer | Decision D23 defers it until v1 traces exist to tune against. Provider-call telemetry is recorded so those traces exist. |
| Automatic re-planning on a provider conflict | Conflicts are detected, stored, attached to findings as caveats and rendered in the report; nothing schedules a resolving call on its own. The necessity gate will expand with `conflict_resolution` if the model asks again. |
| Provider-side egress policy | The model endpoint is loopback-enforced in code. A provider declares its own `requires_network_egress` and is trusted about it, which is weaker than the rest of the design. |
| Active verification (`nuclei`, `http.probe`, exploitation of any kind) | Out of scope by decision. It is also why no finding can reach status `confirmed` from a version match: only an observation of the thing itself does that. |
| Memory retrieval cost, memory persistence and memory-evidence isolation as **metrics** | The properties are tested (`tests/test_memory.py`, `analysers`/`findings` validators); the evaluation plan asks for them as measured numbers and nothing computes them yet. |
| Replay fidelity as a **measured** metric | The evaluator has the metric but a scenario run performs no replay pass, so it reports `not_measured`. The property is verified in `tests/test_replay_offline.py`. |
| A live lab run and a real `nmap` scan | Neither was possible in the environment this was built in. The lab is validated as configuration and the scanner adapter is tested for its degradation path. |
| Third-party MCP server interoperability | The client is exercised over a real pipe against a hand-written server, including a misbehaving one. A real external server was not available. |
| Production SIEM integration, exploitation, persistence, lateral movement | Non-goals in design 00 section 5. |
