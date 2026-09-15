# 08 — Local-First Model, Memory, Provider Routing, and Token Strategy

This document defines the updated architecture that was intentionally missing from the first
design: local-first inference, bounded cross-run memory, long-lived memory, multiple MCP/native
providers, and a necessity-first approach to tool use.

## 1. Local-first means a real default, not a deployment option

The harness starts with a local model client. A default run must be possible without an external
LLM account. Local providers may expose Ollama-, llama.cpp-, vLLM-, or OpenAI-compatible APIs;
the runtime depends only on the internal `ModelClient` contract.

Remote inference is explicitly enabled, never automatically discovered. If enabled, egress rules
specify which context classes may leave the machine. Raw artifacts and long-lived memory are
`local_only` unless a user policy says otherwise.

## 2. Memory has three lifetimes

### Baseline memory

`memory/BASELINE.md` is stable, human-curated and low churn. It contains invariants, conventions
and environment facts that should be in every run. The runtime does not silently rewrite it.

### Active memory

`MEMORY.md` is the small working set loaded every run. It holds current goals, unresolved
questions, recent lessons, tool quirks and relevant environment notes. It has a strict size cap.

### Long-lived memory

Durable items live under `memory/long_term/` and are indexed locally. They are not loaded
wholesale. v1 uses FTS5/keyword retrieval plus recency/type filters. Each entry records source
runs and supersession metadata.

The memory pipeline is:

```text
run state -> candidate memory update -> validate -> active memory
                                      -> promote durable item -> long-lived memory
active memory over cap -> snapshot -> dedupe/compact -> MEMORY.md
```

Memory can influence what the agent chooses to inspect. It cannot support a finding in a new run.

## 3. Capability-first provider model

A provider advertises capabilities rather than becoming part of the planner vocabulary:

```yaml
provider: mcp:scanner-a
capabilities:
  - service.enumerate
  - http.probe
trust_class: external_tool
risk: LOW
estimated_cost:
  latency_ms: 800
  token_payload_hint: 1200
```

Native tools advertise the same shape. The provider registry therefore supports:

```text
service.enumerate -> native:nmap, mcp:scanner-a, mcp:scanner-b
log.query         -> native:duckdb, mcp:log-service
threat.lookup     -> mcp:intel-a, mcp:intel-b
```

The planner asks for the capability; the harness owns implementation choice.

## 4. Necessity before execution

The `NecessityGate` receives:

```text
requested capability + expected evidence
current findings/observations/gaps
cached provider results
eligible providers
remaining tool/token/time budget
skill verification requirements
```

It returns one of:

- `satisfied`: do not call a provider;
- `single(provider)`: one provider is sufficient;
- `expand([providers], reason)`: several are necessary;
- `defer(reason)`: useful but not worth current budget;
- `deny(reason)`: policy/precondition prevents use.

### v1 decision rules

v1 uses deterministic rules, not an LLM judge:

1. reuse current-run/cached evidence when it satisfies the required observation fields;
2. prefer a local/native provider when capability, provenance quality and freshness are equivalent;
3. select one provider by default;
4. add a provider only for `coverage_gap`, `conflict_resolution`, `independent_verification`,
   `provider_failure`, or `trust_diversity`;
5. stop expanding once the declared evidence need is satisfied;
6. enforce hard provider-call and token budgets even when more providers are available.

Every decision is logged, including rejected candidates.

## 5. Why multi-MCP is not multi-agent

Calling two MCP servers does not mean asking two models to reason about the same problem. MCPs are
providers of evidence/capabilities. One local planner remains responsible for choosing the next
information need; deterministic components normalize and compare provider results.

This keeps control flow replayable and avoids duplicating the full prompt across several agents.

## 6. Provider result reconciliation

Normalized observations include provider identity, execution id, artifact digest, trust class and
freshness. The correlator groups semantically equivalent observations and emits:

- agreement: same normalized value supported by multiple sources;
- complement: providers contribute different required fields;
- conflict: incompatible normalized values;
- gap: requested evidence still missing.

A conflict is not silently resolved by model preference. It remains visible and may create a new
evidence need, which again passes through the necessity gate.

## 7. v1 token controls

v1 is intentionally non-optimal but bounded:

- fixed prompt/context ceilings;
- token ledger using the configured local tokenizer;
- deterministic rollups instead of raw provider output;
- bounded evidence-span retrieval;
- memory size cap + selective long-lived retrieval;
- provider-output deduplication;
- cache reuse;
- necessity gate before each provider call and before multi-provider expansion.

These controls are enough to prevent the obvious failure mode: "more providers exist, therefore
call all of them and paste all of their output into the model."

## 8. v2 Token Optimizer — provisional architecture

The optimizer is a **version-two feature** because the correct policy should be informed by v1
traces rather than invented in advance.

Proposed components:

```text
                    +---------------------+
run state --------> | Context Cost Model  |
provider metadata ->| / Local Tokenizer   |
                    +----------+----------+
                               |
                    +----------v----------+
                    | Marginal Utility    |
                    | Estimator           |
                    +----------+----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
+---------v--------+ +---------v---------+ +--------v---------+
| Provider         | | Memory Retrieval  | | Context Budget   |
| Portfolio Planner| | Planner           | | Allocator        |
+---------+--------+ +---------+---------+ +--------+---------+
          |                    |                    |
          +--------------------+--------------------+
                               |
                    +----------v----------+
                    | Compression / Cache|
                    | / Dedup Strategy   |
                    +---------------------+
```

The optimizer should minimize expected cost subject to constraints such as evidence coverage,
confidence requirement, scope, risk and hard run budgets. A practical objective can later be
expressed as:

```text
maximize expected evidence gain - lambda_token * token_cost
                                - lambda_call  * provider_cost
                                - lambda_time  * latency
```

subject to safety/evidence invariants that are never traded away.

The exact estimator/weights/learning method are deliberately open. v1 must merely produce the
telemetry necessary to evaluate choices later.

## 9. Telemetry required now for v2 later

Record per model/provider step:

- token input/output by context category;
- provider candidates considered and rejection reason;
- provider bytes and normalized observation count;
- novelty: new observation keys versus duplicates;
- whether a finding changed;
- whether an EvidenceGap closed;
- latency/failure/cache status;
- memory chunks retrieved and whether they affected the next capability proposal.

This makes v2 an optimization problem over measured traces rather than an architectural guess.
