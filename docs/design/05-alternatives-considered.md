# 05 — Alternatives Considered

Every alternative is judged against three questions: **is it provable, is it necessary, and can
a solo implementer finish it?**

## 1. Loop shape

| Approach | Trade-off | Verdict |
|---|---|---|
| Free-running ReAct | adaptive but drifts and over-calls tools | Reject alone |
| Plan-and-execute | renderable/checkpointable plan | Adopt outer loop |
| Bounded local adaptation | retains adaptivity under budgets | Adopt |
| Reflexion/self-critic | another model opinion without a verification signal | Reject |
| Search over actions | usually costs more than just running the safe tool | Reject |
| Small hypothesis beam | useful only if evidence can score hypotheses | Optional |

## 2. Deterministic orchestration vs a free-running agent

Adopt the deterministic state machine. A security finding must be defensible to a third party;
therefore policy, execution, evidence, budgets, memory writes, provider selection and replay are
runtime responsibilities. The model proposes the next information need.

## 3. Evidence graph vs memory

The evidence graph remains the **current-run source of truth**. Nodes are artifacts,
observations, claims, findings and gaps.

Earlier design text treated this as a reason to remove memory entirely. That conflated two
problems. The corrected split is:

- evidence graph: authoritative current-run facts and provenance;
- `BASELINE.md`: stable human-curated context;
- `MEMORY.md`: bounded cross-run working context;
- long-lived memory: selectively retrieved durable lessons.

Adopt this split. Memory improves continuity for a local model but can never validate a finding.
No vector store is needed in v1; long-lived memory uses local FTS5 retrieval.

## 4. Local-first vs API-first inference

API-first inference makes setup easy but conflicts with the project's local-first goal and makes
security data egress part of the default path.

**Adopt local-first inference.** The model client targets localhost by default and records model
metadata/tokenizer information per run. Remote adapters remain optional and explicitly gated.

The trade-off is that local models may be weaker. That is evaluated rather than hidden; the
architecture compensates by constraining outputs, grounding findings in deterministic evidence,
and keeping the planner task narrow.

## 5. Capability routing vs direct tool naming

Having the model name `nmap`, a particular MCP server, or every available provider couples
reasoning to implementation and encourages provider spam.

**Adopt logical capabilities.** The model requests `service.enumerate`, `log.query`,
`vulnerability.match`, etc. The harness chooses a provider only after checking whether another
call is necessary.

## 6. One provider vs multiple providers

A single provider is cheaper and simpler; multiple providers improve coverage and can resolve
conflicts, but duplicate context and tool calls if used indiscriminately.

**Adopt multi-provider capability with minimum-sufficient execution.** One provider is the
default. A second/third provider requires a machine-recorded reason: coverage gap, conflict,
independent verification, provider failure, or trust diversity. This gives the project the
benefit of multiple MCPs without turning breadth into automatic cost.

## 7. Single agent vs multi-agent

Reject multi-agent as the default. Multiple MCP/native providers are **multiple evidence
sources, not multiple reasoning agents**. Verification should preferentially be deterministic:
re-probe, re-parse, compare normalized observations and assert evidence edges.

## 8. MCP as protocol vs architecture layer

The earlier design demoted MCP to one demonstration server. That is too restrictive for the
updated goal, but MCP still should not become the orchestration layer.

**Adopt MCP as a provider protocol behind the capability registry.** Multiple MCP servers may
advertise overlapping capabilities. Native providers remain first-class, especially when the
harness must own raw evidence bytes. The router treats both uniformly and the necessity gate
prevents "call every server" behaviour.

## 9. Reuse standards

- Sigma remains the log-rule format.
- Nuclei templates remain approval-gated active verification.
- OCSF can be an output mapping, not the internal schema.
- Provenance borrows PROV/in-toto shapes without importing an ontology.

## 10. Token optimization now vs later

A sophisticated optimizer in v1 would add an unvalidated research problem to an already broad
systems project.

**v1:** hard token/tool budgets, context tiers, caching, deduplication, a token ledger, and the
provider necessity gate.

**v2:** a dedicated Token Optimizer that estimates marginal information gain per token/call and
dynamically chooses provider portfolios, memory retrieval, compression and context allocation.
The interface and telemetry are planned now; the optimization policy is deliberately deferred.

## 11. Net effect

| Component | Fate |
|---|---|
| Skill / Agent separation | Kept |
| Local model runtime | Promoted to a first-class constraint |
| Context resolver | Kept; now reads bounded memory |
| Planner | Kept; requests capabilities, not implementations |
| Policy engine | Kept with grants/approval routing |
| Provider registry | Expanded to native + multiple MCP providers |
| Necessity gate | Added before provider execution |
| Memory | Restored with baseline/active/long-lived tiers; never evidence |
| Artifact/evidence system | Kept as source of truth |
| Event bus | Still replaced by append-only hash-chained event log |
| Token Optimizer | Deferred to v2 |
