# Agentic Security Investigation Harness

Final project (PBKK). A **local-first agentic harness** — not an app — where security
investigation capabilities are dropped in as *skills*, *native tools*, and *MCP providers*,
and a locally hosted LLM decides what to investigate next inside a deterministic, auditable
runtime.

> **The model decides what information it needs. The harness decides whether another tool call is necessary, which provider may satisfy it, and how it is allowed to happen.**

Status: **design phase**. Repo is documentation-first; implementation begins from the vertical
slice in `docs/design/06-implementation-roadmap.md`.

## Design docs

| Doc | Contents |
|---|---|
| [00-vision-and-scope.md](docs/design/00-vision-and-scope.md) | Problem, framing, in-scope skills, non-goals, success criteria |
| [01-architecture.md](docs/design/01-architecture.md) | Deterministic spine, local model runtime, investigation loop, provider routing |
| [02-data-model.md](docs/design/02-data-model.md) | Artifacts, findings, evidence binding, event log, tool contracts |
| [03-policy-and-safety.md](docs/design/03-policy-and-safety.md) | Scope model, capability gates, approvals, prompt-injection defense |
| [04-prior-art.md](docs/design/04-prior-art.md) | Survey of existing agentic security projects and frameworks |
| [05-alternatives-considered.md](docs/design/05-alternatives-considered.md) | Competing architectures and why they were rejected or partially adopted |
| [06-implementation-roadmap.md](docs/design/06-implementation-roadmap.md) | Vertical slice, milestones, week-by-week plan |
| [07-evaluation-plan.md](docs/design/07-evaluation-plan.md) | Lab targets, ground truth, metrics, ablations, injections |
| [08-local-first-memory-and-routing.md](docs/design/08-local-first-memory-and-routing.md) | Local model contract, memory lifecycle, multi-provider necessity gate, v2 token optimizer |
| [decisions.md](docs/design/decisions.md) | ADR log — numbered decisions with status |

## Headline decisions

1. **Local-first model execution.** The default planner runs on a local inference endpoint.
   Remote model adapters are opt-in and may never receive evidence or memory implicitly.
2. **Deterministic spine, probabilistic brain.** The run is a state machine; the model
   proposes typed capability needs, while the harness owns execution, policy, budgets and state.
3. **Memory is context, never evidence.** `MEMORY.md` is bounded active memory; stable baseline
   memory and long-lived memory are stored separately. Findings still require artifact-backed
   evidence from the current investigation.
4. **Providers are selected by necessity.** A capability request is satisfied by the minimum
   sufficient set of native tools/MCP providers. Multiple providers require a recorded reason
   such as coverage, conflict resolution, independent verification, or failure fallback.
5. **Tool output never reaches the model wholesale.** Outputs become content-addressed
   artifacts; only deterministic rollups and bounded evidence spans enter context.
6. **Vulnerability mapping is deterministic.** CPE normalization plus offline version-range
   matching against snapshot-stamped vulnerability data decides candidate CVEs.
7. **Scope is structural.** Capability grants derive from an authorization record; out-of-scope
   destinations are unreachable, not merely discouraged.
8. **Every run is replayable.** Append-only, hash-chained events plus recorded model/provider
   responses reproduce structured state without re-touching the network.
9. **Token optimization is staged.** v1 uses hard budgets, fixed context tiers, caching and the
   provider necessity gate. A dynamic Token Optimizer is a version-two subsystem, not a v1
   dependency.

## Planned layout

```text
MEMORY.md                 bounded active working memory
memory/BASELINE.md        stable human-curated memory loaded every run
memory/LONG_TERM.md       durable memory format/index; runtime shards live under memory/long_term/
docs/design/              design plan
src/harness/              runtime, policy, providers, memory, tools, parsers, findings, report
lab/                      docker-compose vulnerable targets + seeded log datasets
eval/                     ground truth, scenario runner, metrics
tests/
```
