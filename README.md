# Agentic Security Investigation Harness

Final project (PBKK). A **harness** — not an app — where security investigation
capabilities are dropped in as *skills*, *tools*, and *MCP servers*, and an LLM
decides what to investigate next inside a deterministic, auditable runtime.

> **The LLM decides what to investigate next. The harness decides how it is allowed to happen.**

Status: **design phase**. Repo is documentation-only; no code yet.

## Design docs

| Doc | Contents |
|---|---|
| [00-vision-and-scope.md](docs/design/00-vision-and-scope.md) | Problem, framing, in-scope skills, non-goals, success criteria |
| [01-architecture.md](docs/design/01-architecture.md) | Component model, investigation loop, run state machine, extension points |
| [02-data-model.md](docs/design/02-data-model.md) | Artifacts, findings, evidence binding, event log, tool contracts |
| [03-policy-and-safety.md](docs/design/03-policy-and-safety.md) | Scope model, capability gates, approvals, prompt-injection defense |
| [04-prior-art.md](docs/design/04-prior-art.md) | Survey of existing agentic security projects and frameworks |
| [05-alternatives-considered.md](docs/design/05-alternatives-considered.md) | Competing architectures and why they were rejected or partially adopted |
| [06-implementation-roadmap.md](docs/design/06-implementation-roadmap.md) | Vertical slice, milestones, week-by-week plan |
| [07-evaluation-plan.md](docs/design/07-evaluation-plan.md) | Lab targets, ground truth, metrics, ablations, injections |
| [decisions.md](docs/design/decisions.md) | ADR log — numbered decisions with status |

## Headline decisions

1. **Deterministic spine, probabilistic brain.** The run is a state machine; the
   LLM proposes typed actions, it never emits shell commands or free-form plans.
2. **Tool output never reaches the model raw.** Outputs are stored as
   content-addressed artifacts and replaced in-context by deterministic parser output.
3. **Findings cannot exist without evidence.** Every finding carries hashed
   evidence references; a validator rejects anything unbound.
4. **Vulnerability mapping is not an LLM task.** CPE normalization plus offline
   version-range matching against OSV/NVD decides candidate CVEs.
5. **Scope is structural.** Capability grants derive from an authorization record;
   out-of-scope destinations are unreachable, not merely discouraged.
6. **Every run is replayable.** Append-only event log plus recorded model responses
   means the same run can be reproduced for grading.

## Planned layout

```
docs/design/          the design plan (this phase)
src/harness/          runtime, policy, tools, parsers, findings, report, skills
lab/                  docker-compose vulnerable targets + seeded log datasets
eval/                 ground truth, scenario runner, metrics
tests/
```

