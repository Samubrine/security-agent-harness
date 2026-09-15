# 00 — Vision and Scope

## 1. Problem

Security tooling is not missing tools. `nmap`, log parsers, vulnerability databases, Sigma,
Nuclei and MCP-connected services already exist. What is missing is **bounded orchestration and
reasoning across them**: an analyst manually decides which capability is actually needed next,
translates outputs, correlates evidence, and repeatedly reconstructs context.

Traditional automation solves this with a fixed pipeline:

```text
scan -> parse -> report
```

That pipeline cannot adapt. A naive agent can adapt, but tends to over-call tools, duplicate
work, inflate context, and spend tokens because another provider is available. This project
therefore treats **tool necessity** as a first-class runtime decision.

## 2. What we are building

A **local-first agentic security investigation harness**: an extensible runtime in which skills
request capabilities, a locally hosted LLM proposes the next information need, and a
deterministic spine decides whether another tool/provider call is necessary.

```text
Objective -> Reason -> Need -> Necessity Gate -> Investigate -> Correlate -> Adapt -> Report
```

The port scanner and log analyser are the first two skills, not the product itself. The product
is the harness: local inference, bounded persistent memory, evidence-backed state, capability
routing, provider selection, policy enforcement, and replay.

## 3. Core project claims

The project should be presented around five claims:

1. **Local-first reasoning:** the default model runs locally; remote inference is explicit opt-in.
2. **Evidence-first security:** every finding is defensible from immutable artifacts.
3. **Persistent but bounded memory:** the agent can retain useful context across runs without
   allowing memory to become a source of truth for findings.
4. **Provider diversity without provider spam:** native tools and multiple MCP servers can satisfy
   the same logical capability, but the harness selects the minimum sufficient provider set.
5. **Auditable autonomy:** the model proposes; the deterministic spine owns scope, execution,
   budget, evidence, memory writes and replay.

## 4. Skills in scope

| Skill | Objective | Status |
|---|---|---|
| `port_scan` | Enumerate exposed services on authorised targets, map to candidate vulnerabilities | Milestone 1 |
| `log_analysis` | Detect suspicious authentication and HTTP activity in a log corpus | Milestone 2 |
| `entry_point` | Correlate scan + log evidence into a supported attack-entry-point hypothesis | Milestone 3 |
| `pcap_analysis`, `ioc_hunt`, `config_audit` | — | Future work |

## 5. Non-goals

- No scanning of systems we do not own; targets are local, containerised and signed into scope.
- No exploitation, persistence, lateral movement, C2, or autonomous remediation.
- No production SIEM integration in v1.
- No multi-agent swarm. Provider plurality means multiple evidence sources, not multiple LLMs.
- No requirement for a vector database.
- No dynamic token-optimization engine in v1. v1 has hard budgets, caching, context tiers and a
  deterministic necessity gate; a proper Token Optimizer is version two.
- Not a general chat assistant; interactions belong to an investigation lifecycle.

## 6. Success criteria

The project succeeds if a grader can observe:

1. One command runs a full local-model investigation and produces an evidence-linked report.
2. Every finding cites immutable current-run evidence; hallucinated CVEs fail validation.
3. The harness resumes across runs with `BASELINE.md`, bounded `MEMORY.md`, and selectively
   retrieved long-lived memory.
4. Memory-only statements cannot validate a finding.
5. A capability with several available providers normally executes only the minimum sufficient
   one; a second provider is invoked only with a recorded necessity reason.
6. A conflicting or incomplete first result can trigger a second provider and the report exposes
   agreement/conflict rather than hiding it.
7. A seeded scope-expansion/prompt-injection attempt is blocked and logged.
8. A recorded run replays without re-touching providers and reconstructs the same findings.

## 7. Vocabulary

| Term | Meaning |
|---|---|
| **Harness** | Runtime, policy, providers, artifacts, memory and reporting |
| **Runtime / spine** | Deterministic owner of lifecycle, state, budgets and transitions |
| **Agent / brain** | Local model policy that proposes the next information need |
| **Skill** | Declarative objective, inputs, allowed capabilities and outputs |
| **Capability** | Logical operation such as `service.enumerate` independent of provider |
| **Provider** | Native tool or MCP server that can satisfy one or more capabilities |
| **Necessity gate** | Decides whether current evidence already satisfies a need and, if not, the minimum provider set |
| **Artifact** | Immutable raw output, content-addressed and hashed |
| **Evidence** | A span inside a named artifact, with a digest |
| **Memory** | Cross-run planning context; never valid finding evidence |
| **Run** | One investigation: objective + scope + budgets + event log |

## 8. Constraints

- Solo implementer, approximately one semester.
- Local inference must be usable on commodity hardware, so prompts and model calls are budgeted.
- All security targets are local/self-owned.
- Network access by providers is explicit and policy-gated.
- Graded on demonstrable, verifiable behaviour rather than architectural ambition.

The final constraint is why v1 deliberately implements a simple, explainable provider-necessity
gate and defers adaptive token optimization to v2.
