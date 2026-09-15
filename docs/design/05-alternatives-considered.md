# 05 — Alternatives Considered

Every alternative below was evaluated against one question: **does it make the harness more
provable?** A design that is more elegant but harder to demonstrate to a grader loses.

## 1. Loop shape: ReAct vs plan-and-execute vs Reflexion vs search

| Approach | Trade-off | Verdict |
|---|---|---|
| ReAct (one step at a time) | Simplest and most adaptive, but terminates worst — security investigation has no natural stop condition, so it drifts toward "let me dig deeper" forever | **Reject alone** |
| Plan-and-execute | Produces a plan object that can be rendered, checkpointed, and edited; less adaptive until re-planning is added | **Adopt as the outer loop** |
| Bounded ReAct inside the plan | Keeps local adaptivity without unbounded drift | **Adopt as the inner loop, with a hard step budget** |
| Reflexion (self-critique) | Needs a verification signal; without one it is confident prose about nothing | **Reject** |
| Tree search over *actions* | Low yield here: tool calls are cheap, deterministic, and re-runnable, so running them beats simulating them | **Reject** |
| Beam search over *hypotheses* | Keeps ~3 candidate explanations alive and scores them against evidence | **Adopt partially**, if time allows |

Adopted shape: **plan-and-execute outer loop, bounded inner loop, hypotheses rather than
actions as the place where branching pays off.**

## 2. Deterministic orchestration vs a free-running loop

A free-running loop is easier to write and produces a more impressive-looking transcript. A
deterministic state machine costs code that feels unnecessary while the happy path works.

**Adopt the state machine.** The deciding argument is not aesthetics: a security finding must
be defensible to a third party — a grader, an auditor, an incident report — so "the run is a
replayable artifact" is a *product requirement*, not hygiene. It is also the direct answer to
the "this is an LLM wrapper" critique, and a replayed run is a far better demo than a live one
that might flail.

Rejected: Temporal (a server dependency and an ops burden for a course project). LangGraph was
considered seriously and is defensible if the graph *is* the system rather than decoration; a
hand-written FSM over a typed state dict is roughly 200 lines and keeps the control flow
readable, which is worth more here than the ecosystem.

## 3. Blackboard and evidence/hypothesis graph

The investigation's state *is* a graph: nodes are artifacts, observations, claims, and
findings; edges are `derived_from`, `supports`, `contradicts`. Producers write into shared
state, and the planner's job is to resolve the next open question the graph implies rather
than to re-read a transcript.

**Adopt, and treat it as the spine.** It makes provenance free, turns cross-source correlation
into a graph query instead of a prompting technique, and makes the report a traversal. The
cost is that the node vocabulary must be fixed early and the graph must be aggressively
aggregated — one broad scan emits thousands of observations — which is why rollup observations
are mandatory in 02.

This also **dissolves the "Memory" component** from the original design. Memory becomes an
index over the graph, and no vector store ships in v1: for questions that are mostly counting,
ranking, and joining, SQL plus a text index beats embeddings and costs far less effort.

## 4. Reuse standards instead of inventing a DSL

| Standard | Fit | Verdict |
|---|---|---|
| **Sigma** | Log detection rules, with a large existing rule corpus | **Adopt as the rule format** for `log_analysis`; implement a small evaluator for the subset used, with `pysigma` as the fallback if fidelity matters |
| **Nuclei templates** | Templated protocol checks, widely accepted | **Adopt as the active-verification tool** — the `HIGH` risk step that moves a finding to `confirmed` |
| **OCSF** | Normalized security event and finding schema | **Adopt as an output shape**, not as internal models; map at report time |
| **CACAO** | The only real workflow playbook standard | **Borrow the input/output shape only**; verbose, thin tooling, and not worth claiming conformance |
| **STIX 2.1** | Threat-intel indicators | **Defer**; emit only if the project ships indicators |
| **PROV-O / in-toto** | Provenance | **Borrow the shape** (`wasGeneratedBy`, `used`, subject/predicate) and emit a few flat triples, rather than importing an ontology into core models |

A bespoke skill DSL is still used, but only as a thin declarative wrapper over inputs,
capabilities, and allowed tools. **Detection logic and vulnerability checks do not get
reinvented.** The practical reason is the question every reviewer asks — "why not Sigma?" — and
the honest answer is that reusing a validated format buys tooling, shareability, and
credibility for less work.

Importing the big ontologies into the core schema, by contrast, is how solo projects die.

## 5. Capability grants vs a risk-tiered policy gate

The original proposal had the agent name a target and a gate approve it: a *checked*
invariant, dependent on every tool faithfully consulting the gate, sitting in an `if` with a
wide bypass surface.

The alternative mints opaque, scoped grants at context resolution; tools accept a grant and
never a raw target, and resolve the real host against it.

**Adopt.** Out-of-scope access becomes structurally inexpressible — there is no syntax for it —
and authority becomes auditable and revocable. Full object-capability purity is overkill for
this project, but the scope-token subset is the highest-leverage safety work available and it
converts "the agent cannot leave scope" from a claim into a property. See 03.

Importantly, **risk tiering is kept for a different question** — when to interrupt a human
before an intrusive action. The original design conflated two mechanisms into one "Policy
Engine" step; they answer "may I" and "should I ask" respectively, and both are needed.

## 6. Single agent vs multi-agent

Planner/executor/critic splits and per-skill subagents are the most commonly proposed upgrade
to a design like this, and the least justified at this scale.

The real benefit of role separation is state discipline — separating "what next" from "how" —
not parallelism. Multi-agent costs context duplication, latency, extra failure modes, and
non-reproducible control flow. Decisively: **a critic without a verification signal is one LLM
reviewing another**, which is theatre and would not survive a question in a defence.

**Reject multi-agent as the default.** Adopt the *verifier* as a deterministic component —
re-probe the port, re-grep the log line, assert that every evidence edge resolves — with the
model consulted only for genuinely ambiguous cases. Skills are playbooks, not processes.

## 7. What the review flagged as overrated

Two original components were demoted, and the reasoning is worth recording because both are
attractive in a slide deck:

- **MCP as an architecture layer.** For a port scanner and log analyser, no tool genuinely
  needs to be remote, so MCP buys a slide and an entire external-protocol dimension. It is
  kept as **one adapter behind the tool registry** — an interface, not a layer. This is a
  partial disagreement: the harness's thesis *is* pluggability, so demonstrating one
  third-party tool arriving with zero core changes is worth a day of work. It is not worth a
  subsystem.
- **The event bus.** A single append-only JSONL run log already delivers replay, audit, and UI
  progress. A bus is infrastructure built to say it was built.

## 8. Net effect on the original design

| Original component | Fate |
|---|---|
| Skill / Agent / Tool separation | Kept, sharpened into contracts |
| Context Resolver | Kept, and promoted: it mints grants |
| Planner | Kept, narrowed: a plan object plus one action per cycle |
| Policy Engine | Split into capability grants and approval routing |
| Tool Registry | Kept |
| MCP integration | Demoted to one adapter |
| Memory | Removed; replaced by the evidence graph and its indexes |
| Artifact system | Kept, promoted to the substrate |
| Event bus | Replaced by an append-only event log |
| Reporter | Kept, made deterministic from structured state |

Ten components became nine, one of which is now the state itself. The count barely moved; what
changed is that the load-bearing ideas are now enforceable rather than aspirational.

