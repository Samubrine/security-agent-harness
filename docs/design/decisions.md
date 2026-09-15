# Decision Log

Statuses: **accepted**, **provisional** (accepted, revisit after M1), **open**, **rejected**.
Each decision records what it supersedes where relevant — the original design conversation is
referred to as *the source design*.

---

## D1 — The LLM proposes; the spine executes
**Accepted.** The model returns a typed `Proposal`; the runtime owns state, budgets, policy,
tool invocation, and finding construction.
*Rationale:* reproducibility, auditability, and unit-testability. It also converts the worst
failure modes — out-of-scope scans, run commands, invented CVEs — from behavioural problems
into type errors.
*Supersedes:* the source design's plan where the model drives the loop.

## D2 — The evidence graph is the system's primary state
**Accepted.** Nodes: artifact, observation, claim, finding, gap, execution, grant. Edges:
`derived_from`, `supports`, `contradicts`, `governs`, `weakens`.
*Rationale:* provenance, cross-source correlation, negative-result tracking, and report
generation all fall out of one structure instead of four mechanisms.
*Consequences:* node vocabulary is frozen early; rollup observations are mandatory because the
raw graph is far too large to prompt.

## D3 — Plan-and-execute outer loop with a bounded inner loop
**Accepted.** The model emits an advisory plan plus exactly one next action, and re-emits the
plan each cycle; plan revisions are diffed and logged.
*Rationale:* security investigation has no natural stop condition, so an unbounded ReAct loop
drifts. A stored plan is renderable, checkpointable, and makes adaptation a visible diff.
*Rejected:* Reflexion (no verification signal available), tree search over actions (tool calls
are cheap and re-runnable).

## D4 — Capability grants, not checked target strings
**Accepted.** Context resolution mints opaque, scoped, expiring grants; tools accept a grant
and resolve the host against it; targets are addressed by alias, and aliases exist only for
granted resources.
*Rationale:* converts scope enforcement from a checked invariant to a structural property. An
out-of-scope host has no representation in the schema.
*Supersedes:* the source design's single policy-gate approval of a target string.

## D5 — The model never authors a finding
**Accepted.** Parsers emit observations; rules and the matcher emit claims; the spine
assembles findings. The model may write `narrative` and propose hypotheses that must cite
existing observation ids.
*Rationale:* if the schema has no field where a model can assert a CVE, a hallucinated CVE is a
type error rather than something prompt engineering has to prevent.

## D6 — Severity is never assigned by the model
**Accepted.** Severity derives from CVSS where a CVE exists, otherwise from a fixed rubric on
observation kind and exposure.
*Rationale:* severity is the most confidently hallucinated value in LLM security tooling.

## D7 — Tool output reaches the model only as parsed observations and rollups
**Accepted.** Raw bytes are content-addressed artifacts; `nmap -oX` is parsed as XML by
`lxml`, never read as text; tiered context (T0–T4) governs what is prompted.
*Rationale:* a broad scan is hundreds of KB to several MB of XML and logs run to gigabytes;
raw injection also invites hallucination.

## D8 — Vulnerability mapping is deterministic, offline, and snapshot-stamped
**Accepted.** CPE normalisation plus version-range matching against a local NVD/OSV subset,
with EPSS and CISA KEV for prioritisation. Every claim records `db_snapshot`.
*Rationale:* the mapping is a lookup, and it is the single place the project can be most
credibly accused of fabricating results. Absence of a database match renders as "no match in
snapshot", never as "not vulnerable".

## D9 — Four-step confirmation ladder
**Accepted.** `possible` → `high` → `confirmed`, plus `not_affected` and `inconclusive`.
Promotion requires new evidence; the model can only *request* active verification.
*Rationale:* separates "this version is in range" from "this is exploitable", which is exactly
where LLM security tools overclaim.

## D10 — Sigma for log rules, Nuclei for active verification
**Accepted.** Log detection uses the Sigma format and a small evaluator over the subset used;
active verification shells out to Nuclei templates as a `HIGH` risk, approval-gated tool.
*Rationale:* reusing validated formats buys tooling, shareability, and credibility for less
work than inventing a DSL, and pre-empts "why not Sigma?".
*Supersedes:* the source design's implicit bespoke detection-rule layer.

## D11 — One agent plus a deterministic verifier; no multi-agent default
**Accepted.** Verification is re-probing, re-grepping, and asserting that evidence edges
resolve. The model is consulted only for ambiguous cases.
*Rationale:* a critic without a verification signal is one LLM reviewing another. Multi-agent
also costs context duplication and non-reproducible control flow.

## D12 — No memory component, and no vector store in v1
**Accepted.** Findings, observations, and gaps accumulate in structured stores; retrieval is
SQL plus SQLite FTS5.
*Rationale:* a memory component with no retrieval contract is a vector database waiting to
happen. For questions that are mostly counting, ranking, and joining, queries beat embeddings.
*Supersedes:* the source design's `Memory` component.

## D13 — MCP is one adapter behind the tool registry
**Accepted (provisional).** One MCP server wired in proves pluggability.
*Rationale:* no tool in this project genuinely needs to be remote, so MCP as an architecture
layer is unjustified; as a demonstration of the extensibility claim it is worth a day.
*Supersedes:* the source design's MCP integration as a first-class layer.

### D13a — Reconciliation of two conflicting review inputs
The prior-art survey recommended the opposite: use `mcp-security-hub`'s dockerized `nmap`,
`masscan`, and `nuclei` rather than writing wrappers, saving about a week. The alternative-
architecture review argued that no tool in this project needs to be remote at all.

**Resolved by which layer needs control of the bytes.** A native wrapper for `nmap` is roughly
thirty lines: build an argv array, run it under a timeout, capture stdout as an artifact. The
evidence model requires exactly that — raw output captured, hashed, and span-addressed by *this*
harness. Routing through an MCP server adds a protocol hop and puts the bytes somewhere the
artifact store does not control, in exchange for saving a trivial amount of code.

So the split is: **native wrappers where the harness must own the raw evidence** (`nmap`,
log reading, Nuclei invocation), **MCP where the underlying knowledge is third-party and the
raw bytes are not evidence** (intel lookups, e.g. a Shodan-style server). That keeps MCP in its
right role — an interface that proves pluggability — without letting it dilute the provenance
guarantee, which is the project's central claim.

## D14 — Append-only event log instead of an event bus
**Accepted.** One JSONL file per run, written by the spine only, monotonic sequence, hash-chained.
*Rationale:* delivers replay, audit, and UI progress for a tenth of the work.
*Supersedes:* the source design's event bus.

## D15 — Hand-written FSM, not an agent framework
**Accepted.** Roughly 200 lines over a typed state dict.
*Rejected:* Temporal (server dependency and ops burden), LangGraph (defensible, but the control
flow is the part of this system that most needs to be readable and inspectable).

## D16 — Structured outputs everywhere, JSON Schema exported once
**Accepted.** Pydantic v2 models define proposals, observations, claims, findings, and tool
I/O; the schema is exported at build time and used both for model output validation and for the
report.
*Rationale:* one definition, two consumers, no drift.

## D17 — Taint tracking and spotlighting as the injection defence
**Accepted.** Tool results carry a taint level; `T3` content is wrapped in a per-run nonce;
side-effectful calls whose arguments derive from `T3` are forced to human approval.
*Rationale:* the trust boundary is the most interesting thing in the project — the harness reads
thousands of strings authored by an adversary. Enforced in code, never in a prompt sentence.
*Novel relative to:* the source design, which did not consider adversarial input at all.

## D18 — Budgets terminate runs, and three consecutive failures stop the run
**Accepted.** Steps, tool calls, tokens, wall clock, artifact bytes, and consecutive failures
are all counted by the spine; exhaustion is a recorded outcome, not an exception.
*Rationale:* the cheapest guard against the classic agent pathology of retrying a broken tool
forever. The model cannot reset its own counter.

## D19 — The evaluation is scored against a scanner baseline
**Accepted.** Every headline metric is reported alongside plain `nmap`+`nuclei` on the same
lab, and the hallucination rate target is exactly zero.
*Rationale:* a project that reports an honest gap is more credible than one reporting a
suspiciously perfect result, and the baseline is the first question a reviewer will ask.

## D20 — Local, self-owned, egress-isolated lab only
**Accepted.** In-scope addresses come from a signed scope file; the lab network is created
`--internal`; no valid signature means exit before any model call.
*Rationale:* UU ITE 11/2008 as amended by UU 1/2024 (Pasal 30, 46) criminalises unauthorised
access regardless of intent or damage, and the same is true in most jurisdictions.

---

## Open questions

| # | Question | Blocking? | Resolution point |
|---|---|---|---|
| O1 | Minimal Sigma evaluator versus `pysigma` for fidelity | No | Before M2 |
| O2 | Hypothesis beam: worth it, or does single-hypothesis reasoning suffice? | No | After M1, if time allows |
| O3 | Whether the T2 rollups alone are sufficient, or retrieval tools (T3) genuinely earn their complexity | No | Measured by ablation A6 |
| O4 | Which single bench or lab set to fix on: the local compose stack, or `AutoPenBench`'s machine definitions | No | M0 |
| O5 | Whether vulnerability-database ingest is scoped to the lab's services or runs full-corpus | No | Week 3 |
