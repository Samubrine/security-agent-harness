# Prior Art & Reusable Frameworks — Agentic Security Harness

**Verdict up front:** nobody has shipped a real policy engine plus a tamper-evident evidence log; that gap is your contribution. Reuse MCP servers for tools, copy Strix's "sandbox, then validate before reporting" discipline, and write the loop yourself (~400-600 LOC). Adopt LangGraph only if durable resume outweighs legibility.

## 1. Pentest-agent projects: what exists, what it teaches

**Strix — https://github.com/usestrix/strix (~62k stars, Apache-2.0, active).** Multi-agent orchestration; agents get terminal + browser inside Docker, write and run their own tooling, and must validate each finding with a working PoC; ships CI integration and auto-fix. *Steal:* the per-target container as the unit of trust, and "no reproduction, no finding" as a hard gate before the report. *Avoid:* its unbounded "hack anything" scope — no policy layer at all, and every run is costly.

**CAI — https://github.com/aliasrobotics/cai (~9.8k stars; paper https://arxiv.org/abs/2504.06017).** Now **archived** (2026), succeeded by Alias Robotics' "Cybersecurity Superintelligence." Best-documented reference implementation: agent loop, tool registry, MCP bridge, human-in-the-loop prompts, per-run cost tracking; 18 papers, 30+ CVEs found. *Steal:* the separation of a reasoning agent from an execution/tool agent, plus token/cost accounting per run — cheap and very demoable. *Avoid:* building on an archived repo; its guardrails are prompt-level, not enforceable policy.

**PentestGPT — https://github.com/GreyDGL/PentestGPT (~15.5k stars; paper https://arxiv.org/abs/2308.06782).** Three modules (reasoning, generation, parsing) over a **Pentesting Task Tree** that persists progress. *Steal:* the explicit task tree — make your memory a structured artifact, not a chat transcript. *Avoid:* prompt-only state with no sandboxed tools and no typed tool contracts; brittle over long engagements.

**hackingBuddyGPT — https://github.com/ipa-lab/hackingBuddyGPT (~1.2k stars, active; paper https://arxiv.org/abs/2308.00121).** Closest fit to your design: LLM connectivity, SSH/local/psexec connectors, capability (tool) wiring, run limits, structured logging, plus a reusable privesc benchmark (https://github.com/ipa-lab/benchmark-privesc-linux). *Steal:* "a use-case is a few dozen lines over shared plumbing" — exactly the extensibility story for scanner-now, log-analyzer-next. *Avoid:* mostly stateless capabilities; no policy engine, no cross-run memory.

**Vulnhuntr — https://github.com/protectai/vulnhuntr (~2.8k stars, last pushed Feb 2025).** Not an agent loop: LLM triage over static analysis that confirms remote exploitability before reporting. *Steal:* have the LLM rank and confirm machine-generated findings rather than discover from scratch — right for a log analyzer. *Avoid:* the "LLM reads all the code" cost model, and its unmaintained status.

**AutoPenBench — https://github.com/lucagioacchini/auto-pen-bench (paper https://arxiv.org/abs/2410.03225).** Eval harness separating "in-vitro" single-shot tasks from multi-step "real" tasks. *Steal:* adopt its task taxonomy as your test suite so you can claim measured improvement. *Avoid:* treating its scores as a leaderboard.

**Benchmarks to run against:** Cybench (https://arxiv.org/abs/2408.08926, https://github.com/andyzorigin/cybench), CyberGym (https://github.com/sunblaze-ucb/cybergym), BoxPwnr (https://github.com/0ca/BoxPwnr).

## 2. Runtime: framework or your own loop?

- **LangGraph** (https://github.com/langchain-ai/langgraph, ~41.6k stars; docs https://docs.langchain.com/oss/python/langgraph/overview) — graph state machine, durable checkpointers, `interrupt()` for human approval, time-travel replay. Best off-the-shelf match for approval gates and "resume the scan tomorrow." Cost: framework vocabulary leaks into your domain model.
- **Pydantic AI** (https://github.com/pydantic/pydantic-ai, ~20k stars) — typed dependencies, typed tools, validated outputs; no durable loop. Use it as your tool/model *layer* inside your own orchestrator.
- **OpenAI Agents SDK** (https://openai.github.io/openai-agents-python/) — agents, handoffs, guardrails, tracing. Fastest to demo; weakest persistence and state story.
- **Apache Burr** (https://github.com/apache/burr, docs https://burr.apache.org/) — explicit FSM with persistence, HITL, tracing UI. Cleanest conceptual match; much smaller ecosystem.
- **Temporal** (https://temporal.io/) — durable workflows/activities, retries, crash recovery. Correct only for hour-long scans surviving process death; server ops are out of scope.
- **smolagents / DSPy** (https://github.com/huggingface/smolagents, https://github.com/stanfordnlp/dspy) — code-writing agents and prompt-program optimization. Orthogonal: neither gives policy or durable state.
- Pattern reading: Anthropic's "Building effective agents" (https://www.anthropic.com/engineering/building-effective-agents) and https://github.com/humanlayer/12-factor-agents (~25.9k stars) — the latter's "own your control flow" is the argument for recommendation #1 below.

## 3. MCP: do not write nmap wrappers

- **FuzzingLabs/mcp-security-hub** (https://github.com/FuzzingLabs/mcp-security-hub, ~786 stars) — dockerized nmap, masscan, nuclei, whatweb, gitleaks, radare2, sqlmap, hashcat, plus wrappers for ZoomEye, ProjectDiscovery (https://github.com/intelligent-ears/pd-tools-mcp) and ExternalAttacker. Closest thing to a ready-made tool registry for Level-1 capabilities.
- **HexStrike AI MCP** (https://github.com/0x4m4/hexstrike-ai, ~11.9k stars) — 150+ security tools behind one FastMCP server with process management and caching. Great coverage, but adopting it as "the architecture" collapses your Tool Registry and Policy Engine into one opaque call — use it as an optional backend.
- **nmap**: https://github.com/PhialsBasement/nmap-mcp-server, https://github.com/imjdl/nmap-mcpserver, https://github.com/0xPratikPatil/NmapMCP (all small; prefer the hub's dockerized nmap).
- **Shodan**: https://github.com/w0h1v/mcp-shodan (~171 stars; now hosts the former BurtTheCoder/mcp-shodan the hub calls "official"), https://github.com/Cyreslab-AI/shodan-mcp-server.
- **Packets**: https://github.com/0xKoda/WireMCP (~584 stars, tshark live capture + pcap analysis), https://github.com/bx33661/Wireshark-MCP.
- **Code/CVE/exploit**: https://github.com/semgrep/mcp, https://github.com/mukul975/cve-mcp-server, https://github.com/GH05TCREW/MetasploitMCP.
- **Kali bridges** (https://github.com/zebbern/zebbern-kali-mcp, https://github.com/i3T4AN/Kali_Linux_MCP) auto-generate a tool per binary — fast, but they hand the model raw shell, which is exactly the blast radius your policy engine exists to shrink.
- Inherited risk: tool descriptions *and tool output* are untrusted input (MCP security best practices, https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices). Treat NSE scripts, banners and log lines as injection-capable text.

## 4. Terminal-agent harnesses: what transfers

- **OpenAI Codex CLI** (https://github.com/openai/codex, ~124k stars) — approval modes, OS sandboxing, patch-based edits, context compaction. *Transfer:* make approval an explicit mode with default-deny, and make every tool call a reviewable, revertable artifact.
- **Claude Code** (https://github.com/anthropics/claude-code; settings/permissions https://code.claude.com/docs/en/settings) — allow/deny/ask rules on tool + arguments, hooks, subagents, compaction. *Transfer:* the "ask" rule list is a shipping Policy Engine — evaluate rules before execution, prompt the human as fallback.
- **OpenHands** (https://github.com/OpenHands/OpenHands, ~88k stars; runtime docs https://docs.openhands.dev/openhands/usage/architecture/runtime) — containerized runtime, event stream, condenser. *Transfer:* event-stream-as-source-of-truth gives replay, audit and UI for free.
- **SWE-agent** (https://github.com/SWE-agent/SWE-agent, ~20k stars) — Agent-Computer Interface: tools shaped for the model instead of raw shell, guardrailed edits, and it now ships offensive-security configs. *Transfer:* design the tool surface deliberately — `scan_ports(target, profile)` beats `run_shell("nmap ...")`.
- **Claude Agent SDK** (https://github.com/anthropics/claude-agent-sdk-python) for the same loop as a library; https://github.com/anthropics/claude-code-security-review as reporter-side prior art.

## Ranked recommendation

1. **Build a thin custom orchestrator and reuse everything else.** ~400-600 LOC Python: Pydantic-typed tool I/O, your own `proposed → approved → executed → observed` state machine, SQLite/JSONL event log + findings table, MCP client for tools. Your differentiating claim *is* the policy engine, evidence log and finding schema — frameworks either hide or fight those. Copy Claude Code's rule-based permissions, OpenHands' event stream, Strix's PoC-before-report gate.
2. **LangGraph** if durable resume and streaming must work in week one — its checkpointer and `interrupt` map 1:1 onto approval gates and long scans. Accept that its vocabulary becomes yours.
3. **Apache Burr** — similar benefits, better FSM tracing, smaller community; pick over LangGraph only if you want to avoid LangChain.
4. **OpenAI Agents SDK** — fastest to a demo with tracing included; weakest persistence. Fine for short runs on a fixed model.
5. **Temporal** — right for multi-hour engagements surviving restarts; wrong cost/benefit for a course project.
6. **Skip for now:** DSPy (prompt optimization is premature), smolagents (code-agent style fights a typed, policy-gated registry), and any 150-tool mega-server used as *the* architecture.

**Cheap concrete wins:** put mcp-security-hub's dockerized nmap plus w0h1v/mcp-shodan behind your registry; lift AutoPenBench/Cybench task shapes for evals; require a PoC before a finding is written.

**Could not verify (flagged, not invented):** "RapidPen", "Nebula" (pentest agents) and "Cleric" (SRE/harness framework) — no credible GitHub or arXiv match under those names. Also unverified: AutoPenBench's task counts and HexStrike's "150+ tools" figure (README claim, not counted). All URLs above returned HTTP 200 when checked.

---

## Verification spot-check

The load-bearing figures above were re-checked independently before being folded into the
plan. The GitHub API was rate-limited from this host, so counts were taken from the rendered
repository pages:

| Repository | Claimed | Observed | Status check |
|---|---|---|---|
| `usestrix/strix` | ~62k | 62,474 | `isArchived: false` — active |
| `aliasrobotics/cai` | ~9.8k | 9,827 | "archived by the owner on Aug 28, 2026. It is now read-only." |
| `langchain-ai/langgraph` | ~41.6k | 41,652 | active |
| `FuzzingLabs/mcp-security-hub` | ~786 | 786 | active |

Two cautions carried forward: **the remaining star counts are single-source and unverified**, and
**stars measure popularity, not suitability** — CAI being simultaneously the best-documented
reference implementation and archived is the cautionary case. "RapidPen", "Nebula", and
"Cleric" could not be confirmed to exist, so no decision in this plan rests on them.

## What this changes in the plan

| Finding | Effect on the design | Where |
|---|---|---|
| No surveyed project pairs an enforceable policy engine with a tamper-evident evidence log | The contribution claim is the *pairing*, and it should be stated as "as far as this survey could determine" rather than as a universal negative | 00 §3, report framing |
| Strix enforces "no reproduction, no finding" before reporting | Adopted as the top rung of the confirmation ladder: `confirmed` requires an active verification artifact, never an assertion | 02 §5, D9 |
| PentestGPT persists state as an explicit task tree rather than a transcript | Independent convergence on the graph-as-state decision, from a project that predates it | 02 §1, D2 |
| Vulnhuntr has the model rank and confirm machine-generated findings rather than discover them | Validates "the spine constructs findings, the model ranks and explains" for the log analyser | 01 §1, D5 |
| hackingBuddyGPT's "a use case is a few dozen lines over shared plumbing" | Supplies the benchmark for the extensibility claim: measure added lines and added core files per new skill, and report both | 01 §8, 07 §4 |
| Claude Code ships allow/deny/ask argument rules as an actual policy engine | The three-verdict model is a proven shape, not an invention; adopt the rule-list structure for the approval router | 03 §3 |
| SWE-agent's agent-computer interface: tools shaped for the model, not raw shell | Confirms the typed tool surface: `port_scan(target, profile)` rather than `run_shell("nmap …")` | 02 §7, D16 |
| OpenHands treats the event stream as the source of truth | Confirms the event log over an event bus, from a shipping 88k-star project | 02 §6, D14 |
| Codex CLI and Claude Code make approval an explicit mode with default-deny | Approval routing is modelled as a mode, and `--dry-run` renders intent without execution | 03 §3, 03 §8 |
| CAI tracks tokens and cost per run | Cost accounting is a metric from M1, not an afterthought | 07 §4 |
| `mcp-security-hub` already ships dockerized nmap, masscan, and nuclei behind MCP | Investigated and **partially** adopted: good for third-party lookups, but `nmap` itself is wrapped natively so the evidence model keeps control of raw byte capture. See D13 for the reconciliation | 06 §3, D13 |
| Kali MCP bridges expose one tool per binary and hand the model raw shell | Rejected outright: that is precisely the blast radius the tool registry exists to shrink | 03 §7, D4 |
| MCP tool descriptions *and* outputs are untrusted input | Reinforces the taint model: a tool's own advertised description is data, not authority | 03 §4, D17 |
| HexStrike collapses 150+ tools behind one server | Rejected as architecture — it would merge the tool registry and policy engine into one opaque call — but acceptable as an optional backend | 03 §2 |
| Recommendation: own the loop, ~400–600 LOC | Confirms D15; LangGraph remains the fallback if durable resume becomes a hard requirement | D15 |

The net effect is a small set of concrete substitutions rather than a redesign: **nmap and Nuclei
arrive as MCP servers instead of hand-written wrappers**, the confirmation ladder gains Strix's
reproduction gate, and the extensibility claim gains a numeric benchmark. The architecture
itself is unchanged by the survey, which is the useful result — the parts that survive a review
of prior art are the same parts the alternative-architecture review independently selected.
