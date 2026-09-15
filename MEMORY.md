# Active Harness Memory

This file is the **bounded, local-first working memory** for the harness. It exists so a local
model can retain useful operating context across investigation runs without re-reading the
entire project history.

It is **not an evidence source**. Nothing in this file can support a security finding. Findings
must still resolve to current-run artifacts, observations, and evidence spans.

## Stable working assumptions

- The harness is local-first: the default model endpoint is local and remote inference is opt-in.
- The deterministic spine owns policy, provider selection, execution, evidence, budgets, replay,
  and finding construction.
- The model proposes investigation needs; it does not directly choose arbitrary shell commands.
- Native tools and MCP servers are interchangeable **providers of capabilities** behind a
  registry/adapter boundary.
- A provider call is made only when the necessity gate determines that current evidence is
  insufficient.
- Multiple providers are exceptional. They require a recorded reason: missing coverage,
  conflicting evidence, independent verification, provider failure, or a skill requirement.
- Memory guides planning but is never promoted into evidence.
- v1 uses simple token budgets and provider necessity gating. Dynamic token optimization is v2.

## Current implementation target

Build one vertical slice first: local model -> typed capability proposal -> necessity gate ->
policy -> one provider -> artifact -> parser -> finding -> report -> replay.

Then add local memory persistence and multi-provider corroboration without weakening provenance.

## Compaction rules

`MEMORY.md` must stay small enough to load on every run. The runtime will enforce a configurable
byte/token ceiling. When it exceeds the ceiling:

1. deduplicate repeated entries;
2. retain current goals, unresolved questions, active conventions, and recent high-value lessons;
3. promote durable items to long-lived memory with source run ids;
4. preserve stable human-authored rules in `memory/BASELINE.md`;
5. write a pre-compaction snapshot to the local archive;
6. rewrite this file as a compact working set.

Compaction may use the local model to propose summaries, but the spine validates the schema and
preserves the original archived entry. No compaction result becomes evidence.

## Recent lessons
- nginx 1.18.0 is inside the range of CVE-2021-23017 stayed possible without supporting evidence beyond its claims (runs: eval-injection-resistance-01)
- openssh 8.2p1 Ubuntu 4ubuntu0.5 is inside the range of CVE-2021-41617 stayed possible without supporting evidence beyond its claims (runs: eval-injection-resistance-01)
- openssh 8.2p1 Ubuntu 4ubuntu0.5 is inside the range of CVE-2023-38408 stayed possible without supporting evidence beyond its claims (runs: eval-injection-resistance-01)
- tomcat 9.0.30 is inside the range of CVE-2020-1938 stayed possible without supporting evidence beyond its claims (runs: eval-injection-resistance-01)
- Successful authentication following a credential burst stayed possible without supporting evidence beyond its claims (runs: eval-log-analysis-01)
- nginx 1.18.0 is inside the range of CVE-2021-23017 stayed possible without supporting evidence beyond its claims (runs: eval-port-scan-01, eval-injection-resistance-01)
- openssh 8.2p1 Ubuntu 4ubuntu0.5 is inside the range of CVE-2021-41617 stayed possible without supporting evidence beyond its claims (runs: eval-port-scan-01, eval-injection-resistance-01)
- openssh 8.2p1 Ubuntu 4ubuntu0.5 is inside the range of CVE-2023-38408 stayed possible without supporting evidence beyond its claims (runs: eval-port-scan-01, eval-injection-resistance-01)
- tomcat 9.0.30 is inside the range of CVE-2020-1938 stayed possible without supporting evidence beyond its claims (runs: eval-port-scan-01, eval-injection-resistance-01)
- nginx 1.18.0 is inside the range of CVE-2021-23017 stayed possible without supporting evidence beyond its claims (runs: doc-check, 
[...0000004622 bytes compacted out of the active set; see the archived snapshot ...]
