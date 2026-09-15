# 06 — Implementation Roadmap

## 1. The ordering rule

**One vertical slice before any horizontal layer.** The failure mode this plan exists to
avoid is building nine subsystems and having nothing that finds anything. So milestone 1 is a
complete run — scope, policy, tool, artifact, parser, finding, report — on a single target,
with several subsystems left deliberately naive. Every later milestone deepens a slice that
already works end to end.

The second rule follows from the first: **each milestone ends at a demo, not at a status**.
A milestone is done when a grader can watch the specific behaviour it exists to prove.

## 2. Milestones

| # | Deliverable | Proof it is done | Weeks |
|---|---|---|---|
| **M0** | Repo, lab, and skeleton | `make lab-up` brings a vulnerable container up on an internal network with no egress; `make check` runs tests and linters green | 1 |
| **M1** | Vertical slice: `port_scan` end to end | One command scans a granted container, produces a report whose findings each link to a byte range in a hashed artifact, and re-running replays identically | 2–4 |
| **M2** | `log_analysis` with Sigma rules and retrieval | Suspicious auth activity found in a seeded log corpus; Sigma rule ids cited; model never receives raw log lines, only rollups and requested spans | 5–7 |
| **M3** | `entry_point` cross-source correlation | A supported hypothesis linking an exposed service to a log-observed access pattern, with both source artifacts cited. Diff for this skill contains only new files plus one registry line | 8–10 |
| **M4** | Safety and trust hardening | Injection suite run: seeded payloads in banners and logs do not widen scope, and appear as findings; decoy host untouched across every scenario; `--dry-run` renders full intent | 10–12 |
| **M5** | Evaluation and report | Ground truth scored automatically; metrics table with ablations; baseline comparison against plain `nmap`+`nuclei`; report and slide deck written from the results | 12–14 |

### M1 in detail, because everything depends on it

Deliberately naive at this stage: fixed single-step planning if needed, hardcoded skill,
one target, markdown report only.

```
scan.yml  →  runtime loop  →  policy (grants)  →  port_scan tool  →  nmap -oX -
          →  artifact store (sha256)  →  nmap XML parser  →  Observations
          →  CPE normalisation  →  version-range matcher  →  Findings + EvidenceRefs
          →  validator  →  report.md with clickable spans
```

Definition of done, checked by hand before moving on:

1. Report contains at least one service observation and, if the version matches, one
   vulnerability candidate with `confidence_basis` naming the snapshot and range.
2. Clicking a finding's evidence link opens the exact bytes the parser read.
3. Deleting the signed scope file causes a hard exit before any model call.
4. `pytest` covers the parser, the matcher, and the validator with fixtures, not live scans.
5. The event log replays to the same finding ids.

If M1 slips past week 5, cut scope elsewhere rather than compressing it — this slice is the
project.

## 3. Repository layout

```
src/harness/
  runtime/     loop.py, fsm.py, budget.py, events.py, replay.py
  context/     resolver.py, builder.py, retrieval.py, taint.py
  policy/      grants.py, engine.py, approvals.py, scope.py
  artifacts/   store.py, provenance.py
  parsers/     nmap_xml.py, auth_log.py, nginx_access.py, registry.py
  analysers/   rules.py, sigma.py, cve_match.py, correlate.py
  findings/    models.py, validate.py
  tools/       registry.py, spec.py, native/, mcp_adapter.py
  llm/         client.py, schemas.py, prompts/
  report/      build.py, templates/
  skills/      port_scan.yaml, log_analysis.yaml, entry_point.yaml
  cli.py
lab/           docker-compose.yml, scope.json, scope.json.sig, logs/
eval/          scenarios/, ground_truth/, runner.py, metrics.py, injections/
tests/
```

Stack: Python 3.12, Pydantic v2, Typer, Rich, `lxml` for nmap XML, DuckDB for normalized rows,
SQLite FTS5 for the vulnerability database and text index, pytest, Docker Compose. No agent
framework — the hand-written FSM over a typed state dict is about 200 lines and is the part of
the system that most needs to be inspectable.

## 4. Week-by-week

| Week | Focus | Checkpoint |
|---|---|---|
| 1 | M0: repo, models, event log, artifact store, lab up | Artifact stored by digest; event log replays trivially |
| 2 | Tool registry, `port_scan` + nmap XML parser | Observations with evidence spans from a real scan |
| 3 | Vulnerability database ingest, CPE normalisation, matcher, validator | First evidence-bound finding; invariants enforced |
| 4 | Policy: scope file, signature, grants, approval gate; report renderer | M1 demo end to end |
| 5 | Log parsers, DuckDB ingestion, T2 rollups | Rollup observations from a seeded corpus |
| 6 | Sigma rule subset and evaluator; retrieval tools | Findings from log rules with rule ids cited |
| 7 | Context builder, budget accounting, termination paths | M2 demo; cost per run measured |
| 8 | Correlation query layer; `entry_point` skill | Cross-source hypothesis with both artifacts cited |
| 9 | Plan object, plan diffing, adaptation events | Adaptation visible in the event log |
| 10 | Taint model, spotlighting, taint gate; injection suite | M3 demo; first injection blocked |
| 11 | MCP adapter with one server behind it | Third-party tool reachable without core edits |
| 12 | Replay, `--dry-run`, M4 hardening | M4 demo; decoy untouched across all scenarios |
| 13 | Scenario harness, ground truth, metrics, ablations | Metrics table generated by command |
| 14 | Report, slides, cleanup, baseline comparison | M5: full defence |

## 5. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scope creep into a platform | High | The non-goals list in 00 is enforced at each milestone; anything not in M0–M5 is a "future work" line, not a branch |
| Hallucinated findings undermine credibility | Medium | Findings are constructed by the spine, not the model; invariant 5 makes an unknown CVE a validation failure |
| `nmap` output too large for context | High if unaddressed | Tiered context from 02: rollups computed in code; raw output is only ever artifact bytes |
| Vulnerability database ingest eats a week | Medium | Start from a scoped subset (the lab's services) and expand only if time allows; record the snapshot date either way |
| Prompt injection demo backfires and looks like a vulnerability | Low | It is presented as a detection, and the negative result — "injection did not change behaviour" — is reported honestly if that is what happens |
| Lab too weak to produce interesting findings | Medium | Use images with deterministic, known CVEs (DVWA, a log4j compose service) so ground truth is unambiguous |
| Replay gives different results | High for live calls | Replay runs against a recorded response cache; fresh-run variance is reported as success@3, not claimed as determinism |

## 6. If behind schedule, cut in this order

Stated in advance so the decision is made calmly rather than in week 13.

1. MCP adapter — an interface demo, not a capability. The tool registry still proves extensibility.
2. The hypothesis beam — single-hypothesis reasoning is adequate; the beam is a refinement.
3. `entry_point` depth — a two-source correlation beats a three-source one.
4. Ablations — keep the headline metrics and drop A4–A6.
5. Third scenario — one rich scenario, fully ground-truthed, beats three shallow ones.

**Never cut:** the vertical slice, evidence binding, the scope mechanism, the injection test,
or replay. Those five are the project.

