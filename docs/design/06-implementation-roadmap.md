# 06 — Implementation Roadmap

## 1. Ordering rule

Build one vertical slice before horizontal sophistication. The first demo must already cross:
local model -> capability proposal -> necessity gate -> policy -> provider -> artifact -> parser
-> evidence -> finding -> report -> replay.

Memory and provider plurality are added only after that slice works; the v2 Token Optimizer is
not allowed to block v1.

## 2. Milestones

| # | Deliverable | Proof it is done | Weeks |
|---|---|---|---|
| M0 | Repo, local model adapter, lab, skeleton | local model healthcheck works; `make lab-up` is egress-isolated; event/artifact primitives tested | 1 |
| M1 | `port_scan` vertical slice | one local-model command produces evidence-bound findings and replay reconstructs them | 2–4 |
| M2 | Local memory + `log_analysis` | restart the harness and recover baseline/active memory; suspicious seeded logs found without raw-log flooding | 5–7 |
| M3 | `entry_point` cross-source correlation | supported hypothesis cites scan + log artifacts; memory-only context cannot validate it | 8–9 |
| M4 | Multi-provider routing | at least two providers can satisfy one capability; one is used normally, second only under a tested necessity reason | 10–11 |
| M5 | Safety, evaluation, report | injection suite, decoy untouched, provider-efficiency metrics, replay demo, final report/slides | 12–14 |

## 3. Repository layout

```text
MEMORY.md
memory/
  BASELINE.md
  LONG_TERM.md
  long_term/               runtime shards (local)
  archive/                 pre-compaction snapshots (local)
src/harness/
  runtime/                 loop.py, fsm.py, budget.py, events.py, replay.py
  context/                 resolver.py, builder.py, retrieval.py, taint.py
  memory/                  manager.py, curator.py, compact.py, index.py
  policy/                  grants.py, engine.py, approvals.py, scope.py
  artifacts/               store.py, provenance.py
  parsers/                 nmap_xml.py, auth_log.py, nginx_access.py, registry.py
  analysers/               rules.py, sigma.py, cve_match.py, correlate.py
  findings/                models.py, validate.py
  providers/               registry.py, spec.py, necessity.py, router.py
    native/
    mcp/
  llm/                     local_client.py, schemas.py, prompts/
  tokens/                  ledger.py, budget.py          # v1 controls only
  report/                  build.py, templates/
  skills/                  port_scan.yaml, log_analysis.yaml, entry_point.yaml
  cli.py
lab/
eval/
tests/
```

Stack remains Python 3.12, Pydantic v2, Typer, Rich, lxml, DuckDB/SQLite FTS5, pytest and Docker
Compose. The model backend is adapter-based and local by default.

## 4. Week-by-week

| Week | Focus | Checkpoint |
|---|---|---|
| 1 | FSM, events, artifacts, lab, local model client | no cloud dependency required for a smoke run |
| 2 | capability/provider registry, native nmap provider, XML parser | first normalized observations |
| 3 | vulnerability snapshot ingest + matcher + validator | first evidence-bound finding |
| 4 | scope grants, approval gate, report, replay | M1 demo |
| 5 | baseline + active memory manager, snapshot/compaction path | memory survives restart and stays under cap |
| 6 | log ingestion, rollups, FTS5 retrieval, Sigma subset | log findings with bounded prompt context |
| 7 | long-lived memory entries + selective retrieval | M2 demo; old run lesson retrieved without loading corpus |
| 8 | cross-source correlation + entry-point skill | two-source hypothesis |
| 9 | plan revisions, taint model, injection fixtures | M3 demo |
| 10 | MCP adapter, capability advertisement, necessity gate tests | second provider registered without planner change |
| 11 | multi-provider conflict/fallback/verification paths | M4 demo; redundant calls visibly skipped |
| 12 | dry-run, replay hardening, hash-chain verification | safety demo |
| 13 | scenario metrics, provider-efficiency + memory tests | results generated automatically |
| 14 | report, slides, cleanup, baseline comparison | final defence |

## 5. v1 necessity-gate definition of done

The gate is intentionally simple:

- existing sufficient evidence -> skip provider call;
- otherwise choose one eligible provider by configured preference/cost/risk;
- second provider only for one enumerated necessity reason;
- third provider requires explicit skill override;
- every choice emits `PROVIDER_SELECTED`, `PROVIDER_REJECTED`, or `CALL_SKIPPED` with reason;
- provider output is normalized/deduplicated before prompt inclusion.

No learned utility model is required for v1.

## 6. Version two: Token Optimizer

Version two adds `src/harness/tokens/optimizer.py` plus pluggable policies for:

- model-specific token-cost estimation;
- dynamic context allocation by investigation phase;
- expected novelty/information-gain estimation;
- provider-portfolio selection under a cost budget;
- memory retrieval planning;
- compression/summarization choice;
- cache/reuse decisions;
- stopping when marginal expected value falls below cost.

v1 must record enough telemetry to make this possible: per-call input/output tokens, normalized
observation novelty, provider latency/failure, bytes returned, cache hits, reason for expansion,
and whether the call changed a finding or closed an EvidenceGap.

## 7. If behind schedule, cut in this order

1. third provider; keep two providers for the same capability;
2. hypothesis beam;
3. advanced long-lived-memory ranking; keep FTS5 + recency filters;
4. ablations beyond the headline ones;
5. extra lab scenarios.

Never cut: local-first model path, vertical evidence slice, scope mechanism, bounded active memory,
provider necessity gate, injection test, or replay. The v2 Token Optimizer is already outside v1.
