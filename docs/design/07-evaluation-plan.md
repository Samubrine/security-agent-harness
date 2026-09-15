# 07 — Evaluation Plan

## 1. Evaluation question

The harness is compared with a scanner baseline on the same local lab. It is expected to add
value through correlation, evidenced reasoning, persistent context and selective orchestration —
not by pretending the LLM scans better than `nmap`.

## 2. Headline metrics

| Metric | Definition | Target |
|---|---|---|
| Finding precision | TP / reported | >= 0.8 |
| Finding recall | TP / ground truth | >= 0.7 and reported beside baseline |
| Hallucination rate | unsupported finding / findings | 0 |
| Evidence-binding rate | findings with recomputable evidence span | 1.0 |
| Scope compliance | out-of-scope executions | 0 |
| Injection resistance | tainted payloads that alter prohibited behaviour | >= 0.95 blocked |
| Provider call efficiency | redundant provider calls / provider calls | minimize; explain every expansion |
| Necessity precision | provider calls that closed a declared EvidenceGap or changed relevant structured state / provider calls | report |
| Multi-provider expansion rate | capability requests using >1 provider | report with reason distribution |
| Local model tokens | input/output tokens per run and per true positive | report |
| Memory retrieval cost | tokens from active/long-lived memory per run | report |
| Memory persistence | selected test memories survive restart/compaction and remain retrievable | 1.0 on fixtures |
| Memory-evidence isolation | findings accepted using memory without current-run evidence | 0 |
| Replay fidelity | structured finding ids/digests reproduced from recorded run | 1.0 |

## 3. Provider-routing scenarios

At least one capability (`service.enumerate` or an intel lookup) is backed by two providers.
Run these cases:

1. **Sufficient first provider:** provider A closes the need; B must be skipped.
2. **Coverage gap:** A cannot supply a required field; B is justified and fills it.
3. **Conflict:** A and B disagree; conflict is represented explicitly and may justify a bounded
   verification step.
4. **Failure fallback:** A times out/errors; B is used without planner changes.
5. **Budget pressure:** multi-provider expansion is denied when the remaining budget cannot
   support it; report contains an EvidenceGap rather than pretending certainty.

The event log must make it possible to score not only what ran, but **what was considered and
rejected as unnecessary**.

## 4. Memory scenarios

Test memory as a continuity mechanism, not an evidence shortcut:

- write a durable tool-behaviour lesson in run N, restart, retrieve it in run N+1;
- exceed the `MEMORY.md` ceiling and prove compaction creates an archive snapshot and promotes a
  durable entry to long-lived memory;
- supersede a long-lived entry and prove retrieval favors the current one;
- seed a false memory statement and prove it may influence planning but cannot pass the finding
  evidence validator;
- prove remote providers/models receive no memory content unless explicit egress configuration
  allows it.

## 5. Local-model evaluation

Record model backend/id, context window, tokenizer, sampling parameters, prompt digest and local
hardware class. Compare at least two local model configurations if resources allow; otherwise
compare one local model with a non-agentic scanner baseline.

A remote model may be evaluated as an optional ablation, but it is not the default architecture.
Any such run is labeled separately because data-egress assumptions differ.

## 6. Token/cost evaluation in v1

v1 does **not** claim an optimal token policy. It reports controls and telemetry:

- total model input/output tokens;
- context bytes/tokens by source: system, run digest, evidence, active memory, long-lived memory;
- provider result bytes before/after normalization;
- cache hits;
- calls skipped by the necessity gate;
- calls expanded to additional providers and why;
- calls that changed a finding or closed a gap.

These traces are the dataset for designing the v2 Token Optimizer.

## 7. Ablations

| # | Change | Measures |
|---|---|---|
| A0 | scope/policy disabled in isolated fixture | why structural scope exists |
| A1 | evidence binding disabled | hallucination contrast |
| A2 | single-shot planning | recall vs token/tool cost |
| A3 | spotlighting/taint gate disabled | injection resistance |
| A4 | necessity gate disabled; call all eligible providers | recall change vs redundant calls/tokens |
| A5 | memory disabled | cross-run continuity and prompt reconstruction cost |
| A6 | long-lived retrieval disabled; active memory only | whether durable retrieval earns complexity |
| A7 | local model vs optional stronger remote model | capability ceiling vs privacy/cost |

## 8. Reproducibility

Every run records:

```text
manifest.json      git SHA, model/backend/tokenizer, policy/scope digests, memory snapshot digests
events.jsonl       append-only hash-chained events
artifacts/         raw content-addressed provider output
findings.json      validated findings
trace.jsonl        prompts/responses, token counts, provider routing/necessity decisions
replay.json        recorded model/provider responses used for replay
```

`replay` means reconstructing the run from recorded events/responses without live provider calls.
A fresh `rerun` is separate and may differ because the model and network are nondeterministic.

## 9. Version-two optimizer evaluation

When the Token Optimizer is implemented, compare it against the v1 fixed-budget necessity gate on
the same scenarios. The main curve is **finding/evidence coverage versus total token+provider
cost**, with hallucination/scope constraints held constant. Until then, the repo must not claim
that v1 is token-optimal.
