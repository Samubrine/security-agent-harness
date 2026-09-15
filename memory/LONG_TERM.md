# Long-Lived Memory Contract

Long-lived memory stores durable lessons that should survive compaction of `MEMORY.md` without
being loaded wholesale into every prompt.

The runtime implementation will store entries under `memory/long_term/` (sharded by month or
size) and build a local SQLite FTS5 index. This file defines the contract and remains small.

Each entry contains:

```yaml
id: mem-...
created_at: ISO-8601
kind: tool_behavior | investigation_pattern | environment_fact | user_convention | lesson
summary: concise durable statement
source_runs: [run-id, ...]
source_refs: [finding-id | observation-id | event-id, ...]
confidence: stable | provisional
last_used_at: ISO-8601 | null
supersedes: [memory-id, ...]
```

Rules:

- Long-lived memory is local by default and is never sent to remote providers implicitly.
- It is retrieved selectively; the full corpus is never placed in model context.
- `source_refs` are provenance pointers for explaining where a memory came from, but the memory
  entry itself is **not** valid finding evidence in a new run.
- Superseded or stale entries remain auditable and can be compacted into archive shards.
- v1 retrieval is deterministic keyword/FTS5 retrieval plus recency/type filters. Embeddings are
  not required.
- v2 may let the Token Optimizer decide whether retrieving another memory chunk is worth its
  token cost.
