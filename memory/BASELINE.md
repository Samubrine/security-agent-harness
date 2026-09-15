# Baseline Memory

Human-curated, low-churn context that is loaded before `MEMORY.md` on every run.

## Invariants

- Local inference is the default.
- Scope and policy are enforced by the harness, never delegated to the model.
- Memory is advisory context, not evidence.
- Security findings require current-run provenance.
- Provider selection is minimum-sufficient by default.
- Multiple MCP/native providers require a necessity justification.
- Remote inference and remote MCP access are disabled unless explicitly configured.

## Mutation policy

The runtime does not silently rewrite this file. Changes are human-authored or explicitly
approved configuration changes. Active/learned context belongs in `MEMORY.md`; durable learned
items belong in long-lived memory.
