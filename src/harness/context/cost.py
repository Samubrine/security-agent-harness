"""Per-tier prompt cost attribution and memory retrieval cost.

Design 08 section 9 imagines a version-two context optimizer that learns where the prompt
budget actually goes. An optimizer can only learn from numbers that were recorded, and the
audit found that compression, cache and memory-retrieval telemetry were not recorded at all.
This module is the *measurement* half of that gap: it turns a prompt bundle and a memory
resolution into the two telemetry records an optimizer -- or a human reading a run report --
would need. It deliberately imports no sibling v1.1 module, so it stays usable on its own and
cannot be dragged into an import cycle by a subsystem that is still being written.

Two properties matter for correctness rather than cosmetics:

* Attribution must be *total*. `total_tokens` is the sum of the tier values rather than a
  separately maintained counter, so no tier can be silently dropped from the total.
* Attribution must not *inflate* a saving. `compression_savings` is floored at zero, because
  a negative "saving" is an arithmetic artefact rather than a negative cost: it means the text
  handed to the model was larger than the text that was supposed to be capped, which is an
  upstream bug. Recording it would poison an optimizer average.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from harness.models import MemoryCostReport, RetrievedMemory, TierCostReport
from harness.util import estimate_tokens


def attribute_prompt_cost(
    *,
    tiers: Mapping[str, int],
    tier_caps: Mapping[str, int] | None = None,
    run_id: str = "",
    step: int = 0,
) -> TierCostReport:
    """Attribute one built prompt to its context tiers and report cap overruns.

    `tiers` is a tier-name to estimated-token-count mapping, as produced by
    `harness.context.builder.PromptBundle`. `tier_caps` is the ceiling each tier was supposed
    to respect. A tier absent from `tier_caps` is never reported as over cap: an
    absent cap is not a zero cap, and inventing one would manufacture an overrun for every
    tier the caller did not mention. A zero cap over a zero-token tier is likewise not an
    overrun, since nothing was discarded.

    `dropped_tokens` is the sum of the individual overages -- what the caps actually threw
    away, not how large the offending tiers are. `over_cap_tiers` is sorted so two runs with
    the same overruns serialise byte-identically, which is what makes the report comparable.

    Counts are validated rather than trusted. A negative token count or cap is not a small
    number, it is a corrupt or tampered record, and summing it would understate the prompt
    the harness sent -- the one number a cost report exists to get right.
    """
    validated_tiers = {name: _non_negative(value, "tier " + repr(name)) for name, value in tiers.items()}
    caps = {name: _non_negative(value, "cap for tier " + repr(name)) for name, value in (tier_caps or {}).items()}

    ordered = dict(sorted(validated_tiers.items()))
    over_cap = sorted(
        name for name, value in validated_tiers.items() if name in caps and value > caps[name]
    )
    dropped = sum(validated_tiers[name] - caps[name] for name in over_cap)

    return TierCostReport(
        run_id=run_id,
        step=step,
        tiers=ordered,
        total_tokens=sum(validated_tiers.values()),
        dropped_tokens=dropped,
        over_cap_tiers=over_cap,
    )


def memory_retrieval_cost(
    *,
    baseline_text: str,
    active_text: str,
    retrieved: Sequence[RetrievedMemory],
) -> MemoryCostReport:
    """Cost one step of memory: baseline, working memory, and retrieval hits.

    Three numbers answer three different questions, and collapsing them would hide the one an
    optimizer needs. `retrieved_tokens` is what the long-lived hits cost;
    `retrieved_entries` is *how many* hits there were -- a count, not a token count -- because
    one enormous hit and a hundred tiny ones can cost the same and mean very different things
    about retrieval quality.

    `total_tokens` sums all three classes, so it stays the true size of the memory portion of
    the prompt for a caller that only wants the headline number.
    """
    baseline_tokens = estimate_tokens(baseline_text)
    active_tokens = estimate_tokens(active_text)
    retrieved_tokens = sum(estimate_tokens(hit.entry.summary) for hit in retrieved)

    return MemoryCostReport(
        baseline_tokens=baseline_tokens,
        active_tokens=active_tokens,
        retrieved_tokens=retrieved_tokens,
        retrieved_entries=len(retrieved),
        total_tokens=baseline_tokens + active_tokens + retrieved_tokens,
    )


def compression_savings(*, raw_text: str, clamped_text: str) -> int:
    """Tokens a tier cap discarded, floored at zero and never negative.

    A negative result would mean `clamped_text` grew relative to `raw_text`. Clamping only
    ever removes text, so growth is an upstream bug, not a negative saving; flooring keeps
    that bug from being recorded as a negative cost where it would drag down every average
    computed from the telemetry.
    """
    return max(0, estimate_tokens(raw_text) - estimate_tokens(clamped_text))


def _non_negative(value: int, what: str) -> int:
    """Reject a negative count instead of quietly summing it into a total."""
    count = int(value)
    if count < 0:
        raise ValueError(f"{what} must not be negative (got {count})")
    return count
