"""Tiered context assembly.

Design 02 section 10 fixes the tiers. This module's job is to honour them literally: raw provider
output never enters a prompt, evidence enters only as bounded spans, and every tier has a ceiling
that is applied before the text is handed to the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from harness.context.resolver import ResolvedContext
from harness.llm.prompts import render_turn_prompt, system_prompt
from harness.util import clamp_text, estimate_tokens

#: Default ceilings, in estimated tokens. v1 uses fixed numbers on purpose: a dynamic allocator
#: is a version-two subsystem (D23), and inventing one now would be an unmeasured guess.
DEFAULT_TIER_CAPS: dict[str, int] = {
    "C0": 2_000,
    "C1": 3_000,
    "C2": 6_000,
    "C3": 1_500,
    "C4": 3_000,
}


@dataclass
class PromptBundle:
    system: str
    user: str
    tiers: dict[str, int] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return sum(self.tiers.values())


class ContextBuilder:
    def __init__(self, *, tier_caps: Mapping[str, int] | None = None) -> None:
        self.tier_caps = dict(DEFAULT_TIER_CAPS)
        if tier_caps:
            self.tier_caps.update({k: int(v) for k, v in tier_caps.items() if v})

    # -- tier text -------------------------------------------------------------------------

    def memory_tier(self, resolved: ResolvedContext) -> str:
        """C1 (baseline + active) followed by C3 (retrieved long-lived entries)."""
        parts: list[str] = ["### Baseline memory (stable, human-curated)", resolved.baseline_text.strip()]
        parts += ["", "### Active working memory (bounded)", resolved.active_text.strip()]
        if resolved.retrieved:
            parts += ["", "### Retrieved long-lived memory (advisory, may be stale)"]
            for hit in resolved.retrieved:
                entry = hit.entry
                parts.append(
                    f"- [{entry.id}] ({entry.kind}, {entry.confidence}) {entry.summary}"
                    + (f" (from runs: {', '.join(entry.source_runs)})" if entry.source_runs else "")
                )
        parts += [
            "",
            "Reminder: none of the above can be used as evidence for a finding. It may only",
            "influence which capability you request next.",
        ]
        return "\n".join(parts)

    def build(
        self,
        *,
        resolved: ResolvedContext,
        catalogue: Mapping[str, Any],
        run_digest: Any,
        evidence_rollup: str = "",
    ) -> PromptBundle:
        system = system_prompt()
        memory_text = clamp_text(self.memory_tier(resolved), self.tier_caps["C1"] * 4)
        digest_text = clamp_text(
            run_digest if isinstance(run_digest, str) else _canonical(run_digest),
            self.tier_caps["C2"] * 4,
        )
        evidence_text = clamp_text(evidence_rollup, self.tier_caps["C4"] * 4)
        catalogue_text = _canonical(catalogue)

        user = render_turn_prompt(
            objective=resolved.objective,
            skill=resolved.skill,
            catalogue=catalogue,
            run_digest=digest_text,
            memory_context=memory_text,
            evidence_context=evidence_text,
        )

        c1_tokens = estimate_tokens(resolved.baseline_text) + estimate_tokens(resolved.active_text)
        c3_tokens = estimate_tokens(memory_text) - c1_tokens if memory_text else 0
        tiers = {
            "C0": estimate_tokens(system) + estimate_tokens(catalogue_text),
            "C1": max(c1_tokens, 0),
            "C2": estimate_tokens(digest_text),
            "C3": max(c3_tokens, 0),
            "C4": estimate_tokens(evidence_text),
        }
        return PromptBundle(system=system, user=user, tiers=tiers)


def _canonical(payload: Any) -> str:
    from harness.util import canonical_json

    return canonical_json(payload)
