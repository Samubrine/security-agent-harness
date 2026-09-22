"""Tiered context assembly.

Design 02 section 10 fixes the tiers. This module's job is to honour them literally: raw provider
output never enters a prompt, evidence enters only as bounded spans, and every tier has a ceiling
that is applied before the text is handed to the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from harness.context.resolver import ResolvedContext
from harness.context.spotlight import Spotlight
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
        """The sum of the tier estimates: where the prompt went, per design 08 section 9."""
        return sum(self.tiers.values())

    @property
    def prompt_tokens(self) -> int:
        """What the prompt actually costs: system plus user.

        The budget is charged this and not the tier sum. The tiers describe the parts design 08 wants
        to optimize; the skeleton around them - headings, the objective, the output-shape example - was
        in every prompt and in no tier (R2-27).
        """
        return estimate_tokens(self.system) + estimate_tokens(self.user)


class ContextBuilder:
    def __init__(self, *, tier_caps: Mapping[str, int] | None = None) -> None:
        self.tier_caps = dict(DEFAULT_TIER_CAPS)
        if tier_caps:
            self.tier_caps.update({k: int(v) for k, v in tier_caps.items() if v})

    # -- tier text -------------------------------------------------------------------------

    def memory_tier(self, resolved: ResolvedContext, *, spotlight: Spotlight | None = None) -> str:
        """The whole memory block, C1 followed by C3, for callers that want the text as one string."""
        c1, c3 = self.memory_tiers(resolved, spotlight=spotlight)
        return "\n".join(part for part in (c1, c3) if part.strip())

    def memory_tiers(
        self, resolved: ResolvedContext, *, spotlight: Spotlight | None = None
    ) -> tuple[str, str]:
        """The C1 half (baseline + active) and the C3 half (retrieved entries) as separate texts.

        Separate because the tier counts have to describe what was actually sent. This used to
        estimate C1 from the *unclamped* baseline and active texts and C3 as "the clamped total minus
        that number", so the two numbers described a prompt nobody received - the clamp was applied to
        the joined block, which is neither (R2-27).
        """
        c1 = "\n".join(
            [
                "### Baseline memory (stable, human-curated)",
                resolved.baseline_text.strip(),
                "",
                "### Active working memory (bounded)",
                resolved.active_text.strip(),
            ]
        )
        if not resolved.retrieved:
            return c1, ""
        retrieved: list[str] = ["### Retrieved long-lived memory (advisory, may be stale)"]
        for hit in resolved.retrieved:
            entry = hit.entry
            summary = entry.summary
            if spotlight is not None:
                summary = spotlight.wrap(summary, origin=f"memory:{entry.id}", level="T3")
            retrieved.append(
                f"- [{entry.id}] ({entry.kind}, {entry.confidence}) {summary}"
                + (f" (from runs: {', '.join(entry.source_runs)})" if entry.source_runs else "")
            )
        retrieved += [
            "",
            "Reminder: none of the above can be used as evidence for a finding. It may only",
            "influence which capability you request next.",
        ]
        return c1, "\n".join(retrieved)

    def build(
        self,
        *,
        resolved: ResolvedContext,
        catalogue: Mapping[str, Any],
        run_digest: Any,
        evidence_rollup: str = "",
        spotlight: Spotlight | None = None,
    ) -> PromptBundle:
        system = system_prompt()
        # Each tier is clamped to its own ceiling and counted from the text that survived it, so the
        # tier numbers describe the prompt that was sent rather than a version of it (R2-27).
        c1_text = clamp_text(self.memory_tiers(resolved, spotlight=spotlight)[0], self.tier_caps["C1"] * 4)
        c3_text = clamp_text(self.memory_tiers(resolved, spotlight=spotlight)[1], self.tier_caps["C3"] * 4)
        memory_text = "\n".join(part for part in (c1_text, c3_text) if part.strip())
        digest_text = _bounded_digest(run_digest, self.tier_caps["C2"] * 4)
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

        tiers = {
            "C0": estimate_tokens(system) + estimate_tokens(catalogue_text),
            "C1": estimate_tokens(c1_text),
            "C2": estimate_tokens(digest_text),
            "C3": estimate_tokens(c3_text),
            "C4": estimate_tokens(evidence_text),
        }
        return PromptBundle(system=system, user=user, tiers=tiers)


def _canonical(payload: Any) -> str:
    from harness.util import canonical_json

    return canonical_json(payload)


def _bounded_digest(payload: Any, limit_chars: int) -> str:
    """Serialise the run digest inside a character budget, dropping detail rather than characters.

    Clamping the serialised document mid-string cut the closing tag of the block it lives in, so the
    planner could no longer read it and the run ended as a model failure - which is what a large
    multi-provider run did as soon as the untrusted values were rendered wrapped (R2-02, R2-27). The
    cap is honoured by *withholding detail*: untrusted values are dropped oldest-first, then whole
    observations, and the digest carries a `digest_budget` field saying what it left out. A reader
    therefore gets a smaller true document instead of a larger false one.
    """
    if isinstance(payload, str):
        text = payload
        return text if len(text) <= limit_chars else clamp_text(text, limit_chars)
    text = _canonical(payload)
    if len(text) <= limit_chars or not isinstance(payload, dict):
        return text

    digest = dict(payload)
    observations = [dict(entry) for entry in digest.get("observations") or ()]
    omitted_values = 0
    omitted_observations = 0
    while observations and len(_canonical({**digest, "observations": observations})) > limit_chars:
        index = next(
            (i for i, entry in enumerate(observations) if entry.get("untrusted_value")), None
        )
        if index is None:
            observations.pop()
            omitted_observations += 1
            continue
        # Sorted by id and dropped from the front: the newest evidence is what a planner is asking
        # about, and it is the values that carry the bytes.
        observations[index] = {**observations[index], "untrusted_value": None}
        omitted_values += 1
    digest["observations"] = observations
    digest["digest_budget"] = {
        "limit_chars": limit_chars,
        "omitted_untrusted_values": omitted_values,
        "omitted_observations": omitted_observations,
    }
    return _canonical(digest)
