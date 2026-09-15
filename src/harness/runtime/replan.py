"""Conflict-driven re-planning: a conflict schedules its own resolving call.

Design 08 says an unresolved conflict *may* create a new evidence need, and the necessity gate is
willing to expand with ``conflict_resolution`` when it is asked. The audit finding was that nothing
ever asked: the conflict was correlated, displayed, and then dropped, so the run finished with two
providers disagreeing and no third call to settle it.

This module is the missing half. It derives :class:`FollowUpNeed` records from run state alone - no
model turn is involved - so that a disagreement is *scheduled* rather than merely reported. The
whole value is in what it refuses to do: agreement and complement never produce a need (that would
be the wasted call the necessity gate exists to prevent), an attempted capability is never retried,
and a capability already expanded for conflict resolution is never expanded twice.

Why the capability table is imported rather than restated: the gate decides "would I expand for
``conflict_resolution``?" by testing the correlation's key prefix kind against the kinds a
capability is declared to produce. A second copy of that table here would eventually disagree with
the first, and the failure mode is silent - needs are produced for a capability the gate will not
expand for, so the run looks busy while the conflict stays unresolved. ``CAPABILITY_FOR_KIND`` is
therefore the literal inversion of the gate's own ``CAPABILITY_OUTPUT_KINDS``, computed at import
time.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence

from harness.models import Correlation, FollowUpNeed, Observation, ProviderDecision
from harness.providers.necessity import CAPABILITY_OUTPUT_KINDS
from harness.util import canonical_json, clamp_text, new_id

#: The only relation that justifies spending another provider call. ``agreement`` and
#: ``complement`` are explicitly absent: two providers agreeing is corroboration already in hand,
#: and re-asking would be the necessity gate's own failure mode committed by the planner.
RESOLVING_RELATION = "conflict"

def _invert(table: Mapping[str, set[str]]) -> dict[str, str]:
    """kind -> capability, built in sorted order so the result never depends on dict ordering.

    First-wins on a collision keeps this a pure function of the gate's table even if some future
    edit makes it ambiguous. The suite asserts the table is unambiguous, so this is a guard.
    """
    inverted: dict[str, str] = {}
    for capability in sorted(table):
        for kind in sorted(table[capability]):
            inverted.setdefault(kind, capability)
    return inverted


#: The capability that serves each observation kind, derived from the gate so the two cannot drift.
CAPABILITY_FOR_KIND: dict[str, str] = _invert(CAPABILITY_OUTPUT_KINDS)


def _expects_for(capability: str) -> str:
    """What the re-asked question expects back, spelled as the gate's declared output kinds.

    Recording the capability's own declared output rather than free text keeps the follow-up need
    self-describing: the reason a second call is wanted is that these kinds are currently in doubt.
    """
    return ", ".join(sorted(CAPABILITY_OUTPUT_KINDS.get(capability) or ()))


def _capability_for(correlation: Correlation, observations: Mapping[str, Observation]) -> str | None:
    """The single capability that serves the observations this correlation names.

    The correlation's key begins with the observation kind it groups (see
    ``Observation.correlation_key``), and the gate matches a conflict to a capability on exactly
    that prefix. Preferring the prefix's kind - rather than, say, the alphabetically first kind - is
    what guarantees the need this function emits is a need the gate will actually see the conflict
    for. A correlation naming only kinds nothing produces yields ``None``: an unmappable conflict
    cannot be resolved by any registered capability, so inventing one would be a call with no
    question attached.
    """
    prefix_kind = correlation.key.split("|", 1)[0]
    mapped: dict[str, str] = {}
    for observation_id in sorted(correlation.observation_ids):
        observation = observations.get(observation_id)
        if observation is None:
            # A correlation citing an observation the caller did not supply is tampered or partial
            # state. It is skipped rather than trusted: an id that resolves to nothing must not be
            # able to steer a provider call.
            continue
        capability = CAPABILITY_FOR_KIND.get(observation.kind)
        if capability is not None:
            mapped.setdefault(observation.kind, capability)
    if not mapped:
        # No named observation maps to a capability, so no capability can resolve this conflict.
        # The correlation's key prefix is deliberately *not* used as a fallback: a need derived
        # from a kind nobody observed would be emitted for a capability the gate cannot match the
        # conflict for, which spends budget on a call that resolves nothing.
        return None
    if prefix_kind in mapped:
        return mapped[prefix_kind]
    capabilities = set(mapped.values())
    if len(capabilities) == 1:
        return next(iter(capabilities))
    # The correlator keys a correlation by one observation kind, so several capabilities here means
    # the correlation is internally inconsistent. Refusing is the honest answer: any pick would be
    # a capability that does not serve the conflicting kind the gate decides on.
    return None


def _detail_for(correlation: Correlation, observations: Mapping[str, Observation]) -> str:
    """One line naming the values that disagree.

    Clamped because observation values are attacker-influenced: an unbounded conflict detail is a
    free way for a payload to write megabytes of instructions into the next prompt.
    """
    rendered = [
        f"{observation_id}={canonical_json(observations[observation_id].value)}"
        for observation_id in sorted(correlation.observation_ids)
        if observation_id in observations
    ]
    if rendered:
        return clamp_text(f"{correlation.key} disagrees: " + "; ".join(rendered), 240)
    if correlation.detail:
        return clamp_text(f"{correlation.key} disagrees: {correlation.detail}", 240)
    return correlation.key


def _already_expanded(decisions: Sequence[ProviderDecision]) -> set[str]:
    """Capabilities a previous decision already spent a second provider on for the conflict.

    Without this the re-planner would re-propose the same capability on every subsequent pass and
    the run would loop: each iteration detects the same unresolved conflict and asks for the same
    expansion. One expansion per capability is the ceiling.
    """
    return {
        decision.capability
        for decision in decisions
        if decision.expansion_reason == "conflict_resolution"
    }


def follow_up_needs(
    *,
    run_id: str,
    conflicts: Sequence[Correlation],
    observations: Mapping[str, Observation],
    decisions: Sequence[ProviderDecision] = (),
    already_attempted: Collection[str] = (),
    max_needs: int = 2,
) -> list[FollowUpNeed]:
    """Derive the resolving provider calls a set of correlations justifies.

    Exactly one need per capability, sorted by ``(capability, correlation_id)`` and truncated to
    ``max_needs``. Sorting the *inputs* is what makes the outcome stable across calls even though
    the ids themselves are random: the same conflict set must always produce the same capability
    set, or a replayed run would re-plan differently from the live one.
    """
    if max_needs <= 0:
        return []

    attempted = set(already_attempted)
    expanded = _already_expanded(decisions)

    # capability -> the winning correlation. Keeping the lowest correlation id per capability is
    # arbitrary but deterministic, and it is what collapses two conflicts about one capability into
    # a single need instead of two. Sorting the input also makes the outcome independent of the
    # caller's ordering.
    winners: dict[str, Correlation] = {}
    for correlation in sorted(conflicts, key=lambda c: (c.id,)):
        if correlation.relation != RESOLVING_RELATION:
            continue
        capability = _capability_for(correlation, observations)
        if capability is None:
            continue
        if capability in attempted or capability in expanded:
            continue
        existing = winners.get(capability)
        if existing is None or correlation.id < existing.id:
            winners[capability] = correlation

    needs: list[FollowUpNeed] = []
    for capability in sorted(winners):
        correlation = winners[capability]
        needs.append(
            FollowUpNeed(
                id=new_id("fn"),
                run_id=run_id,
                capability=capability,
                expects=_expects_for(capability),
                reason="conflict_resolution",
                correlation_id=correlation.id,
                observation_ids=sorted(correlation.observation_ids),
                detail=_detail_for(correlation, observations),
            )
        )
        if len(needs) >= max_needs:
            break
    return needs
