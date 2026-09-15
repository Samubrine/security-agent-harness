"""Per-tier prompt cost attribution and memory retrieval cost.

These tests are written to fail if a property is broken rather than to execute lines. The two
properties the audit cared about are (a) the report is total -- the total is the sum of what
was actually sent, so an optimizer never learns from a number that silently omits a tier --
and (b) a saving is never fabricated, because a negative saving is an upstream bug recorded
as a cost. The adversarial cases cover inputs a tampered or buggy caller would produce: a
negative count, a cap that does not exist for a tier, a duplicated retrieval hit.
"""

from __future__ import annotations

import pytest

from harness.context.cost import attribute_prompt_cost, compression_savings, memory_retrieval_cost
from harness.models import MemoryEntry, RetrievedMemory, TierCostReport
from harness.util import canonical_json, estimate_tokens, utcnow


def _entry(entry_id: str, summary: str, *, kind: str = "tool_behavior") -> MemoryEntry:
    return MemoryEntry(id=entry_id, created_at=utcnow(), kind=kind, summary=summary)


def _hit(entry_id: str, summary: str, *, score: float = 1.0) -> RetrievedMemory:
    return RetrievedMemory(entry=_entry(entry_id, summary), score=score, retrieved_for="plan")


def _text(chars: int) -> str:
    """A deterministic string of an exact length, so the estimate is pinned rather than guessed."""
    if chars <= 0:
        return ""
    unit = "abcdefghijklmnopqrstuvwxyz0123456789 .-_"
    return (unit * (chars // len(unit) + 1))[:chars]


def _assert_totals_agree(report: TierCostReport) -> None:
    """The total must be recoverable from the per-tier numbers a consumer can see."""
    assert report.total_tokens == sum(report.tiers.values())
    assert report.dropped_tokens >= 0


def test_over_cap_tier_contributes_exactly_its_overage() -> None:
    report = attribute_prompt_cost(
        tiers={"C0": 1_000, "C1": 5_500, "C2": 2, "C3": 10_887},
        tier_caps={"C0": 2_000, "C1": 3_000, "C2": 6_000, "C3": 1_500},
    )
    # C0 and C2 are under their caps; only the overage of the two offending tiers is dropped.
    assert report.over_cap_tiers == ["C1", "C3"]
    assert report.dropped_tokens == (5_500 - 3_000) + (10_887 - 1_500) == 11_887
    _assert_totals_agree(report)


def test_over_cap_tiers_sorted_by_name_not_by_input_order() -> None:
    report = attribute_prompt_cost(
        tiers={"C4": 9, "C0": 9, "C2": 9},
        tier_caps={"C0": 1, "C2": 1, "C4": 1},
    )
    assert report.over_cap_tiers == ["C0", "C2", "C4"]
    assert report.dropped_tokens == 24


def test_tier_equal_to_its_cap_is_not_over_cap() -> None:
    # The boundary is the property. An off-by-one here reports a discard that never happened,
    # and a future optimizer would chase a budget problem that does not exist.
    at_cap = attribute_prompt_cost(tiers={"C1": 3_000}, tier_caps={"C1": 3_000})
    assert at_cap.over_cap_tiers == []
    assert at_cap.dropped_tokens == 0

    over = attribute_prompt_cost(tiers={"C1": 3_001}, tier_caps={"C1": 3_000})
    assert over.over_cap_tiers == ["C1"]
    assert over.dropped_tokens == 1


def test_zero_cap_flags_only_a_non_empty_tier() -> None:
    assert attribute_prompt_cost(tiers={"C3": 0}, tier_caps={"C3": 0}).over_cap_tiers == []
    flagged = attribute_prompt_cost(tiers={"C3": 1}, tier_caps={"C3": 0})
    assert flagged.over_cap_tiers == ["C3"]
    assert flagged.dropped_tokens == 1


def test_tier_absent_from_caps_is_never_over_cap() -> None:
    # An absent cap is not a zero cap. Inventing one would manufacture an overrun for every
    # tier a caller did not mention, and the dropped tokens would be fiction.
    report = attribute_prompt_cost(
        tiers={"C0": 100, "C5": 10**9, "C9": 7},
        tier_caps={"C0": 50},
    )
    assert report.over_cap_tiers == ["C0"]
    assert report.dropped_tokens == 50
    assert report.tiers["C5"] == 10**9


def test_caps_do_not_invent_tiers_that_were_not_sent() -> None:
    report = attribute_prompt_cost(tiers={"C0": 5}, tier_caps={"C0": 10, "C4": 1})
    assert set(report.tiers) == {"C0"}
    assert report.total_tokens == 5
    assert report.over_cap_tiers == []


def test_absent_or_empty_caps_leave_every_tier_unflagged() -> None:
    tiers = {"C0": 5, "C1": 10**6}
    for caps in (None, {}):
        report = attribute_prompt_cost(tiers=tiers, tier_caps=caps)
        assert report.over_cap_tiers == []
        assert report.dropped_tokens == 0
        assert report.total_tokens == 10**6 + 5


def test_total_is_the_sum_of_the_tiers_and_names_are_sorted() -> None:
    tiers = {"C4": 3, "C0": 1, "C10": 5, "C1": 2}
    report = attribute_prompt_cost(tiers=tiers)
    assert list(report.tiers) == sorted(tiers)
    assert list(report.tiers) == ["C0", "C1", "C10", "C4"]
    assert report.total_tokens == 11
    # The echoed mapping is sorted on the wire too, so two equal reports serialise identically.
    assert canonical_json(report.tiers) == canonical_json(dict(sorted(tiers.items())))


def test_run_id_and_step_are_echoed_so_the_report_can_be_attributed() -> None:
    report = attribute_prompt_cost(tiers={"C0": 1}, run_id="run-abc", step=7)
    assert (report.run_id, report.step) == ("run-abc", 7)
    assert isinstance(report, TierCostReport)


def test_empty_tiers_is_an_all_zero_report_not_an_error() -> None:
    report = attribute_prompt_cost(tiers={}, tier_caps={"C0": 10})
    assert report.tiers == {}
    assert report.total_tokens == 0
    assert report.dropped_tokens == 0
    assert report.over_cap_tiers == []


@pytest.mark.parametrize("bad", [-1, -10_000])
def test_negative_tier_count_is_rejected_rather_than_summed(bad: int) -> None:
    # A negative count is a corrupt or tampered record. Summing it would understate the prompt
    # the harness sent, which is the one number a cost report exists to get right.
    with pytest.raises(ValueError):
        attribute_prompt_cost(tiers={"C0": bad}, tier_caps={"C0": 10})


def test_negative_cap_is_rejected() -> None:
    with pytest.raises(ValueError):
        attribute_prompt_cost(tiers={"C0": 1}, tier_caps={"C0": -5})


def test_a_negative_tier_does_not_sneak_into_the_dropped_total() -> None:
    # The tempting shortcut is to let a negative tier offset a genuine overage elsewhere.
    with pytest.raises(ValueError):
        attribute_prompt_cost(tiers={"C0": 50, "C1": -100}, tier_caps={"C0": 10, "C1": 10})



def test_memory_cost_uses_the_shared_estimator_on_every_text() -> None:
    baseline = _text(400)
    active = _text(80)
    summaries = [_text(120), _text(40), _text(4_000)]
    hits = [_hit("mem-" + str(i), summary) for i, summary in enumerate(summaries)]

    report = memory_retrieval_cost(baseline_text=baseline, active_text=active, retrieved=hits)

    assert report.baseline_tokens == estimate_tokens(baseline) == 100
    assert report.active_tokens == estimate_tokens(active) == 20
    assert report.retrieved_tokens == sum(estimate_tokens(summary) for summary in summaries)
    assert report.retrieved_entries == 3
    assert report.total_tokens == report.baseline_tokens + report.active_tokens + report.retrieved_tokens


def test_retrieved_entries_is_a_count_not_a_token_count() -> None:
    # The classic telemetry bug is reporting len(hits) tokens or sum(tokens) entries.
    hits = [_hit("mem-a", _text(4_000)), _hit("mem-b", _text(4_000))]
    report = memory_retrieval_cost(baseline_text="", active_text="", retrieved=hits)
    assert report.retrieved_entries == 2
    assert report.retrieved_tokens == 2_000
    assert report.retrieved_entries != report.retrieved_tokens


def test_one_huge_hit_and_many_small_hits_differ_by_count_not_only_tokens() -> None:
    huge = memory_retrieval_cost(baseline_text="", active_text="", retrieved=[_hit("mem-h", _text(4_000))])
    many = memory_retrieval_cost(
        baseline_text="", active_text="", retrieved=[_hit("mem-" + str(i), _text(40)) for i in range(100)]
    )
    # 100 hits of 40 chars and one hit of 4000 chars cost the same; only the count differs.
    assert huge.retrieved_tokens == many.retrieved_tokens == 1_000
    assert (huge.retrieved_entries, many.retrieved_entries) == (1, 100)


def test_empty_retrieval_and_empty_texts_still_produce_a_report() -> None:
    report = memory_retrieval_cost(baseline_text="", active_text="", retrieved=[])
    assert report.retrieved_tokens == 0
    assert report.retrieved_entries == 0
    # The estimator floors at one token, so the totals are small but never negative.
    assert report.baseline_tokens == estimate_tokens("") == 1
    assert report.total_tokens == 2


def test_duplicate_hits_are_counted_twice_because_they_were_sent_twice() -> None:
    # A retrieval bug that returns the same entry twice really does cost the prompt twice.
    hit = _hit("mem-dup", _text(400))
    report = memory_retrieval_cost(baseline_text="", active_text="", retrieved=[hit, hit])
    assert (report.retrieved_entries, report.retrieved_tokens) == (2, 200)
    assert report.total_tokens == 202


def test_only_the_entry_summary_is_counted_not_the_whole_hit() -> None:
    # Score and retrieved_for are metadata about the hit, not prompt text; counting them
    # would inflate the number an optimizer attributes to retrieval.
    bare = memory_retrieval_cost(baseline_text="", active_text="", retrieved=[_hit("mem-x", "short")])
    padded = _hit("mem-x", "short", score=9_999.0)
    decorated = memory_retrieval_cost(baseline_text="", active_text="", retrieved=[padded])
    assert bare.retrieved_tokens == decorated.retrieved_tokens


def test_memory_cost_accepts_any_sequence_and_a_tuple_is_not_mistaken_for_one_hit() -> None:
    hits = (_hit("mem-t1", _text(40)), _hit("mem-t2", _text(40)))
    report = memory_retrieval_cost(baseline_text=_text(40), active_text=_text(40), retrieved=hits)
    assert report.retrieved_entries == 2
    assert report.retrieved_tokens == 2 * estimate_tokens(_text(40))


def test_memory_report_serialises_with_the_fields_the_optimizer_reads() -> None:
    report = memory_retrieval_cost(
        baseline_text=_text(400), active_text=_text(40), retrieved=[_hit("mem-s", _text(40))]
    )
    payload = canonical_json(report)
    fields = ("baseline_tokens", "active_tokens", "retrieved_tokens", "retrieved_entries", "total_tokens")
    for field in fields:
        assert field in payload


def test_identical_text_has_zero_compression_savings() -> None:
    text = _text(1_000)
    assert compression_savings(raw_text=text, clamped_text=text) == 0
    assert compression_savings(raw_text="", clamped_text="") == 0


def test_text_that_grew_reports_zero_and_never_a_negative_saving() -> None:
    # Growth means the caller clamped the wrong thing. A negative saving would be recorded as
    # a negative cost and would drag down every average computed from the telemetry.
    savings = compression_savings(raw_text="short", clamped_text=_text(40_000))
    assert savings == 0
    assert savings >= 0


def test_savings_is_the_estimator_difference_when_text_was_actually_trimmed() -> None:
    raw = _text(4_000)
    clamped = _text(400)
    assert compression_savings(raw_text=raw, clamped_text=clamped) == 1_000 - 100 == 900


def test_savings_survives_the_one_token_floor_of_the_estimator() -> None:
    # Below four characters the estimator floors at one token, so trimming tiny text is not a
    # saving. Reporting otherwise would be an artefact of the estimator, not a real discard.
    assert compression_savings(raw_text="abcd", clamped_text="ab") == 0
    assert compression_savings(raw_text="abcde", clamped_text="ab") == 1


def test_cap_discard_flows_from_tiers_through_to_the_reported_saving() -> None:
    # End-to-end shape a caller actually uses: cap a tier, then ask what the cap discarded.
    raw = _text(4_000)
    clamped = raw[:400]
    saved = compression_savings(raw_text=raw, clamped_text=clamped)
    report = attribute_prompt_cost(
        tiers={"C4": estimate_tokens(clamped)}, tier_caps={"C4": 50}, run_id="run-e2e", step=3
    )
    assert report.over_cap_tiers == ["C4"]
    assert report.dropped_tokens == estimate_tokens(clamped) - 50
    assert saved > 0
