"""Post-run memory curation: turn a finished run into bounded, provenance-carrying memory.

The curator is deliberately the *only* component that decides a learned statement is durable,
and it decides using rules a reviewer can replay, not by asking a model how confident it feels.
Three rules carry the security weight:

1. a statement is promoted as "stable" only when it is corroborated by a *different* run. One
   observation -- however emphatic -- is a hypothesis, and a failed run is not evidence that its
   view of the world is correct. A run that failed can therefore contribute provisional notes
   and nothing more, so a run cannot launder its own failure into permanent context;
2. every promoted entry records the run that produced it in source_runs. Retrieval results are
   labelled memory context, and provenance is what lets a reader check the claim behind one;
3. summaries and bullets are reduced to a single inert line (see compact.sanitise_bullet).
   Provider output and model prose are untrusted: a newline in a payload must not be able to
   forge a heading or a bullet inside MEMORY.md, or smuggle a "[durable]" tag that would push
   attacker-chosen text into long-lived memory.

The curator can only write MemoryEntry records and active-memory text. It cannot build a Claim
or a Finding, and it never imports them: memory is context, never evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from harness.memory.compact import (
    heading_title,
    normalise_key,
    sanitise_bullet,
    strip_provenance_claims,
)
from harness.memory.index import LongTermIndex
from harness.memory.manager import MemoryManager
from harness.models import MemoryCompaction, MemoryConfidence, MemoryEntry, MemoryKind
from harness.util import new_id, sha256_text, utcnow

if TYPE_CHECKING:
    # Annotation-only imports: the curator reads these records, and keeping them out of the
    # runtime namespace makes it structurally obvious that this module constructs none of them.
    from harness.models import EventRecord, EvidenceGap, Finding, ProviderCallTelemetry

#: Gap kinds that mean "the provider did not deliver", as opposed to "the data said nothing".
FAILURE_GAP_KINDS = frozenset(
    {"provider_failure", "tool_timeout", "permission_denied", "unreachable", "budget_exhausted"}
)
#: Run outcomes that make this run's conclusions unusable as a stable lesson.
FAILED_RUN_STATUS = frozenset({"failed", "denied", "budget_exhausted", "error", "timeout"})

#: Section title used for each memory kind in the active working set.
SECTION_FOR_KIND: dict[str, str] = {
    "tool_behavior": "Tool quirks",
    "investigation_pattern": "Investigation patterns",
    "lesson": "Recent lessons",
    "environment_fact": "Environment notes",
    "user_convention": "Conventions",
}


@dataclass
class CuratorProposal:
    """Candidate memory updates for one finished run. Nothing is written until commit()."""

    active_sections: dict[str, list[str]]
    long_term_entries: list[MemoryEntry]
    rationale: str


@dataclass
class CuratorCommit:
    promoted: list[str]
    compaction: MemoryCompaction | None
    active_sha256: str


@dataclass
class _Candidate:
    """One derived memory statement, before it becomes a MemoryEntry."""

    kind: MemoryKind
    summary: str
    source_refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class MemoryCurator:
    """Derive and commit memory updates from a finished run."""

    def __init__(self, manager: MemoryManager, index: LongTermIndex) -> None:
        self._manager = manager
        self._index = index

    # -- proposal ----------------------------------------------------------------------

    def propose(
        self,
        *,
        run_id: str,
        findings: Sequence[Finding],
        gaps: Sequence[EvidenceGap],
        provider_calls: Sequence[ProviderCallTelemetry],
        events: Sequence[EventRecord],
    ) -> CuratorProposal:
        """Derive candidate updates. Deterministic: sorted inputs, sorted output."""
        run_failed = self._run_failed(events)
        candidates: list[_Candidate] = []
        candidates.extend(self._tool_behaviour(gaps, events))
        candidates.extend(self._investigation_patterns(provider_calls))
        candidates.extend(self._lessons(findings, gaps))
        candidates.sort(key=lambda item: (item.kind, normalise_key(item.summary)))
        entries = [self._entry(run_id, run_failed, candidate) for candidate in candidates]
        # Re-curating the same run must not duplicate what it already recorded, so statements
        # this run has already promoted are dropped before they can grow the corpus.
        recorded = {
            (entry.kind, normalise_key(entry.summary))
            for entry in self._index.all()
            if run_id and run_id in entry.source_runs
        }
        entries = [
            entry
            for entry in entries
            # A blank statement (a payload that sanitised away to nothing) is not a memory.
            if entry.summary and (entry.kind, normalise_key(entry.summary)) not in recorded
        ]
        entries.sort(key=lambda entry: (entry.kind, normalise_key(entry.summary)))
        rationale = self._rationale(run_id, run_failed, entries)
        return CuratorProposal(
            active_sections=self._sections(entries),
            long_term_entries=entries,
            rationale=rationale,
        )

    # -- commit ------------------------------------------------------------------------

    def commit(self, proposal: CuratorProposal, *, run_id: str) -> CuratorCommit:
        """Write entries to the index, then rewrite active memory under the cap."""
        promoted: list[str] = []
        for entry in sorted(proposal.long_term_entries, key=lambda item: item.id):
            if run_id and run_id not in entry.source_runs:
                # The rule is that every promoted entry names the run that produced it; enforce
                # it here as well as in propose(), because a proposal may be assembled by hand.
                entry.source_runs = [run_id, *entry.source_runs]
            self._index.add(entry)
            promoted.append(entry.id)
        text = self._merge_into_active(proposal.active_sections)
        compaction = self._manager.write_active(text, run_id=run_id)
        if compaction is not None:
            # The compaction record describes this rewrite, so the entries promoted *by* this
            # rewrite belong in it alongside whatever the manager archived on its own.
            merged = list(compaction.promoted_entries)
            merged.extend(entry_id for entry_id in promoted if entry_id not in merged)
            compaction.promoted_entries = merged
        return CuratorCommit(
            promoted=promoted,
            compaction=compaction,
            active_sha256=sha256_text(self._manager.load_active()),
        )

    # -- derivation rules --------------------------------------------------------------

    def _run_failed(self, events: Sequence[EventRecord]) -> bool:
        for event in events:
            kind = str(event.type).upper()
            if kind == "RUN_FAILED":
                return True
            if kind == "RUN_ENDED":
                status = str(event.data.get("status", "")).casefold()
                if status in FAILED_RUN_STATUS:
                    return True
        return False

    def _tool_behaviour(
        self, gaps: Sequence[EvidenceGap], events: Sequence[EventRecord]
    ) -> list[_Candidate]:
        """Derive tool-behaviour notes from provider failures and repeated gaps."""
        out: list[_Candidate] = []
        failures: dict[tuple[str, str, str], list[str]] = {}
        repeats: dict[tuple[str, str], list[str]] = {}
        for gap in sorted(gaps, key=lambda item: item.id):
            capability = gap.capability or "unknown"
            repeats.setdefault((gap.kind, capability), []).append(gap.id)
            if gap.kind not in FAILURE_GAP_KINDS:
                continue
            provider = str(gap.scope.get("provider") or gap.scope.get("provider_id") or "unknown-provider")
            failures.setdefault((provider, capability, gap.kind), []).append(gap.id)
        for event in sorted(events, key=lambda item: (item.seq, item.type)):
            if str(event.type).upper() != "PROVIDER_FAILED":
                continue
            provider = str(event.data.get("provider") or "unknown-provider")
            capability = str(event.data.get("capability") or "unknown")
            key = (provider, capability, "provider_failure")
            # A failure reported by both an event and a gap is one failure, not two.
            if key not in failures:
                failures[key] = [f"event:{event.seq}"]
        for (provider, capability, gap_kind), refs in failures.items():
            count = len(refs)
            times = f"{count} times " if count > 1 else ""
            out.append(
                _Candidate(
                    kind="tool_behavior",
                    summary=f"{provider} failed on {capability} {times}({gap_kind.replace('_', ' ')})",
                    source_refs=sorted(refs),
                    tags=["provider_failure", gap_kind],
                )
            )
        for (gap_kind, capability), refs in repeats.items():
            if len(refs) < 2 or gap_kind in FAILURE_GAP_KINDS:
                continue
            out.append(
                _Candidate(
                    kind="tool_behavior",
                    summary=(
                        f"{capability} recorded {len(refs)} {gap_kind.replace('_', ' ')} gaps; "
                        "expect this coverage gap rather than retrying blindly"
                    ),
                    source_refs=sorted(refs),
                    tags=["repeated_gap", gap_kind],
                )
            )
        return out

    def _investigation_patterns(
        self, provider_calls: Sequence[ProviderCallTelemetry]
    ) -> list[_Candidate]:
        """Derive what an effective capability order (or a wasteful provider) looked like."""
        out: list[_Candidate] = []
        calls = sorted(provider_calls, key=lambda item: (item.step, item.execution_id))
        capabilities: list[str] = []
        for call in calls:
            if call.capability not in capabilities:
                capabilities.append(call.capability)
        if len(calls) >= 2 and len(capabilities) >= 2:
            productive = sum(
                1
                for call in calls
                if call.new_observation_keys or call.changed_finding or call.closed_gap
            )
            out.append(
                _Candidate(
                    kind="investigation_pattern",
                    summary=(
                        f"Order {' -> '.join(capabilities)} produced new observations on "
                        f"{productive} of {len(calls)} provider calls"
                    ),
                    source_refs=sorted(call.execution_id for call in calls),
                    tags=["capability_order"],
                )
            )
        for call in calls:
            if call.duplicate_observations > 0 and call.duplicate_observations >= max(
                1, call.normalized_observations
            ):
                out.append(
                    _Candidate(
                        kind="tool_behavior",
                        summary=(
                            f"{call.provider} mostly re-reported known observations for "
                            f"{call.capability} ({call.duplicate_observations} duplicates)"
                        ),
                        source_refs=[call.execution_id],
                        tags=["duplicate_output"],
                    )
                )
        return out

    def _lessons(
        self, findings: Sequence[Finding], gaps: Sequence[EvidenceGap]
    ) -> list[_Candidate]:
        """Derive lessons from what the run could *not* establish.

        An unconfirmed finding is the useful material: it records where evidence ran out, which
        is what a later run should close before asserting the same thing.
        """
        gap_kinds = {gap.id: gap.kind for gap in gaps}
        out: list[_Candidate] = []
        for finding in sorted(findings, key=lambda item: item.id):
            if finding.status not in {"possible", "inconclusive"}:
                continue
            open_kinds = sorted({gap_kinds[gap_id] for gap_id in finding.gaps if gap_id in gap_kinds})
            tail = (
                f" while {', '.join(open_kinds)} gaps were open"
                if open_kinds
                else " without supporting evidence beyond its claims"
            )
            out.append(
                _Candidate(
                    kind="lesson",
                    summary=f"{finding.title} stayed {finding.status}{tail}",
                    source_refs=sorted({finding.id, *finding.gaps}),
                    tags=["unconfirmed", finding.status],
                )
            )
        return out

    # -- entry construction ------------------------------------------------------------

    def _entry(self, run_id: str, run_failed: bool, candidate: _Candidate) -> MemoryEntry:
        # Strip provenance trailers and durability tags out of the derived text: both are claims
        # about where a statement came from and how durable it is, and untrusted provider or
        # model prose must not be able to assert either (a stray "[durable]" would be enough to
        # push attacker-chosen text into long-lived memory on the next compaction).
        summary = sanitise_bullet(strip_provenance_claims(candidate.summary))
        source_runs = [run_id] if run_id else []
        confidence: MemoryConfidence = "provisional"
        supersedes: list[str] = []
        prior = self._corroborating(candidate.kind, summary, run_id)
        if prior is not None and not run_failed:
            # Corroboration across runs is the only thing that promotes a statement, and the new
            # entry supersedes the old one so retrieval keeps returning a single current version
            # with the accumulated provenance.
            confidence = "stable"
            supersedes = [prior.id]
            for existing_run in prior.source_runs:
                if existing_run not in source_runs:
                    source_runs.append(existing_run)
        return MemoryEntry(
            id=new_id("mem"),
            created_at=utcnow(),
            kind=candidate.kind,
            summary=summary,
            source_runs=source_runs,
            source_refs=sorted(set(candidate.source_refs)),
            confidence=confidence,
            supersedes=supersedes,
            tags=sorted(set(candidate.tags)),
        )

    def _corroborating(self, kind: MemoryKind, summary: str, run_id: str) -> MemoryEntry | None:
        """Find an existing entry that says the same thing and came from another run."""
        target = normalise_key(summary)
        for entry in sorted(self._index.all(), key=lambda item: item.id):
            if entry.kind != kind or normalise_key(entry.summary) != target:
                continue
            if any(source != run_id for source in entry.source_runs):
                return entry
        return None

    def _rationale(self, run_id: str, run_failed: bool, entries: Sequence[MemoryEntry]) -> str:
        stable = sum(1 for entry in entries if entry.confidence == "stable")
        if run_failed:
            outcome = (
                f"run {run_id} ended in failure, so every entry is provisional: a failed run "
                "cannot certify its own conclusions"
            )
        else:
            outcome = (
                f"run {run_id} completed; {stable} of {len(entries)} entries were corroborated "
                "by an earlier run and are stable, the rest stay provisional"
            )
        return f"{outcome}; {len(entries)} candidate entries derived from gaps, telemetry and findings"

    def _sections(self, entries: Sequence[MemoryEntry]) -> dict[str, list[str]]:
        """Group the same statements into active-memory sections.

        Each bullet carries its run provenance so a human editing MEMORY.md can see where a
        learned line came from, and so compaction can decide what is durable without guessing.
        """
        sections: dict[str, list[str]] = {}
        for entry in entries:
            title = SECTION_FOR_KIND.get(str(entry.kind), "Recent notes")
            runs = ", ".join(entry.source_runs) if entry.source_runs else "unknown"
            sections.setdefault(title, []).append(f"- {entry.summary} (runs: {runs})")
        return sections

    def _merge_into_active(self, sections: dict[str, list[str]]) -> str:
        """Append section bullets to the current working set without duplicating lines."""
        lines = self._manager.load_active().splitlines()
        seen = {normalise_key(line) for line in lines}
        for title in sorted(sections):
            bullets = [bullet for bullet in sections[title] if normalise_key(bullet) not in seen]
            if not bullets:
                continue
            target = normalise_key(title)
            heading_index = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if normalise_key(heading_title(line) or "") == target
                ),
                None,
            )
            if heading_index is None:
                if lines and lines[-1].strip():
                    lines.append("")
                lines.append(f"## {title}")
                lines.extend(bullets)
            else:
                insert_at = heading_index + 1
                while insert_at < len(lines) and heading_title(lines[insert_at]) is None:
                    insert_at += 1
                lines[insert_at:insert_at] = bullets
            seen.update(normalise_key(bullet) for bullet in bullets)
        return "\n".join(lines)
