"""Tier one and two of memory: the baseline file and the bounded active working set.

The three tiers are deliberately different, and this module refuses to blur them:

* memory/BASELINE.md -- human-curated invariants, loaded every run, never rewritten here;
* MEMORY.md (under the configured root) -- the bounded working set a run may rewrite, with a
  hard byte cap that is enforced on every write rather than assumed;
* memory/long_term/* -- durable entries, indexed for selective retrieval (see index.py).

The cap is the reason this module exists. An unbounded working set is an unbounded prompt: it
pushes evidence out of the context window and lets one run smuggle arbitrary text into every
future run. So write_active() is the only writer, it enforces the cap on every path, and when
it has to shrink the text it first archives the pre-compaction content. The cap is applied to
the *file*, which is what the runtime's frozen run digests actually cover.

Nothing here can produce a Claim, a Finding or an EvidenceRef. Memory is context; the evidence
graph is built from artifacts and observations, and there is no path from this module into it.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from harness.errors import ConfigError, ValidationError
from harness.memory.compact import (
    archive_name,
    collect_durable_candidates,
    dedupe_repeated_bullets,
    hard_clamp,
    heading_title,
    normalise_key,
    sanitise_bullet,
)
from harness.memory.index import ENTRY_ID_RE, SHARD_GLOB, LongTermIndex
from harness.models import MemoryCompaction, MemoryDigests, MemoryEntry
from harness.util import atomic_write_text, new_id, sha256_hex, sha256_text, utcnow

#: Conventional root: the repository itself, where MEMORY.md and memory/ live. Callers pass an
#: explicit root (a run directory or tmp_path in tests) so a run never writes the shared files
#: by accident.
DEFAULT_ROOT = Path(__file__).resolve().parents[3]


class MemoryManager:
    """Read and rewrite the file-backed memory tiers under a configurable root."""

    def __init__(self, root: Path | None = None, *, active_cap_bytes: int = 4096) -> None:
        self._root = Path(root) if root is not None else DEFAULT_ROOT
        cap = int(active_cap_bytes)
        if cap <= 0:
            # A zero cap would make "bounded" mean "empty", silently discarding everything a
            # run learned; refuse the configuration instead of degrading quietly.
            raise ConfigError(f"active_cap_bytes must be positive, got {active_cap_bytes!r}")
        self._active_cap_bytes = cap
        self._index: LongTermIndex | None = None

    # -- paths -------------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def active_path(self) -> Path:
        return self._root / "MEMORY.md"

    @property
    def baseline_path(self) -> Path:
        return self._root / "memory" / "BASELINE.md"

    @property
    def archive_dir(self) -> Path:
        return self._root / "memory" / "archive"

    @property
    def long_term_dir(self) -> Path:
        return self._root / "memory" / "long_term"

    @property
    def active_cap_bytes(self) -> int:
        return self._active_cap_bytes

    @property
    def index(self) -> LongTermIndex:
        """The long-term index at the conventional path for this root.

        Lazy so that a reader that only loads the baseline never opens a database, and shared
        so that compaction-promoted entries and curator-promoted entries land in the same
        corpus instead of two files that diverge.
        """
        if self._index is None:
            self._index = LongTermIndex(self.long_term_dir / "index.sqlite")
        return self._index

    # -- reads -------------------------------------------------------------------------

    def load_baseline(self) -> str:
        """Human-curated invariants. A missing file loads as empty text, never as a crash.

        A fresh checkout may legitimately have no baseline; the run digests record the digest
        of what was actually loaded (the empty string), so "no invariants were in context" is
        auditable rather than invisible.
        """
        return self._read_text(self.baseline_path)

    def load_active(self) -> str:
        return self._read_text(self.active_path)

    def digests(self) -> MemoryDigests:
        """Digest the memory a run is about to freeze.

        Long-term entries are pinned as "id:sha256" rather than bare ids: run.json must be able
        to prove *which bytes* of a durable lesson were used, otherwise rewriting memory after
        the fact would silently change what a finished run claims to have seen.
        """
        return MemoryDigests(
            baseline_sha256=sha256_text(self.load_baseline()),
            active_sha256=sha256_text(self.load_active()),
            long_term_entries=self._long_term_digests(),
        )

    # -- writes ------------------------------------------------------------------------

    def write_active(self, text: str, *, run_id: str = "") -> MemoryCompaction | None:
        """Persist the working set, compacting when it would exceed the cap.

        Returns None when the text fits. Otherwise the pre-compaction content is archived, then
        the text is de-duplicated, durable bullets are promoted to long-lived memory, and the
        remainder is written. After this call the file is guaranteed to be at or under the cap.

        run_id is recorded in the compaction record; it is an additive keyword-only parameter
        because MemoryCompaction.run_id is a required field and the manager has no other way to
        learn which run triggered the rewrite.
        """
        final = self._finalise(text)
        if len(final.encode("utf-8")) <= self._active_cap_bytes:
            atomic_write_text(self.active_path, final)
            return None

        existing = self.load_active() if self.active_path.exists() else None
        # Archive what is being replaced, so before_digest always identifies the archived bytes.
        archived_text = existing if existing is not None else text
        snapshot = self._write_snapshot(archived_text)

        lines, removed = dedupe_repeated_bullets(text.splitlines())
        promoted_ids, promoted_lines = self._promote(lines, run_id)
        kept = [line for index, line in enumerate(lines) if index not in promoted_lines]
        compacted = self._finalise("\n".join(kept))
        if len(compacted.encode("utf-8")) > self._active_cap_bytes:
            compacted = self._hard_bounded(compacted)
        self._assert_under_cap(compacted)
        after_digest = sha256_text(compacted)
        atomic_write_text(self.active_path, compacted)
        return MemoryCompaction(
            id=new_id("mc"),
            run_id=run_id,
            performed_at=utcnow(),
            before_digest=sha256_text(archived_text),
            after_digest=after_digest,
            archived_snapshot=str(snapshot),
            promoted_entries=promoted_ids,
            removed_duplicates=removed,
            local_model_used=False,
        )

    def append_active_section(self, title: str, bullets: Sequence[str]) -> None:
        """Add bullets under a section, enforcing the cap through write_active.

        Appending is the common shape of a post-run memory update, but it must not become a
        bypass of the cap, so the new document goes through the same writer as any rewrite.
        """
        clean_title = sanitise_bullet(title)
        if not clean_title:
            raise ConfigError("active memory sections need a title")
        additions: list[str] = []
        for bullet in bullets:
            text = sanitise_bullet(bullet)
            if text:
                additions.append(f"- {text}")
        lines = self.load_active().splitlines()
        target = normalise_key(clean_title)
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
            lines.append(f"## {clean_title}")
            lines.extend(additions)
        else:
            insert_at = heading_index + 1
            while insert_at < len(lines) and not heading_title(lines[insert_at]):
                insert_at += 1
            lines[insert_at:insert_at] = additions
        self.write_active("\n".join(lines))

    # -- internals ---------------------------------------------------------------------

    def _read_text(self, path: Path) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def _finalise(self, text: str) -> str:
        """Normalise a document for storage: exactly one trailing newline."""
        stripped = text.rstrip("\n")
        if not stripped:
            return ""
        return stripped + "\n"

    def _hard_bounded(self, text: str) -> str:
        """Last-resort byte bound, reserving room for the trailing newline."""
        return hard_clamp(text.rstrip("\n"), max(1, self._active_cap_bytes - 1)).rstrip("\n") + "\n"

    def _assert_under_cap(self, text: str) -> None:
        """Refuse to write an over-cap document: the cap is checked before the bytes land."""
        size = len(text.encode("utf-8"))
        if size > self._active_cap_bytes:
            raise ValidationError(
                f"active memory is {size} bytes, above the {self._active_cap_bytes} byte cap"
            )

    def _write_snapshot(self, content: str) -> Path:
        """Write the pre-compaction snapshot, never overwriting an existing one."""
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = archive_name(utcnow())
        candidate = self.archive_dir / stamp
        counter = 1
        while candidate.exists():
            counter += 1
            candidate = self.archive_dir / stamp.replace("-MEMORY.md", f"-{counter}-MEMORY.md")
        atomic_write_text(candidate, content)
        return candidate

    def _promote(self, lines: Sequence[str], run_id: str) -> tuple[list[str], set[int]]:
        """Move durable bullets into long-lived memory and report which lines left the file.

        Promoted entries are provisional: compaction is a size-management operation and has no
        run outcome to reason about, so it must not be able to assert that a lesson is durable.
        Confidence is the curator's judgement (see curator.py), made with the run's evidence in
        hand. If an identical entry already exists the existing id is reused, which keeps
        repeated compactions from multiplying the corpus.

        Provenance comes from the bullet's "(runs: ...)" trailer when it has one, and otherwise
        from the run that triggered the rewrite: an entry with no source run at all would be
        context nobody could trace back to a run.
        """
        candidates = collect_durable_candidates(lines)
        if not candidates:
            return [], set()
        existing = {(entry.kind, normalise_key(entry.summary)): entry.id for entry in self.index.all()}
        promoted_ids: list[str] = []
        promoted_lines: set[int] = set()
        for candidate in candidates:
            key = (candidate.kind, normalise_key(candidate.summary))
            entry_id = existing.get(key)
            if entry_id is None:
                entry = MemoryEntry(
                    id=new_id("mem"),
                    created_at=utcnow(),
                    kind=candidate.kind,
                    summary=candidate.summary,
                    source_runs=list(candidate.run_ids) or ([run_id] if run_id else []),
                    source_refs=[],
                    confidence="provisional",
                    tags=["compaction", "section:" + normalise_key(candidate.section)],
                )
                self.index.add(entry)
                existing[key] = entry.id
                entry_id = entry.id
            if entry_id not in promoted_ids:
                promoted_ids.append(entry_id)
            promoted_lines.add(candidate.line_index)
        return promoted_ids, promoted_lines

    def _long_term_digests(self) -> list[str]:
        """Content digests of the durable shards, in a stable order."""
        if not self.long_term_dir.exists():
            return []
        out: list[str] = []
        for path in sorted(self.long_term_dir.glob(SHARD_GLOB)):
            entry_id = path.stem
            if not ENTRY_ID_RE.match(entry_id):
                continue
            try:
                MemoryEntry.model_validate_json(path.read_text(encoding="utf-8"))
            except (ValueError, ValidationError) as exc:
                # Corrupt durable memory must be loud: a run that silently ran without a lesson
                # it believes it has is worse than a run that refuses to start.
                raise ValidationError(f"long-term memory shard is not a valid entry: {path}") from exc
            out.append(f"{entry_id}:{sha256_hex(path.read_bytes())}")
        return out
