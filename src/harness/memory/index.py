"""Durable long-lived memory: sharded JSON entries plus a rebuildable SQLite FTS5 index.

Retrieval is keyword-based and selective by contract -- the corpus is never loaded wholesale
into a prompt, and no embeddings or vector database are involved.

Layout (both pieces live in the same directory, conventionally memory/long_term/):

* the JSON shard "<entry-id>.json" is durable truth and stays readable by a human;
* the SQLite database "index.sqlite" is a derived index that can be deleted and rebuilt.

add() writes the shard before the row, and __init__ re-indexes shards whose ids are missing
from the database, so a corrupt or deleted index loses no memory. Writing the durable copy
first is deliberate: an index pointing at content that does not exist would be worse than no
index at all, because retrieval would return entries a reviewer cannot check.

Entry ids are used as filenames, so they are validated against a conservative pattern before
they reach the filesystem. A memory id is untrusted input in the same way an artifact digest
is: it may have been written by an earlier run or edited by a human, and it must never be able
to name a path outside the shard directory.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from harness.errors import ConfigError, ValidationError
from harness.models import MemoryEntry, MemoryKind, RetrievedMemory
from harness.util import atomic_write_text, canonical_json, iso

#: Filename-safe entry id: a short token with no path separators, dots-only names, etc.
ENTRY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
#: Shard files are recognised by this glob so that unrelated JSON in the directory is ignored.
SHARD_GLOB = "mem-*.json"
#: Tokens used to build an FTS5 MATCH expression. Anything else is dropped, which is what makes
#: a malformed query (quotes, parentheses, FTS operators) a no-match instead of an SQL error.
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS memory_entries (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        kind TEXT NOT NULL,
        summary TEXT NOT NULL,
        tags TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        superseded_by TEXT,
        supersedes TEXT NOT NULL DEFAULT '[]'
    )
    """,
    "CREATE INDEX IF NOT EXISTS memory_entries_kind ON memory_entries(kind)",
    "CREATE INDEX IF NOT EXISTS memory_entries_superseded ON memory_entries(superseded_by)",
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
        id UNINDEXED, summary, tags, tokenize='porter unicode61'
    )
    """,
)


def _fts_expression(query: str) -> str | None:
    """Turn free text into a safe FTS5 MATCH expression, or None when there is nothing to match.

    Every token is quoted, so FTS5 syntax characters cannot smuggle an operator into the query.
    Tokens are OR-ed: retrieval feeds a planner, and a query built from an objective should not
    return nothing merely because one word is absent from the corpus.
    """
    tokens: list[str] = []
    for token in _TOKEN_RE.findall(query or ""):
        low = token.casefold()
        if low not in tokens:
            tokens.append(low)
    if not tokens:
        return None
    return " OR ".join(f'"{token}"' for token in tokens)


class LongTermIndex:
    """Local FTS5 index over the durable long-lived memory entries."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._shard_dir = self._db_path.parent
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        for statement in _SCHEMA:
            self._conn.execute(statement)
        self._conn.commit()
        self._reindex_missing_shards()
        self._rebuild_supersession()

    # -- paths -------------------------------------------------------------------------

    @property
    def db_path(self) -> Path:
        return self._db_path

    def shard_path(self, entry_id: str) -> Path:
        """Path of the durable shard for an entry, refusing ids that could escape the shard dir."""
        if not ENTRY_ID_RE.match(entry_id):
            raise ValidationError(f"memory entry id is not a safe shard filename: {entry_id!r}")
        return self._shard_dir / f"{entry_id}.json"

    def close(self) -> None:
        self._conn.close()

    # -- writes ------------------------------------------------------------------------

    def add(self, entry: MemoryEntry) -> None:
        """Persist an entry durably and index it for retrieval.

        Idempotent: re-adding the same id refreshes the stored content instead of creating a
        second row, so a curator that proposes the same lesson twice cannot inflate the corpus.
        """
        path = self.shard_path(entry.id)
        atomic_write_text(path, canonical_json(entry.model_dump(mode="json")) + "\n")
        self._upsert(entry)
        self._apply_supersession(entry)
        self._conn.commit()

    def mark_used(self, entry_ids: Sequence[str], when: datetime) -> None:
        """Record that entries were surfaced into a run. Unknown ids are ignored.

        last_used_at is what lets a later curator prefer what is actually consulted over what
        merely exists; a missing entry is not an error because memory may have been archived.
        """
        for entry_id in entry_ids:
            entry = self.get(entry_id)
            if entry is None:
                continue
            entry.last_used_at = when
            atomic_write_text(self.shard_path(entry.id), canonical_json(entry.model_dump(mode="json")) + "\n")
            self._upsert(entry)
        self._conn.commit()

    # -- reads -------------------------------------------------------------------------

    def get(self, entry_id: str) -> MemoryEntry | None:
        row = self._conn.execute("SELECT payload FROM memory_entries WHERE id = ?", (entry_id,)).fetchone()
        return self._entry(row["payload"]) if row is not None else None

    def all(self) -> list[MemoryEntry]:
        rows = self._conn.execute(
            "SELECT payload FROM memory_entries ORDER BY created_at ASC, id ASC"
        ).fetchall()
        return [self._entry(row["payload"]) for row in rows]

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        kinds: Sequence[MemoryKind] | None = None,
        include_superseded: bool = False,
    ) -> list[RetrievedMemory]:
        """Rank entries for a query by FTS rank, then by recency.

        Superseded entries are excluded by default, which is what makes a corrected lesson
        actually replace the wrong one. When they are requested explicitly they are still
        ordered behind the entries that replaced them, so a caller cannot accidentally read a
        stale statement first. A query with no usable tokens degrades to recency order rather
        than returning nothing: an empty objective still deserves recent context.
        """
        if limit <= 0:
            return []
        kinds_filter = [str(kind) for kind in (kinds or [])]
        match = _fts_expression(query)
        params: list[Any] = []
        if match is None:
            sql = "SELECT m.payload AS payload, 0.0 AS rank FROM memory_entries m WHERE 1 = 1"
            order = " ORDER BY m.created_at DESC, m.id ASC"
        else:
            sql = (
                "SELECT m.payload AS payload, bm25(memory_fts) AS rank "
                "FROM memory_fts JOIN memory_entries m ON m.id = memory_fts.id "
                "WHERE memory_fts MATCH ?"
            )
            params.append(match)
            order = " ORDER BY (m.superseded_by IS NOT NULL) ASC, rank ASC, m.created_at DESC, m.id ASC"
        if not include_superseded:
            sql += " AND m.superseded_by IS NULL"
        if kinds_filter:
            sql += " AND m.kind IN (" + ", ".join("?" for _ in kinds_filter) + ")"
            params.extend(kinds_filter)
        sql += order + " LIMIT ?"
        params.append(int(limit))
        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:  # pragma: no cover - FTS5 is required by design
            raise ConfigError(f"SQLite FTS5 search failed: {exc}") from exc
        hits: list[RetrievedMemory] = []
        for row in rows:
            rank = float(row["rank"])
            # bm25 is negative with "smaller is better", so the negated value reads as a
            # relevance score; the keyword-less recency fallback carries no match score.
            score = round(-rank, 6) if rank else 0.0
            hits.append(
                RetrievedMemory(
                    entry=self._entry(row["payload"]),
                    score=score,
                    retrieved_for=query,
                )
            )
        return hits

    # -- internals ---------------------------------------------------------------------

    def _entry(self, payload: str) -> MemoryEntry:
        return MemoryEntry.model_validate_json(payload)

    @staticmethod
    def _tags(entry: MemoryEntry) -> str:
        return " ".join(entry.tags)

    def _upsert(self, entry: MemoryEntry) -> None:
        payload = canonical_json(entry.model_dump(mode="json"))
        self._conn.execute(
            """
            INSERT INTO memory_entries
                (id, payload, kind, summary, tags, created_at, last_used_at, superseded_by, supersedes)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
            ON CONFLICT(id) DO UPDATE SET
                payload = excluded.payload,
                kind = excluded.kind,
                summary = excluded.summary,
                tags = excluded.tags,
                created_at = excluded.created_at,
                supersedes = excluded.supersedes,
                last_used_at = COALESCE(excluded.last_used_at, memory_entries.last_used_at)
            """,
            (
                entry.id,
                payload,
                str(entry.kind),
                entry.summary,
                self._tags(entry),
                iso(entry.created_at),
                iso(entry.last_used_at) if entry.last_used_at is not None else None,
                canonical_json(list(entry.supersedes)),
            ),
        )
        # FTS5 has no UPSERT, so the row is replaced explicitly to keep one row per entry id.
        self._conn.execute("DELETE FROM memory_fts WHERE id = ?", (entry.id,))
        self._conn.execute(
            "INSERT INTO memory_fts (id, summary, tags) VALUES (?, ?, ?)",
            (entry.id, entry.summary, self._tags(entry)),
        )

    def _apply_supersession(self, entry: MemoryEntry) -> None:
        """Mark the entries this one replaces, and honour out-of-order ingestion.

        Supersession is recorded on both sides: the new entry lists what it replaces, but a
        shard replayed after the fact (or a human editing the corpus) may add an *older*
        statement whose replacement already exists. Both directions must resolve to "the
        replacement wins", otherwise which statement is current would depend on write order.
        """
        for superseded in entry.supersedes:
            self._conn.execute(
                "UPDATE memory_entries SET superseded_by = ? WHERE id = ? AND superseded_by IS NULL",
                (entry.id, superseded),
            )
        rows = self._conn.execute(
            "SELECT id, supersedes FROM memory_entries WHERE id != ? AND supersedes LIKE ?",
            (entry.id, f'%"{entry.id}"%'),
        ).fetchall()
        for row in rows:
            self._conn.execute(
                "UPDATE memory_entries SET superseded_by = ? WHERE id = ? AND superseded_by IS NULL",
                (row["id"], entry.id),
            )

    def _rebuild_supersession(self) -> None:
        """Recompute supersession from the stored supersedes lists. Idempotent."""
        self._conn.execute("UPDATE memory_entries SET superseded_by = NULL")
        rows = self._conn.execute("SELECT id, supersedes FROM memory_entries").fetchall()
        for row in rows:
            for superseded in _supersedes_of(row["supersedes"]):
                self._conn.execute(
                    "UPDATE memory_entries SET superseded_by = ? WHERE id = ? AND superseded_by IS NULL",
                    (row["id"], superseded),
                )
        self._conn.commit()

    def _reindex_missing_shards(self) -> None:
        """Re-index durable shards that the SQLite index does not have (or has stale).

        This is what makes the database disposable. A shard that cannot be parsed is a hard
        error rather than a skipped file: silently forgetting a durable lesson is exactly the
        failure mode long-lived memory exists to prevent.
        """
        known = {
            row["id"]: row["payload"]
            for row in self._conn.execute("SELECT id, payload FROM memory_entries").fetchall()
        }
        for path in sorted(self._shard_dir.glob(SHARD_GLOB)):
            if not ENTRY_ID_RE.match(path.stem):
                continue
            try:
                entry = MemoryEntry.model_validate_json(path.read_text(encoding="utf-8"))
            except (PydanticValidationError, ValueError) as exc:  # a hand-edited or truncated shard
                raise ValidationError(f"long-term memory shard is not a valid entry: {path}") from exc
            payload = canonical_json(entry.model_dump(mode="json"))
            if known.get(entry.id) != payload:
                self._upsert(entry)
        self._conn.commit()

def _supersedes_of(raw: str) -> list[str]:
    """Read the JSON-encoded supersedes list stored next to an entry."""
    try:
        parsed = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, str)]
