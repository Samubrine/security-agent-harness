"""Append-only, hash-chained event log (design 02, section 12).

Why the chain exists: the event log is the one artefact a third party is asked to trust when the
run is questioned after the fact. A plain JSONL file proves nothing -- anyone can rewrite a line
and the file still parses. Chaining every canonical event into the previous event's hash makes a
silent edit detectable, and recomputing the chain from the bytes *actually on disk* (never from a
schema-normalised copy the attacker never saw) is what makes the check worth anything.

Append-only is a construction property here, not a convention: :meth:`EventLog.append` only ever
appends and flushes, so a process that dies mid-run leaves a prefix of the chain that still
verifies from event 1.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.errors import EventChainError
from harness.models import EventRecord
from harness.util import append_jsonl, canonical_json, sha256_text, utcnow


class EventLog:
    """One canonical JSON event per line, each hash-linked to its predecessor.

    The hash rule is the frozen one from ``docs/design/02-data-model.md``:

        event_hash = sha256(prev_event_hash + canonical_json(event_without_event_hash))

    The first event links to the empty string, which pins the start of the chain instead of
    leaving it floating.
    """

    def __init__(self, path: Path, run_id: str) -> None:
        if not run_id:
            raise ValueError("an event log must belong to a run: run_id may not be empty")
        self._path = Path(path)
        self._run_id = run_id

    # -- writing ---------------------------------------------------------------------

    def append(self, event_type: str, data: dict[str, Any] | None = None) -> EventRecord:
        """Seal one event onto the chain and flush it to disk before returning.

        The returned record is the exact one that was written, so a caller can log the same
        hash it just committed. ``data`` is copied so that later mutation of the caller's dict
        cannot make the in-memory record disagree with the file.
        """
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")

        tail = self._tail()
        prev_hash = str(tail.get("event_hash", "")) if tail else ""
        prev_seq = int(tail["seq"]) if tail else 0

        record = EventRecord(
            seq=prev_seq + 1,
            run_id=self._run_id,
            type=event_type,
            at=utcnow(),
            data=dict(data) if data is not None else {},
            prev_event_hash=prev_hash,
        )
        record.event_hash = record.computed_hash()
        # canonical_json of this same dump is what verify_chain re-derives from the file, so the
        # hash we commit and the hash a verifier recomputes are the same computation.
        append_jsonl(self._path, record.model_dump(mode="json"))
        return record

    # -- reading ---------------------------------------------------------------------

    def records(self) -> list[EventRecord]:
        """Re-read the file and re-validate every line as an :class:`EventRecord`.

        Reading state back from the log rather than from memory is deliberate: replay and any
        post-run audit must be able to reconstruct the run from the file alone. A line that is
        not valid JSON, not an object, or carries unknown fields is a chain failure rather than a
        silently skipped event.
        """
        out: list[EventRecord] = []
        for lineno, raw in self._raw_events():
            try:
                out.append(EventRecord.model_validate(raw))
            except Exception as exc:  # pydantic ValidationError; re-typed for the caller
                raise EventChainError(f"event log line {lineno} is not a valid event record: {exc}") from exc
        return out

    @property
    def head_hash(self) -> str:
        """Hash of the last event, or ``""`` for an empty log (the genesis value)."""
        tail = self._tail()
        return str(tail.get("event_hash", "")) if tail else ""

    def count(self) -> int:
        return len(self._raw_events())

    # -- verification ----------------------------------------------------------------

    def verify_chain(self) -> bool:
        """Recompute every link from the on-disk bytes; raise on the first bad sequence number.

        Naming the first bad ``seq`` is the point of the error message: "the chain is broken" is
        not actionable during an incident, "event 7 no longer matches its recorded hash" is.
        Three distinct failures are checked in order: sequence continuity, predecessor linkage
        (which catches a deleted or reordered line), and hash equality (which catches an edited
        field).
        """
        expected_seq = 1
        prev_hash = ""
        for lineno, raw in self._raw_events():
            seq = raw.get("seq")
            if seq != expected_seq:
                raise EventChainError(
                    f"event chain broken at line {lineno}: expected seq {expected_seq}, found {seq!r}"
                )
            if raw.get("prev_event_hash", "") != prev_hash:
                raise EventChainError(
                    f"event chain broken at seq {seq}: prev_event_hash does not link to the "
                    f"previous event (expected {prev_hash[:12] or '<genesis>'})"
                )
            stored = raw.get("event_hash", "")
            recomputed = self._hash_of(raw, prev_hash)
            if stored != recomputed:
                raise EventChainError(
                    f"event chain broken at seq {seq}: recorded hash {str(stored)[:12]!r} does not "
                    f"match recomputed hash {recomputed[:12]!r}"
                )
            prev_hash = stored
            expected_seq += 1
        return True

    # -- internals -------------------------------------------------------------------

    @staticmethod
    def _hash_of(raw: dict[str, Any], prev_hash: str) -> str:
        """Recompute an event hash from the raw parsed line, omitting ``event_hash``.

        Deliberately not routed through ``EventRecord``: verification hashes exactly the fields
        that are on disk, so a schema change can never quietly rewrite history into a form that
        verifies.
        """
        payload = {k: v for k, v in raw.items() if k != "event_hash"}
        return sha256_text(prev_hash + canonical_json(payload))

    def _raw_events(self) -> list[tuple[int, dict[str, Any]]]:
        if not self._path.exists():
            return []
        out: list[tuple[int, dict[str, Any]]] = []
        for lineno, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                # A torn or hand-edited line must fail loudly: a log that cannot be parsed is a
                # log that cannot be audited, and skipping the line would hide exactly the event
                # someone wanted gone.
                raise EventChainError(f"event log line {lineno} is not valid JSON: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise EventChainError(f"event log line {lineno} is not a JSON object")
            out.append((lineno, obj))
        return out

    def _tail(self) -> dict[str, Any] | None:
        """Parse only the last event so appending stays cheap on a long log."""
        events = self._raw_events()
        if not events:
            return None
        raw = events[-1][1]
        if not isinstance(raw.get("seq"), int) or "event_hash" not in raw:
            raise EventChainError(f"last event log line has no usable seq/event_hash: {raw!r}")
        return raw
