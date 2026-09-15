"""Content-addressed immutable artifact store and the flat provenance log.

Why content addressing: a finding is only defensible if the bytes it cites cannot change after the
fact. The store names every blob by the SHA-256 of its own content, so "the evidence for this
claim" is a digest rather than a file path that some later step could overwrite. Two consequences
are implemented rather than documented:

* writing identical bytes twice is idempotent -- the second write is a no-op that returns the
  first writer's metadata, so provenance cannot be rewritten by a later producer;
* reading an artifact re-hashes it, so bytes that no longer match their address raise instead of
  being handed to a parser as if they were the evidence.

Evidence spans are recomputable for the same reason: an :class:`EvidenceRef` carries the hash of
the exact byte slice it points at, and :meth:`ArtifactStore.verify_ref` recomputes that hash from
the stored artifact. Verification never raises on a missing artifact or a shifted span -- a
negative answer is the useful answer there, and raising would let a caller mistake "could not
verify" for "verified".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from harness.errors import BudgetExhausted, EvidenceError, HarnessError
from harness.models import ArtifactMeta, EvidenceRef, TaintLevel
from harness.util import (
    append_jsonl,
    atomic_write_bytes,
    atomic_write_json,
    iso,
    read_json,
    read_jsonl,
    sha256_hex,
    utcnow,
)

#: A digest is a typed token, not free text. Anchoring the grammar here means no digest string can
#: ever reach the filesystem as a path component, which is what makes directory traversal
#: structurally impossible rather than merely unlikely.
_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")


def _hex_of(digest: str) -> str:
    match = _DIGEST_RE.match(digest or "")
    if match is None:
        raise EvidenceError(f"not a content digest (expected 'sha256:<64 hex>'): {digest!r}")
    return match.group(1)


class ArtifactStore:
    """``root/artifacts/<aa>/<sha256>`` plus ``<sha256>.meta.json`` (``aa`` = first two hex chars)."""

    def __init__(self, root: Path, run_id: str, *, max_bytes: int = 32 * 1024 * 1024) -> None:
        self._root = Path(root)
        self._run_id = run_id
        self._max_bytes = int(max_bytes)
        self._artifacts = self._root / "artifacts"

    # -- layout ----------------------------------------------------------------------

    def _bytes_path(self, hexd: str) -> Path:
        return self._artifacts / hexd[:2] / hexd

    def _meta_path(self, hexd: str) -> Path:
        return self._artifacts / hexd[:2] / f"{hexd}.meta.json"

    def _stored_bytes(self) -> int:
        """Sum the recorded length of every artifact already in the store.

        Read from the metadata files rather than kept in an instance counter so the byte budget
        survives a store being re-opened (or inspected) mid-run -- a budget that resets when the
        process does is not a budget.
        """
        total = 0
        if not self._artifacts.is_dir():
            return 0
        for meta_path in sorted(self._artifacts.glob("*/*.meta.json")):
            total += int(read_json(meta_path)["byte_length"])
        return total

    # -- writing ---------------------------------------------------------------------

    def put(
        self,
        data: bytes,
        *,
        media_type: str,
        producer: str,
        execution_id: str | None = None,
        taint: TaintLevel = "T2",
    ) -> ArtifactMeta:
        """Store bytes and return their metadata; identical bytes are stored once.

        Idempotency is the immutability property in action: the digest *is* the identity, so a
        second ``put`` of the same bytes must not replace the first writer's metadata. Otherwise a
        later step could relabel earlier evidence with a different producer or a lower taint.
        """
        if not media_type:
            raise ValueError("an artifact must declare a media_type: parsers dispatch on it")
        if not producer:
            raise ValueError("an artifact must name its producer for provenance")

        raw = bytes(data)
        digest = f"sha256:{sha256_hex(raw)}"
        if self.exists(digest):
            return self.meta(digest)

        stored = self._stored_bytes()
        if stored + len(raw) > self._max_bytes:
            raise BudgetExhausted(
                f"artifact byte budget exhausted: max_artifact_bytes={self._max_bytes}, "
                f"already stored {stored} byte(s), this artifact would add {len(raw)}"
            )

        atomic_write_bytes(self._bytes_path(_hex_of(digest)), raw)
        meta = ArtifactMeta(
            digest=digest,
            media_type=media_type,
            byte_length=len(raw),
            created_at=utcnow(),
            producer=producer,
            execution_id=execution_id,
            run_id=self._run_id,
            taint=taint,
        )
        atomic_write_json(self._meta_path(_hex_of(digest)), meta.model_dump(mode="json"))
        return meta

    def put_text(self, text: str, **kw: Any) -> ArtifactMeta:
        """UTF-8 convenience wrapper; text payloads declare their media type explicitly."""
        kw.setdefault("media_type", "text/plain; charset=utf-8")
        return self.put(text.encode("utf-8"), **kw)

    # -- reading ---------------------------------------------------------------------

    def get(self, digest: str) -> bytes:
        """Return artifact bytes, re-hashing them against their address before handing them out."""
        hexd = _hex_of(digest)
        path = self._bytes_path(hexd)
        if not path.is_file():
            raise EvidenceError(f"artifact {digest} is not in this store")
        raw = path.read_bytes()
        if sha256_hex(raw) != hexd:
            raise EvidenceError(
                f"artifact {digest} does not match its content address; the stored bytes were "
                "changed since they were written"
            )
        return raw

    def exists(self, digest: str) -> bool:
        """True when the bytes file is present. A malformed digest is a bug, so it raises rather
        than answering ``False`` -- ``verify_ref`` is the soft, never-raising path."""
        return self._bytes_path(_hex_of(digest)).is_file()

    def meta(self, digest: str) -> ArtifactMeta:
        hexd = _hex_of(digest)
        path = self._meta_path(hexd)
        if not path.is_file():
            raise EvidenceError(f"artifact metadata {digest} is not in this store")
        meta = ArtifactMeta.model_validate(read_json(path))
        if meta.digest != digest:
            raise EvidenceError(
                f"artifact metadata at {path.name} claims digest {meta.digest}; refusing to treat "
                f"it as {digest}"
            )
        return meta

    # -- evidence spans --------------------------------------------------------------

    def ref(
        self,
        digest: str,
        *,
        byte_start: int,
        byte_end: int,
        locator: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        taint: TaintLevel = "T3",
    ) -> EvidenceRef:
        """Build a span reference whose ``span_sha256`` is the hash of the exact sliced bytes.

        The span is resolved against real artifact bytes at creation time, so an out-of-range
        offset fails where it is written instead of at report time, when the author is gone. The
        default taint is ``T3`` because anything a tool returned is attacker-reachable data.
        """
        raw = self.get(digest)
        if byte_start < 0 or byte_end < byte_start or byte_end > len(raw):
            raise EvidenceError(
                f"evidence span {byte_start}:{byte_end} is not inside artifact {digest} "
                f"({len(raw)} byte(s))"
            )
        meta = self.meta(digest)
        ref = EvidenceRef(
            artifact=digest,
            media_type=meta.media_type,
            byte_start=byte_start,
            byte_end=byte_end,
            line_start=line_start,
            line_end=line_end,
            locator=locator,
            taint=taint,
        )
        ref.span_sha256 = ref.compute_span_sha256(raw)
        return ref

    def verify_ref(self, ref: EvidenceRef) -> bool:
        """Recompute a span hash from the artifact. Returns ``False`` instead of raising.

        A verification routine that raises on a missing artifact invites callers to wrap it in a
        blanket ``except`` and turn a failed check into an accepted finding. A boolean makes the
        failure mode impossible to misread, and an empty ``span_sha256`` is treated as
        unverifiable rather than as "nothing to check".
        """
        if not ref.span_sha256:
            return False
        try:
            raw = self.get(ref.artifact)
        except HarnessError:
            return False
        if ref.byte_start < 0 or ref.byte_end < ref.byte_start or ref.byte_end > len(raw):
            return False
        return ref.compute_span_sha256(raw) == ref.span_sha256


class ProvenanceLog:
    """Append-only ``(subject, relation, object)`` triples, one canonical JSON line each.

    This is the flat, greppable half of the provenance graph: the artifact store holds the bytes
    and this file holds the ``derived_from``/``produced``/``supports`` edges that make "where did
    this finding come from?" a query rather than an interview.
    """

    #: Reserved so an ``extra`` field can never overwrite the edge itself or its timestamp.
    _RESERVED = ("subject", "relation", "object", "at")

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def add(self, subject: str, relation: str, obj: str, **extra: Any) -> None:
        if not subject or not relation or not obj:
            raise ValueError("a provenance triple needs a non-empty subject, relation and object")
        clash = sorted(set(extra) & set(self._RESERVED))
        if clash:
            raise ValueError(f"extra keys may not shadow the triple itself: {clash}")
        record = {
            "subject": subject,
            "relation": relation,
            "object": obj,
            # Recorded explicitly rather than folded into anything hashable: when an edge was
            # asserted is audit data, not part of the edge's identity.
            "at": iso(utcnow()),
            **extra,
        }
        append_jsonl(self._path, record)

    def triples(self) -> list[dict[str, Any]]:
        return read_jsonl(self._path)
