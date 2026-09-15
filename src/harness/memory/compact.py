"""Deterministic line-level rules for active-memory compaction.

Compaction is the one place in the memory subsystem where context is *removed*, so every step
here is a pure function over lines of text instead of a model call: the same input must always
produce the same smaller output, and a reviewer must be able to replay why a line disappeared.

Two rules encode the security intent:

* nothing is dropped before a durable copy exists -- the caller writes an archive snapshot
  first, and each promoted bullet becomes a long-lived entry that keeps its source run ids;
* promotion is driven by an allow-list of *learned* sections (tool quirks, environment facts,
  conventions) or by an explicit "[durable]" tag -- never by the text merely sounding durable.
  Hand-written invariants live under headings this module does not recognise, so a byte-cap
  rewrite can never quietly relocate the rules a human maintains out of the file a human
  reviews.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from harness.models import MemoryKind
from harness.util import iso, strip_control_chars

#: A markdown bullet: "- x", "* x", "+ x" or an ordered "1. x" / "1) x".
BULLET_RE = re.compile(r"^(?P<indent>\s*)(?P<marker>[-*+]|\d{1,3}[.)])\s+(?P<body>.*)$")
#: An ATX heading. Mirrors the shapes used in the repository memory files.
HEADING_RE = re.compile(r"^(?P<indent>\s{0,3})(?P<hashes>#{1,6})\s+(?P<title>.*?)\s*$")
#: Machine-readable provenance trailer emitted by the curator: "(runs: run-a, run-b)".
PROVENANCE_RE = re.compile(r"\(runs?:\s*(?P<ids>[^)]*)\)\s*$", re.IGNORECASE)
#: The same shape anywhere in a line, used to strip provenance *claims* out of untrusted text.
PROVENANCE_ANYWHERE_RE = re.compile(r"\(runs?:\s*[^)]*\)", re.IGNORECASE)
#: Explicit marker asking for a bullet to be promoted out of active memory.
DURABLE_TAG_RE = re.compile(r"\[durable\]", re.IGNORECASE)

#: Section titles (normalised) whose bullets describe durable, learned facts. Deliberately an
#: allow-list: an unknown or human-curated heading is not a promotion source.
DURABLE_SECTIONS: tuple[str, ...] = (
    "tool quirks",
    "tool behaviour",
    "tool behavior",
    "environment facts",
    "environment notes",
    "conventions",
    "user conventions",
)

#: Longest summary persisted for one memory entry. Keeps a poisoned provider payload from
#: writing a kilobyte of instructions into both long-lived memory and the active working set.
MAX_SUMMARY_CHARS = 320

_KIND_HINTS: tuple[tuple[str, MemoryKind], ...] = (
    ("tool quir", "tool_behavior"),
    ("tool behavio", "tool_behavior"),
    ("environment", "environment_fact"),
    ("convention", "user_convention"),
    ("lesson", "lesson"),
    ("investigation", "investigation_pattern"),
)


@dataclass(frozen=True)
class DurableCandidate:
    """A bullet that should survive compaction as a long-lived memory entry."""

    line_index: int
    section: str
    kind: MemoryKind
    summary: str
    run_ids: tuple[str, ...]


def is_bullet(line: str) -> bool:
    return BULLET_RE.match(line) is not None


def bullet_body(line: str) -> str | None:
    match = BULLET_RE.match(line)
    return match.group("body") if match else None


def heading_title(line: str) -> str | None:
    match = HEADING_RE.match(line)
    return match.group("title") if match else None


def normalise_key(text: str) -> str:
    """Case- and whitespace-insensitive identity used for duplicate detection.

    Control characters are stripped first so an ANSI sequence cannot make two otherwise
    identical lines compare as different and defeat de-duplication.
    """
    return re.sub(r"\s+", " ", strip_control_chars(text)).strip().casefold()


def bound_single_line(text: str, limit: int = MAX_SUMMARY_CHARS) -> str:
    """Bound text for one bullet line, keeping it a single line.

    harness.util.clamp_text is the shared bounder, but its truncation marker contains a
    newline, which would break the one-statement-per-line structure this module relies on for
    provenance trailers and section detection. Bounding therefore happens here instead.
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    keep = max(0, limit - len(" [truncated]"))
    return text[:keep].rstrip() + " [truncated]"


def sanitise_bullet(text: str) -> str:
    """Reduce untrusted text to exactly one inert bullet body.

    Provider payloads and model prose reach the curator, so a summary may contain ANSI
    escapes, embedded newlines or a leading dash. Collapsing whitespace and stripping a
    leading bullet marker keeps a payload from forging a *new* line -- for example a fake
    heading that would reorder MEMORY.md -- while the statement itself stays readable.
    """
    flat = re.sub(r"\s+", " ", strip_control_chars(text)).strip()
    flat = re.sub(r"^[-*+]\s+", "", flat)
    return bound_single_line(flat)


def parse_provenance(text: str) -> tuple[str, tuple[str, ...]]:
    """Split a trailing "(runs: ...)" trailer off a bullet body."""
    match = PROVENANCE_RE.search(text)
    if not match:
        return text.strip(), ()
    ids = tuple(part.strip() for part in match.group("ids").split(",") if part.strip())
    return text[: match.start()].strip(), ids


def heading_kind(title: str) -> MemoryKind | None:
    """Map a section heading to the memory kind its bullets describe, if any."""
    low = title.casefold()
    for hint, kind in _KIND_HINTS:
        if hint in low:
            return kind
    return None


def strip_provenance_claims(text: str) -> str:
    """Remove every provenance trailer and durability tag from untrusted text.

    Provenance and durability are decided by the harness -- source_runs on a promoted entry and
    the curator's promotion rule -- so a statement must not be able to carry its own. Without
    this, a provider banner or a model-authored finding title could claim "(runs: run-x)" or
    "[durable]" and have that text read as harness provenance on the next compaction.
    Only the *trailing* trailer counts as provenance when reading a bullet (see
    parse_provenance); this function governs what may be written.
    """
    return DURABLE_TAG_RE.sub(" ", PROVENANCE_ANYWHERE_RE.sub(" ", text))


def is_durable_section(title: str) -> bool:
    return normalise_key(title) in DURABLE_SECTIONS


def dedupe_repeated_bullets(lines: Sequence[str]) -> tuple[list[str], int]:
    """Drop repeated bullet lines, keeping the first occurrence.

    Only bullets are de-duplicated: headings and prose are structural, and collapsing two
    equal-looking headings would change the document's meaning rather than its size.
    """
    seen: set[str] = set()
    kept: list[str] = []
    removed = 0
    for line in lines:
        body = bullet_body(line)
        if body is None:
            kept.append(line)
            continue
        key = normalise_key(body)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        kept.append(line)
    return kept, removed


def collect_durable_candidates(lines: Sequence[str]) -> list[DurableCandidate]:
    """Select the bullets that must be preserved outside the active file.

    A bullet qualifies either because a human tagged it [durable] or because it sits in a
    section this module classifies as learned and durable. Any "(runs: ...)" trailer is parsed
    off and reported separately: it is provenance to be stored on the entry, not part of the
    statement.
    """
    section = ""
    out: list[DurableCandidate] = []
    for index, line in enumerate(lines):
        title = heading_title(line)
        if title is not None:
            section = title
            continue
        body = bullet_body(line)
        if body is None:
            continue
        tagged = DURABLE_TAG_RE.search(body) is not None
        kind = heading_kind(section)
        text, run_ids = parse_provenance(body)
        promoted = tagged or (is_durable_section(section) and kind is not None)
        if not promoted:
            continue
        summary = sanitise_bullet(DURABLE_TAG_RE.sub(" ", text))
        if not summary:
            continue
        out.append(
            DurableCandidate(
                line_index=index,
                section=section,
                kind=kind or "investigation_pattern",
                summary=summary,
                run_ids=run_ids,
            )
        )
    return out


def archive_name(when: datetime) -> str:
    """Deterministic, lexicographically sortable snapshot filename.

    Derived from the UTC instant ("2026-09-15T12-48-00Z-MEMORY.md") so the archive directory
    sorts chronologically in a plain directory listing; colons are dropped because they are not
    portable in filenames. Sorting is what lets a reviewer find the snapshot predating a
    rewrite.
    """
    return f"{iso(when).replace(':', '-')}-MEMORY.md"


def hard_clamp(text: str, limit: int) -> str:
    """Shrink text to at most limit UTF-8 bytes, always leaving a truncation marker.

    Last resort after de-duplication and promotion, when a single enormous line cannot be
    structurally reduced. The marker is fixed-width (the byte count is zero-padded) so the
    arithmetic holds, and it points the reader at the archive rather than pretending the text
    is complete. Slicing is done on bytes and decoded with errors="ignore" so a multi-byte
    character split by the cap is truncated instead of corrupting the file.
    """
    if limit <= 0:
        return ""
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text
    marker = f"\n[...{len(data):010d} bytes compacted out of the active set; see the archived snapshot ...]\n"
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= limit:
        return data[:limit].decode("utf-8", errors="ignore")
    head = data[: limit - len(marker_bytes)].decode("utf-8", errors="ignore")
    out = head + marker
    if len(out.encode("utf-8")) > limit:
        out = out.encode("utf-8")[:limit].decode("utf-8", errors="ignore")
    return out
