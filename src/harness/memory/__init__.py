"""Harness memory: three lifetimes, one contract.

* MemoryManager owns the file tiers (BASELINE.md, the bounded MEMORY.md, the archive) and
  enforces the active-memory cap.
* LongTermIndex owns the durable long-lived entries and their local FTS5 retrieval.
* MemoryCurator derives post-run updates and decides what has earned "stable".

Submodules are imported directly (harness.memory.index, harness.memory.manager, ...) so the
package stays importable in any order and no sibling subsystem is pulled in implicitly. Memory
depends on harness.models, harness.util and harness.errors, and on nothing else.
"""

from __future__ import annotations

from harness.memory.compact import (
    DURABLE_SECTIONS,
    MAX_SUMMARY_CHARS,
    DurableCandidate,
    archive_name,
    collect_durable_candidates,
    dedupe_repeated_bullets,
    hard_clamp,
    sanitise_bullet,
)
from harness.memory.curator import CuratorCommit, CuratorProposal, MemoryCurator
from harness.memory.index import ENTRY_ID_RE, LongTermIndex
from harness.memory.manager import MemoryManager

__all__ = [
    "DURABLE_SECTIONS",
    "ENTRY_ID_RE",
    "MAX_SUMMARY_CHARS",
    "CuratorCommit",
    "CuratorProposal",
    "DurableCandidate",
    "LongTermIndex",
    "MemoryCurator",
    "MemoryManager",
    "archive_name",
    "collect_durable_candidates",
    "dedupe_repeated_bullets",
    "hard_clamp",
    "sanitise_bullet",
]
