"""Selective long-lived memory retrieval.

The corpus is never loaded wholesale: a run retrieves a handful of entries relevant to the
objective and skill, and labels them as advisory. Retrieval is deterministic (FTS5 plus filters),
because a plan that changes between two identical runs is a plan that cannot be replayed.
"""

from __future__ import annotations

from harness.models import RetrievedMemory, SkillSpec

#: Words that carry no retrieval signal in this domain. Dropped so that a common word cannot
#: dominate an FTS5 match against a large corpus.
STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "that", "this", "from", "into", "onto", "over",
        "are", "was", "were", "has", "have", "had", "not", "but", "all", "any", "its",
        "target", "identify", "detect", "enumerate", "report", "analyse", "analyze",
    }
)


def build_query(objective: str, skill: SkillSpec) -> str:
    tokens = [
        token
        for token in _tokenize(objective)
        if token not in STOPWORDS and len(token) > 2
    ]
    tokens.extend(part for part in _tokenize(skill.name) if part not in STOPWORDS)
    for capability in skill.capabilities:
        tokens.extend(part for part in _tokenize(capability) if part not in STOPWORDS)
    # Order matters only for readability of the trace; dedupe while preserving determinism.
    seen: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.append(token)
    return " OR ".join(seen)


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    for ch in text.lower():
        if ch.isalnum() or ch in "_-.":
            current.append(ch)
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return out


def retrieve_for_plan(
    index: object,
    *,
    objective: str,
    skill: SkillSpec,
    limit: int = 3,
) -> list[RetrievedMemory]:
    """Retrieve at most ``limit`` admissible entries. No query means no retrieval, not everything."""
    query = build_query(objective, skill)
    if not query:
        return []
    return list(index.search(query, limit=limit))
