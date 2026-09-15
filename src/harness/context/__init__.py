"""Context assembly: what the model is allowed to see, and in what proportion."""

from __future__ import annotations

from harness.context.builder import ContextBuilder, PromptBundle
from harness.context.resolver import ContextResolver, ResolvedContext
from harness.context.retrieval import retrieve_for_plan
from harness.context.spotlight import Spotlight

__all__ = [
    "ContextBuilder",
    "ContextResolver",
    "PromptBundle",
    "ResolvedContext",
    "Spotlight",
    "retrieve_for_plan",
]
