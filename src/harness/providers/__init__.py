"""Capability-first providers: registry, necessity gate and router.

The planner asks for a *capability*; provider identities (native:nmap, mcp:scanner-a) never
become planner vocabulary. Registration of a provider therefore never implies its use: several
providers may serve one capability and the necessity gate decides whether any of them runs, and
whether more than one is justified.

Only the deterministic decision surface is re-exported here. The native and mcp subpackages add
implementations underneath it, which is why adding a provider for an existing capability
changes nothing above this line.
"""

from __future__ import annotations

from harness.providers.base import (
    Provider,
    ProviderRequest,
    ProviderResult,
    failed_result,
    make_gap,
)
from harness.providers.necessity import CAPABILITY_OUTPUT_KINDS, NecessityGate
from harness.providers.registry import ProviderRegistry
from harness.providers.router import Router

__all__ = [
    "CAPABILITY_OUTPUT_KINDS",
    "NecessityGate",
    "Provider",
    "ProviderRegistry",
    "ProviderRequest",
    "ProviderResult",
    "Router",
    "failed_result",
    "make_gap",
]
