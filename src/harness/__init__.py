"""Local-first agentic security investigation harness.

The package is split along one boundary that never moves: a **deterministic spine**
(runtime, policy, providers, artifacts, parsers, findings, replay) and a **local
probabilistic brain** (the model client) that may only propose typed capability needs.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
