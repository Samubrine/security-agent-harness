"""The deterministic spine.

Everything that must be provable lives here: the run lifecycle, budgets, provider invocation,
parsing, correlation, finding construction and replay. The model is a caller-supplied proposal
source and nothing more.
"""

from __future__ import annotations

from harness.runtime.fsm import RunState, State
from harness.runtime.replay import Replayer, ReplayWriter

__all__ = ["Replayer", "ReplayWriter", "RunState", "State"]
