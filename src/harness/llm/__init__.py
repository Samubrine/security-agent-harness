"""Local-first model layer.

The harness has exactly one probabilistic component, and it is not allowed to reach the
network by accident. Every client in this package targets a local endpoint by default;
``is_local`` is recorded in the run manifest so a reviewer can tell from the artifact alone
whether this run's reasoning happened on the machine that ran it.
"""

from __future__ import annotations

from harness.llm.client import ModelClient, ModelResponse, build_client
from harness.llm.replay import ReplayModelClient
from harness.llm.scripted import ScriptedModelClient

__all__ = [
    "ModelClient",
    "ModelResponse",
    "ReplayModelClient",
    "ScriptedModelClient",
    "build_client",
]
