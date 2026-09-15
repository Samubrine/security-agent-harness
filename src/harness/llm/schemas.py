"""JSON Schema export.

Design decision D16 requires the structured contracts to be defined once. These schemas are
generated from the same pydantic models the runtime validates against, so a schema file that
disagrees with the validator is impossible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from harness.models import (
    AgentTurn,
    CapabilityProposal,
    Claim,
    EvidenceGap,
    Finding,
    MemoryEntry,
    Observation,
    PolicyDecision,
    ProviderDecision,
    ProviderSpec,
    RunConfig,
    SkillSpec,
)
from harness.util import atomic_write_json

_MODELS: dict[str, type] = {
    "agent_turn": AgentTurn,
    "capability_proposal": CapabilityProposal,
    "claim": Claim,
    "evidence_gap": EvidenceGap,
    "finding": Finding,
    "memory_entry": MemoryEntry,
    "observation": Observation,
    "policy_decision": PolicyDecision,
    "provider_decision": ProviderDecision,
    "provider_spec": ProviderSpec,
    "run_config": RunConfig,
    "skill_spec": SkillSpec,
}


def agent_turn_schema() -> dict[str, Any]:
    return AgentTurn.model_json_schema()


def export_schemas(dest: Path) -> dict[str, Path]:
    """Write every model schema to ``dest`` and return name -> path."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, model in _MODELS.items():
        path = dest / f"{name}.schema.json"
        atomic_write_json(path, model.model_json_schema())
        written[name] = path
    return written
