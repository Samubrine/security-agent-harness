"""The structured contracts are defined once and exported from the same definitions (D16).

If a schema file could disagree with the validator, a model could be shown one contract and judged
by another. These tests pin that the exported schema and the runtime's own parser agree.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.llm.prompts import parse_agent_turn
from harness.llm.schemas import agent_turn_schema, export_schemas
from harness.models import AgentTurn


def test_agent_turn_schema_describes_the_contract_the_parser_enforces() -> None:
    schema = agent_turn_schema()
    assert schema["title"] == "AgentTurn"
    properties = schema["properties"]
    assert {"plan", "next_action"} <= set(properties)
    assert "next_action" in schema["required"]
    # The schema is generated from the same model the runtime validates into, not hand-maintained.
    assert set(properties) == set(AgentTurn.model_fields)


def test_every_model_schema_is_exported(tmp_path: Path) -> None:
    written = export_schemas(tmp_path)
    for name, path in written.items():
        assert path.exists(), name
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "title" in payload or "$defs" in payload, name
    assert {"agent_turn", "finding", "observation", "provider_decision"} <= set(written)


def test_a_document_the_schema_permits_is_accepted_by_the_parser() -> None:
    minimal = {
        "plan": [{"step": 1, "capability": "service.enumerate", "intent": "enumerate"}],
        "next_action": {
            "kind": "capability",
            "proposal": {
                "grant": "g-1",
                "capability": "service.enumerate",
                "args": {"profile": "service_detection"},
                "expects": "service observations",
                "evidence_needed": "nothing yet",
            },
        },
    }
    turn = parse_agent_turn(json.dumps(minimal))
    assert turn.next_action.kind == "capability"
    assert turn.next_action.proposal.grant == "g-1"


def test_a_capability_proposal_has_no_field_for_a_target_or_provider() -> None:
    """The structural scope guarantee, asserted against the published contract.

    A model cannot name a host or a provider because there is nowhere to write one. If a future
    change added such a field, this test would fail before any policy was consulted.
    """
    schema = agent_turn_schema()
    proposal = schema["$defs"]["CapabilityProposal"]
    assert set(proposal["properties"]) == {
        "grant",
        "capability",
        "args",
        "expects",
        "evidence_needed",
        "hypothesis_id",
    }
    assert proposal.get("additionalProperties") is False
