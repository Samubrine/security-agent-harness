"""The structured contracts are defined once and exported from the same definitions (D16).

If a schema file could disagree with the validator, a model could be shown one contract and judged
by another. These tests pin that the exported schema and the runtime's own parser agree.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.llm.prompts import parse_agent_turn
from harness.llm.schemas import agent_turn_schema, export_schemas
from harness.models import AgentTurn, SkillSpec
from harness.skills import list_skills


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


#: Fields of a skill the runtime reads, and where. Keeping the list here rather than describing it in
#: prose is the point: a field added to `SkillSpec` must be classified before the suite goes green,
#: because the alternative is what the round-2 audit found - `independent_for`,
#: `allow_second_provider_by_default` and `inputs` were declared by every skill and read by nothing
#: (R2-24, K5), so a request for independent verification had no effect for a whole release.
CONSUMED_SKILL_FIELDS = frozenset(
    {
        "name",  # the run manifest, the report, and the objective's skill pairing
        "capabilities",  # the action catalogue
        "verification",  # max_providers_per_need and independent_for, via the necessity gate
        "budget_override",  # runner._budgets_for
        "allow_second_provider_by_default",  # loop._corroboration_required
        "inputs",  # runner._require_skill_inputs
    }
)

#: Fields that are deliberately display-only: a human reads them in the skill file or the report, no
#: code branches on them. Anything else about a skill has to be consumed by the runtime.
DISPLAY_ONLY_SKILL_FIELDS = frozenset({"version", "description", "completion_criteria"})


def test_every_skill_field_is_consumed_or_declared_display_only() -> None:
    """A new skill setting with no consumer must fail here, not ship as dead configuration.

    The failure message names the section to read, because "unexpected field" is not actionable and
    the disposition is a decision (honour it, or delete it and say why) rather than a rename.
    """
    known = CONSUMED_SKILL_FIELDS | DISPLAY_ONLY_SKILL_FIELDS
    declared = set(SkillSpec.model_fields)
    unexplained = sorted(declared - known)
    assert not unexplained, (
        f"SkillSpec gains {unexplained} with no consumer and no stated disposition. Every skill "
        "field must either be read by the runtime or be listed as display-only - see WS-07 and "
        "decision D25 in docs/dev/AUDIT-v12.md."
    )
    stale = sorted(known - declared)
    assert not stale, (
        f"{stale} is classified but no longer declared on SkillSpec; remove it from the lists in "
        "tests/test_schemas_contract.py so a future field cannot reuse the name unchecked."
    )


def test_the_consumed_skill_fields_are_the_ones_the_skill_files_use() -> None:
    """The lists above describe the shipped skills, so a field only tests set would be a false pass."""
    for skill in list_skills():
        assert set(skill.model_fields_set) <= (CONSUMED_SKILL_FIELDS | DISPLAY_ONLY_SKILL_FIELDS), (
            skill.name
        )
        assert skill.name and skill.capabilities, skill.name
