"""Prompt construction is part of the trust boundary, so it gets adversarial tests."""

from __future__ import annotations

import pytest

from harness.errors import ModelClientError
from harness.llm.prompts import parse_agent_turn, render_turn_prompt, system_prompt
from harness.models import CapabilityAction, StopAction
from harness.skills import load_skill


def _prompt(**overrides):
    kwargs = dict(
        objective="Enumerate exposed services on lab-web-01.",
        skill=load_skill("port_scan"),
        catalogue={"capabilities": []},
        run_digest={"objective_kind": "port_scan", "observations": [], "executed": []},
    )
    kwargs.update(overrides)
    return render_turn_prompt(**kwargs)


def test_system_prompt_states_the_instruction_data_separation() -> None:
    # The prompt is wrapped for readability, so compare on normalised whitespace.
    text = " ".join(system_prompt().lower().split())
    assert "data" in text and "never an instruction" in text
    assert "never emit a command" in text


def test_prompt_contains_the_catalogue_and_digest_blocks() -> None:
    rendered = _prompt()
    assert rendered.count("<capability_catalogue>") == 1
    assert rendered.count("</capability_catalogue>") == 1
    assert rendered.count("<run_digest>") == 1


def test_parses_fenced_json() -> None:
    turn = parse_agent_turn('```json\n{"plan": [], "next_action": {"kind": "stop", "reason": "done"}}\n```')
    assert isinstance(turn.next_action, StopAction)


def test_parses_bare_json() -> None:
    turn = parse_agent_turn('{"plan": [], "next_action": {"kind": "stop", "reason": "done"}}')
    assert turn.next_action.kind == "stop"


def test_parses_json_wrapped_in_prose() -> None:
    text = 'Sure, here is my plan.\n{"plan": [], "next_action": {"kind": "stop", "reason": "done"}}\nHope that helps.'
    turn = parse_agent_turn(text)
    assert isinstance(turn.next_action, StopAction)


def test_parses_a_real_capability_action() -> None:
    payload = (
        '{"plan": [{"step": 1, "capability": "service.enumerate", "intent": "x"}],'
        ' "next_action": {"kind": "capability", "proposal": {"grant": "g-1", "capability":'
        ' "service.enumerate", "args": {"profile": "service_detection"}, "expects": "services",'
        ' "evidence_needed": "nothing yet"}}}'
    )
    turn = parse_agent_turn(payload)
    assert isinstance(turn.next_action, CapabilityAction)
    assert turn.next_action.proposal.grant == "g-1"


@pytest.mark.parametrize("garbage", ["", "   ", "no json at all", "{not json}"])
def test_garbage_raises_instead_of_becoming_a_default(garbage: str) -> None:
    with pytest.raises(ModelClientError):
        parse_agent_turn(garbage)


def test_a_model_that_returns_a_shell_command_is_rejected() -> None:
    # The classic injection outcome: the model tries to answer with a command instead of a
    # capability proposal. It must fail validation, not be coerced into an action.
    with pytest.raises(ModelClientError):
        parse_agent_turn('{"next_action": {"kind": "command", "cmd": "nmap -sV 10.77.0.99"}}')


def test_memory_prompt_section_is_labelled_advisory() -> None:
    rendered = _prompt(memory_context="remembered: nginx 1.18 has a resolver bug")
    lowered = rendered.lower()
    assert "never evidence" in lowered
    assert "advisory" in lowered
