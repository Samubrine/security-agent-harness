"""The scripted planner is what makes runs reproducible; its determinism is load-bearing."""

from __future__ import annotations

import pytest

from harness.errors import ModelClientError
from harness.llm.client import build_client
from harness.llm.prompts import render_turn_prompt, system_prompt
from harness.llm.scripted import ScriptedModelClient
from harness.models import CapabilityAction, ModelMetadata, StopAction
from harness.skills import load_skill


def _catalogue(capabilities):
    return {"capabilities": capabilities}


SERVICE_CAP = {
    "capability": "service.enumerate",
    "intent_hint": "enumerate exposed services",
    "expects": "service, product, version and CPE observations",
    "expected_kinds": ["service", "host_state", "scan_meta"],
    "grants": [{"grant": "g-7f21", "alias": "lab-web-01", "args": {"profile": "service_detection"}}],
}
CVE_CAP = {
    "capability": "vulnerability.match",
    "intent_hint": "map versions to candidate CVEs",
    "expects": "candidate CVE observations",
    "expected_kinds": ["vulnerability_match"],
    "grants": [{"grant": "g-7f21", "alias": "lab-web-01", "args": {}}],
}


def _prompt(digest, caps=None):
    return render_turn_prompt(
        objective="Enumerate exposed services on lab-web-01.",
        skill=load_skill("port_scan"),
        catalogue=_catalogue(caps or [SERVICE_CAP, CVE_CAP]),
        run_digest=digest,
    )


def test_walks_service_then_cve_then_stops() -> None:
    client = build_client(backend="scripted", model_id="scripted")
    step1 = client.complete(system=system_prompt(), user=_prompt({"objective_kind": "port_scan", "observations": [], "executed": []}), step=1)
    from harness.llm.prompts import parse_agent_turn

    turn1 = parse_agent_turn(step1.text)
    assert isinstance(turn1.next_action, CapabilityAction)
    assert turn1.next_action.proposal.capability == "service.enumerate"
    assert turn1.next_action.proposal.grant == "g-7f21"

    digest2 = {
        "objective_kind": "port_scan",
        "observations": [{"kind": "service"}, {"kind": "host_state"}, {"kind": "scan_meta"}],
        "executed": [{"capability": "service.enumerate", "exit_status": "completed"}],
    }
    turn2 = parse_agent_turn(client.complete(system=system_prompt(), user=_prompt(digest2), step=2).text)
    assert isinstance(turn2.next_action, CapabilityAction)
    assert turn2.next_action.proposal.capability == "vulnerability.match"

    digest3 = {
        "objective_kind": "port_scan",
        "observations": [{"kind": "service"}, {"kind": "host_state"}, {"kind": "scan_meta"}, {"kind": "vulnerability_match"}],
        "executed": [{"capability": "service.enumerate"}, {"capability": "vulnerability.match"}],
    }
    turn3 = parse_agent_turn(client.complete(system=system_prompt(), user=_prompt(digest3), step=3).text)
    assert isinstance(turn3.next_action, StopAction)


def test_identical_inputs_produce_byte_identical_turns() -> None:
    client = build_client(backend="scripted", model_id="scripted")
    digest = {"objective_kind": "port_scan", "observations": [], "executed": []}
    first = client.complete(system=system_prompt(), user=_prompt(digest), step=1)
    second = client.complete(system=system_prompt(), user=_prompt(digest), step=1)
    assert first.text == second.text


def test_never_proposes_a_capability_outside_the_catalogue() -> None:
    client = build_client(backend="scripted", model_id="scripted")
    # Only vulnerability.match is offered and it has no grant, so the planner must stop rather
    # than invent a way to satisfy the objective.
    digest = {"objective_kind": "port_scan", "observations": [], "executed": []}
    prompt = _prompt(digest, caps=[{**CVE_CAP, "grants": []}])
    from harness.llm.prompts import parse_agent_turn

    turn = parse_agent_turn(client.complete(system=system_prompt(), user=prompt, step=1).text)
    assert isinstance(turn.next_action, StopAction)


def test_missing_run_digest_block_is_a_hard_error() -> None:
    client = ScriptedModelClient(ModelMetadata(backend="scripted", model_id="x"))
    with pytest.raises(ModelClientError):
        client.complete(system="s", user="no digest here", step=1)
