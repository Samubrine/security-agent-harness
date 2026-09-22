"""Settings and records the runtime now actually reads (WS-07: R2-24, R2-25, R2-29).

The round-2 audit's complaint was not that these fields were unused but that they were *declared*: a
reader takes `independent_for: [entry_point.hypothesis]` or an `inputs` block as a control that
exists, and for a whole release neither had any effect. Each test below fails if the consumer it
names is removed again; the dispositions are recorded in `docs/design/decisions.md` (D25), and the
prompt-facing half of the hypothesis contract is deferred there to WS-02.7.

The loop is the one `tests/test_integration_v11.py` builds - the real spine, assembled the way
`execute_run` assembles it. A second builder here would be a second idea of what a run is, which is
how field-by-field drift starts.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from harness.errors import ConfigError, NecessityDenied
from harness.models import CapabilityProposal, ScopeFile, ScopeNetwork, ScopeWindow
from harness.policy.grants import GrantBook, mint_from_scope
from harness.policy.scope import load_scope, sign_scope
from harness.runtime.runner import RunRequest, _require_skill_inputs, execute_run
from harness.skills.loader import load_skill
from harness.util import atomic_write_json, read_json, read_jsonl, utcnow
from test_integration_v11 import _advance_to_planning, _build_loop


def _scope_with(lab_environment, tmp_path: Path, *, filesystem: list[str], aliases: dict[str, str]) -> Path:
    """A signed scope carrying only the resources a test wants to make available."""
    now = utcnow()
    scope = ScopeFile(
        scope_id="lab-inert-settings",
        authorized_by="pytest",
        networks=[ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11"])],
        filesystem=filesystem,
        aliases=aliases,
        window=ScopeWindow(**{"from": now - timedelta(minutes=5), "to": now + timedelta(hours=1)}),
    )
    path = tmp_path / "scope.json"
    atomic_write_json(path, sign_scope(scope, lab_environment.private_key).model_dump(mode="json"))
    return path


def _log_analysis_request(lab_environment, scope_path: Path, run_id: str) -> RunRequest:
    return lab_environment.request(
        objective="Read the authentication log and report what it shows.",
        skill="log_analysis",
        scope_path=scope_path,
        run_id=run_id,
    )


def _grants(lab_environment) -> GrantBook:
    scope = load_scope(lab_environment.scope_path, public_key_path=lab_environment.public_key)
    return mint_from_scope(scope, run_id="run-inert-settings")


# ---------------------------------------------------------------------------------------------
# SkillSpec.inputs
# ---------------------------------------------------------------------------------------------


def test_a_skill_input_the_scope_cannot_supply_refuses_the_run(lab_environment, tmp_path: Path) -> None:
    """`inputs` says what a skill needs; the runtime checks it before the model is called."""
    network_only = _scope_with(
        lab_environment, tmp_path, filesystem=[], aliases={"lab-web-01": "net:10.77.0.11"}
    )

    with pytest.raises(ConfigError) as refusal:
        execute_run(_log_analysis_request(lab_environment, network_only, "run-inert-no-corpus"))

    assert "log_analysis" in str(refusal.value)
    assert "scope_fs_target" in str(refusal.value)


def test_a_skill_input_the_scope_supplies_lets_the_run_start(lab_environment, tmp_path: Path) -> None:
    """The companion: the check is about the scope, not a refusal of log analysis as such."""
    with_corpus = _scope_with(
        lab_environment,
        tmp_path,
        filesystem=["/lab/logs"],
        aliases={"lab-logs": "fs:/lab/logs"},
    )

    artifacts = execute_run(_log_analysis_request(lab_environment, with_corpus, "run-inert-corpus"))

    assert artifacts.summary.status == "completed"


def test_an_unknown_input_type_is_a_configuration_error(lab_environment) -> None:
    """A typo in a skill file must not silently disable the check the skill asked for."""
    skill = load_skill("port_scan")
    broken = skill.model_copy(
        update={"inputs": {"target": {"type": "scope_targt", "required": True}}}
    )

    with pytest.raises(ConfigError) as refusal:
        _require_skill_inputs(broken, _grants(lab_environment))

    assert "unknown type" in str(refusal.value)


# ---------------------------------------------------------------------------------------------
# Hypotheses: recorded, and citable only when they exist
# ---------------------------------------------------------------------------------------------


def _loop(lab_environment, tmp_path: Path, run_id: str):
    loop = _build_loop(lab_environment, tmp_path, run_id=run_id)
    _advance_to_planning(loop)
    return loop


def _proposal(catalogue: dict, **overrides) -> CapabilityProposal:
    offered = catalogue["capabilities"][0]
    fields = {
        "grant": offered["grants"][0]["grant"],
        "capability": offered["capability"],
        "expects": "service observations",
        "evidence_needed": "nothing yet",
    }
    fields.update(overrides)
    return CapabilityProposal(**fields)


def test_a_hypothesis_statement_is_recorded_with_an_id(lab_environment, tmp_path: Path) -> None:
    loop = _loop(lab_environment, tmp_path, "run-inert-hypothesis")
    loop._record_hypotheses(["the AJP connector on 8009 looks exposed", "   "])

    assert len(loop.state.hypotheses) == 1, "a blank statement is not a hypothesis"
    recorded = loop.state.hypotheses[0]
    assert recorded["statement"] == "the AJP connector on 8009 looks exposed"
    assert str(recorded["id"]).startswith("h-")


def test_a_proposal_can_only_cite_a_hypothesis_the_run_recorded(lab_environment, tmp_path: Path) -> None:
    """Design D5: the model may propose hypotheses only against existing ids."""
    loop = _loop(lab_environment, tmp_path, "run-inert-cite")
    catalogue = loop.build_catalogue()

    assert loop._validate(_proposal(catalogue, hypothesis_id="h-ghost"), catalogue) is False
    assert any(
        "h-ghost" in str(item.get("reason")) for item in loop.state.rejected_proposals
    ), loop.state.rejected_proposals

    loop._record_hypotheses(["a banner suggests an exposed AJP connector"])
    recorded = str(loop.state.hypotheses[0]["id"])
    assert loop._validate(_proposal(catalogue, hypothesis_id=recorded), catalogue) is True
    # The reference is optional: a call with no hypothesis behind it is still a legal call.
    assert loop._validate(_proposal(catalogue), catalogue) is True


# ---------------------------------------------------------------------------------------------
# Router, execution_id and the artifact-byte counter
# ---------------------------------------------------------------------------------------------


class _TamperedGate:
    """A gate that hands back a decision the registry cannot honour."""

    def __init__(self, decision) -> None:
        self._decision = decision

    def decide(self, **kwargs):  # noqa: ANN003 - the real gate's own keyword surface
        return self._decision


def test_an_inconsistent_decision_is_refused_before_anything_runs(lab_environment, tmp_path: Path) -> None:
    """`Router.resolve` is the execution boundary that re-checks a decision against the registry.

    A decision is a record that may have been replayed from disk or assembled by hand, so a selection
    naming a provider that does not exist has to fail loudly rather than reach a lookup error inside
    the loop - which is what happens when the router is constructed and never invoked (R2-25).
    """
    loop = _loop(lab_environment, tmp_path, "run-inert-router")
    catalogue = loop.build_catalogue()
    proposal = _proposal(catalogue)
    real = loop.gate.decide(
        capability=proposal.capability,
        evidence_needed=proposal.evidence_needed,
        expects=proposal.expects,
        existing_observations=[],
    )
    assert loop._validate(proposal, catalogue) is True
    loop.gate = _TamperedGate(real.model_copy(update={"selected": ["native:not-registered"]}))

    with pytest.raises(NecessityDenied) as refusal:
        loop._pursue(proposal, catalogue)

    assert "native:not-registered" in str(refusal.value)


def test_a_policy_decision_names_the_execution_it_authorised(lab_environment) -> None:
    """The reverse link, so the run audit compares two ids instead of two Nones."""
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-inert-execution-link",
        )
    )
    decisions = read_jsonl(artifacts.run_dir / "policy-decisions.jsonl")
    executions = read_json(artifacts.run_dir / "executions.json")
    assert executions, "a run that executed nothing proves nothing here"

    by_id = {row["id"]: row for row in executions}
    linked = [row for row in decisions if row["execution_id"]]
    assert linked, "no policy decision names the execution it authorised"
    for decision in linked:
        assert by_id[decision["execution_id"]]["policy_decision"] == decision["id"]


def test_the_recorded_budget_snapshot_states_the_bytes_the_run_used(lab_environment) -> None:
    """A snapshot that always says zero bytes is a number a report renders as fact (R2-24)."""
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-inert-bytes",
        )
    )
    decisions = read_jsonl(artifacts.run_dir / "provider-decisions.jsonl")
    recorded = [row["budget_snapshot"].get("artifact_bytes") for row in decisions]

    assert recorded, "the run recorded no decisions"
    assert any(value for value in recorded), recorded
