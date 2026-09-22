"""How a run records why it ended (WS-04, R2-04).

`RunSummary.status` was the constant ``"completed"`` written next to a stop reason that could say
anything, so a budget-exhausted run and a run whose parser exploded were indistinguishable from a
finished investigation: in ``run.json``, in the ``RUN_ENDED`` event, and in ``report.json``, which
reads the status from that event. The consequence was measured rather than theoretical -
``memory/curator.py`` refuses to certify the conclusions of a failed run, read that status, and
promoted them anyway.

Each terminal condition below is forced through the real `execute_run`, and the tests check the
three places the status is written plus the curation decision that turns on it. The clean run is the
control: a derivation that reported a failure for everything would satisfy every other test here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harness.errors import ParserError
from harness.models import Budget, ProviderSpec
from harness.providers.base import ProviderResult
from harness.providers.registry import ProviderRegistry
from harness.runtime.analysers import CveMatcherProvider
from harness.runtime.runner import execute_run
from harness.util import read_json, read_jsonl

OBJECTIVE = "Enumerate exposed services on lab-web-01."


def _run(env, run_id: str, **overrides):
    return execute_run(
        env.request(
            objective=OBJECTIVE,
            skill="port_scan",
            target_alias="lab-web-01",
            run_id=run_id,
            **overrides,
        )
    )


def _statuses(run_dir: Path) -> tuple[str, str]:
    """The status as `run.json` records it and as the `RUN_ENDED` event records it.

    Both are written from the same summary, and both are read by somebody: `run.json` by an
    operator or a downstream tool, `RUN_ENDED` by the report builder and the curator.
    """
    manifest = read_json(run_dir / "run.json")
    ended = [row for row in read_jsonl(run_dir / "events.jsonl") if row.get("type") == "RUN_ENDED"]
    assert ended, "the run recorded no RUN_ENDED event"
    return str(manifest["status"]), str(ended[-1]["data"]["status"])


def _curation_rationale(run_dir: Path) -> str:
    """What memory curation recorded about this run, read from the run's own event trail.

    The curator refuses to certify the conclusions of a failed run, and says so in the rationale;
    this is the end-to-end proof that it saw the status this workstream derives.
    """
    proposals = [
        row
        for row in read_jsonl(run_dir / "events.jsonl")
        if row.get("type") == "MEMORY_UPDATE_PROPOSED"
    ]
    assert proposals, "the run recorded no curation proposal, so the curator's reading is unknown"
    return str(proposals[-1]["data"]["rationale"])


@dataclass
class _IntrusiveProvider:
    """A provider the policy will not run unattended: HIGH risk means "intrusive" (design 03)."""

    spec: ProviderSpec

    def invoke(self, request):  # pragma: no cover - the policy refuses before this is reached
        raise AssertionError("a refused provider must not be invoked")


def _intrusive_provider() -> _IntrusiveProvider:
    return _IntrusiveProvider(
        ProviderSpec(
            id="native:intrusive",
            kind="native",
            capabilities=["service.enumerate"],
            output_media_type="application/nmap+xml",
            parser="nmap_xml",
            risk="HIGH",
            trust_class="local_tool",
            requires_network_egress=False,
        )
    )


def _intrusive_provider(capability: str) -> _IntrusiveProvider:
    media_type = "text/x-authlog" if capability.startswith("log.") else "application/nmap+xml"
    parser = "auth_log" if capability.startswith("log.") else "nmap_xml"
    return _IntrusiveProvider(
        ProviderSpec(
            id="native:intrusive",
            kind="native",
            capabilities=[capability],
            output_media_type=media_type,
            parser=parser,
            risk="HIGH",
            trust_class="local_tool",
            requires_network_egress=False,
        )
    )


def _refused_run(env, monkeypatch, label: str, *, skill: str, capability: str, objective: str):
    """A run whose only capability is served by a provider the policy will not run unattended.

    The registry is narrowed so the refusal is the only thing that can happen: the provider is
    never invoked, and once the capability is denied the catalogue is empty and the loop stops.

    The real cve matcher stays registered even though this skill does not use it, because
    `execute_run` wires it after building the registry -- a stand-in registry would be a
    stand-in for the spine, which is the thing under test.
    """
    from harness.runtime import runner as runner_module

    provider = _intrusive_provider(capability)

    def only_this_provider(request, snapshot, observations, run_id):  # noqa: ARG001 - the real builder's signature
        return ProviderRegistry(
            [provider, CveMatcherProvider(snapshot=snapshot, observations=observations)]
        )

    monkeypatch.setattr(runner_module, "_build_registry", only_this_provider)
    return execute_run(
        env.request(objective=objective, skill=skill, target_alias="lab-logs", run_id=label)
    )


# ---------------------------------------------------------------------------------------------
# The status the run reports
# ---------------------------------------------------------------------------------------------


def test_a_clean_run_is_completed(lab_environment) -> None:
    """The control for everything below: the derivation does not invent a failure."""
    artifacts = _run(lab_environment, "run-ws04-clean", enable_memory_curation=True)

    assert artifacts.summary.status == "completed"
    assert _statuses(artifacts.run_dir) == ("completed", "completed")
    assert read_json(artifacts.report_json)["status"] == "completed"
    assert "completed" in _curation_rationale(artifacts.run_dir)


def test_a_budget_exhausted_run_is_not_reported_as_completed(lab_environment, monkeypatch) -> None:
    """The run that could be curated into durable memory while saying it had completed."""
    from harness.runtime import runner as runner_module

    monkeypatch.setattr(runner_module, "_budgets_for", lambda skill: Budget(max_steps=1))
    artifacts = _run(lab_environment, "run-ws04-budget", enable_memory_curation=True)

    assert artifacts.summary.status == "budget_exhausted"
    assert _statuses(artifacts.run_dir) == ("budget_exhausted", "budget_exhausted")
    assert read_json(artifacts.report_json)["status"] == "budget_exhausted"
    exhausted = [
        row
        for row in read_jsonl(artifacts.run_dir / "events.jsonl")
        if row.get("type") == "RUN_BUDGET_EXHAUSTED"
    ]
    assert exhausted and "max_steps" in str(exhausted[-1]["data"]["reason"])
    assert "ended in failure" in _curation_rationale(artifacts.run_dir)


def test_a_harness_error_ends_the_run_as_failed(lab_environment, monkeypatch) -> None:
    """An unrecoverable error is not a completed investigation, whatever the stop text says."""
    from harness.runtime import runner as runner_module

    def exploding_parsers(parsers) -> None:
        def explode(*args, **kwargs):
            raise ParserError("this parser refuses the payload")

        parsers.register("application/nmap+xml", "exploding_nmap", explode)

    monkeypatch.setattr(runner_module, "_register_parsers", exploding_parsers)
    artifacts = _run(lab_environment, "run-ws04-error", enable_memory_curation=True)

    assert artifacts.summary.status == "failed"
    assert _statuses(artifacts.run_dir) == ("failed", "failed")
    assert read_json(artifacts.report_json)["status"] == "failed"
    failures = [
        row
        for row in read_jsonl(artifacts.run_dir / "events.jsonl")
        if row.get("type") == "RUN_FAILED"
    ]
    assert failures and failures[-1]["data"]["type"] == "ParserError"
    assert "ended in failure" in _curation_rationale(artifacts.run_dir)


def test_a_refused_run_is_denied_rather_than_completed(lab_environment, monkeypatch) -> None:
    """Nothing executed because authority refused every call, so the run was denied, not finished.

    This is also the case that used to end with the *wrong* reason: the catalogue empties because
    the capability was denied, and the loop used to report that no capability "has both a
    registered provider and a grant" -- which was not true, and is the failure mode the first
    audit flagged in prose (R1-10).
    """
    artifacts = _refused_run(
        lab_environment,
        monkeypatch,
        "run-ws04-denied",
        skill="log_analysis",
        capability="log.read",
        objective="Read the authentication log and report what it shows.",
    )

    assert artifacts.summary.provider_calls == 0, "the refusal must happen before any call"
    assert artifacts.summary.status == "denied"
    assert _statuses(artifacts.run_dir) == ("denied", "denied")
    assert "log.read was denied" in (artifacts.stop_reason or "")
    verdicts = [
        row
        for row in read_jsonl(artifacts.run_dir / "policy-decisions.jsonl")
        if row["verdict"] == "ask"
    ]
    assert verdicts, "the run must have been routed to approval, or 'denied' means nothing here"


def test_a_dry_run_is_completed_rather_than_denied(lab_environment) -> None:
    """A rehearsal's proposals are marked denied by the harness itself, not by authority.

    Rendering the plan without executing it is what a dry run is for, so it completed its job;
    counting its own markers as a refusal would report every dry run as denied.
    """
    artifacts = _run(lab_environment, "run-ws04-dry", dry_run=True)

    assert artifacts.summary.provider_calls == 0
    rejections = [
        row
        for row in read_jsonl(artifacts.run_dir / "events.jsonl")
        if row.get("type") == "PROVIDER_REJECTED"
    ]
    assert rejections, "the dry run recorded no rejection, so this test proves nothing"
    assert artifacts.summary.status == "completed"


def test_the_summary_counts_match_the_records(lab_environment) -> None:
    """The counters in the summary are read from state, not invented alongside the status."""
    artifacts = _run(lab_environment, "run-ws04-counters")

    assert artifacts.summary.provider_calls == len(
        read_jsonl(artifacts.run_dir / "executions.jsonl")
    )
    assert artifacts.summary.findings == len(read_json(artifacts.run_dir / "findings.json"))
    assert artifacts.summary.provider_calls > 0, "a run that executed nothing proves nothing here"


# ---------------------------------------------------------------------------------------------
# An untrusted producer cannot choose when the run ends (R2-18, R2-19)
# ---------------------------------------------------------------------------------------------


def _unparsable_provider(trust_class: str):
    """A provider whose media type no parser is registered for.

    That is the shortest path to a `ParserError` from a real call: a remote peer declares output the
    harness has no reader for. Whether the run survives it depends on who produced the bytes, which is
    the distinction these two tests pin.
    """
    from harness.providers.base import ProviderResult

    @dataclass
    class _Provider:
        spec: ProviderSpec

        def invoke(self, request):
            return ProviderResult(
                provider=self.spec.id,
                capability=request.capability,
                exit_status="completed",
                stdout=b"nothing here declares a format anyone can read",
                media_type="application/x-nothing-registers-this",
            )

    return _Provider(
        ProviderSpec(
            id="mcp:loose-server",
            kind="mcp" if trust_class != "local_tool" else "native",
            capabilities=["log.read"],
            output_media_type="application/x-nothing-registers-this",
            parser="nothing",
            risk="LOW",
            trust_class=trust_class,
            requires_network_egress=False,
        )
    )


def _run_with_unparsable_output(env, monkeypatch, label: str, trust_class: str):
    from harness.runtime import runner as runner_module

    provider = _unparsable_provider(trust_class)

    def only_this_provider(request, snapshot, observations, run_id):  # noqa: ARG001
        return ProviderRegistry(
            [provider, CveMatcherProvider(snapshot=snapshot, observations=observations)]
        )

    monkeypatch.setattr(runner_module, "_build_registry", only_this_provider)
    return execute_run(
        env.request(
            objective="Read the authentication log and report what it shows.",
            skill="log_analysis",
            target_alias="lab-logs",
            run_id=label,
        )
    )


def test_a_remote_payload_the_harness_cannot_read_is_a_recorded_failure(lab_environment, monkeypatch) -> None:
    """A server sending a format nothing parses must not be able to end the investigation.

    The run ends on the *step budget* rather than on a traceback: the scripted planner keeps asking for
    the same capability, and the budget is what stops it asking - which is the run's own limit doing its
    job. What matters here is that the unreadable payload produced a recorded failure, and that the
    provider is not asked again.
    """
    artifacts = _run_with_unparsable_output(lab_environment, monkeypatch, "run-ws05-unparsable", "local_mcp")

    assert artifacts.summary.status in {"completed", "budget_exhausted"}, artifacts.stop_reason
    assert "Traceback" not in (artifacts.stop_reason or "")
    gaps = read_jsonl(artifacts.run_dir / "gaps.jsonl")
    assert any(gap["kind"] == "provider_failure" for gap in gaps), gaps
    failed = [
        row for row in read_json(artifacts.run_dir / "executions.json") if row["provider"] == "mcp:loose-server"
    ]
    assert failed and failed[0]["exit_status"] == "failed"
    assert any(
        row["type"] == "PROVIDER_FAILED" and row["data"]["provider"] == "mcp:loose-server"
        for row in read_jsonl(artifacts.run_dir / "events.jsonl")
    )


def test_a_native_payload_the_harness_cannot_read_still_aborts(lab_environment, monkeypatch) -> None:
    """The companion: bytes from a tool the harness runs itself are its own bug, and it is fixed."""
    artifacts = _run_with_unparsable_output(lab_environment, monkeypatch, "run-ws05-native-unparsable", "local_tool")

    assert artifacts.summary.status == "failed"
    assert "harness error" in (artifacts.stop_reason or "")
