"""Tests for Work Package 1: Model BYOK, Authentication, and Prompt Egress Redaction."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from harness.cli import app
from harness.context.builder import PromptBundle
from harness.errors import EgressViolation
from harness.llm.client import (
    ModelResponse,
    OpenAICompatClient,
    build_client,
)
from harness.models import Budget, MemoryDigests, ModelMetadata, RunConfig
from harness.runtime.loop import InvestigationLoop
from harness.runtime.replay import Replayer, ReplayWriter
from harness.runtime.runner import RunRequest, execute_run
from harness.tokens import BudgetGuard, TokenLedger
from harness.util import read_jsonl, sha256_text, utcnow


# ==============================================================================
# Model BYOK & Authentication Tests
# ==============================================================================


def test_openai_compat_client_explicit_api_key() -> None:
    client = OpenAICompatClient(
        base_url="http://127.0.0.1:8080/v1",
        model_id="test-model",
        api_key="sk-explicit-test-key",
    )
    assert client.api_key == "sk-explicit-test-key"

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    fake_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=fake_response) as mock_post:
        resp = client.complete(system="sys", user="usr", step=1)
        assert resp.text == "ok"
        mock_post.assert_called_once()
        headers = mock_post.call_args.kwargs.get("headers")
        assert headers is not None
        assert headers.get("Authorization") == "Bearer sk-explicit-test-key"


@pytest.mark.parametrize(
    ("env_var", "env_val"),
    [
        ("HARNESS_API_KEY", "key-harness"),
        ("OPENAI_API_KEY", "key-openai"),
        ("DEEPSEEK_API_KEY", "key-deepseek"),
        ("ANTHROPIC_API_KEY", "key-anthropic"),
        ("OPENROUTER_API_KEY", "key-openrouter"),
        ("GROQ_API_KEY", "key-groq"),
    ],
)
def test_openai_compat_client_env_fallbacks(monkeypatch: pytest.MonkeyPatch, env_var: str, env_val: str) -> None:
    for var in (
        "HARNESS_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv(env_var, env_val)
    client = OpenAICompatClient(
        base_url="http://127.0.0.1:8080/v1",
        model_id="test-model",
    )
    assert client.api_key == env_val

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "choices": [{"message": {"content": "response"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    fake_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=fake_response) as mock_post:
        client.complete(system="sys", user="usr", step=1)
        headers = mock_post.call_args.kwargs.get("headers")
        assert headers.get("Authorization") == f"Bearer {env_val}"


def test_openai_compat_client_env_fallback_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "HARNESS_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("OPENAI_API_KEY", "lower-prio")
    monkeypatch.setenv("HARNESS_API_KEY", "higher-prio")

    client = OpenAICompatClient(
        base_url="http://127.0.0.1:8080/v1",
        model_id="test-model",
    )
    assert client.api_key == "higher-prio"

    client_explicit = OpenAICompatClient(
        base_url="http://127.0.0.1:8080/v1",
        model_id="test-model",
        api_key="override-key",
    )
    assert client_explicit.api_key == "override-key"


def test_openai_compat_client_no_api_key_no_header(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "HARNESS_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    client = OpenAICompatClient(
        base_url="http://127.0.0.1:8080/v1",
        model_id="test-model",
    )
    assert client.api_key is None

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "choices": [{"message": {"content": "hello"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    fake_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=fake_response) as mock_post:
        client.complete(system="sys", user="usr", step=1)
        headers = mock_post.call_args.kwargs.get("headers")
        assert "Authorization" not in (headers or {})


def test_build_client_backend_aliases_defaults() -> None:
    ds_client = build_client(
        backend="deepseek",
        model_id="deepseek-chat",
        allow_remote=True,
        api_key="sk-ds",
    )
    assert isinstance(ds_client, OpenAICompatClient)
    assert ds_client.base_url == "https://api.deepseek.com/v1"
    assert ds_client.api_key == "sk-ds"
    assert ds_client.metadata.backend == "deepseek"
    assert ds_client.metadata.is_local is False

    or_client = build_client(
        backend="openrouter",
        model_id="qwen/qwen-2.5-72b-instruct",
        allow_remote=True,
        api_key="sk-or",
    )
    assert isinstance(or_client, OpenAICompatClient)
    assert or_client.base_url == "https://openrouter.ai/api/v1"
    assert or_client.api_key == "sk-or"
    assert or_client.metadata.backend == "openrouter"
    assert or_client.metadata.is_local is False

    gr_client = build_client(
        backend="groq",
        model_id="llama3-70b-8192",
        allow_remote=True,
        api_key="sk-gr",
    )
    assert isinstance(gr_client, OpenAICompatClient)
    assert gr_client.base_url == "https://api.groq.com/openai/v1"
    assert gr_client.api_key == "sk-gr"
    assert gr_client.metadata.backend == "groq"
    assert gr_client.metadata.is_local is False


def test_build_client_backend_aliases_endpoint_override() -> None:
    client = build_client(
        backend="deepseek",
        model_id="deepseek-chat",
        endpoint="https://custom-proxy.internal/v1",
        allow_remote=True,
    )
    assert isinstance(client, OpenAICompatClient)
    assert client.base_url == "https://custom-proxy.internal/v1"


def test_build_client_backend_aliases_enforce_local() -> None:
    with pytest.raises(EgressViolation):
        build_client(backend="deepseek", model_id="deepseek-chat", allow_remote=False)

    with pytest.raises(EgressViolation):
        build_client(backend="openrouter", model_id="some-model", allow_remote=False)

    with pytest.raises(EgressViolation):
        build_client(backend="groq", model_id="some-model", allow_remote=False)


def test_run_request_and_cli_api_key(lab_environment) -> None:
    req = lab_environment.request(
        objective="Investigate",
        skill="port_scan",
        run_id="run-byok-test",
        api_key="cli-api-key-12345",
    )
    assert req.api_key == "cli-api-key-12345"

    runner = CliRunner()
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--api-key" in result.output


# ==============================================================================
# Prompt Egress Redaction Tests
# ==============================================================================


class _RecordingMockModel:
    def __init__(self, is_local: bool = True) -> None:
        self.metadata = ModelMetadata(
            backend="mock",
            model_id="mock-model",
            is_local=is_local,
            context_window=8192,
        )
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse:
        self.calls.append({"system": system, "user": user, "step": step})
        content = json.dumps({
            "plan": [],
            "hypotheses": [],
            "next_action": {"kind": "stop", "reason": "test finished"},
        })
        return ModelResponse(text=content, input_tokens=10, output_tokens=10)


def _build_test_loop(
    tmp_path: Path,
    *,
    enable_remote_egress: bool,
    model: Any,
) -> InvestigationLoop:
    from harness.artifacts import ArtifactStore, ProvenanceLog
    from harness.events import EventLog
    from harness.parsers.registry import ParserRegistry
    from harness.policy.engine import AutoDenyGate, PolicyEngine
    from harness.policy.grants import GrantBook
    from harness.providers.necessity import NecessityGate
    from harness.providers.registry import ProviderRegistry

    run_dir = tmp_path / "test-loop-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = "run-loop-test"

    budgets = Budget()
    config = RunConfig(
        run_id=run_id,
        objective="Test investigation loop",
        skill="port_scan",
        scope_id="scope-1",
        scope_sha256="abc123",
        model=model.metadata,
        budgets=budgets,
        memory=MemoryDigests(baseline_sha256="b", active_sha256="a"),
        harness_version="test",
        created_at=utcnow(),
        enable_remote_egress=enable_remote_egress,
    )

    context = MagicMock()
    context.skill.name = "port_scan"
    context.skill.capabilities = []
    context.baseline_text = "baseline"
    context.active_text = "active"
    context.retrieved = []
    context.grants.grants = []

    registry = ProviderRegistry([])
    parsers = ParserRegistry()

    return InvestigationLoop(
        config=config,
        context=context,
        model=model,
        registry=registry,
        gate=NecessityGate(registry, budgets, skill=context.skill),
        policy=PolicyEngine(GrantBook([])),
        approvals=AutoDenyGate(),
        store=ArtifactStore(run_dir, run_id, max_bytes=budgets.max_artifact_bytes),
        events=EventLog(run_dir / "events.jsonl", run_id),
        provenance=ProvenanceLog(run_dir / "provenance.jsonl"),
        ledger=TokenLedger(run_dir / "trace.jsonl", model.metadata),
        budgets=BudgetGuard(budgets),
        parsers=parsers,
        replay=ReplayWriter(run_dir / "replay.jsonl"),
        rules=None,
        snapshot=MagicMock(),
        correlator=MagicMock(),
    )


def test_prompt_egress_redaction_fires_when_remote_egress_enabled(tmp_path: Path) -> None:
    model = _RecordingMockModel(is_local=True)
    loop = _build_test_loop(tmp_path, enable_remote_egress=True, model=model)

    sensitive_system = "Instructions citing MEMORY.md and run-abc1234."
    sensitive_user = (
        "Found sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
        "referencing mem-fedcba98 at bytes 10-250."
    )
    bundle = PromptBundle(
        system=sensitive_system,
        user=sensitive_user,
        tiers={"C0": 10, "C1": 10, "C2": 10, "C3": 10, "C4": 10},
    )

    outcome = loop._ask_model(bundle)
    assert outcome is not None
    assert outcome["stop"] is True

    assert len(model.calls) == 1
    call = model.calls[0]
    assert "[redacted:memory_section]" in call["system"]
    assert "[redacted:run_identifier]" in call["system"]
    assert "[redacted:artifact_digest]" in call["user"]
    assert "[redacted:memory_reference]" in call["user"]
    assert "[redacted:evidence_span]" in call["user"]
    assert "sha256:0123456789" not in call["user"]
    assert "MEMORY.md" not in call["system"]

    events = loop.events.records()
    redact_events = [e for e in events if e.type == "PROMPT_EGRESS_REDACTED"]
    assert len(redact_events) == 1
    event_data = redact_events[0].data
    assert event_data["step"] == loop.state.step
    assert sorted(event_data["classes"]) == [
        "artifact_digest",
        "evidence_span",
        "memory_reference",
        "memory_section",
        "run_identifier",
    ]
    assert event_data["count"] == 5

    replay_records = read_jsonl(loop.replay.path)
    model_replays = [r for r in replay_records if r.get("kind") == "model"]
    assert len(model_replays) == 1
    rec = model_replays[0]
    expected_request = call["system"] + "\x00" + call["user"]
    assert rec["request_text"] == expected_request
    assert rec["request_sha256"] == sha256_text(expected_request)


def test_prompt_egress_redaction_fires_when_model_is_not_local(tmp_path: Path) -> None:
    model = _RecordingMockModel(is_local=False)
    loop = _build_test_loop(tmp_path, enable_remote_egress=False, model=model)

    bundle = PromptBundle(
        system="System prompt with MEMORY.md",
        user="User prompt with mem-01234567",
        tiers={"C0": 5, "C1": 5},
    )

    loop._ask_model(bundle)
    call = model.calls[0]
    assert "[redacted:memory_section]" in call["system"]
    assert "[redacted:memory_reference]" in call["user"]

    events = loop.events.records()
    redact_events = [e for e in events if e.type == "PROMPT_EGRESS_REDACTED"]
    assert len(redact_events) == 1
    assert redact_events[0].data["count"] == 2


def test_prompt_egress_redaction_disabled_when_local(tmp_path: Path) -> None:
    model = _RecordingMockModel(is_local=True)
    loop = _build_test_loop(tmp_path, enable_remote_egress=False, model=model)

    raw_sys = "Instructions citing MEMORY.md and run-abc."
    raw_usr = "Found mem-01234567."
    bundle = PromptBundle(system=raw_sys, user=raw_usr, tiers={"C0": 5, "C1": 5})

    loop._ask_model(bundle)
    call = model.calls[0]
    assert call["system"] == raw_sys
    assert call["user"] == raw_usr

    events = loop.events.records()
    redact_events = [e for e in events if e.type == "PROMPT_EGRESS_REDACTED"]
    assert len(redact_events) == 0


def test_prompt_egress_redaction_no_event_if_count_zero(tmp_path: Path) -> None:
    model = _RecordingMockModel(is_local=True)
    loop = _build_test_loop(tmp_path, enable_remote_egress=True, model=model)

    bundle = PromptBundle(
        system="Completely safe instructions.",
        user="Enumerate ports on target web-01.",
        tiers={"C0": 5, "C1": 5},
    )

    loop._ask_model(bundle)
    events = loop.events.records()
    redact_events = [e for e in events if e.type == "PROMPT_EGRESS_REDACTED"]
    assert len(redact_events) == 0


def test_end_to_end_replay_consistency_with_egress_redaction(lab_environment) -> None:
    req = lab_environment.request(
        objective="Enumerate exposed services on lab-web-01 and identify version-level weaknesses.",
        skill="port_scan",
        run_id="run-e2e-egress-replay",
        allow_remote=True,
    )
    artifacts = execute_run(req)
    assert artifacts.summary.status == "completed"

    events = read_jsonl(artifacts.run_dir / "events.jsonl")
    egress_events = [e for e in events if e.get("type") == "PROMPT_EGRESS_REDACTED"]
    assert len(egress_events) >= 1
    for ev in egress_events:
        assert ev["data"]["count"] > 0
        assert len(ev["data"]["classes"]) > 0

    replayer = Replayer(artifacts.run_dir)
    assert replayer.verify() is True
    assert len(replayer.problems) == 0
