"""The local-first guarantee is only real if a remote endpoint is refused by code."""

from __future__ import annotations

import pytest

from harness.errors import ConfigError, EgressViolation
from harness.llm.client import build_client, is_loopback


def test_unknown_backend_is_a_config_error_not_a_silent_fallback() -> None:
    with pytest.raises(ConfigError):
        build_client(backend="definitely-not-a-backend", model_id="whatever")


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:11434", "http://localhost:8080/v1", "http://[::1]:9000"])
def test_loopback_endpoints_are_accepted(endpoint: str) -> None:
    client = build_client(backend="ollama", model_id="llama3", endpoint=endpoint)
    assert client.metadata.is_local is True


@pytest.mark.parametrize(
    "endpoint",
    ["http://10.0.0.5:11434", "https://api.example.com/v1", "http://0.0.0.0:11434"],
)
def test_non_loopback_endpoint_is_refused_without_explicit_egress(endpoint: str) -> None:
    with pytest.raises(EgressViolation):
        build_client(backend="openai", model_id="gpt-ish", endpoint=endpoint)


def test_bind_all_is_not_loopback() -> None:
    # 0.0.0.0 means "every interface", which is the opposite of staying on this machine.
    assert is_loopback("http://0.0.0.0:11434") is False
    assert is_loopback("http://127.0.0.1:11434") is True
    assert is_loopback("unix:/run/llama.sock") is True
    assert is_loopback(None) is False


def test_egress_can_be_enabled_explicitly_and_is_recorded_as_non_local() -> None:
    client = build_client(
        backend="openai", model_id="remote", endpoint="https://api.example.com/v1", allow_remote=True
    )
    # A remote run must be distinguishable from a local one in the run manifest.
    assert client.metadata.is_local is False


def test_importing_the_llm_package_does_not_import_httpx() -> None:
    import subprocess
    import sys

    code = (
        "import sys; import harness.llm; "
        "sys.exit(1 if 'httpx' in sys.modules else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)
    assert result.returncode == 0, "importing the model layer must not open the door to networking"


def test_replay_backend_requires_a_recorded_file(tmp_path) -> None:
    with pytest.raises(ConfigError):
        build_client(backend="replay", model_id="any")


def test_reasoning_blocks_are_stripped_before_the_turn_is_parsed() -> None:
    from harness.llm.client import strip_reasoning

    assert strip_reasoning('<think>maybe {"a": 1}?</think>\n{"b": 2}') == '{"b": 2}'
    assert strip_reasoning("<THINK>x</THINK>answer") == "answer"
    # An unclosed block means the model ran out before answering: nothing usable remains.
    assert strip_reasoning("<think>still going {") == ""
    assert strip_reasoning("plain answer") == "plain answer"


def test_openai_client_sends_the_gateway_key_from_the_environment(monkeypatch) -> None:
    import httpx

    seen: dict = {}

    def fake_post(url, json, headers, timeout):  # noqa: A002 - mirrors httpx's keyword
        seen["url"], seen["headers"] = url, headers
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "<think>hmm</think>{\"ok\": true}"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setenv("HARNESS_MODEL_API_KEY", "sk-test")
    monkeypatch.setattr(httpx, "post", fake_post)
    client = build_client(
        backend="openai", model_id="qwen3:14b", endpoint="https://gateway.example/v1", allow_remote=True
    )
    response = client.complete(system="s", user="u", step=1)
    assert seen["url"] == "https://gateway.example/v1/chat/completions"
    assert seen["headers"] == {"Authorization": "Bearer sk-test"}
    assert response.text == '{"ok": true}'


def test_openai_client_sends_no_auth_header_without_a_key(monkeypatch) -> None:
    import httpx

    seen: dict = {}

    def fake_post(url, json, headers, timeout):  # noqa: A002
        seen["headers"] = headers
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "{}"}}]}, request=httpx.Request("POST", url)
        )

    monkeypatch.delenv("HARNESS_MODEL_API_KEY", raising=False)
    monkeypatch.setattr(httpx, "post", fake_post)
    build_client(backend="openai", model_id="m").complete(system="s", user="u", step=1)
    assert seen["headers"] == {}
