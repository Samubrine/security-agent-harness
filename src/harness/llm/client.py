"""Model clients: one internal contract, several local backends.

Design 01 section 3 requires the runtime to depend only on ``ModelClient``. Anything that can
speak one of the supported local APIs plugs in without the investigation loop changing.

Two things are enforced here rather than documented as policy:

* an endpoint that is not loopback is refused unless remote egress was explicitly enabled, and
* the transport library is imported lazily so that importing the harness never opens a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from harness.errors import ConfigError, EgressViolation, ModelClientError
from harness.models import ModelMetadata
from harness.util import estimate_tokens

#: Hosts that are unambiguously this machine. A bind-all address is deliberately absent:
#: 0.0.0.0 means "every interface", which is the opposite of staying local.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1"})


@dataclass
class ModelResponse:
    text: str
    input_tokens: int
    output_tokens: int
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ModelClient(Protocol):
    metadata: ModelMetadata

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse: ...


def is_loopback(endpoint: str | None) -> bool:
    """True only for a same-machine endpoint. A Unix socket path counts as local."""
    if not endpoint:
        return False
    if endpoint.startswith("unix:") or endpoint.startswith("/"):
        return True
    parsed = urlparse(endpoint if "://" in endpoint else f"http://{endpoint}")
    return (parsed.hostname or "").lower() in LOOPBACK_HOSTS


def enforce_local(endpoint: str | None, *, allow_remote: bool, backend: str) -> None:
    """Raise unless the endpoint is local or egress was explicitly granted.

    This is the single choke point for the local-first claim: no adapter may skip it, and it
    is called at construction *and* at request time so a mutated endpoint cannot slip through.
    """
    if is_loopback(endpoint):
        return
    if allow_remote:
        return
    raise EgressViolation(
        f"backend {backend!r} endpoint {endpoint!r} is not loopback; "
        "enable remote egress explicitly before sending investigation context off-machine"
    )


def _heuristic_usage(system: str, user: str, text: str) -> tuple[int, int]:
    return estimate_tokens(system + user), estimate_tokens(text)


class OpenAICompatClient:
    """Any OpenAI-compatible local server (vLLM, llama.cpp server, LM Studio, Ollama's /v1)."""

    def __init__(
        self,
        *,
        base_url: str,
        model_id: str,
        temperature: float = 0.0,
        seed: int | None = 0,
        context_window: int = 8192,
        timeout_s: float = 120.0,
        allow_remote: bool = False,
        tokenizer_id: str = "heuristic-4chars",
    ) -> None:
        enforce_local(base_url, allow_remote=allow_remote, backend="openai")
        self.base_url = base_url.rstrip("/")
        self._allow_remote = allow_remote
        self.metadata = ModelMetadata(
            backend="openai",
            model_id=model_id,
            context_window=context_window,
            tokenizer_id=tokenizer_id,
            temperature=temperature,
            seed=seed,
            is_local=is_loopback(base_url),
        )
        self.timeout_s = timeout_s
        self.seed = seed

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse:
        import httpx

        enforce_local(self.base_url, allow_remote=self._allow_remote, backend="openai")
        payload: dict[str, Any] = {
            "model": self.metadata.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.metadata.temperature,
            "stream": False,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        try:
            resp = httpx.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout_s)
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:  # noqa: BLE001 - transport failures are all the same to the caller
            raise ModelClientError(f"local model request failed: {exc}") from exc

        try:
            text = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelClientError(f"unexpected model response shape: {body!r}") from exc
        usage = body.get("usage") or {}
        in_toks, out_toks = _heuristic_usage(system, user, text)
        return ModelResponse(
            text=text,
            input_tokens=int(usage.get("prompt_tokens", in_toks)),
            output_tokens=int(usage.get("completion_tokens", out_toks)),
            raw=body,
        )


class OllamaClient:
    """Ollama's native ``/api/chat``. Still a local endpoint, still egress-checked."""

    def __init__(
        self,
        *,
        base_url: str,
        model_id: str,
        temperature: float = 0.0,
        seed: int | None = 0,
        context_window: int = 8192,
        timeout_s: float = 120.0,
        allow_remote: bool = False,
        tokenizer_id: str = "heuristic-4chars",
    ) -> None:
        enforce_local(base_url, allow_remote=allow_remote, backend="ollama")
        self.base_url = base_url.rstrip("/")
        self._allow_remote = allow_remote
        self.metadata = ModelMetadata(
            backend="ollama",
            model_id=model_id,
            context_window=context_window,
            tokenizer_id=tokenizer_id,
            temperature=temperature,
            seed=seed,
            is_local=is_loopback(base_url),
        )
        self.timeout_s = timeout_s
        self.seed = seed

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse:
        import httpx

        enforce_local(self.base_url, allow_remote=self._allow_remote, backend="ollama")
        options: dict[str, Any] = {"temperature": self.metadata.temperature}
        if self.seed is not None:
            options["seed"] = self.seed
        payload = {
            "model": self.metadata.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
            "options": options,
        }
        try:
            resp = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout_s)
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise ModelClientError(f"local ollama request failed: {exc}") from exc

        try:
            text = body["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ModelClientError(f"unexpected ollama response shape: {body!r}") from exc
        in_toks = int(body.get("prompt_eval_count") or _heuristic_usage(system, user, text)[0])
        out_toks = int(body.get("eval_count") or _heuristic_usage(system, user, text)[1])
        return ModelResponse(text=text, input_tokens=in_toks, output_tokens=out_toks, raw=body)


def build_client(
    *,
    backend: str,
    model_id: str,
    endpoint: str | None = None,
    temperature: float = 0.0,
    seed: int | None = 0,
    context_window: int = 8192,
    script: Path | None = None,
    allow_remote: bool = False,
    tokenizer_id: str = "heuristic-4chars",
) -> ModelClient:
    """Construct a client. Unknown backends are a configuration error, not a fallback.

    Silently falling back to a different backend would make the run manifest a lie, so an
    unrecognised name stops here.
    """
    from harness.llm.replay import ReplayModelClient
    from harness.llm.scripted import ScriptedModelClient

    name = (backend or "").strip().lower()
    if name in {"scripted", "fake", "deterministic"}:
        return ScriptedModelClient(
            ModelMetadata(
                backend="scripted",
                model_id=model_id or "scripted-planner",
                context_window=context_window,
                tokenizer_id=tokenizer_id,
                is_local=True,
            )
        )
    if name == "replay":
        if script is None:
            raise ConfigError("the replay backend needs the path to a recorded replay file")
        return ReplayModelClient.from_path(script)
    if name == "ollama":
        return OllamaClient(
            base_url=endpoint or "http://127.0.0.1:11434",
            model_id=model_id,
            temperature=temperature,
            seed=seed,
            context_window=context_window,
            allow_remote=allow_remote,
            tokenizer_id=tokenizer_id,
        )
    if name in {"openai", "openai-compatible", "vllm", "llamacpp", "llama.cpp"}:
        return OpenAICompatClient(
            base_url=endpoint or "http://127.0.0.1:8080/v1",
            model_id=model_id,
            temperature=temperature,
            seed=seed,
            context_window=context_window,
            allow_remote=allow_remote,
            tokenizer_id=tokenizer_id,
        )
    raise ConfigError(
        f"unknown model backend {backend!r}; expected one of: scripted, replay, ollama, openai"
    )
