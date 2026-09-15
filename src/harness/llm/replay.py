"""Offline model client backed by a recorded run.

Replay is not a convenience feature: design decision D24 makes it the mechanism that lets a
grader re-derive a run's structured state without re-touching the network or the target. It is
also why a run records its prompts verbatim — a replay that cannot match a request is a hard
error rather than a silent divergence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from harness.errors import ReplayError
from harness.llm.client import ModelResponse
from harness.models import ModelMetadata, ReplayRecord
from harness.util import read_jsonl, sha256_text


def request_digest(system: str, user: str) -> str:
    """Identity of a model request. Replay matches on this before falling back to step order."""
    return sha256_text(system + "\x00" + user)


class ReplayModelClient:
    def __init__(self, records: Sequence[ReplayRecord]) -> None:
        self._records = [r for r in records if r.kind == "model"]
        if not self._records:
            raise ReplayError("the recorded replay file contains no model responses")
        self._used: set[int] = set()
        self.metadata = ModelMetadata(
            backend="replay",
            model_id="replayed-local-model",
            is_local=True,
            context_window=8192,
        )

    @classmethod
    def from_path(cls, path: Path) -> ReplayModelClient:
        rows = read_jsonl(Path(path))
        records = [ReplayRecord.model_validate(row) for row in rows if row.get("kind") == "model"]
        return cls(records)

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse:
        want = request_digest(system, user)
        for idx, record in enumerate(self._records):
            if idx in self._used:
                continue
            if record.request_sha256 == want:
                self._used.add(idx)
                return self._to_response(record)
        for idx, record in enumerate(self._records):
            if idx in self._used:
                continue
            if record.step == step:
                self._used.add(idx)
                return self._to_response(record)
        raise ReplayError(
            f"no recorded model response for step {step} (request digest {want[:12]}); "
            "the prompt changed since the run was recorded"
        )

    @staticmethod
    def _to_response(record: ReplayRecord) -> ModelResponse:
        payload: dict[str, Any] = record.response or {}
        return ModelResponse(
            text=str(payload.get("text", "")),
            input_tokens=int(payload.get("input_tokens", 0)),
            output_tokens=int(payload.get("output_tokens", 0)),
            raw=dict(payload.get("raw") or {}),
        )
