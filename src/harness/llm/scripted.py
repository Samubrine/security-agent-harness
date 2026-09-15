"""A deterministic stand-in for the local model.

This is not a stub that returns canned text. It is a *policy* that reads the same rendered
prompt a real model would read, and proposes the same kind of typed capability need. It exists
because three things in this project need a model that behaves identically every time:

* the integration tests, which assert that a run reproduces itself;
* the evaluation harness, which must be able to re-run a scenario; and
* any machine without a local inference server, which is the case for CI.

It deliberately reads the machine-readable block of the prompt rather than guessing from prose,
so that the harness's real prompt contract is exercised by the tests that use it.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence

from harness.errors import ModelClientError
from harness.llm.client import ModelResponse
from harness.models import (
    AgentTurn,
    CapabilityAction,
    CapabilityProposal,
    ModelMetadata,
    PlanStep,
    StopAction,
)
from harness.util import canonical_json, estimate_tokens

#: Markers the prompt renderer emits and this client consumes. Kept as module constants so the
#: renderer and the reader cannot drift apart silently.
CATALOGUE_OPEN, CATALOGUE_CLOSE = "<capability_catalogue>", "</capability_catalogue>"
DIGEST_OPEN, DIGEST_CLOSE = "<run_digest>", "</run_digest>"


def _block(text: str, open_tag: str, close_tag: str) -> str | None:
    match = re.search(re.escape(open_tag) + r"(.*?)" + re.escape(close_tag), text, re.DOTALL)
    return match.group(1).strip() if match else None


def read_embedded_json(text: str, open_tag: str, close_tag: str) -> Any | None:
    """Pull a JSON block out of a rendered prompt. Shared with the prompt tests."""
    raw = _block(text, open_tag, close_tag)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


class ScriptedModelClient:
    def __init__(
        self,
        metadata: ModelMetadata,
        *,
        plan: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        self.metadata = metadata
        self._explicit_plan = [dict(step) for step in plan] if plan else None

    # -- policy ----------------------------------------------------------------------------

    def complete(self, *, system: str, user: str, step: int) -> ModelResponse:
        catalogue = read_embedded_json(user, CATALOGUE_OPEN, CATALOGUE_CLOSE)
        digest = read_embedded_json(user, DIGEST_OPEN, DIGEST_CLOSE)
        if digest is None:
            raise ModelClientError(
                "the scripted planner needs a run digest block in the prompt; "
                "the prompt renderer and this client have drifted apart"
            )
        capabilities = self._capabilities(catalogue, digest)
        turn = self._decide(digest, capabilities)
        text = json.dumps(turn.model_dump(mode="json"), indent=2, sort_keys=True)
        return ModelResponse(
            text=text,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=estimate_tokens(text),
            raw={"backend": "scripted", "step": step},
        )

    @staticmethod
    def _capabilities(catalogue: Any, digest: Mapping[str, Any]) -> list[dict[str, Any]]:
        if isinstance(catalogue, Mapping):
            entries = catalogue.get("capabilities")
        else:
            entries = catalogue
        if not isinstance(entries, list) or not entries:
            entries = digest.get("capabilities") or []
        return [dict(entry) for entry in entries if isinstance(entry, Mapping)]

    def _decide(
        self, digest: Mapping[str, Any], capabilities: list[dict[str, Any]]
    ) -> AgentTurn:
        observed_kinds = {str(obs.get("kind")) for obs in digest.get("observations") or []}
        # Progress is tracked per (capability, grant), not per capability: a call that failed is
        # still worth retrying on the same grant, while a call that completed moves on to the next
        # offered grant (for example, the second log file).
        completed = {
            (str(e.get("capability")), str(e.get("grant")))
            for e in digest.get("executed") or []
            if e.get("exit_status") == "completed"
        }
        denied = {
            str(item.get("capability")) for item in digest.get("denied") or [] if isinstance(item, Mapping)
        }
        objective_kind = str(digest.get("objective_kind") or "")

        plan = self._explicit_plan or [
            {"step": idx + 1, "capability": str(cap.get("capability")), "intent": str(cap.get("intent_hint", ""))}
            for idx, cap in enumerate(capabilities)
        ]
        plan_steps = [
            PlanStep(step=int(item.get("step", i + 1)), capability=str(item["capability"]), intent=str(item.get("intent", "")))
            for i, item in enumerate(plan)
            if item.get("capability")
        ]

        for cap in capabilities:
            name = str(cap.get("capability") or "")
            grants = list(cap.get("grants") or [])
            if not name or not grants:
                continue
            expected = {str(k) for k in (cap.get("expected_kinds") or [])}
            if expected and expected <= observed_kinds:
                continue
            if name in denied:
                continue
            grant = next((g for g in grants if (name, str(g.get("grant"))) not in completed), None)
            if grant is None:
                continue
            proposal = CapabilityProposal(
                grant=str(grant.get("grant")),
                capability=name,
                args=dict(grant.get("args") or {}),
                expects=str(cap.get("expects", "")),
                evidence_needed=self._evidence_needed(name, expected, observed_kinds),
            )
            return AgentTurn(
                plan=plan_steps,
                next_action=CapabilityAction(proposal=proposal),
                hypotheses=list(digest.get("hypotheses") or []),
            )

        reason = (
            f"no capability in the catalogue for objective {objective_kind or 'unknown'} "
            "is both authorised and still missing evidence"
        )
        return AgentTurn(plan=plan_steps, next_action=StopAction(reason=reason))

    @staticmethod
    def _evidence_needed(capability: str, expected: set[str], observed: set[str]) -> str:
        missing = sorted(expected - observed) if expected else []
        if missing:
            return f"No current-run observations of kind: {', '.join(missing)}."
        return f"Capability {capability} has not produced observations in this run yet."

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ScriptedModelClient(model_id={self.metadata.model_id!r})"
