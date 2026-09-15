"""Taint tracking, spotlighting, and the injection detector.

The harness's input is attacker-authored text by design: SSH banners, HTTP bodies, log lines and
MCP responses are all strings an adversary controls. The response is not "tell the model to be
careful" but a mechanical label plus a mechanical gate.

* Every origin (an artifact digest, a span, a memory entry) gets a `TaintLevel`. The gate
  and the prompt builder read the same numbers.
* Untrusted text enters prompts wrapped in a per-run random nonce (`spotlight`), with the
  nonce stripped from the payload first so a hostile payload cannot close the wrapper early and
  continue writing outside it.
* A side-effectful or egress call whose arguments derive from `T3`, or whose proposal was
  authored while `T3` was in context and names a novel resource, is escalated to
  `ask` - enforced in `harness.policy.engine.PolicyEngine`, not in prose.

Injection detection deliberately delegates to `harness.util.detect_injection`: the parsers
(which read the same banners) and this gate must not hold two different definitions of "this
payload is instruction-shaped".
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from harness.models import TaintLevel, Tainted
from harness.util import clamp_text, strip_control_chars
from harness.util import detect_injection as _util_detect_injection

_LEVEL_RANK: dict[str, int] = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}

#: An origin the tracker has never seen is treated as hostile until it is registered. Failing
#: closed here costs an extra approval prompt; failing open would silently trust a remote
#: banner, which is exactly the threat this module exists for.
UNKNOWN_ORIGIN_LEVEL: TaintLevel = "T3"

#: Longest untrusted block handed to the prompt builder. A payload cannot buy itself extra
#: context budget by being enormous.
SPOTLIGHT_MAX_CHARS = 4096

_NONCE_BYTES = 8
_NONCE_MARKER = "[nonce-stripped]"
_TAG_MARKER = "[untrusted-tag-stripped]"
_ORIGIN_ATTR_MAX = 200
_MAX_WALK_NODES = 10_000

#: Any opening or closing spotlight-shaped tag is neutralised, not only our own nonce: a
#: payload that emits a fake delimiter should not be able to make the next reader believe a
#: boundary moved.
_TAG_RE = re.compile(r"</?untrusted[-A-Za-z0-9_]*\s*/?>", re.IGNORECASE)

#: Characters allowed inside a spotlight attribute. Anything else - quotes, angle brackets,
#: equals signs, whitespace - becomes "_", so an origin string can never be read as an extra
#: attribute or as the start of a new tag.
_ATTR_ALLOWED_RE = re.compile(r"[^A-Za-z0-9:./#\-_@+]")


def level_rank(level: TaintLevel) -> int:
    """Numeric order of a taint level, so "at least as tainted as" is a comparison."""
    try:
        return _LEVEL_RANK[level]
    except KeyError as exc:  # pragma: no cover - the Literal type makes this unreachable
        raise ValueError(f"unknown taint level {level!r}") from exc


def higher(a: TaintLevel, b: TaintLevel) -> TaintLevel:
    """The more hostile of two levels. Used everywhere taint could otherwise be lowered."""
    return a if level_rank(a) >= level_rank(b) else b


def coerce_level(value: object) -> TaintLevel:
    """Read a level from possibly-untrusted input, failing closed on anything unrecognised.

    The policy engine promises never to raise, and a caller that hand-built an argument bag or
    forwarded a level straight out of JSON can produce something that is not a level at all. An
    unrecognised value becomes `T3`: a nonsense label must never be read as "trusted".
    """
    return value if isinstance(value, str) and value in _LEVEL_RANK else UNKNOWN_ORIGIN_LEVEL  # type: ignore[return-value]


def arg_taint_level(value: Any) -> TaintLevel:
    """Highest taint level found anywhere inside proposal arguments.

    Accepts a `Tainted` record or its serialized form (a mapping carrying both
    `value` and `level`), because arguments may have been round-tripped through
    JSON before the policy engine sees them. Containers are walked iteratively with a node
    budget: argument nesting is attacker-influenced, so recursion depth must not be.
    """
    best: TaintLevel = "T0"
    stack: list[Any] = [value]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > _MAX_WALK_NODES:
            # Bail out conservatively: an argument tree this large was not produced by an honest
            # proposal, and treating it as hostile is the fail-safe reading.
            return higher(best, "T3")
        if isinstance(node, Tainted):
            best = higher(best, node.level)
            continue
        if node is None or isinstance(node, str | bytes | int | float | bool):
            continue
        if isinstance(node, Mapping):
            level = _serialized_level(node)
            if level is not None:
                best = higher(best, level)
                continue
            stack.extend(node.values())
            continue
        if isinstance(node, Sequence | set | frozenset):
            stack.extend(node)
    return best


def _serialized_level(node: Mapping[Any, Any]) -> TaintLevel | None:
    """Level of a serialized `Tainted` mapping, or `None` for anything else."""
    level = node.get("level")
    if isinstance(level, str) and level in _LEVEL_RANK and "value" in node:
        return level
    return None


def detect_injection(text: str) -> list[str]:
    """Names of every injection pattern matched in `text`, via `harness.util`.

    A match is *evidence that the payload is instruction-shaped*, never permission to follow it.
    """
    return _util_detect_injection(text)


class TaintTracker:
    """Per-run provenance levels, spotlight wrapping and the taint gate.

    Created once per run so the spotlight nonce is fixed for that run. Registering a level is a
    dict write, and every decision the tracker feeds is deterministic given its registrations.
    """

    def __init__(self, *, nonce: str | None = None) -> None:
        if nonce is not None and not nonce.strip():
            # An empty nonce would produce a wrapper anyone can close by writing the delimiter,
            # which is worse than no wrapper because it still looks like one.
            raise ValueError("spotlight nonce must be a non-empty string")
        self._nonce = nonce if nonce is not None else secrets.token_hex(_NONCE_BYTES)
        self._levels: dict[str, TaintLevel] = {}

    @property
    def nonce(self) -> str:
        """The delimiter token for this run. Random, and unguessable from the payload."""
        return self._nonce

    def register(self, level: TaintLevel, origin: str) -> None:
        """Record the level of `origin`, never lowering a level already recorded.

        Monotonic on purpose: a second sighting of the same artifact that claims a lower level
        must not be able to talk the run back down to trusting it.
        """
        if not origin or not origin.strip():
            raise ValueError("taint origin must be a non-empty provenance string")
        self._levels[origin] = higher(level, self._levels.get(origin, "T0"))

    def level_of(self, origin: str) -> TaintLevel:
        """Level recorded for `origin`, or `T3` if it was never registered.

        Fail closed: unlabelled content is treated as hostile until something registers it.
        Use `registered_level` when "unknown" and "hostile" must be distinguished.
        """
        return self._levels.get(origin, UNKNOWN_ORIGIN_LEVEL)

    def registered_level(self, origin: str) -> TaintLevel | None:
        """Level for a known origin, or `None` if the tracker has never seen it."""
        return self._levels.get(origin)

    def max_level(self) -> TaintLevel:
        """Highest level seen in this run; `T0` when nothing is registered."""
        best: TaintLevel = "T0"
        for level in self._levels.values():
            best = higher(best, level)
        return best

    def taint_gate_triggered(
        self,
        *,
        args: dict[str, Any],
        proposal_new_resource: bool,
        side_effectful: bool,
    ) -> bool:
        """Whether tainted input must escalate an otherwise-permitted call to `ask`.

        The gate is scoped to calls that can change remote state or leave the machine. Reading a
        hostile banner locally is the job; acting on it is the risk. Two triggers, matching
        section 4 of the policy design:

        * the arguments themselves carry `T3` content;
        * the proposal was authored while `T3` was in this run's context and it names a
          resource that is not already part of the plan.
        """
        if not side_effectful:
            return False
        if level_rank(arg_taint_level(args)) >= level_rank("T3"):
            return True
        return bool(proposal_new_resource) and level_rank(self.max_level()) >= level_rank("T3")

    def spotlight(self, text: str, *, origin: str, level: TaintLevel = "T3") -> str:
        """Wrap untrusted `text` in a nonce-delimited block for prompt inclusion.

        The order is the whole defence: control characters (which could hide a delimiter), this
        run's nonce, and any spotlight-shaped tag are removed *before* the wrapper is added. The
        result is length-capped so a hostile payload cannot consume the context budget.

        The wrapped level is never lower than a level already recorded for `origin`; the
        origin is then registered at that level, so later taint decisions see what actually
        entered context rather than what the caller hoped it was.
        """
        registered = self.registered_level(origin)
        effective: TaintLevel = higher(level, registered) if registered is not None else level
        self.register(effective, origin)
        body = clamp_text(self.strip_nonce(strip_control_chars(text)), SPOTLIGHT_MAX_CHARS)
        return (
            f"<untrusted-{self._nonce} origin=\"{_attr_safe(origin)}\" level=\"{effective}\">\n"
            f"{body}\n"
            f"</untrusted-{self._nonce}>"
        )

    def strip_nonce(self, text: str) -> str:
        """Remove this run's spotlight delimiter from a payload.

        Two removals, not one: the run nonce itself, and any tag shaped like a spotlight block.
        An attacker who guessed the nonce (or read it from an earlier prompt) must not be able to
        emit a closing tag, and neither must an attacker who emits a delimiter for a nonce they
        invented.
        """
        # Tags are neutralised before the nonce is removed so the nonce never survives anywhere
        # in the body, including inside a delimiter an attacker forged with it.
        return _TAG_RE.sub(_TAG_MARKER, text).replace(self._nonce, _NONCE_MARKER)

    def detect_injection(self, text: str) -> list[str]:
        """`TaintTracker`-shaped access to `detect_injection`."""
        return detect_injection(text)


def _attr_safe(origin: str) -> str:
    """Render an origin for an XML-ish attribute as an allowlisted, inert string.

    An allowlist rather than an escaping rule: provenance strings are produced by the harness, so
    anything outside the allowlist is either a bug or an attempt to relabel the block, and both
    should be visible as underscores.
    """
    cleaned = _ATTR_ALLOWED_RE.sub("_", strip_control_chars(origin))
    return cleaned[:_ORIGIN_ATTR_MAX]
