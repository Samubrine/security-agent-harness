"""Spotlighting: delimiting untrusted text so the model can tell data from instruction.

The wrapper is only meaningful if the payload cannot forge it. Two measures make that true: a
fresh random nonce per run, and stripping that nonce out of the payload before wrapping. A
payload that contains the closing tag is therefore unable to close the block early.
"""

from __future__ import annotations

import re

from harness.models import TaintLevel
from harness.policy.taint import TaintTracker

_BLOCK = re.compile(r"<untrusted-([0-9a-f]+)([^>]*)>(.*?)</untrusted-\1>", re.DOTALL)


class Spotlight:
    def __init__(self, tracker: TaintTracker) -> None:
        self._tracker = tracker

    @property
    def nonce(self) -> str:
        return self._tracker.nonce

    def wrap(self, text: str, *, origin: str, level: TaintLevel = "T3") -> str:
        self._tracker.register(level, origin)
        return self._tracker.spotlight(text, origin=origin, level=level)

    def unwrap(self, text: str) -> str:
        """Strip every untrusted block wrapper, keeping the payload."""
        return _BLOCK.sub(lambda m: m.group(3), text)

    def blocks(self, text: str) -> list[tuple[str, str]]:
        """Return ``(origin, payload)`` for every untrusted block, for taint accounting."""
        return [(m.group(2).strip(), m.group(3)) for m in _BLOCK.finditer(text)]
