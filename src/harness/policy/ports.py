"""Port specifications: one grammar for "which ports does this call reach".

Two different questions are asked about a port argument, and they are asked by different components:

* **Can this be executed?** The adapter's own shape check (``providers/native/nmap.py``) refuses
  anything it cannot turn into a command line.
* **Is this authorised?** The policy engine compares the ports a call would reach against the
  window the scope's network authorises. That is this module.

Keeping the authorisation grammar here rather than borrowing the adapter's regex is deliberate: the
adapter's check exists to avoid passing nonsense to a subprocess, while this one has to be able to
say "these ports are inside the window" and must refuse a specification it cannot read. A
disagreement between the two fails closed either way - the adapter refuses what it cannot run, the
policy refuses what it cannot compare - so neither has to be a superset of the other.

The grammar is the one operators write: ``80``, ``80,443``, ``1-65535``, ``22,8000-8010``. Whitespace
around entries is tolerated because it is a human writing a scope-constrained proposal.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable

_MAX_PORT = 65535


def parse_port_spec(value: object) -> list[tuple[int, int]] | None:
    """The inclusive ranges a port specification names, or ``None`` if it is not one.

    ``None`` means "this is not a port specification", which the caller must treat as unauthorised
    rather than as "all ports": an unreadable argument is exactly what a caller trying to slip past
    a window would send.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    ranges: list[tuple[int, int]] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            return None
        head, sep, tail = item.partition("-")
        start = _port(head)
        if start is None:
            return None
        if not sep:
            ranges.append((start, start))
            continue
        end = _port(tail)
        if end is None or end < start:
            return None
        ranges.append((start, end))
    return ranges or None


def _port(text: str) -> int | None:
    candidate = text.strip()
    if not candidate.isdigit():
        return None
    number = int(candidate)
    return number if 0 < number <= _MAX_PORT else None


def all_within(spec: object, allowed: Collection[int]) -> bool:
    """Whether every port a specification names is in the authorised window.

    Compares numbers rather than ranges: the window in a scope record is a set of ports, and asking
    "is 1-65535 inside {80, 443}" by materialising the range is both simpler and cheaper than interval
    arithmetic over a set that was never expressed as intervals.
    """
    ranges = parse_port_spec(spec)
    if ranges is None:
        return False
    permitted = {int(port) for port in allowed}
    for start, end in ranges:
        expected = end - start + 1
        present = sum(1 for port in range(start, end + 1) if port in permitted)
        if present != expected:
            return False
    return True


def render_window(allowed: Iterable[int]) -> str:
    """The window as a port specification, so a catalogue can offer only what is authorised.

    Consecutive ports collapse into ranges: a window of twenty consecutive ports is one entry, which
    is what an operator would have written by hand.
    """
    ports = sorted({int(port) for port in allowed})
    parts: list[str] = []
    start = previous = None
    for port in ports:
        if start is None:
            start = previous = port
            continue
        if port == previous + 1:
            previous = port
            continue
        parts.append(f"{start}-{previous}" if start != previous else str(start))
        start = previous = port
    if start is not None:
        parts.append(f"{start}-{previous}" if start != previous else str(start))
    return ",".join(parts)
