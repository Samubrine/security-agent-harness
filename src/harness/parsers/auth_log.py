"""Reader for sshd-style authentication logs (``text/x-authlog``).

Two design points shape this parser.

* **A burst and a success are different facts.** Folding "14 failures then an accepted login from
  the same address" into one record would destroy the only interesting relationship in the corpus.
  Per-event observations are emitted, and the rollup reports the burst while a separate
  observation records the success that followed it.
* **The source address is attacker-controlled in a different sense.** It is not prose, but it is
  remote input, so it is T2/T3 data and never a target. The *granted* host is the target; the
  addresses inside the lines are actors within the evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable

from harness.models import EvidenceGap, EvidenceRef, Observation, ProviderExecution, TrustClass
from harness.parsers.registry import ParseContext, ParseResult
from harness.util import new_id, out_of_scope_ips

AUTHLOG_MEDIA_TYPE = "text/x-authlog"
PARSER_NAME = "auth_log"
PARSER_VERSION = "0.1.0"

#: How many failures from one source inside the window turn a run of errors into a burst. Eight is
#: a deliberate, stated threshold rather than a tuned one: the point of v1 is that the rule is
#: inspectable and its output is explainable, not that it is optimal.
BURST_THRESHOLD = 8

_SYSDLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r" port (\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (\d+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True, slots=True)
class _Event:
    timestamp: datetime
    src_ip: str
    user: str
    event: str
    outcome: str
    byte_start: int
    byte_end: int


def parse_auth_log(
    data: bytes,
    *,
    execution: ProviderExecution,
    run_id: str,
    trust_class: TrustClass = "local_tool",
    artifact_digest: str | None = None,
    evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None,
    target: str | None = None,
) -> ParseResult:
    ctx = ParseContext(
        data=bytes(data),
        media_type=AUTHLOG_MEDIA_TYPE,
        run_id=run_id,
        execution=execution,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        trust_class=trust_class,
        artifact_digest=artifact_digest,
        evidence_of=evidence_of,
        target=target,
    )
    host = target or "unknown"
    events = _extract_events(ctx.data)
    observations: list[Observation] = []
    for event in events:
        observations.append(
            ctx.observe(
                "auth_event",
                {
                    "target": host,
                    "event": event.event,
                    "src_ip": event.src_ip,
                    "user": event.user,
                    "timestamp": event.timestamp.isoformat(),
                    "outcome": event.outcome,
                },
                byte_start=event.byte_start,
                byte_end=event.byte_end,
                # A log file inside granted scope is local data about remote actors: T2.
                taint="T2",
                locator="sshd authentication line",
                freshness=event.timestamp,
            )
        )

    gaps: list[EvidenceGap] = []
    if not events:
        gaps.append(
            EvidenceGap(
                id=new_id("g"),
                run_id=run_id,
                kind="empty_result",
                scope={"target": host, "parser": PARSER_NAME},
                impact="the authentication log contained no recognisable sshd events",
                capability=execution.capability,
            )
        )
        return ParseResult(observations=observations, gaps=gaps)

    summary_start = events[0].byte_start
    summary_end = events[-1].byte_end
    observations.append(
        ctx.observe(
            "auth_summary",
            _summarise(events, host),
            byte_start=summary_start,
            byte_end=summary_end,
            taint="T2",
            locator="authentication rollup",
            freshness=events[-1].timestamp,
        )
    )

    # An instruction shipped inside a username or a service field is still attacker-authored text,
    # so it is screened here too rather than only in the parsers that read obviously hostile prose.
    unauthorised = out_of_scope_ips(ctx.data.decode("utf-8", errors="replace"), {host})
    if unauthorised and any("ignore" in e.user.lower() for e in events):
        gaps.append(
            EvidenceGap(
                id=new_id("g"),
                run_id=run_id,
                kind="prompt_injection_attempt",
                scope={"target": host, "out_of_scope_ips": unauthorised},
                impact=(
                    "authentication log content contains instruction-shaped text naming "
                    f"{', '.join(unauthorised)}; it is recorded, not acted on"
                ),
                capability=execution.capability,
            )
        )
    return ParseResult(observations=observations, gaps=gaps)


def _extract_events(data: bytes) -> list[_Event]:
    out: list[_Event] = []
    for line, start, end in _iter_lines(data):
        text = line.decode("utf-8", errors="replace")
        match = _SYSDLOG.match(text.strip())
        if not match:
            continue
        stamp = _timestamp(match)
        if stamp is None:
            continue
        message = match.group("message")
        failed = _FAILED.search(message)
        if failed:
            out.append(
                _Event(stamp, failed.group("ip"), failed.group("user"), "failed_password", "failure", start, end)
            )
            continue
        accepted = _ACCEPTED.search(message)
        if accepted:
            out.append(
                _Event(
                    stamp,
                    accepted.group("ip"),
                    accepted.group("user"),
                    "accepted_login",
                    "success",
                    start,
                    end,
                )
            )
    return out


def _summarise(events: list[_Event], host: str) -> dict[str, Any]:
    failures = [e for e in events if e.outcome == "failure"]
    successes = [e for e in events if e.outcome == "success"]
    counts: dict[str, int] = {}
    for event in failures:
        counts[event.src_ip] = counts.get(event.src_ip, 0) + 1
    top_source = max(sorted(counts), key=lambda ip: counts[ip]) if counts else ""
    first = min(e.timestamp for e in events)
    last = max(e.timestamp for e in events)
    return {
        "target": host,
        "window": f"{first.isoformat()}..{last.isoformat()}",
        "failed_logins": len(failures),
        "successful_logins": len(successes),
        "distinct_sources": len({e.src_ip for e in events}),
        "top_source": top_source,
        "top_source_failures": counts.get(top_source, 0),
        "burst_threshold": BURST_THRESHOLD,
        "burst_detected": bool(top_source) and counts.get(top_source, 0) >= BURST_THRESHOLD,
        # Recorded explicitly so a later reader can tell "no successes at all" from "successes
        # existed but were not correlated", rather than inferring it from an empty list.
        "success_after_burst": bool(
            top_source
            and successes
            and any(s.src_ip == top_source and s.timestamp >= max(f.timestamp for f in failures)
                    for s in successes)
        ),
    }


def _timestamp(match: re.Match[str]) -> datetime | None:
    month = _MONTHS.get(match.group("mon"))
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    # auth.log has no year. The current UTC year is used and the assumption is stated here rather
    # than hidden: a log from a different year will be timestamped wrongly, but consistently, and
    # the observation still quotes the exact artifact line it came from.
    year = datetime.now(UTC).year
    try:
        return datetime(year, month, int(match.group("day")), hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None


def _iter_lines(data: bytes) -> list[tuple[bytes, int, int]]:
    out: list[tuple[bytes, int, int]] = []
    offset = 0
    for raw in data.split(b"\n"):
        start = offset
        end = offset + len(raw)
        if raw.strip():
            out.append((raw, start, end))
        offset = end + 1
    return out
