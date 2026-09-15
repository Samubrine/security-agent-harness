"""Reader for combined-format HTTP access logs (``text/x-nginx-access``).

An access log is a list of requests an adversary *chose to make*, which makes it the closest thing
this project has to a confession. Three consequences shape the parser:

* **Suspicion is a structural property of the request line, not a score.** A traversal shape, an
  injection shape, a scanner user agent and a sensitive-path probe are named explicitly, so a
  finding can cite *which* property matched instead of quoting a number.
* **The user agent and the path are attacker-authored.** They are screened for instructions like
  any other hostile text, and the rollup never quotes them into a prompt unbounded.
* **A 200 response is not a hit.** The parser records the status code and lets the analyser decide;
  it never upgrades "the request was made" into "the request succeeded".
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Callable

from harness.models import EvidenceGap, EvidenceRef, Observation, ProviderExecution, TrustClass
from harness.parsers.registry import ParseContext, ParseResult, injection_observations
from harness.util import clamp_text, new_id, strip_control_chars

NGINX_MEDIA_TYPE = "text/x-nginx-access"
PARSER_NAME = "nginx_access"
PARSER_VERSION = "0.1.0"

#: How many distinct suspicious requests before the rollup calls the traffic a campaign rather
#: than a coincidence. Stated as a constant so the threshold is auditable, not tuned per run.
CAMPAIGN_THRESHOLD = 5

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]*?) '
    r'(?P<proto>HTTP/\d\.\d)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" '
    r'"(?P<agent>[^"]*)"'
)

_TRAVERSAL = re.compile(r"(\.\./|%2e%2e|\.\.%2f|%2e%2e%2f|%252e)", re.IGNORECASE)
_INJECTION = re.compile(
    r"(union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|"
    r"<script|javascript:|\bexec\s*\(|information_schema)",
    re.IGNORECASE,
)
_NULL_BYTE = re.compile("%00|\x00")
_SENSITIVE = re.compile(
    r"(/\.env\b|/\.git/|/etc/(passwd|shadow)|phpmyadmin|server-status|\.sql\b|\.bak\b|"
    r"/config\.(php|json|yml|yaml)|/wp-login\.php|/admin\b|/phpinfo\.php)",
    re.IGNORECASE,
)
_SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wfuzz|hydra|nuclei|acunetix|nessus|"
    r"zgrab|libwww-perl|wpscan)",
    re.IGNORECASE,
)

#: Reasons that describe the *shape of the request* rather than the client's self-description. Only
#: these can make a successful response meaningful: a recognised scanner fetching / is not a probe
#: that worked, but a 200 for ../../etc/passwd is a request worth escalating. Keeping the two
#: classes apart is what stops the report from calling ordinary curl traffic a success.
STRUCTURAL_REASONS = frozenset({"path_traversal", "injection_syntax", "null_byte", "sensitive_path"})

_TIME = re.compile(r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})"
                   r" (?P<offset>[+-]\d{4})")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True, slots=True)
class _Request:
    timestamp: datetime | None
    src_ip: str
    method: str
    path: str
    status: int
    agent: str
    reasons: tuple[str, ...]
    byte_start: int
    byte_end: int

    @property
    def suspicious(self) -> bool:
        return bool(self.reasons)


def parse_nginx_access(
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
        media_type=NGINX_MEDIA_TYPE,
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
    requests = _extract(ctx.data)
    observations: list[Observation] = []
    for request in requests:
        observations.append(
            ctx.observe(
                "http_event",
                {
                    "target": host,
                    "src_ip": request.src_ip,
                    "method": request.method,
                    "path": request.path,
                    "status": request.status,
                    "timestamp": request.timestamp.isoformat() if request.timestamp else "",
                    "suspicious": request.suspicious,
                    "reasons": list(request.reasons),
                    "probe_shaped": bool(set(request.reasons) & STRUCTURAL_REASONS),
                    "user_agent": request.agent,
                },
                byte_start=request.byte_start,
                byte_end=request.byte_end,
                taint="T2",
                locator=f"{request.method} {request.path}",
                freshness=request.timestamp,
            )
        )

    gaps: list[EvidenceGap] = []
    if not requests:
        gaps.append(
            EvidenceGap(
                id=new_id("g"),
                run_id=run_id,
                kind="empty_result",
                scope={"target": host, "parser": PARSER_NAME},
                impact="the access log contained no recognisable combined-format requests",
                capability=execution.capability,
            )
        )
        return ParseResult(observations=observations, gaps=gaps)

    observations.append(
        ctx.observe(
            "http_summary",
            _summarise(requests, host),
            byte_start=requests[0].byte_start,
            byte_end=requests[-1].byte_end,
            taint="T2",
            locator="http rollup",
            freshness=requests[-1].timestamp,
        )
    )

    # The request line and user agent are attacker-authored. Screen them for instruction-shaped
    # content so a scanner probing "/?q=ignore previous instructions" is reported as an injection
    # attempt rather than quietly averaged into traffic statistics.
    for request in requests:
        text = f"{request.path} {request.agent}"
        found, gap = injection_observations(
            ctx,
            text=text,
            source="http-request",
            byte_start=request.byte_start,
            byte_end=request.byte_end,
            target=host,
            authorised={host},
        )
        observations.extend(found)
        if gap is not None:
            gaps.append(gap)
    return ParseResult(observations=observations, gaps=gaps)


def _extract(data: bytes) -> list[_Request]:
    out: list[_Request] = []
    for line, start, end in _iter_lines(data):
        text = line.decode("utf-8", errors="replace").strip()
        match = _COMBINED.match(text)
        if not match:
            continue
        path = strip_control_chars(match.group("path"))
        agent = strip_control_chars(match.group("agent"))
        out.append(
            _Request(
                timestamp=_timestamp(match.group("time")),
                src_ip=match.group("ip"),
                method=match.group("method"),
                path=clamp_text(path, 500),
                status=int(match.group("status")),
                agent=clamp_text(agent, 200),
                reasons=tuple(_reasons(path, agent)),
                byte_start=start,
                byte_end=end,
            )
        )
    return out


def _reasons(path: str, agent: str) -> list[str]:
    """Name every structural property that makes a request interesting.

    Reasons accumulate rather than short-circuit: a request that is both a traversal and a scanner
    probe should be citable as both, because the report's job is to show its work.

    Matching runs against the percent-decoded path as well as the raw one. Attackers encode
    precisely to defeat naive string matching, and a detector that only reads the raw request line
    would miss the most common form of every injection payload.
    """
    decoded = _decode(path)
    reasons: list[str] = []
    if _TRAVERSAL.search(path) or _TRAVERSAL.search(decoded):
        reasons.append("path_traversal")
    if _INJECTION.search(path) or _INJECTION.search(decoded):
        reasons.append("injection_syntax")
    if _NULL_BYTE.search(path) or _NULL_BYTE.search(decoded):
        reasons.append("null_byte")
    if _SENSITIVE.search(path) or _SENSITIVE.search(decoded):
        reasons.append("sensitive_path")
    if _SCANNER_AGENTS.search(agent):
        reasons.append("scanner_user_agent")
    return reasons


def _decode(path: str) -> str:
    """Percent-decode for matching only. The raw path is what the evidence span points at."""
    try:
        return urllib.parse.unquote(path, errors="replace")
    except Exception:  # noqa: BLE001 - a path that cannot be decoded simply matches nothing
        return ""


def _summarise(requests: list[_Request], host: str) -> dict[str, Any]:
    suspicious = [r for r in requests if r.suspicious]
    by_source: dict[str, int] = {}
    for request in suspicious:
        by_source[request.src_ip] = by_source.get(request.src_ip, 0) + 1
    top_source = max(sorted(by_source), key=lambda ip: by_source[ip]) if by_source else ""
    paths: list[str] = []
    for request in suspicious:
        if request.path not in paths:
            paths.append(request.path)
    return {
        "target": host,
        "total_requests": len(requests),
        "suspicious_requests": len(suspicious),
        "paths": paths[:20],
        "distinct_sources": len({r.src_ip for r in requests}),
        "top_source": top_source,
        "reason_counts": _reason_counts(suspicious),
        "campaign_threshold": CAMPAIGN_THRESHOLD,
        "campaign_detected": len(suspicious) >= CAMPAIGN_THRESHOLD,
        # Whether the probes appear to have worked. Recorded, not concluded: a 403 is a refusal and
        # a 200 for a traversal path is the only combination that would raise status above possible.
        "successful_suspicious": [
            {"path": r.path, "status": r.status, "reasons": list(r.reasons)}
            for r in suspicious
            if r.status < 400 and set(r.reasons) & STRUCTURAL_REASONS
        ],
    }


def _reason_counts(requests: list[_Request]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for request in requests:
        for reason in request.reasons:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _timestamp(value: str) -> datetime | None:
    match = _TIME.match(value.strip())
    if not match:
        return None
    month = _MONTHS.get(match.group("mon").title())
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    offset = match.group("offset")
    tz = UTC
    sign = 1 if offset[0] == "+" else -1
    delta_minutes = sign * (int(offset[1:3]) * 60 + int(offset[3:5]))
    if delta_minutes:
        tz = timezone(timedelta(minutes=delta_minutes))
    try:
        return datetime(
            int(match.group("year")), month, int(match.group("day")), hour, minute, second, tzinfo=tz
        ).astimezone(UTC)
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
