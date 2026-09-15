"""Deterministic reader for nmap XML (``application/nmap+xml``).

A scan result is the first artifact the harness trusts to tell it what exists on a host, so three
decisions in this module are structural rather than cosmetic:

* entity resolution and network DTD fetching are switched off. A service banner is
  attacker-authored text, and it would be an embarrassing bug for hostile scan output to turn into
  a file read inside the harness that is supposed to be reading it as evidence;
* every span is located by searching the artifact bytes for the element that was actually parsed,
  never reconstructed from a line number. A span therefore still verifies after the artifact is
  re-read byte for byte (or re-encoded with different line endings);
* the banner is data even when it is full of imperative text. ``detect_injection`` turns that text
  into an ``injection_attempt`` observation plus a ``prompt_injection_attempt`` gap naming the
  hosts the payload tried to add to scope. Nothing here ever follows it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable

from lxml import etree

from harness.errors import ParserError
from harness.models import EvidenceRef, Observation, ProviderExecution, TrustClass
from harness.parsers.registry import ParseContext, ParseResult, injection_observations
from harness.util import clamp_text, iso, strip_control_chars

NMAP_MEDIA_TYPE = "application/nmap+xml"
PARSER_NAME = "nmap_xml"
PARSER_VERSION = "0.1.0"

#: A banner is quoted into the record only up to this many characters. The full payload stays in
#: the artifact where the evidence span points, so truncation cannot hide anything.
BANNER_LIMIT = 2000


@dataclass(frozen=True, slots=True)
class _Untrusted:
    """An attacker-reachable region of the document, queued for injection screening."""

    source: str
    text: str
    byte_start: int
    byte_end: int
    target: str


def parse_nmap_xml(
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
        media_type=NMAP_MEDIA_TYPE,
        run_id=run_id,
        execution=execution,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        trust_class=trust_class,
        artifact_digest=artifact_digest,
        evidence_of=evidence_of,
        target=target,
    )
    raw = ctx.data
    root = _root(raw)
    observations: list[Observation] = []
    untrusted: list[_Untrusted] = []
    started_at = _started_at(root)

    meta_span = _element_span(raw, b"nmaprun", 0, whole=False)
    if meta_span is None:
        raise ParserError(
            "parsed an <nmaprun> root but could not locate its bytes; refusing to invent a span"
        )
    observations.append(
        ctx.observe(
            "scan_meta",
            {
                "scanner": root.get("scanner") or "nmap",
                "scan_type": _scan_type(root),
                # The epoch attribute is what nmap was told; the string form is only a fallback.
                "started_at": iso(started_at) if started_at is not None else "",
            },
            byte_start=meta_span[0],
            byte_end=meta_span[1],
            locator="nmaprun header",
            freshness=started_at,
        )
    )

    addresses: list[str] = []
    cursor = 0
    for host in root.iter("host"):
        host_span = _element_span(raw, b"host", cursor, whole=False)
        if host_span is None:
            raise ParserError("parsed a <host> element but could not locate its bytes")
        cursor = host_span[0] + 1
        address_el = host.find("address")
        addr = (address_el.get("addr") or "").strip() if address_el is not None else ""
        if addr:
            addresses.append(addr)
        state, status_span = _host_state(raw, host, addr, host_span[0])
        observations.append(
            ctx.observe(
                "host_state",
                {"target": addr, "state": state},
                byte_start=status_span[0],
                byte_end=status_span[1],
                locator=f"host {addr} status",
                freshness=started_at,
            )
        )
        ports_el = host.find("ports")
        if ports_el is not None:
            observations.extend(
                _port_observations(ctx, raw, ports_el, host_span[0], addr, started_at, untrusted)
            )
            extra_span = _extraports(raw, ports_el, host_span[0])
            if extra_span is not None:
                text, span = extra_span
                observations.append(
                    ctx.observe(
                        "banner",
                        {
                            "target": addr,
                            "port": None,
                            "banner": clamp_text(strip_control_chars(text).strip(), BANNER_LIMIT),
                            "product": "",
                            "version": "",
                        },
                        byte_start=span[0],
                        byte_end=span[1],
                        taint="T2",
                        locator=f"host {addr} extraports",
                        freshness=started_at,
                    )
                )

    _collect_http_titles(raw, root, untrusted)

    # An address the scan itself touched is, by construction, an address the grant authorised.
    # Anything else named inside attacker-controlled text is an attempt to widen scope.
    authorised = set(addresses)
    gaps = []
    for region in untrusted:
        found, gap = injection_observations(
            ctx,
            text=region.text,
            source=region.source,
            byte_start=region.byte_start,
            byte_end=region.byte_end,
            target=region.target,
            authorised=authorised,
        )
        observations.extend(found)
        if gap is not None:
            gaps.append(gap)
    return ParseResult(observations=observations, gaps=gaps)


def _port_observations(
    ctx: ParseContext,
    raw: bytes,
    ports_el: Any,
    host_start: int,
    addr: str,
    started_at: datetime | None,
    untrusted: list[_Untrusted],
) -> list[Observation]:
    out: list[Observation] = []
    cursor = host_start
    for port_el in ports_el.findall("port"):
        port_span = _element_span(raw, b"port", cursor)
        if port_span is None:
            raise ParserError(f"parsed a <port> element for host {addr} but could not locate it")
        cursor = port_span[0] + 1
        state_el = port_el.find("state")
        port_state = (state_el.get("state") or "").strip() if state_el is not None else ""
        # Only open ports become services: a closed port is an absence, and an absence has no
        # banner, product or version to cite. The host-level record already carries the state.
        if port_state != "open":
            continue
        port_id = _int_attr(port_el, "portid")
        protocol = (port_el.get("protocol") or "").strip()
        service_el = port_el.find("service")
        service_span = (
            _element_span(raw, b"service", port_span[0]) if service_el is not None else None
        ) or port_span
        name = _attr(service_el, "name")
        product = _attr(service_el, "product")
        version = _attr(service_el, "version")
        cpes = _cpes(service_el)
        locator = f"{addr}:{port_id}/{protocol}"
        out.append(
            ctx.observe(
                "service",
                {
                    "target": addr,
                    "port": port_id,
                    "protocol": protocol,
                    "state": port_state,
                    "service": name,
                    "product": product,
                    "version": version,
                    # A single string, not a list: the version-range matcher keys off this value,
                    # and a list would make it unusable as a key (and unreadable in a report).
                    "cpe": cpes[0] if cpes else "",
                },
                byte_start=service_span[0],
                byte_end=service_span[1],
                locator=locator,
                freshness=started_at,
            )
        )
        banner_el = service_el.find("banner") if service_el is not None else None
        banner_text = _text(banner_el)
        if not banner_text:
            continue
        banner_span = _element_span(raw, b"banner", service_span[0]) or service_span
        out.append(
            ctx.observe(
                "banner",
                {
                    "target": addr,
                    "port": port_id,
                    "banner": clamp_text(strip_control_chars(banner_text).strip(), BANNER_LIMIT),
                    "product": product,
                    "version": version,
                },
                byte_start=banner_span[0],
                byte_end=banner_span[1],
                # A banner is remote, attacker-reachable text: T3, data only, never instructions.
                taint="T3",
                locator=f"{locator} banner",
                freshness=started_at,
            )
        )
        untrusted.append(
            _Untrusted(
                source="banner",
                text=banner_text,
                byte_start=banner_span[0],
                byte_end=banner_span[1],
                target=addr,
            )
        )
    return out


def _host_state(
    raw: bytes, host: Any, addr: str, host_start: int
) -> tuple[str, tuple[int, int]]:
    status_el = host.find("status")
    if status_el is None:
        raise ParserError(f"host {addr or '<unknown>'} has no <status> element to cite")
    span = _element_span(raw, b"status", host_start, whole=False)
    if span is None:
        raise ParserError(f"parsed a <status> element for host {addr} but could not locate it")
    return (status_el.get("state") or "").strip(), span


def _extraports(raw: bytes, ports_el: Any, host_start: int) -> tuple[str, tuple[int, int]] | None:
    """nmap's ``<extraports>`` text summarises ports it did not report individually.

    It is surfaced as a ``banner`` observation because the frozen table has no other home for
    "prose nmap emitted about a host"; the span points at the real element either way.
    """
    extra = ports_el.find("extraports")
    if extra is None:
        return None
    span = _element_span(raw, b"extraports", host_start)
    if span is None:
        return None
    parts = [
        f"{reason.get('reason') or 'unknown'}: {reason.get('count') or '?'}"
        for reason in extra.findall("extrareasons")
    ]
    text = "; ".join(parts) or (extra.get("reason") or "")
    return text, span


def _collect_http_titles(raw: bytes, root: Any, untrusted: list[_Untrusted]) -> None:
    """Page titles are attacker-controlled too, so they get screened for instructions as well.

    They are not one of the observation kinds the table fixes, so they are not promoted into the
    evidence graph on their own -- only an instruction found inside one is.
    """
    cursor = 0
    for title_el in root.iter("http-title"):
        span = _element_span(raw, b"http-title", cursor)
        if span is None:
            continue
        cursor = span[0] + 1
        text = _text(title_el)
        if text:
            untrusted.append(
                _Untrusted(
                    source="http-title",
                    text=text,
                    byte_start=span[0],
                    byte_end=span[1],
                    target="",
                )
            )


def _root(data: bytes) -> Any:
    """Parse with entity resolution, DTD loading and network access all disabled.

    A DOCTYPE is still accepted (nmap writes one), but its entity definitions are inert and cannot
    reach the filesystem or the network: hostile scan output must not be able to read a file inside
    the harness that is supposed to be reading *it*.
    """
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
        recover=False, huge_tree=False,
    )
    try:
        root = etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise ParserError(f"nmap XML is not well formed: {exc}") from exc
    if root is None or _localname(root) != "nmaprun":
        raise ParserError("artifact is not an nmap XML document (no <nmaprun> root)")
    return root


def _localname(element: Any) -> str:
    try:
        return etree.QName(element).localname
    except ValueError:  # pragma: no cover - non-element nodes
        return ""


def _element_span(
    data: bytes, tag: bytes, start: int, *, whole: bool = True
) -> tuple[int, int] | None:
    """Byte span of the first ``<tag ...>`` element at or after ``start``.

    ``whole=True`` extends the span through ``</tag>`` when the document closes the element, since
    attributes *and* children are what the parser read. ``whole=False`` stops at the end of the
    opening tag, which is the honest span for a self-closing element such as ``<status/>``.
    """
    open_at = -1
    for suffix in (b" ", b">", b"\t", b"\r", b"\n"):
        found = data.find(b"<" + tag + suffix, start)
        if found >= 0 and (open_at < 0 or found < open_at):
            open_at = found
    if open_at < 0:
        return None
    close = data.find(b">", open_at)
    if close < 0:
        return None
    end = close + 1
    if whole:
        close_tag = b"</" + tag + b">"
        close_at = data.find(close_tag, end)
        if close_at >= 0:
            end = close_at + len(close_tag)
    return open_at, end


def _attr(element: Any, name: str) -> str:
    if element is None:
        return ""
    return (element.get(name) or "").strip()


def _int_attr(element: Any, name: str) -> int:
    raw = (element.get(name) or "").strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise ParserError(f"<port> element has a non-numeric {name}={raw!r}") from exc


def _text(element: Any) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def _cpes(service_el: Any) -> list[str]:
    if service_el is None:
        return []
    out: list[str] = []
    for cpe_el in service_el.findall("cpe"):
        value = (cpe_el.text or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def _scan_type(root: Any) -> str:
    """Name the technique that actually produced the versions, since that is what the scan did.

    The argparse string is the primary source because ``<scaninfo>`` only knows the port scan
    method, and the report should not describe a version-detection run as a bare SYN scan.
    """
    args = root.get("args") or ""
    if "-sV" in args:
        return "service_detection"
    scaninfo = root.find("scaninfo")
    info_type = (scaninfo.get("type") or "").strip() if scaninfo is not None else ""
    return info_type or "unknown"


def _started_at(root: Any) -> datetime | None:
    """Scan start as an aware UTC datetime, from the epoch attribute or nmap's string form.

    An unparsable header yields ``None`` and an empty ``started_at`` value rather than a guess: a
    fabricated freshness timestamp is worse than an admitted absence.
    """
    epoch = (root.get("start") or "").strip()
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=UTC)
    startstr = (root.get("startstr") or "").strip()
    if startstr:
        try:
            return datetime.strptime(startstr, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            return None
    return None
