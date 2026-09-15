"""Provider-side egress policy: invariant 12, decided from the endpoint, not the declaration.

The v1 gap this closes is a component grading itself. ``ProviderSpec.requires_network_egress``
is a *claim made by the provider*; the policy engine consumed it as if it were a fact, so a
remote transport registered with ``requires_network_egress=False`` was treated as a local
source and its output was allowed to keep a low taint level. Everything here re-derives the
answer from evidence the harness owns - the endpoint string, plus (when the harness itself
spawns the process) the fact that it did - and records the provider's claim only so that a
disagreement is visible.

Two properties are load-bearing and both are fail-closed:

* A name that is not an IP literal and is not ``localhost`` is **public**. A DNS name points
  somewhere; assuming it points at this host is precisely the bug. This module therefore never
  performs name resolution, and it deliberately does not import any resolver module. A name
  whose text is not even shaped like a host (whitespace, punctuation that no hostname may
  contain) is ``unknown`` rather than ``public``, and ``unknown`` is still refused by default.
* An endpoint the harness cannot classify is refused unless egress was explicitly enabled. The
  decision is an explicit table (see ``EGRESS_TABLE``), not the tempting one-liner
  ``not required or enabled`` - that formula would silently permit ``unknown``.

``classify_prompt_content``/``redact_for_egress`` are a second, content-side gate: they name
the classes of material that must not leave the machine and can strip them. They are a
pattern match, so an **empty result is not a certificate that the text is safe** - it means
nothing that this module recognises was found, which is a much weaker statement.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from harness.errors import EgressViolation
from harness.models import EgressAssessment

EndpointClass = Literal["loopback", "private", "public", "unknown"]

# ---------------------------------------------------------------------------------------------
# The permission table.
#
# This is normative (INTERFACES.md 6.2) and is written as data because the obvious formula
# ``permitted = not egress_actually_required or egress_enabled`` is wrong: it would permit
# ``unknown``, i.e. an endpoint nobody could classify would be treated as local. Keeping the
# table explicit means a future endpoint class has to be given a row deliberately.
#
#   class      egress_actually_required  permitted_when_egress_disabled
_EGRESS_TABLE: dict[EndpointClass, tuple[bool, bool]] = {
    "loopback": (False, True),
    "private": (False, True),  # the lab network; still local, so still no egress
    "public": (True, False),
    "unknown": (False, False),  # fail closed: unclassifiable is not local
}

REASON_DECLARATION_MISMATCH = "declaration_mismatch"
REASON_ENDPOINT_PUBLIC = "endpoint_public"
REASON_ENDPOINT_LOCAL = "endpoint_local"
REASON_ENDPOINT_UNKNOWN = "endpoint_unknown"
REASON_LOCAL_EXECUTION = "local_execution"
REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT = "local_execution_public_endpoint"
REASON_EGRESS_ENABLED = "egress_enabled"
REASON_PERMITTED = "permitted"
REASON_NOT_PERMITTED = "not_permitted"

# Hosts are matched as ASCII text. A token with whitespace or punctuation is not a host at all,
# so it is ``unknown`` (refused) rather than a routable name.
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9._-]+")
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def _extract_host(endpoint: str | None) -> str | None:
    """Reduce ``scheme://user@host:port/path?query#frag`` to ``host``, or ``None``.

    Returns ``None`` for anything that cannot be reduced unambiguously; the caller turns that
    into ``unknown``, which is refused by default. A malformed string is never repaired into a
    plausible host, because repairing attacker-supplied text is how a check gets bypassed.
    """
    if not isinstance(endpoint, str):
        return None
    text = endpoint.strip()
    if not text:
        return None
    scheme = _SCHEME_RE.match(text)
    if scheme:
        text = text[scheme.end() :]
    # Path, query and fragment are not part of the authority.
    text = re.split(r"[/?#]", text, maxsplit=1)[0]
    # Credentials are not part of the host; keep the part after the last '@'.
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None  # unterminated bracketed literal
        host = text[1:end]
        rest = text[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        if rest.startswith(":") and not rest[1:].isdigit():
            return None
    elif text.count(":") > 1:
        # An unbracketed IPv6 literal has no port (a port requires the bracketed form), so the
        # whole remainder is the host. This must be checked before the ``host:port`` split or
        # ``fd00::1`` would be read as host ``fd00::`` plus port ``1``.
        host = text
    elif ":" in text:
        host, _, port = text.rpartition(":")
        if not port.isdigit():
            return None
    else:
        host = text
    host = host.strip()
    return host or None


def _classify_host(host: str) -> EndpointClass:
    """Classify an already-extracted host. Pure text work; no resolution of any kind."""
    lowered = host.lower()
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        addr = None
    if addr is not None:
        # ``::ffff:127.0.0.1`` is loopback. If a stdlib ever stops unwrapping v4-mapped
        # addresses we unwrap it here rather than let a loopback endpoint read as public - an
        # over-strict answer denies a legitimate local call, which is the safe direction.
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        return "public"
    # A trailing dot is a fully-qualified *DNS* name, not the literal ``localhost`` token, and
    # only the token is loopback. Anything else that is a name resolves somewhere off this
    # machine until proven otherwise, so it is public.
    if lowered == "localhost":
        return "loopback"
    if _HOSTNAME_RE.fullmatch(lowered):
        return "public"
    return "unknown"


def classify_endpoint(endpoint: str | None) -> EndpointClass:
    """Classify an endpoint as ``loopback``, ``private``, ``public`` or ``unknown``.

    Accepts ``host``, ``host:port`` and ``scheme://host:port/path``. ``None``, empty text and
    text that is not shaped like a host are ``unknown``. Note that ``unknown`` is *not* a
    synonym for local: the permission table refuses it unless egress is explicitly enabled.
    """
    host = _extract_host(endpoint)
    if host is None:
        return "unknown"
    return _classify_host(host)


def assess_provider_egress(
    provider: str,
    *,
    endpoint: str | None = None,
    declared_requires_egress: bool = False,
    egress_enabled: bool = False,
    local_subprocess: bool = False,
) -> EgressAssessment:
    """Decide whether one provider call may leave the local network, from its endpoint.

    ``declared_requires_egress`` is the provider's own claim and is never trusted: it is echoed
    as ``declared_by_provider`` and a disagreement with the derived fact is recorded as a
    ``declaration_mismatch`` reason *even when the call is permitted*, because policy's risk
    computation consumed the declaration and an auditor needs to see that it was wrong.

    ``local_subprocess`` says the harness itself runs the provider on this host (a native
    binary, or an MCP stdio transport bound to a local argv). That is loopback by construction
    and permitted regardless of ``egress_enabled``. It is a fact about how the harness runs the
    provider, which is why it is a separate argument from anything the provider says; if an
    explicit endpoint is also supplied and is not local, the contradiction is recorded as a
    reason so it cannot pass unremarked.

    Under ``local_subprocess`` there is deliberately **no** ``declaration_mismatch``, whatever
    ``declared_requires_egress`` says. For a locally executed provider that flag describes
    whether the *tool* reaches out to a target - nmap declares ``True`` while running as a plain
    local process, because it sends packets at a host rather than calling a remote service. That
    is a scope question, and scope is bounded by the grant and the policy engine; it is not a
    claim about transport. Recording it here as a transport lie would fire on every nmap run and
    would train an operator to ignore the reason.
    """
    derived = classify_endpoint(endpoint)
    endpoint_class: EndpointClass = "loopback" if local_subprocess else derived
    egress_actually_required, permitted_when_disabled = _EGRESS_TABLE[endpoint_class]
    permitted = bool(egress_enabled) or permitted_when_disabled

    reasons: list[str] = []
    if endpoint_class == "public":
        reasons.append(REASON_ENDPOINT_PUBLIC)
    elif endpoint_class == "unknown":
        reasons.append(REASON_ENDPOINT_UNKNOWN)
    else:
        reasons.append(REASON_ENDPOINT_LOCAL)
    if local_subprocess:
        reasons.append(REASON_LOCAL_EXECUTION)
        # Only a genuinely supplied endpoint can contradict local execution. ``classify_endpoint``
        # reports ``unknown`` for ``None``, so without the ``is not None`` guard every local tool
        # with no endpoint at all would be flagged as if it had a remote one - noise that would
        # bury the real contradiction. ("public" in the reason name means "not local"; an
        # explicitly supplied endpoint the harness cannot classify is not local either.)
        if endpoint is not None and derived != "loopback":
            reasons.append(REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT)
    if egress_enabled:
        reasons.append(REASON_EGRESS_ENABLED)
    declared = bool(declared_requires_egress)
    # A locally executed provider cannot disagree about transport: the harness started it, so the
    # transport is a fact rather than a claim. The mismatch reason exists only to expose a
    # provider whose *claim* about reaching a service contradicts its endpoint.
    if not local_subprocess and declared != egress_actually_required:
        reasons.append(REASON_DECLARATION_MISMATCH)
    reasons.append(REASON_PERMITTED if permitted else REASON_NOT_PERMITTED)

    return EgressAssessment(
        provider=provider,
        endpoint=endpoint,
        endpoint_class=endpoint_class,
        declared_by_provider=declared,
        egress_actually_required=egress_actually_required,
        permitted=permitted,
        reasons=reasons,
    )


def require_permitted(assessment: EgressAssessment) -> None:
    """Raise ``EgressViolation`` naming the provider and its endpoint class, or return.

    The message is built from the assessment rather than from a fresh decision so that the
    refusal an operator reads is the same one that was recorded.
    """
    if assessment.permitted:
        # A record may not simply assert its way past the table. For any class the table refuses
        # by default, permission is only explicable by the reason that says egress was explicitly
        # enabled - ``EgressAssessment`` has no ``egress_enabled`` field of its own, so that reason
        # is the only evidence available. An internally inconsistent record is refused, which is
        # the direction that fails closed against a hand-written or tampered assessment.
        _, permitted_when_disabled = _EGRESS_TABLE.get(assessment.endpoint_class, (False, False))
        if not permitted_when_disabled and REASON_EGRESS_ENABLED not in assessment.reasons:
            raise EgressViolation(
                f"provider {assessment.provider!r} claims permission while classifying as "
                f"{assessment.endpoint_class} (endpoint {assessment.endpoint!r}) without an "
                f"explicit egress-enabled reason"
            )
        return
    raise EgressViolation(
        f"provider {assessment.provider!r} classifies as {assessment.endpoint_class} "
        f"(endpoint {assessment.endpoint!r}) and egress is not enabled"
    )


# ---------------------------------------------------------------------------------------------
# Content-side gate.
#
# One alternation, so that classification and redaction can never disagree about what a marker
# is. Order is significant: an earlier alternative wins at a given position, so the specific
# digest form is listed before the generic span forms.
# ---------------------------------------------------------------------------------------------
_MARKER_PATTERNS: tuple[tuple[str, str], ...] = (
    # ``sha256:<64 hex>`` - an immutable artifact address. Handing one to a remote endpoint
    # names a file it may be able to fetch. No leading word boundary: a digest glued to other
    # characters is a false positive that costs a redaction, while missing one leaks the address.
    ("artifact_digest", r"sha256:[0-9a-fA-F]{64}\b"),
    # The memory files themselves, by literal name. Case-insensitive because a filesystem may
    # be too, and matching the loose form only over-reports.
    ("memory_section", r"\b(?:MEMORY|BASELINE)\.md\b"),
    # ``mem-<hex>`` long-lived memory ids.
    ("memory_reference", r"\bmem-[0-9a-fA-F]{6,}\b"),
    # ``run-...`` run identifiers.
    ("run_identifier", r"\brun-[A-Za-z0-9][A-Za-z0-9._-]*"),
    # Evidence spans: the ``EvidenceRef`` field names, or a ``#0-812`` / ``bytes 0-812`` span.
    (
        "evidence_span",
        r"\b(?:byte_start|byte_end|span_sha256|line_start|line_end)\b|#\d+-\d+|\bbytes?\s*\d+\s*[-:]\s*\d+\b",
    ),
)

_MARKER_RE = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _MARKER_PATTERNS),
    re.IGNORECASE,
)


def classify_prompt_content(text: str) -> list[str]:
    """Return the sorted, deduplicated classes of egress-sensitive markers found in ``text``.

    Classes are one entry per class, not per occurrence: ``artifact_digest``,
    ``evidence_span``, ``memory_reference``, ``memory_section`` and ``run_identifier``.

    An empty list means nothing sensitive was *recognised*. It is not a certificate that the
    text is safe, and it must not be recorded as one - the harness decides egress from the
    endpoint (``assess_provider_egress``), and this function only reports what it can name.
    """
    return sorted({match.lastgroup for match in _MARKER_RE.finditer(text) if match.lastgroup})


def redact_for_egress(text: str) -> tuple[str, int]:
    """Replace every recognised marker with ``[redacted:<class>]``; return the text and count.

    The count is substitutions, not classes, so a caller can record *how much* was stripped.
    Redaction is a mitigation, not a licence to send the remainder: it removes what this module
    can name, and a negative on classification is not a safety certificate.
    """
    count = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"[redacted:{match.lastgroup}]"

    return _MARKER_RE.sub(_replace, text), count
