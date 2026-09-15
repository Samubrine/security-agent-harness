"""Rule evaluation over normalised observations.

Decision D5 keeps the model out of finding construction, and this module is where that decision is
enforced: a claim exists because a named rule matched a typed observation, so "why is this in the
report?" has a one-line answer that does not involve reading a prompt transcript.

Rules are data. Adding one is an entry in a list, not a branch in the runtime (design 01, section
11), and every claim it produces carries the rule id that produced it.

Two rule shapes exist, because the interesting detections are of two kinds:

* ``kind`` + ``requires``: one observation of a given kind whose fields match. This is how a
  threshold that the parser already computed becomes a claim.
* ``requires_kinds``: several kinds must all be present. This is the cross-source shape, and it is
  the only honest way to express "the scan and the logs together support this hypothesis": the
  claim cites both sets of observations rather than one of them twice.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from harness.models import Claim, Observation
from harness.util import new_id

#: The shipped rule set. Each entry is declarative on purpose: its thresholds live in the parser
#: that computed them, so a rule cannot disagree with the evidence it cites about what it counted.
DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "service_exposed",
        "kind": "service",
        "statement": (
            "{product} {version} is listening on {target}:{port}/{protocol}."
        ),
        "assertion": "observed",
        "confidence": "observed",
        "confidence_basis": "read directly from the scan artifact; the evidence span is the banner",
    },
    {
        "id": "vulnerability_match_recorded",
        "kind": "vulnerability_match",
        "statement": (
            "{cve} applies to {product} {version} (CVSS {cvss}); the match came from the recorded "
            "offline snapshot, not from a model."
        ),
        "assertion": "rule_derived",
        "confidence": "high",
        "confidence_basis": "deterministic version-range comparison against a digest-stamped snapshot",
    },
    {
        "id": "injection_attempt_observed",
        "kind": "injection_attempt",
        "statement": (
            "Attacker-controlled text from {source} contains instruction-shaped content "
            "({pattern}) and was recorded as an observation instead of being followed."
        ),
        "assertion": "observed",
        "confidence": "observed",
        "confidence_basis": "the payload is quoted verbatim from the artifact",
    },
    {
        "id": "auth_bruteforce",
        "kind": "auth_summary",
        "requires": {"burst_detected": True},
        "statement": (
            "Credential brute force: {top_source_failures} failed logins from {top_source} "
            "inside the window {window}."
        ),
        "assertion": "rule_derived",
        "confidence": "high",
        "confidence_basis": "counted directly from authentication lines in the artifact",
    },
    {
        "id": "auth_success_after_burst",
        "kind": "auth_summary",
        "requires": {"success_after_burst": True},
        "statement": (
            "A successful authentication from {top_source} follows the failed-login burst, which is "
            "consistent with the burst having succeeded."
        ),
        "assertion": "rule_derived",
        "confidence": "medium",
        "confidence_basis": "temporal ordering of parsed events, not a causal proof",
        "caveats": [
            "a legitimate login from the same address, or a shared NAT egress, produces the same shape",
            "the account owner's own activity was not consulted in this run",
        ],
    },
    {
        "id": "http_probe_campaign",
        "kind": "http_summary",
        "requires": {"campaign_detected": True},
        "statement": (
            "{suspicious_requests} of {total_requests} requests carry probe signatures "
            "({reason_counts}), consistent with an automated reconnaissance campaign."
        ),
        "assertion": "rule_derived",
        "confidence": "high",
        "confidence_basis": "structural request properties matched in the access log",
    },
    {
        "id": "http_traversal_probe",
        "kind": "http_event",
        "requires_contains": {"reasons": "path_traversal"},
        "statement": "A request for {path} from {src_ip} has a path-traversal shape and returned {status}.",
        "assertion": "rule_derived",
        "confidence": "high",
        "confidence_basis": "the request line matches a traversal shape",
        "caveats": ["the response status shows whether the traversal succeeded; a 4xx is a refusal"],
    },
    {
        "id": "http_injection_probe",
        "kind": "http_event",
        "requires_contains": {"reasons": "injection_syntax"},
        "statement": "A request from {src_ip} carries injection syntax in {path} and returned {status}.",
        "assertion": "rule_derived",
        "confidence": "high",
        "confidence_basis": "the request line matches an injection shape",
        "caveats": ["a 4xx response means the input was rejected, not that the endpoint is safe"],
    },
    {
        "id": "sensitive_path_probe",
        "kind": "http_event",
        "requires_contains": {"reasons": "sensitive_path"},
        "statement": "A request for {path} from {src_ip} targets a sensitive path and returned {status}.",
        "assertion": "rule_derived",
        "confidence": "medium",
        "confidence_basis": "the requested path is on the sensitive-path list",
    },
    {
        "id": "scanner_user_agent",
        "kind": "http_event",
        "requires_contains": {"reasons": "scanner_user_agent"},
        "statement": "A request declaring {user_agent} from {src_ip} identifies an automated scanner.",
        "assertion": "observed",
        "confidence": "medium",
        "confidence_basis": "the client identified itself; a user agent is trivially forgeable",
        "caveats": ["the user agent is self-declared and proves nothing about the sender"],
    },
    {
        "id": "entry_point_cross_source",
        "requires_kinds": {
            "scan": ["service"],
            "logs": ["auth_summary", "http_summary"],
        },
        "statement": (
            "Scan and log evidence from this run support an entry-point hypothesis: a reachable "
            "exposed service ({scan_count} service observations) coincides with hostile activity "
            "in the logs ({logs_count} log rollups). The hypothesis rests on two independent "
            "sources, which is why it is reported separately from either one."
        ),
        "assertion": "rule_derived",
        "confidence": "medium",
        "confidence_basis": "correlation of two independent artifact sources from this run",
        "caveats": [
            "co-occurrence is not causation: the probes may target a service other than the one matched",
            "no exploitation was attempted, so the hypothesis is not confirmed by this harness",
        ],
    },
)


class RuleEngine:
    """Evaluates rules over observations and returns the claims they support."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self._rules = [dict(rule) for rule in (rules if rules is not None else DEFAULT_RULES)]
        self.skipped: list[tuple[str, str]] = []

    def rule_ids(self) -> list[str]:
        return [str(rule.get("id", "")) for rule in self._rules]

    def evaluate(self, observations: Sequence[Observation]) -> list[Claim]:
        claims: list[Claim] = []
        for rule in self._rules:
            try:
                claims.extend(self._evaluate_rule(rule, observations))
            except (KeyError, IndexError, ValueError) as exc:
                # A rule whose template disagrees with the observation it matched is a rule bug.
                # It is recorded and skipped rather than crashing a run that is otherwise fine, but
                # it is never silently swallowed: the report and the tests can both see it.
                self.skipped.append((str(rule.get("id", "?")), str(exc)))
        return claims

    # -- shapes --------------------------------------------------------------------------

    def _evaluate_rule(self, rule: dict[str, Any], observations: Sequence[Observation]) -> list[Claim]:
        if "requires_kinds" in rule:
            claim = self._cross_source(rule, observations)
            return [claim] if claim is not None else []
        kind = rule.get("kind")
        if not kind:
            return []
        out: list[Claim] = []
        for observation in observations:
            if observation.kind != kind:
                continue
            if not self._matches(rule, observation):
                continue
            out.append(self._claim(rule, observation))
        return out

    @staticmethod
    def _matches(rule: dict[str, Any], observation: Observation) -> bool:
        value = observation.value or {}
        for field, expected in (rule.get("requires") or {}).items():
            if value.get(field) != expected:
                return False
        for field, expected in (rule.get("requires_contains") or {}).items():
            actual = value.get(field)
            if not isinstance(actual, list) or expected not in actual:
                return False
        return True

    def _claim(self, rule: dict[str, Any], observation: Observation) -> Claim:
        value = dict(observation.value or {})
        value.setdefault("observation", observation.id)
        return Claim(
            id=new_id("c"),
            statement=str(rule["statement"]).format(**value),
            assertion=rule.get("assertion", "rule_derived"),
            rule_id=str(rule.get("id", "")),
            supports=[observation.id],
            contradicts=[],
            confidence=rule.get("confidence", "medium"),
            confidence_basis=str(rule.get("confidence_basis", "")),
            caveats=list(rule.get("caveats") or []),
        )

    def _cross_source(self, rule: dict[str, Any], observations: Sequence[Observation]) -> Claim | None:
        groups: dict[str, list[Observation]] = {}
        for group, kinds in (rule.get("requires_kinds") or {}).items():
            hits = [obs for obs in observations if obs.kind in kinds]
            if not hits:
                return None
            groups[str(group)] = hits
        context: dict[str, Any] = {
            f"{group}_count": len(hits) for group, hits in groups.items()
        }
        # Supports are ordered scan-first so the claim reads as the correlation it is: the scan
        # established reachability, the logs established activity.
        supports: list[str] = []
        for group in sorted(groups):
            supports.extend(obs.id for obs in groups[group])
        return Claim(
            id=new_id("c"),
            statement=str(rule["statement"]).format(**context),
            assertion=rule.get("assertion", "rule_derived"),
            rule_id=str(rule.get("id", "")),
            supports=supports,
            contradicts=[],
            confidence=rule.get("confidence", "medium"),
            confidence_basis=str(rule.get("confidence_basis", "")),
            caveats=list(rule.get("caveats") or []),
        )


def claims_by_rule(claims: Iterable[Claim]) -> dict[str, list[Claim]]:
    out: dict[str, list[Claim]] = {}
    for claim in claims:
        out.setdefault(claim.rule_id or "unattributed", []).append(claim)
    return out
