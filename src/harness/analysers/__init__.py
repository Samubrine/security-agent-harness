"""Deterministic analysis: rules, offline vulnerability matching, correlation.

Nothing in this package consults a model. Decision D5 keeps finding construction here precisely so
that a claim's provenance can be read off the code that produced it.
"""

from __future__ import annotations

from harness.analysers.correlate import Correlator
from harness.analysers.cve_match import (
    CveCandidate,
    VulnerabilitySnapshot,
    candidate_cves,
    cpe_from_observation,
    extract_cpes,
    parse_cpe,
    severity_from_cvss,
    version_key,
)
from harness.analysers.rules import RuleEngine

__all__ = [
    "Correlator",
    "CveCandidate",
    "RuleEngine",
    "VulnerabilitySnapshot",
    "candidate_cves",
    "cpe_from_observation",
    "extract_cpes",
    "parse_cpe",
    "severity_from_cvss",
    "version_key",
]
