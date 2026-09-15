"""Finding construction and validation.

Findings are assembled here from claims and matcher output, never from model prose (D5), and every
one of them has to survive :func:`harness.findings.validate.validate_all` before it reaches a
report.
"""

from __future__ import annotations

from harness.findings.builder import build_findings
from harness.findings.validate import ValidationResult, validate_all, validate_finding

__all__ = ["ValidationResult", "build_findings", "validate_all", "validate_finding"]
