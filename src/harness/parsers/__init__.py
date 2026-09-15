"""Deterministic parsers: raw provider bytes in, evidence-bound observations out.

A parser is the boundary where a security claim stops being text and starts being structured
state. Every parser here shares the guarantees implemented once in
:mod:`harness.parsers.registry`: spans are located in the artifact's real bytes, observations are
stamped with the execution that produced them, and attacker-controlled prose is screened for
instructions rather than followed.
"""

from __future__ import annotations

from harness.parsers.registry import ParseContext, ParseResult, ParserRegistry, injection_observations

__all__ = [
    "ParseContext",
    "ParseResult",
    "ParserRegistry",
    "injection_observations",
]
