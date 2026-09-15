"""Typed errors. Every failure the spine can produce is one of these.

The runtime never catches bare ``Exception``; a typed error is how the FSM decides
whether a step is retryable, degradable into an ``EvidenceGap``, or fatal.
"""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for every harness error."""


class ConfigError(HarnessError):
    """Invalid or missing configuration."""


class ScopeError(HarnessError):
    """Scope record missing, malformed, expired, or unsigned."""


class ScopeSignatureError(ScopeError):
    """The scope record's signature did not verify."""


class GrantError(HarnessError):
    """Grant is unknown, expired, revoked, or does not cover the request."""


class ProposalValidationError(HarnessError):
    """A model proposal failed schema, catalogue, grant, or argument validation."""


class PolicyDenied(HarnessError):
    """Policy denied the invocation. Not retryable without new authority."""


class ApprovalRejected(HarnessError):
    """A human rejected an ``ask`` verdict. Terminal for that invocation."""


class NecessityDenied(HarnessError):
    """The necessity gate refused to spend budget on a provider call."""


class ProviderError(HarnessError):
    """A provider failed before producing usable output."""


class ProviderTimeout(ProviderError):
    """A provider exceeded its enforced timeout."""


class ParserError(HarnessError):
    """A deterministic parser could not read an artifact."""


class EvidenceError(HarnessError):
    """An evidence span could not be recomputed from its artifact."""


class ValidationError(HarnessError):
    """A finding violated a provenance invariant and was rejected."""


class BudgetExhausted(HarnessError):
    """A hard run budget was reached. Terminates the run cleanly with a gap."""


class EventChainError(HarnessError):
    """The append-only event hash chain did not verify."""


class ReplayError(HarnessError):
    """A recorded run could not be replayed faithfully."""


class ModelClientError(HarnessError):
    """The local model endpoint was unreachable or returned an unusable response."""


class EgressViolation(HarnessError):
    """A context class that must stay local was about to leave the machine."""
