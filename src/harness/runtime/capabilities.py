"""Binding between the two capability vocabularies in this system.

They exist for different reasons and conflating them is the mistake this module prevents.

* A **grant capability** (`net.connect`, `net.raw`, `net.tls`, `fs.read`) describes what the
  *resource* permits. It is derived from the signed scope and is never negotiated from model
  output. It is the vocabulary in which "a read-only banner tool cannot inherit `net.raw`" is
  even expressible.
* A **logical capability** (`service.enumerate`, `vulnerability.match`, `log.read`) is what a
  skill may ask for. It is resource-independent by design, which is what lets a second provider
  satisfy it without the planner changing.

The transport level stays authoritative and stays enforced in two places that do not consult the
model: the provider adapter, which is harness-authored and only ever declares the logical
capabilities it serves, and the policy risk table, which reads the provider's declared risk and
egress flag rather than its name.

Two consequences worth stating explicitly, because they are the reason this file exists rather
than a convention:

1. Adding a provider for an existing logical capability is a registration change and nothing
   else -- no binding edit, no planner edit.
2. A logical capability that no grant can serve is absent from the catalogue, so the model cannot
   request it at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from harness.models import Grant
from harness.policy.grants import GrantBook


@dataclass(frozen=True)
class Binding:
    """What a logical capability needs from a granted resource.

    ``resource_kind is None`` means the capability is a local derivation that reads no resource of
    its own (the offline CVE matcher is the only one today). Such a capability may borrow any
    grant in the run, because the grant is what proves the *run* is authorised, not what the call
    consumes.
    """

    name: str
    resource_kind: str | None
    transport: str | None
    intent_hint: str


BINDINGS: dict[str, Binding] = {
    "service.enumerate": Binding(
        "service.enumerate", "net", "net.connect", "enumerate exposed services"
    ),
    "http.probe": Binding("http.probe", "net", "net.connect", "probe HTTP endpoints"),
    "vulnerability.match": Binding(
        "vulnerability.match", None, None, "map observed versions to candidate CVEs"
    ),
    "log.read": Binding("log.read", "fs", "fs.read", "read a bounded log file"),
    "log.query": Binding("log.query", "fs", "fs.read", "query the parsed log corpus"),
}


def binding_for(capability: str) -> Binding:
    """Unknown capabilities get a binding that no grant satisfies, which means "not offerable"."""
    return BINDINGS.get(
        capability, Binding(capability, "unbound", None, capability)
    )


def grants_serving(capability: str, grants: Sequence[Grant]) -> list[Grant]:
    """Grants that authorise this logical capability, in the scope's own ordering."""
    binding = binding_for(capability)
    if capability not in BINDINGS:
        return []
    if binding.resource_kind is None:
        return list(grants)
    return [grant for grant in grants if grant.kind == binding.resource_kind]


def with_logical_capabilities(book: GrantBook) -> GrantBook:
    """Return a grant book whose grants also list the logical capabilities their resource serves.

    The transport capabilities are preserved rather than replaced: the audit question "what was
    this run authorised to touch?" is answered by the resource level, and the planner question
    "what may be asked for?" is answered by the logical level. Keeping both on the grant is what
    lets the policy engine's single membership check stay meaningful for either question.
    """
    expanded: list[Grant] = []
    for grant in book.grants:
        extra = [
            binding.name
            for binding in BINDINGS.values()
            if binding.resource_kind is None or binding.resource_kind == grant.kind
        ]
        merged = list(grant.capabilities)
        for name in extra:
            if name not in merged:
                merged.append(name)
        expanded.append(grant.model_copy(update={"capabilities": merged}))
    return GrantBook(expanded)


def required_transport(capability: str) -> str | None:
    """The resource-level capability a logical capability rides on, for the audit trail."""
    return binding_for(capability).transport
