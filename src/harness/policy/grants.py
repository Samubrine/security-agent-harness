"""Capability grants: the only bridge from "authorised" to "nameable".

The design's structural move is that a tool receives a **grant**, never a target. A model can
hold a grant id; it cannot forge one, and it cannot write "10.77.0.99" anywhere that would be
resolved into a host, because hosts are addressed by alias and aliases exist only for resources
the signed scope actually covers.

What that buys, concretely:

* an out-of-scope host has no name, so touching it is not a policy decision but a validation
  error that happens before the policy engine runs;
* authority is bounded (`capabilities`) and expiring (`expires_at`), so a read-only
  banner tool cannot inherit `net.raw` from the run;
* every grant carries `origin` - the digest of the signed scope that authorised it - so
  "under whose authority did this run act?" is a graph query rather than an interview.

Note the deliberate asymmetry on networks: an alias must name an IP that a scope network lists in
`include`. The CIDR alone is not enough. The lab's decoy (10.77.0.99) sits inside
10.77.0.0/24 but outside the include list, which is exactly why it can never be named.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from pathlib import Path

from harness.errors import GrantError, ScopeError
from harness.models import Grant, ScopeFile, ScopeNetwork
from harness.util import canonical_json, iso, new_id, safe_relpath, sha256_json, sha256_text, utcnow

#: Capabilities are derived from what the resource *is*, not from what a caller asks for. A
#: network resource can be connected to, raw-socketed and TLS-handshaked; a filesystem resource
#: can only be read. Nothing here is negotiable from model output.
_CAPABILITIES_BY_KIND: dict[str, tuple[str, ...]] = {
    "net": ("net.connect", "net.raw", "net.tls"),
    "fs": ("fs.read",),
}


class GrantBook:
    """The run's minted grants, queryable by id or by the alias the model is allowed to use."""

    def __init__(self, grants: list[Grant]) -> None:
        self._grants = list(grants)
        self._by_id: dict[str, Grant] = {}
        for grant in self._grants:
            if grant.id in self._by_id:
                # Duplicate ids would make "which grant did this execution use?" ambiguous in the
                # provenance graph, which is worse than refusing to start.
                raise GrantError(f"duplicate grant id {grant.id}")
            self._by_id[grant.id] = grant

    @property
    def grants(self) -> list[Grant]:
        """Grants in mint order. Returned as a copy so a caller cannot edit the run's authority."""
        return list(self._grants)

    def by_alias(self, alias: str) -> list[Grant]:
        """Every grant a model-facing alias resolves to (a list, because aliases are not unique)."""
        return [g for g in self._grants if g.alias == alias]

    def get(self, grant_id: str) -> Grant:
        """The grant with this id, or a GrantError if there is none."""
        try:
            return self._by_id[grant_id]
        except (KeyError, TypeError) as exc:
            # A non-string id is a malformed proposal, not an internal bug: both become GrantError
            # so the policy engine can degrade to "deny" instead of raising.
            raise GrantError(f"unknown grant {grant_id!r}") from exc

    def require(self, grant_id: str, capability: str, when: datetime | None = None) -> Grant:
        """Return the grant if it currently covers `capability`; else raise.

        This is the second of the two checks the design calls "defence in depth": the catalogue
        was already filtered by grant, and the runner re-checks here at execution time.
        """
        at = when if when is not None else utcnow()
        if at.tzinfo is None:
            raise GrantError("grant check timestamp must be timezone-aware")
        grant = self.get(grant_id)
        if at > grant.expires_at:
            raise GrantError(f"grant {grant.id} expired at {grant.expires_at.isoformat()}")
        if capability not in grant.capabilities:
            raise GrantError(
                f"grant {grant.id} for {grant.alias} does not include capability {capability!r}"
            )
        return grant

    def catalogue_for(self, capability: str) -> list[str]:
        """Aliases that can serve `capability` right now, sorted for stable prompts.

        Expired grants are excluded: offering the model a name that policy will refuse is just a
        guaranteed wasted step.
        """
        at = utcnow()
        aliases = {g.alias for g in self._grants if g.covers(capability, at)}
        return sorted(aliases)

    def digest(self) -> str:
        """Stable digest of the whole book, for run records and replay comparison."""
        payload = [g.model_dump(mode="json") for g in sorted(self._grants, key=lambda g: g.id)]
        return f"sha256:{sha256_text(canonical_json(payload))}"


def mint_from_scope(
    scope: ScopeFile,
    *,
    run_id: str,
    ttl_s: int = 3600,
    now: datetime | None = None,
) -> GrantBook:
    """Turn a loaded scope record into one expiring grant per alias.

    Refusing an out-of-scope alias here - rather than letting a tool discover it later - is the
    difference between "the decoy host is discouraged" and "the decoy host is unnameable". Every
    alias is validated against the scope's networks/filesystem, and validation failures are
    ScopeError, never warnings.
    """
    when = now if now is not None else utcnow()
    if when.tzinfo is None:
        raise ScopeError("grant mint timestamp must be timezone-aware")
    # A grant may not outlive the authority it was minted from. The window is evaluated once, at
    # load, so `now + ttl` could otherwise extend past it and leave a call possible after the scope
    # had expired (R2-09).
    if when > scope.window.to:
        raise ScopeError(
            f"scope {scope.scope_id} expired at {iso(scope.window.to)}; refusing to mint grants "
            "under a window that has already closed"
        )
    expires_at = min(when + timedelta(seconds=ttl_s), scope.window.to)
    origin = _grant_origin(scope, run_id)

    grants: list[Grant] = []
    for alias in sorted(scope.aliases):
        resource = scope.aliases[alias]
        kind, value = _split_resource(alias, resource)
        ports: list[int] | None = None
        if kind == "net":
            network = _authorising_network(scope, alias, value)
            # The window travels with the network that authorises the host, which is where the scope
            # states it. `None` keeps the pre-v1.2 behaviour: the scope says nothing about ports, so
            # the grant does not constrain them (R2-05).
            ports = list(network.ports) if network.ports is not None else None
        else:
            _require_authorised_path(scope, alias, value)
        grants.append(
            Grant(
                id=new_id("g"),
                resource=resource,
                alias=alias,
                capabilities=list(_CAPABILITIES_BY_KIND[kind]),
                ports=ports,
                expires_at=expires_at,
                origin=origin,
                kind=kind,
            )
        )
    return GrantBook(grants)


def _split_resource(alias: str, resource: str) -> tuple[str, str]:
    """Parse net:<ip> / fs:<path>, refusing any other scheme.

    An unknown scheme is refused rather than ignored: a scope file inventing "smb:" or "ssh:"
    must not silently mint a grant whose capabilities nobody defined.
    """
    if not isinstance(resource, str) or ":" not in resource:
        raise ScopeError(f"alias {alias!r} resource {resource!r} is not '<kind>:<value>'")
    prefix, value = resource.split(":", 1)
    kind = prefix.strip().lower()
    if kind not in _CAPABILITIES_BY_KIND:
        raise ScopeError(f"alias {alias!r} uses unsupported resource kind {prefix!r}")
    if not value:
        raise ScopeError(f"alias {alias!r} has an empty resource value")
    return kind, value


def _authorising_network(scope: ScopeFile, alias: str, value: str) -> ScopeNetwork:
    """The network that authorises this alias, or a ScopeError.

    Returns the network rather than a bool because the network carries the rest of what is being
    authorised for those hosts - its port window - and re-deriving which network matched would be a
    second implementation of this check (R2-05).
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ScopeError(f"alias {alias!r} names {value!r}, which is not an IP address") from exc
    for network in scope.networks:
        try:
            cidr = ipaddress.ip_network(network.cidr, strict=False)
        except ValueError as exc:
            raise ScopeError(f"scope {scope.scope_id} network {network.cidr!r} is not a CIDR") from exc
        if ip not in cidr:
            continue
        for entry in network.include:
            try:
                allowed = ipaddress.ip_address(entry)
            except ValueError as exc:
                # A hostname in an allowlist cannot be compared structurally and would invite a
                # DNS re-resolution at execution time; that is a scope bug, not a warning.
                raise ScopeError(
                    f"scope {scope.scope_id} include entry {entry!r} is not an IP address"
                ) from exc
            if allowed == ip:
                return network
    raise ScopeError(
        f"alias {alias!r} names {value}, which the scope {scope.scope_id} does not include"
    )


def _require_authorised_path(scope: ScopeFile, alias: str, value: str) -> None:
    """The path must resolve inside one of the scope's filesystem roots."""
    if not scope.filesystem:
        raise ScopeError(
            f"alias {alias!r} names filesystem path {value!r} but the scope grants no paths"
        )
    for root in scope.filesystem:
        try:
            safe_relpath(Path(root), Path(value))
        except ValueError:
            continue
        return
    raise ScopeError(f"alias {alias!r} names {value!r}, which escapes the scope's filesystem roots")


def _grant_origin(scope: ScopeFile, run_id: str) -> str:
    """The authority chain recorded on every grant: scope id, scope digest, signature digest.

    The scope digest is taken over the signed payload, so a grant cannot be traced back to a scope
    record that has since been edited; the signature digest distinguishes "signed by
    project-owner" from "loaded with allow_unsigned in a test".
    """
    payload_digest = sha256_json(scope.signing_payload())
    signature_digest = sha256_text(scope.signature) if scope.signature else "unsigned"
    return (
        f"scope:{scope.scope_id}:payload:sha256:{payload_digest}:"
        f"sig:sha256:{signature_digest}:run:{run_id}"
    )
