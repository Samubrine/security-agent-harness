"""Tests for capability grants minted from a scope record.

The security property is that authority is *derived and bounded*: every alias maps to a resource
the scope covers, every resource yields a fixed capability set, and every grant expires. A test
that only checked "three grants were returned" would pass with the decoy host in the book.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from harness.errors import GrantError, ScopeError
from harness.models import Grant, ScopeFile, ScopeNetwork, ScopeWindow
from harness.policy import GrantBook, generate_keypair, mint_from_scope, sign_scope
from harness.util import utcnow


def make_scope(*, aliases: dict[str, str] | None = None, filesystem: list[str] | None = None) -> ScopeFile:
    now = utcnow()
    return ScopeFile(
        scope_id="lab-test",
        authorized_by="project-owner",
        networks=[ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11", "10.77.0.12"])],
        filesystem=["/lab/logs"] if filesystem is None else filesystem,
        aliases=aliases
        if aliases is not None
        else {
            "lab-web-01": "net:10.77.0.11",
            "lab-web-02": "net:10.77.0.12",
            "lab-logs": "fs:/lab/logs",
        },
        window=ScopeWindow(from_at=now - timedelta(hours=1), to=now + timedelta(hours=1)),
    )


def signing_key(tmp_path: Path, name: str = "scope") -> Path:
    priv = tmp_path / f"{name}.key"
    generate_keypair(priv, tmp_path / f"{name}.pub")
    return priv


def signed_scope(tmp_path: Path, *, name: str = "scope", **kw) -> ScopeFile:
    return sign_scope(make_scope(**kw), signing_key(tmp_path, name))


FIXED_EXPIRY = utcnow() + timedelta(hours=1)


def fixed_grant(**overrides) -> Grant:
    base: dict = {
        "id": "g-fixed1",
        "resource": "net:10.77.0.11",
        "alias": "lab-web-01",
        "capabilities": ["net.connect"],
        "ports": None,
        "expires_at": FIXED_EXPIRY,
        "origin": "scope:lab-test:payload:sha256:x:sig:sha256:y:run:r1",
        "kind": "net",
    }
    base.update(overrides)
    return Grant(**base)


def test_mint_creates_one_grant_per_alias_with_derived_capabilities(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1")

    assert sorted(g.alias for g in book.grants) == ["lab-logs", "lab-web-01", "lab-web-02"]
    by_alias = {g.alias: g for g in book.grants}
    assert by_alias["lab-web-01"].resource == "net:10.77.0.11"
    assert by_alias["lab-web-01"].kind == "net"
    assert by_alias["lab-web-01"].capabilities == ["net.connect", "net.raw", "net.tls"]
    assert by_alias["lab-logs"].resource == "fs:/lab/logs"
    assert by_alias["lab-logs"].kind == "fs"
    # A filesystem grant must not inherit raw network authority, which is the whole point of
    # deriving capabilities from the resource kind rather than from what the caller asks for.
    assert by_alias["lab-logs"].capabilities == ["fs.read"]
    assert all(g.id.startswith("g-") for g in book.grants)
    assert len({g.id for g in book.grants}) == 3


def test_grants_expire_at_the_minted_ttl(tmp_path: Path) -> None:
    now = utcnow()
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1", ttl_s=60, now=now)
    grant = book.by_alias("lab-web-01")[0]
    assert grant.expires_at == now + timedelta(seconds=60)
    assert book.require(grant.id, "net.connect", when=now) is grant
    with pytest.raises(GrantError):
        book.require(grant.id, "net.connect", when=now + timedelta(seconds=61))


def test_an_expired_book_offers_no_catalogue_entries(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1", ttl_s=-1)
    assert book.catalogue_for("net.connect") == []
    with pytest.raises(GrantError) as excinfo:
        book.require(book.by_alias("lab-web-01")[0].id, "net.connect")
    assert "expired" in str(excinfo.value)


@pytest.mark.parametrize(
    ("alias", "resource"),
    [
        ("lab-decoy", "net:10.77.0.99"),       # inside the CIDR, absent from the include list
        ("lab-elsewhere", "net:192.168.1.5"),  # inside no network at all
        ("lab-gateway", "net:10.77.0.1"),      # a real host on the segment that was never granted
    ],
)
def test_aliases_outside_the_authorised_networks_are_refused(
    tmp_path: Path, alias: str, resource: str
) -> None:
    # If any of these mints, the out-of-scope host becomes nameable and the design's central
    # claim - that crossing the boundary has no syntax - is false.
    scope = signed_scope(tmp_path, aliases={alias: resource})
    with pytest.raises(ScopeError):
        mint_from_scope(scope, run_id="run-1")


def test_the_include_list_is_the_allowlist_not_the_cidr(tmp_path: Path) -> None:
    # A host that is both included and inside the CIDR is authorised: this proves the check is a
    # real membership test rather than "reject anything unusual".
    scope = make_scope(aliases={"lab-app-03": "net:10.77.0.13"})
    scope.networks = [ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.13"])]
    book = mint_from_scope(sign_scope(scope, signing_key(tmp_path)), run_id="run-1")
    assert [(g.alias, g.resource) for g in book.grants] == [("lab-app-03", "net:10.77.0.13")]


def test_an_include_entry_outside_its_own_cidr_authorises_nothing(tmp_path: Path) -> None:
    # An internally inconsistent scope must not widen authority: the IP has to be inside the CIDR
    # *and* in the include list, so listing it in include is not enough on its own.
    scope = make_scope(aliases={"rogue": "net:10.99.0.50"})
    scope.networks = [ScopeNetwork(cidr="10.77.0.0/24", include=["10.99.0.50"])]
    with pytest.raises(ScopeError):
        mint_from_scope(sign_scope(scope, signing_key(tmp_path)), run_id="run-1")


def test_aliases_that_are_not_ip_literals_or_known_schemes_are_refused(tmp_path: Path) -> None:
    bad_aliases = {
        "hostname-instead-of-ip": "net:lab-web-01.internal",
        "unknown-scheme": "smb:lab-web-01",
        "missing-scheme": "10.77.0.11",
        "empty-resource": "net:",
    }
    for name, resource in bad_aliases.items():
        scope = signed_scope(tmp_path, name=name, aliases={name: resource})
        with pytest.raises(ScopeError):
            mint_from_scope(scope, run_id="run-1")


def test_a_hostname_in_the_scope_include_list_is_a_scope_error(tmp_path: Path) -> None:
    scope = make_scope(aliases={"lab-web-01": "net:10.77.0.11"})
    scope.networks = [ScopeNetwork(cidr="10.77.0.0/24", include=["lab-web-01.lab"])]
    # A hostname cannot be compared structurally and would invite a DNS re-resolution at
    # execution time, so the scope is refused rather than resolved.
    with pytest.raises(ScopeError):
        mint_from_scope(sign_scope(scope, signing_key(tmp_path)), run_id="run-1")


def test_filesystem_aliases_cannot_escape_the_granted_roots(tmp_path: Path) -> None:
    escapes = {
        "passwd": "fs:/etc/passwd",
        "sibling": "fs:/lab/logs-evil",
        "traversal": "fs:/lab/logs/../../etc/shadow",
    }
    for name, resource in escapes.items():
        scope = signed_scope(tmp_path, name=name, aliases={"sneaky": resource})
        with pytest.raises(ScopeError):
            mint_from_scope(scope, run_id="run-1")

    inside = signed_scope(tmp_path, name="inside", aliases={"nginx-logs": "fs:/lab/logs/nginx/access.log"})
    assert mint_from_scope(inside, run_id="run-1").grants[0].capabilities == ["fs.read"]


def test_a_filesystem_alias_with_no_granted_root_is_refused(tmp_path: Path) -> None:
    scope = signed_scope(tmp_path, aliases={"lab-logs": "fs:/lab/logs"}, filesystem=[])
    with pytest.raises(ScopeError):
        mint_from_scope(scope, run_id="run-1")


def test_require_rejects_a_capability_the_grant_does_not_include(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1")
    logs = book.by_alias("lab-logs")[0]
    with pytest.raises(GrantError) as excinfo:
        book.require(logs.id, "net.raw")
    assert "does not include" in str(excinfo.value)
    assert book.require(logs.id, "fs.read").alias == "lab-logs"


def test_unknown_grant_ids_are_grant_errors(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1")
    for bogus in ("", "g-does-not-exist", None, 17):
        with pytest.raises(GrantError):
            book.get(bogus)  # type: ignore[arg-type]


def test_catalogue_lists_only_aliases_that_can_serve_the_capability(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1")
    assert book.catalogue_for("net.connect") == ["lab-web-01", "lab-web-02"]
    assert book.catalogue_for("net.raw") == ["lab-web-01", "lab-web-02"]
    assert book.catalogue_for("fs.read") == ["lab-logs"]
    assert book.catalogue_for("vulnerability.match") == []


def test_grants_property_returns_a_copy(tmp_path: Path) -> None:
    book = mint_from_scope(signed_scope(tmp_path), run_id="run-1")
    book.grants.clear()
    # A caller must not be able to delete the run's authority through a property accessor.
    assert len(book.grants) == 3


def test_origin_records_the_authority_chain(tmp_path: Path) -> None:
    scope = signed_scope(tmp_path)
    origin = mint_from_scope(scope, run_id="run-42").grants[0].origin
    assert origin.startswith("scope:lab-test:payload:sha256:")
    assert ":sig:sha256:" in origin
    assert origin.endswith(":run:run-42")
    # An unsigned development scope is visibly unsigned in the provenance chain.
    unsigned = mint_from_scope(make_scope(), run_id="run-42").grants[0].origin
    assert ":sig:sha256:unsigned:" in unsigned
    # A different run id, or an edited scope, produces a different authority chain.
    assert mint_from_scope(scope, run_id="run-43").grants[0].origin != origin


def test_digest_is_stable_and_sensitive_to_any_grant_change() -> None:
    assert GrantBook([fixed_grant()]).digest() == GrantBook([fixed_grant()]).digest()
    weaker = GrantBook([fixed_grant(capabilities=["net.connect", "net.raw"])])
    assert weaker.digest() != GrantBook([fixed_grant()]).digest()
    longer = GrantBook([fixed_grant(expires_at=FIXED_EXPIRY + timedelta(days=2))])
    assert longer.digest() != GrantBook([fixed_grant()]).digest()


def test_duplicate_grant_ids_are_refused() -> None:
    with pytest.raises(GrantError):
        GrantBook([fixed_grant(), fixed_grant()])


def test_minting_the_same_scope_twice_yields_the_same_authority(tmp_path: Path) -> None:
    scope = signed_scope(tmp_path)
    first = mint_from_scope(scope, run_id="run-1")
    second = mint_from_scope(scope, run_id="run-1")
    # Grant ids are random by design, but the *authority* they carry must be identical, or two
    # runs over the same scope would offer the model different capabilities.
    shape = lambda book: sorted(  # noqa: E731 - a one-line projection reads better than a def
        (g.alias, g.resource, tuple(g.capabilities), g.origin) for g in book.grants
    )
    assert shape(first) == shape(second)
