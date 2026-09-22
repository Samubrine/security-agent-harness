"""Authorisation gaps the round-2 audit proved by executing them (WS-06: R2-05 … R2-09, R2-32).

Five claims, each of which was a *silent* absence rather than a bug in a check: port-level authority
did not exist (`Grant.ports` was always `None`), the trust anchor was optional on every documented
path, `scope.dry_run` was signed and unread, a grant could outlive the window it was minted from, and
a naive timestamp in the window escaped as a `TypeError` instead of a refusal.

Each test fails if the corresponding enforcement disappears. Where the property is "something is
refused", the companion case next to it proves the refusal is about the property and not about the
call being impossible in the first place.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from harness.errors import ConfigError, ScopeError
from harness.models import PAYLOAD_VERSION, ScopeFile, ScopeNetwork, ScopeWindow
from harness.policy.engine import PolicyEngine, REASON_ARGUMENTS_INVALID, REASON_PORTS_NOT_GRANTED
from harness.policy.grants import mint_from_scope
from harness.policy.ports import all_within, parse_port_spec, render_window
from harness.policy.scope import generate_keypair, load_scope, sign_scope
from harness.providers.native.nmap import NmapProvider
from harness.runtime.capabilities import with_logical_capabilities
from harness.runtime.runner import execute_run
from harness.util import atomic_write_json, read_json, read_jsonl, utcnow


def _scope(*, ports: list[int] | None = None, dry_run: bool = False, naive_window: bool = False) -> ScopeFile:
    now = utcnow()
    window = ScopeWindow(**{"from": now - timedelta(minutes=5), "to": now + timedelta(hours=1)})
    if naive_window:
        window = ScopeWindow(**{"from": now.replace(tzinfo=None), "to": now + timedelta(hours=1)})
    return ScopeFile(
        scope_id="lab-authority",
        authorized_by="pytest",
        networks=[ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11"], ports=ports)],
        aliases={"lab-web-01": "net:10.77.0.11"},
        window=window,
        dry_run=dry_run,
        # A record carrying a field only a later payload covers has to declare that payload version;
        # `sign_scope` stamps it on the way out, and building one by hand is declaring it.
        payload_version=PAYLOAD_VERSION,
    )


def _book(tmp_path: Path, scope: ScopeFile):
    private, public = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(private, public)
    path = tmp_path / "scope.json"
    atomic_write_json(path, sign_scope(scope, private).model_dump(mode="json"))
    loaded = load_scope(path, public_key_path=public)
    return with_logical_capabilities(mint_from_scope(loaded, run_id="run-authority")), public


def _decide(book, args: dict):
    grant = book.grants[0]
    return PolicyEngine(book).decide(
        provider=NmapProvider().spec,
        capability="service.enumerate",
        grant_id=grant.id,
        args=args,
        taint="T1",
    )


# ---------------------------------------------------------------------------------------------
# R2-05 — port-level authorisation
# ---------------------------------------------------------------------------------------------


def test_the_scope_port_window_is_minted_onto_the_grant(tmp_path: Path) -> None:
    book, _ = _book(tmp_path, _scope(ports=[443, 80]))
    assert book.grants[0].ports == [80, 443], "the window did not reach the grant"


def test_a_call_outside_the_port_window_is_denied(tmp_path: Path) -> None:
    """A scope authorising 80 and 443 denies a scan of every port, and names why."""
    book, _ = _book(tmp_path, _scope(ports=[80, 443]))

    denial = _decide(book, {"ports": "1-65535"})
    assert denial.verdict == "deny"
    assert REASON_PORTS_NOT_GRANTED in denial.reasons

    allowed = _decide(book, {"ports": "80,443"})
    assert allowed.verdict == "allow", allowed.reasons
    assert REASON_PORTS_NOT_GRANTED not in allowed.reasons


def test_a_call_naming_no_ports_is_denied_when_a_window_exists(tmp_path: Path) -> None:
    """The provider would pick its own default set, which the window never authorised."""
    book, _ = _book(tmp_path, _scope(ports=[80, 443]))
    denial = _decide(book, {"profile": "service_detection"})
    assert denial.verdict == "deny"
    assert REASON_PORTS_NOT_GRANTED in denial.reasons


def test_a_scope_without_a_port_window_keeps_the_old_behaviour(tmp_path: Path) -> None:
    """The documented compatibility case: silence about ports is not a restriction."""
    book, _ = _book(tmp_path, _scope())
    assert book.grants[0].ports is None
    assert _decide(book, {"ports": "1-65535"}).verdict == "allow"


def test_the_denial_is_recorded_in_the_run(tmp_path: Path, lab_environment, monkeypatch) -> None:
    """A decision that produced no execution is only visible in the record, so it has to be there.

    The catalogue is made to offer a port specification the scope does not authorise, which is the
    case R2-05 is about: a model-supplied `args.ports` reaching further than the window. Without that,
    the catalogue offers the window itself and the call is simply allowed - which is the other half of
    the same design.
    """
    from harness.runtime import loop as loop_module

    monkeypatch.setitem(
        loop_module.CATALOGUE_EXPECTATIONS["service.enumerate"], "args", {"ports": "1-65535"}
    )
    scope = _scope(ports=[80])
    private, public = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(private, public)
    path = tmp_path / "scope.json"
    atomic_write_json(path, sign_scope(scope, private).model_dump(mode="json"))

    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-authority-ports",
            scope_path=path,
            public_key_path=public,
        )
    )
    decisions = read_jsonl(artifacts.run_dir / "policy-decisions.jsonl")
    assert any(REASON_PORTS_NOT_GRANTED in row["reasons"] for row in decisions), decisions


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", [(80, 80)]),
        ("80,443", [(80, 80), (443, 443)]),
        ("1-65535", [(1, 65535)]),
        ("22,8000-8010", [(22, 22), (8000, 8010)]),
        (" 80 , 443 ", [(80, 80), (443, 443)]),
        ("", None),
        ("garbage", None),
        ("443-80", None),
        ("0", None),
        ("70000", None),
        ("80,,443", None),
    ],
)
def test_the_port_grammar_is_the_one_operators_write(spec: str, expected) -> None:
    assert parse_port_spec(spec) == expected


def test_the_window_renders_consecutive_ports_as_ranges() -> None:
    assert render_window([443, 80, 81, 82]) == "80-82,443"
    assert all_within("80-82", [80, 81, 82]) is True
    assert all_within("80-83", [80, 81, 82]) is False


# ---------------------------------------------------------------------------------------------
# R2-06 — the trust anchor
# ---------------------------------------------------------------------------------------------


def test_a_run_without_a_trust_anchor_is_refused(lab_environment) -> None:
    """Without an anchor the scope vouches for itself, which is not authorisation."""
    with pytest.raises(ConfigError) as refusal:
        execute_run(
            lab_environment.request(
                objective="Enumerate exposed services on lab-web-01.",
                skill="port_scan",
                target_alias="lab-web-01",
                run_id="run-authority-none",
                public_key_path=None,
            )
        )
    assert "trust anchor" in str(refusal.value)


def test_the_embedded_key_mode_is_explicit_and_recorded(lab_environment) -> None:
    """`--dev-embedded-key` is allowed, and the run says that is what it was."""
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-authority-selfsigned",
            public_key_path=None,
            dev_embedded_key=True,
        )
    )

    assert artifacts.summary.status == "completed"
    assert read_json(artifacts.run_dir / "run.json")["authority"] == "self-signed"
    authority = [row for row in read_jsonl(artifacts.run_dir / "events.jsonl") if row["type"] == "AUTHORITY_VERIFIED"]
    assert authority and authority[0]["data"]["authority"] == "self-signed"
    markdown = artifacts.report_markdown.read_text(encoding="utf-8")
    assert "Self-signed authority" in markdown
    assert "verified against the operator's public key" not in markdown


def test_an_anchored_run_records_the_anchor_fingerprint(lab_environment) -> None:
    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-authority-anchored",
        )
    )

    manifest = read_json(artifacts.run_dir / "run.json")
    assert manifest["authority"] == "anchored"
    assert len(manifest["anchor_fingerprint"]) == 64
    markdown = artifacts.report_markdown.read_text(encoding="utf-8")
    assert "verified against the operator's public key" in markdown
    assert "self-consistent" not in markdown


# ---------------------------------------------------------------------------------------------
# R2-08, R2-09, R2-32 — the rest of the authorisation record
# ---------------------------------------------------------------------------------------------


def test_a_scope_marked_dry_run_can_never_execute(tmp_path: Path, lab_environment) -> None:
    """`dry_run` is part of the signed payload and was read by nothing, so a rehearsal ran for real."""
    scope = _scope(dry_run=True)
    private, public = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(private, public)
    path = tmp_path / "scope.json"
    atomic_write_json(path, sign_scope(scope, private).model_dump(mode="json"))

    artifacts = execute_run(
        lab_environment.request(
            objective="Enumerate exposed services on lab-web-01.",
            skill="port_scan",
            target_alias="lab-web-01",
            run_id="run-authority-dry",
            scope_path=path,
            public_key_path=public,
        )
    )

    assert artifacts.summary.provider_calls == 0
    assert read_json(artifacts.run_dir / "run.json")["dry_run"] is True


def test_a_grant_cannot_outlive_the_scope_window(tmp_path: Path) -> None:
    """The window is evaluated once, at load, so the ttl had to be bounded by it."""
    scope = _scope()
    scope.window = ScopeWindow(
        **{"from": utcnow() - timedelta(minutes=5), "to": utcnow() + timedelta(minutes=10)}
    )
    # A ttl longer than what is left of the window.
    book = mint_from_scope(scope, run_id="run-authority-ttl", ttl_s=3600)
    assert all(grant.expires_at <= scope.window.to for grant in book.grants)


def test_minting_under_a_closed_window_is_refused(tmp_path: Path) -> None:
    scope = _scope()
    scope.window = ScopeWindow(
        **{"from": utcnow() - timedelta(hours=2), "to": utcnow() - timedelta(hours=1)}
    )
    with pytest.raises(ScopeError) as refusal:
        mint_from_scope(scope, run_id="run-authority-closed")
    assert "closed" in str(refusal.value) or "expired" in str(refusal.value)


def test_a_naive_window_timestamp_is_a_scope_error_not_a_type_error() -> None:
    """It used to reach a datetime comparison and escape every handler as a bare TypeError."""
    with pytest.raises(ValueError) as refusal:
        _scope(naive_window=True)
    assert "timezone-aware" in str(refusal.value)


def test_a_naive_window_timestamp_in_a_file_is_refused_with_the_refusal_panel(tmp_path: Path) -> None:
    now = utcnow()
    path = tmp_path / "naive.json"
    path.write_text(
        json.dumps(
            {
                "scope_id": "lab-naive",
                "authorized_by": "pytest",
                "networks": [{"cidr": "10.77.0.0/24", "include": ["10.77.0.11"]}],
                "aliases": {"lab-web-01": "net:10.77.0.11"},
                "window": {
                    "from": now.replace(tzinfo=None).isoformat(),
                    "to": (now + timedelta(hours=1)).isoformat(),
                },
                "signature": None,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScopeError):
        load_scope(path, allow_unsigned=True)


# ---------------------------------------------------------------------------------------------
# R2-07 — the provider's declared argument schema
# ---------------------------------------------------------------------------------------------


def test_arguments_the_provider_does_not_declare_are_denied(tmp_path: Path) -> None:
    """`ProviderSpec.input_schema` was declared by every adapter and enforced nowhere."""
    book, _ = _book(tmp_path, _scope())

    denial = _decide(book, {"ports": "1-65535", "totally_unknown_arg": "junk"})
    assert denial.verdict == "deny"
    assert REASON_ARGUMENTS_INVALID in denial.reasons
    assert any("totally_unknown_arg" in reason for reason in denial.reasons)

    valid = _decide(book, {"profile": "service_detection"})
    assert valid.verdict == "allow", valid.reasons


def test_an_argument_of_the_wrong_type_is_denied(tmp_path: Path) -> None:
    book, _ = _book(tmp_path, _scope())
    denial = _decide(book, {"profile": 7})
    assert denial.verdict == "deny"
    assert REASON_ARGUMENTS_INVALID in denial.reasons
