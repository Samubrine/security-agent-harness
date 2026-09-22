"""Tests for the signed scope record.

The property under test is not "signing works" but "authority cannot be edited, borrowed or
expired into existence". Each test below fails if the corresponding refusal disappears, which is
the only reason the scope file can be called an authorisation record instead of configuration.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from harness.errors import ScopeError, ScopeSignatureError
from harness.models import PAYLOAD_VERSION, ScopeFile, ScopeNetwork, ScopeWindow
from harness.policy import generate_keypair, key_protection, load_scope, sign_scope, verify_scope
from harness.util import canonical_json, utcnow


def make_scope(
    *,
    starts=None,
    ends=None,
    aliases: dict[str, str] | None = None,
    networks: list[ScopeNetwork] | None = None,
) -> ScopeFile:
    now = utcnow()
    return ScopeFile(
        scope_id="lab-test",
        authorized_by="project-owner",
        networks=networks
        if networks is not None
        else [ScopeNetwork(cidr="10.77.0.0/24", include=["10.77.0.11", "10.77.0.12"])],
        filesystem=["/lab/logs"],
        aliases=aliases
        if aliases is not None
        else {"lab-web-01": "net:10.77.0.11", "lab-logs": "fs:/lab/logs"},
        window=ScopeWindow(
            from_at=starts if starts is not None else now - timedelta(hours=1),
            to=ends if ends is not None else now + timedelta(hours=1),
        ),
    )


def write_scope(path: Path, scope: ScopeFile) -> Path:
    path.write_text(
        json.dumps(scope.model_dump(mode="json", by_alias=True), indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def keypair(tmp_path: Path, name: str = "scope") -> tuple[Path, Path]:
    priv, pub = tmp_path / f"{name}.key", tmp_path / f"{name}.pub"
    generate_keypair(priv, pub)
    return priv, pub


def raw_public_b64(public_path: Path) -> str:
    key = serialization.load_pem_public_key(public_path.read_bytes())
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def test_generate_keypair_writes_pem_keys_and_protects_the_private_key(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    # A private signing key that anyone on the box can read is not a key, it is a suggestion. What
    # enforces that differs by platform: mode bits on POSIX, an explicit ACL on Windows, where
    # os.chmod only sets the read-only attribute - which is why asserting a mode there asserted
    # nothing (R1-11). `key_protection` reads the platform back instead of trusting the mode.
    assert key_protection(priv) == ("windows-acl" if os.name == "nt" else "posix-mode")
    if os.name != "nt":
        assert (priv.stat().st_mode & 0o777) == 0o600


def test_key_protection_reports_none_for_an_unprotected_key(tmp_path: Path) -> None:
    """The negative control for the test above: an ordinary file is not reported as protected."""
    loose = tmp_path / "loose.key"
    loose.write_bytes(b"not a key, but the same kind of file")
    assert key_protection(loose) == "none"


@pytest.mark.skipif(os.name != "nt", reason="the POSIX mode is the protection there")
def test_windows_key_protection_removes_inherited_access(tmp_path: Path) -> None:
    """The property, checked against the ACL itself rather than against the function that set it.

    A key created under an inherited ACL is readable by every account the parent directory grants
    access to, which is what the mode 0600 assertion silently accepted before. The permission
    markers icacls prints are the same in every installation, unlike the account names beside them.
    """
    priv, _ = keypair(tmp_path)
    entries = [
        line
        for line in subprocess.run(
            ["icacls", str(priv)], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        if ":(" in line
    ]
    assert len(entries) == 1, entries
    assert "(I)" not in entries[0], "the entry is inherited, so the parent's permissions still apply"


def test_a_rotated_key_is_still_protected(tmp_path: Path) -> None:
    """Rotation must not leave the new key behind with weaker protection than the old one."""
    priv, pub = keypair(tmp_path)
    generate_keypair(priv, pub, force=True)
    assert key_protection(priv) != "none"


def test_the_keypair_script_rotates_the_key_when_forced(tmp_path: Path) -> None:
    """The script's own message tells the operator to re-run with `--force`; that has to work.

    It did not: the script checked for the existing key itself and then called `generate_keypair`
    without `force`, so the refusal fired one level down as an uncaught ScopeError (R2-13).
    """
    from scripts.gen_scope_keypair import main as gen_main

    private, public = tmp_path / "keys" / "scope.key", tmp_path / "keys" / "scope.pub"
    assert gen_main(["--private-key", str(private), "--public-key", str(public)]) == 0
    first = public.read_bytes()

    # Negative control: without --force the same invocation must still refuse, or the test above
    # would pass for a script that overwrites unconditionally.
    with pytest.raises(SystemExit) as refusal:
        gen_main(["--private-key", str(private), "--public-key", str(public)])
    assert refusal.value.code == 2
    assert public.read_bytes() == first

    assert gen_main(["--private-key", str(private), "--public-key", str(public), "--force"]) == 0
    assert public.read_bytes() != first, "rotation produced the same key"
    assert key_protection(private) != "none"


def test_the_keypair_script_refuses_a_stale_public_key(tmp_path: Path) -> None:
    """A public key with no private key beside it is a half-deleted keypair.

    Replacing only the private half would pair a new key with the old anchor, so the mismatch
    `generate_keypair` refuses must not be reachable by the script passing `force`.
    """
    from scripts.gen_scope_keypair import main as gen_main

    private, public = tmp_path / "keys" / "scope.key", tmp_path / "keys" / "scope.pub"
    public.parent.mkdir(parents=True)
    public.write_bytes(b"-----BEGIN PUBLIC KEY-----\nstale\n")

    with pytest.raises(SystemExit) as refusal:
        gen_main(["--private-key", str(private), "--public-key", str(public)])
    assert refusal.value.code == 2
    assert public.read_bytes() == b"-----BEGIN PUBLIC KEY-----\nstale\n"
    assert not private.exists()


def test_generate_keypair_refuses_to_overwrite_existing_authority(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    before = priv.read_bytes()
    with pytest.raises(ScopeError):
        generate_keypair(priv, pub)
    # The old key must survive the attempt: rotating it silently would orphan every signed scope.
    assert priv.read_bytes() == before


def test_signed_scope_verifies_with_an_anchor_and_with_the_embedded_key(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    signed = sign_scope(make_scope(), priv)
    assert signed.signature and signed.signature_alg == "ed25519"
    assert signed.signer_public_key == raw_public_b64(pub)
    verify_scope(signed, pub)
    verify_scope(signed, None)


def test_signing_is_deterministic_over_the_canonical_payload(tmp_path: Path) -> None:
    priv, _ = keypair(tmp_path)
    scope = make_scope()
    first = sign_scope(scope, priv)
    second = sign_scope(scope, priv)
    # Ed25519 is deterministic: identical records produce identical signatures, which is what
    # lets a replay compare signature bytes rather than merely "some signature verified".
    assert first.signature == second.signature
    # The signed bytes are the canonical form of everything except the signature itself, at the
    # payload version the record was signed under. A record this build issues declares the current
    # version, so nothing it holds sits outside its signature.
    assert first.payload_version == PAYLOAD_VERSION
    payload = canonical_json(first.signing_payload())
    assert json.loads(payload).keys() == first.model_dump(mode="json").keys() - {"signature"}
    assert "signer_public_key" in payload


def test_an_older_record_is_verified_against_the_payload_shape_it_declares(tmp_path: Path) -> None:
    """Growing the model must not turn authority that was signed earlier into unverifiable bytes.

    The run frozen in `tests/fixtures/run/port_scan` is signed exactly this way, with a key that no
    longer exists to re-sign it: its payload has no `payload_version` and no network port window, so
    that is the shape its signature covers (R2-05 and rule 0.1.4 of the ledger).
    """
    priv, pub = keypair(tmp_path)
    v1 = make_scope()
    assert v1.payload_version < PAYLOAD_VERSION
    key = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    v1.signer_public_key = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    v1.signature = base64.b64encode(key.sign(canonical_json(v1.signing_payload()).encode("utf-8"))).decode("ascii")

    path = write_scope(tmp_path / "v1.json", v1)
    raw = json.loads(path.read_text(encoding="utf-8"))
    # Written the way a v1.1 build would have written it: no fields it did not know about.
    raw.pop("payload_version", None)
    for network in raw["networks"]:
        network.pop("ports", None)
    path.write_text(json.dumps(raw), encoding="utf-8")

    loaded = load_scope(path, public_key_path=pub)
    assert loaded.scope_id == v1.scope_id
    assert "payload_version" not in loaded.signing_payload()

    # And a field that version did not have cannot be added to it without invalidating the signature.
    raw["networks"][0]["ports"] = [1, 2, 3]
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path, public_key_path=pub)


def test_a_scope_edited_after_signing_fails_verification(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    signed = sign_scope(make_scope(), priv)

    tampered = signed.model_copy(deep=True)
    tampered.aliases["lab-attacker"] = "net:10.77.0.99"

    with pytest.raises(ScopeSignatureError):
        verify_scope(tampered, pub)
    # The embedded-key path must catch it too, even without a configured anchor.
    with pytest.raises(ScopeSignatureError):
        verify_scope(tampered, None)
    with pytest.raises(ScopeSignatureError):
        load_scope(write_scope(tmp_path / "tampered.json", tampered), public_key_path=pub)

    # A different edit - widening the window - is caught by the same property.
    widened = signed.model_copy(deep=True)
    widened.window.to = signed.window.to + timedelta(days=365)
    with pytest.raises(ScopeSignatureError):
        verify_scope(widened, pub)


def test_a_signature_from_a_different_key_is_rejected(tmp_path: Path) -> None:
    priv_a, _ = keypair(tmp_path, "a")
    _, pub_b = keypair(tmp_path, "b")
    signed = sign_scope(make_scope(), priv_a)
    with pytest.raises(ScopeSignatureError):
        verify_scope(signed, pub_b)


def test_a_scope_cannot_smuggle_in_its_own_signing_key(tmp_path: Path) -> None:
    priv_a, pub_a = keypair(tmp_path, "a")
    _, pub_b = keypair(tmp_path, "b")
    signed = sign_scope(make_scope(), priv_a)
    smuggled = signed.model_copy(deep=True)
    smuggled.signer_public_key = raw_public_b64(pub_b)
    with pytest.raises(ScopeSignatureError):
        verify_scope(smuggled, pub_a)


def test_unsigned_scope_is_refused_unless_explicitly_allowed(unsigned_scope_path: Path) -> None:
    with pytest.raises(ScopeError):
        load_scope(unsigned_scope_path)
    scope = load_scope(unsigned_scope_path, allow_unsigned=True)
    assert scope.scope_id == "lab-2026-09"
    assert scope.signature is None


def test_allow_unsigned_does_not_allow_a_tampered_signature(tmp_path: Path) -> None:
    priv, _ = keypair(tmp_path)
    signed = sign_scope(make_scope(), priv)
    tampered = signed.model_copy(deep=True)
    tampered.aliases["lab-attacker"] = "net:10.77.0.99"
    path = write_scope(tmp_path / "tampered.json", tampered)
    # allow_unsigned is a development affordance for scopes with no signature; it must never
    # become a way to accept a signature that has been broken.
    with pytest.raises(ScopeSignatureError):
        load_scope(path, allow_unsigned=True)


def test_verify_scope_rejects_a_missing_signature(tmp_path: Path) -> None:
    with pytest.raises(ScopeError) as excinfo:
        verify_scope(make_scope(), None)
    # Nothing to verify is a different failure from a broken signature, and callers rely on it.
    assert not isinstance(excinfo.value, ScopeSignatureError)


def test_malformed_signature_encodings_are_refused(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    signed = sign_scope(make_scope(), priv)

    not_base64 = signed.model_copy(deep=True)
    not_base64.signature = "not base64!!"
    with pytest.raises(ScopeSignatureError):
        verify_scope(not_base64, pub)

    wrong_length = signed.model_copy(deep=True)
    wrong_length.signature = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(ScopeSignatureError):
        verify_scope(wrong_length, pub)

    bad_key = signed.model_copy(deep=True)
    bad_key.signer_public_key = base64.b64encode(b"too-short").decode("ascii")
    with pytest.raises(ScopeSignatureError):
        verify_scope(bad_key, None)


def test_unsupported_signature_algorithm_is_refused(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    signed = sign_scope(make_scope(), priv)
    downgraded = signed.model_copy(deep=True)
    downgraded.signature_alg = "rsa"
    with pytest.raises(ScopeError):
        verify_scope(downgraded, pub)


def test_expired_and_not_yet_valid_windows_are_refused(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    now = utcnow()

    expired = sign_scope(
        make_scope(starts=now - timedelta(days=30), ends=now - timedelta(seconds=1)), priv
    )
    with pytest.raises(ScopeError) as expired_info:
        load_scope(write_scope(tmp_path / "expired.json", expired), public_key_path=pub)
    assert "expired" in str(expired_info.value)

    future = sign_scope(
        make_scope(starts=now + timedelta(days=1), ends=now + timedelta(days=30)), priv
    )
    with pytest.raises(ScopeError) as future_info:
        load_scope(write_scope(tmp_path / "future.json", future), public_key_path=pub)
    assert "not yet valid" in str(future_info.value)

    # An expired window stays expired even for an unsigned development scope: time is not a
    # property that allow_unsigned is allowed to soften.
    unsigned_expired = write_scope(
        tmp_path / "unsigned-expired.json",
        make_scope(starts=now - timedelta(days=30), ends=now - timedelta(seconds=1)),
    )
    with pytest.raises(ScopeError):
        load_scope(unsigned_expired, allow_unsigned=True)


def test_window_boundaries_are_inclusive(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    now = utcnow()
    edge = sign_scope(make_scope(starts=now, ends=now), priv)
    path = write_scope(tmp_path / "edge.json", edge)
    # The record authorises exactly the instant it names, so an exact-boundary read is valid.
    assert load_scope(path, public_key_path=pub, now=now).scope_id == "lab-test"
    with pytest.raises(ScopeError):
        load_scope(path, public_key_path=pub, now=now + timedelta(microseconds=1))


def test_naive_timestamps_are_refused(tmp_path: Path) -> None:
    from datetime import datetime

    priv, pub = keypair(tmp_path)
    path = write_scope(tmp_path / "scope.json", sign_scope(make_scope(), priv))
    with pytest.raises(ScopeError):
        load_scope(path, public_key_path=pub, now=datetime(2026, 9, 15, 12, 0, 0))


def test_malformed_scope_files_are_scope_errors(tmp_path: Path) -> None:
    priv, pub = keypair(tmp_path)
    good = make_scope().model_dump(mode="json", by_alias=True)

    missing_field = dict(good)
    missing_field.pop("window")
    cases = {
        "missing-field.json": json.dumps(missing_field),
        "not-an-object.json": json.dumps([1, 2, 3]),
        "not-json.json": "{this is not json",
        "unknown-field.json": json.dumps({**good, "extra_authority": True}),
        "null-alias.json": json.dumps({**good, "aliases": None}),
    }
    for name, text in cases.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope(path, public_key_path=pub)

    with pytest.raises(ScopeError):
        load_scope(tmp_path / "does-not-exist.json", public_key_path=pub)
