"""Signed scope records: the authorisation artefact a run cannot start without.

The scope file is not configuration with a polite comment attached - it is the record of who
authorised which hosts. So it is treated as a *signed statement*, not as a settings file:

* the signature is computed over the canonical JSON of every field except the signature
  itself, which means a single edited character (an extra host, a longer window) invalidates
  it;
* `load_scope` refuses to return a scope whose signature does not verify, whose window
  does not cover now, or which carries no signature while unsigned scopes are not explicitly
  allowed;
* every refusal is a typed `harness.errors.ScopeError` (or the
  `ScopeSignatureError` subclass) so the runtime can stop loudly instead of degrading
  into a run with less authority than the operator believes it has.

Trust anchors
-------------
Verification either uses a caller-supplied public key, or, when none is given, the key embedded
in the record. The embedded key alone only proves *internal consistency*: anyone able to edit
the file can also re-sign it with their own key. A run therefore gets a real trust anchor from
configuration (the CLI passes --public-key); the embedded-key path exists so a tampered scope is
still caught when no anchor is configured, and it is never silently trusted as authorisation.

Key material
------------
The private key is the trust root, so its protection is reported as a fact rather than assumed:
:func:`protect_private_key` applies the mechanism the platform actually enforces (mode bits on
POSIX, an explicit ACL on Windows) and reads it back, and :func:`key_protection` answers what
protects a key right now. A platform that can enforce neither answers ``none``, and a caller that
is told ``none`` can say so instead of believing the key is protected.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from harness.errors import ScopeError, ScopeSignatureError
from harness.models import PAYLOAD_VERSION, ScopeFile
from harness.util import atomic_write_bytes, canonical_json, iso, read_json, utcnow

#: Only Ed25519 is accepted. A record naming another algorithm is refused rather than
#: dispatched to a weaker verifier, because algorithm agility here buys nothing and costs a
#: signature-downgrade path.
SIGNATURE_ALG = "ed25519"

_PRIVATE_KEY_MODE = 0o600
_PUBLIC_KEY_MODE = 0o644


def _payload_bytes(scope: ScopeFile) -> bytes:
    """The exact bytes that are signed: canonical JSON of the record without its signature."""
    return canonical_json(scope.signing_payload()).encode("utf-8")


def _require_aware(when: datetime, what: str) -> None:
    if when.tzinfo is None:
        raise ScopeError(f"{what} must be timezone-aware; a naive value cannot be compared to a scope window")


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(_public_key_bytes(key)).decode("ascii")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ScopeError(f"scope signing key {p} could not be read: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise ScopeError(f"scope signing key {p} is not a readable unencrypted private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ScopeError(f"scope signing key {p} is not an Ed25519 key")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ScopeError(f"scope trust anchor {p} could not be read: {exc}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise ScopeError(f"scope trust anchor {p} is not a readable public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ScopeError(f"scope trust anchor {p} is not an Ed25519 public key")
    return key


def _embedded_public_key_bytes(scope: ScopeFile, *, required: bool) -> bytes | None:
    """Decode `signer_public_key`; `required` turns absence into a hard refusal.

    Called with two tolerances: verification without an anchor must have a key to check
    against, while comparison against an anchor only compares when one is present in the record.
    """
    if not scope.signer_public_key:
        if required:
            raise ScopeError(
                f"scope {scope.scope_id} has no embedded signer key and no trust anchor was supplied"
            )
        return None
    try:
        raw = base64.b64decode(scope.signer_public_key.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ScopeSignatureError("scope signer_public_key is not valid base64") from exc
    if len(raw) != 32:
        raise ScopeSignatureError("scope signer_public_key is not a 32-byte Ed25519 public key")
    return raw


def generate_keypair(private_path: Path, public_path: Path, *, force: bool = False) -> str:
    """Create an Ed25519 keypair for signing scope records.

    Overwriting an existing key is refused unless `force` is set: silently rotating the
    signing key orphans every scope signed with the old one, and the failure then shows up much
    later as "no scope verifies" instead of as "you just replaced the key".

    The private key is restricted to the current account (see :func:`protect_private_key`) and
    belongs outside anything the agent can reach. Returns the mechanism that protects it, so a
    caller can report what is actually enforced instead of assuming it.
    """
    priv, pub = Path(private_path), Path(public_path)
    if not force:
        for candidate, label in ((priv, "private"), (pub, "public")):
            if candidate.exists():
                raise ScopeError(
                    f"{label} key {candidate} already exists; refusing to overwrite authority material"
                )
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    atomic_write_bytes(priv, private_bytes)
    atomic_write_bytes(pub, public_bytes)
    # The public key needs no protection: it is the anchor, not the secret.
    try:
        pub.chmod(_PUBLIC_KEY_MODE)
    except OSError:
        pass
    return protect_private_key(priv)


def protect_private_key(path: Path) -> str:
    """Restrict a private key to the current account and return what actually enforces that.

    "Only the account that owns this key can read it" is expressed differently on each platform,
    and a POSIX mode is only one of the expressions. ``os.chmod`` on Windows sets a read-only
    attribute and nothing else, so a mode-based check passed there while every account that could
    reach the file kept its inherited access - the guard was measuring a number the platform
    ignores (R1-11). Windows is therefore handled with an explicit ACL: inheritance is removed and
    the owner is granted full control, which is what mode 0600 means (read and write for the owner,
    nothing for anyone else) and keeps key rotation possible.

    The result is read back rather than assumed: ``"posix-mode"`` and ``"windows-acl"`` mean the
    protection was verified in place, and ``"none"`` means this platform offers no way to restrict
    the file, which is the value a caller needs in order not to claim protection it does not have.
    """
    private = Path(path)
    if os.name == "nt":
        account = os.environ.get("USERNAME", "").strip()
        if not account:
            return "none"
        try:
            subprocess.run(  # noqa: S603 - fixed argv, no shell, no interpolation
                ["icacls", str(private), "/inheritance:r", "/grant:r", f"{account}:F"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return "none"
        return key_protection(private)
    try:
        private.chmod(_PRIVATE_KEY_MODE)
    except OSError:
        return "none"
    return key_protection(private)


def key_protection(path: Path) -> str:
    """What protects the private key at `path` right now, asked of the platform.

    ``"posix-mode"`` when the file's own mode keeps group and other out, ``"windows-acl"`` when its
    ACL is a single entry for the current account with nothing inherited, and ``"none"`` otherwise.
    """
    private = Path(path)
    if os.name == "nt":
        return "windows-acl" if _windows_acl_is_exclusive(private) else "none"
    try:
        mode = private.stat().st_mode & 0o777
    except OSError:
        return "none"
    return "posix-mode" if mode == _PRIVATE_KEY_MODE else "none"


def _windows_acl_is_exclusive(path: Path) -> bool:
    """True when the ACL grants one account and inherits nothing.

    Reads ``icacls`` back rather than trusting the command that wrote the ACL. The permission
    markers it prints - ``(I)`` for an inherited entry, ``(F)``/``(M)``/``(W)``/``(R)`` for the
    grant - are the same in every Windows installation, unlike the account names beside them, so
    only the markers and the marker count are used here.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    if completed.returncode != 0:
        return False
    entries = [line for line in completed.stdout.splitlines() if ":(" in line]
    if len(entries) != 1:
        # More than one entry means somebody other than the owner is still named; none at all means
        # the output did not parse and nothing was verified.
        return False
    return "(I)" not in entries[0]


def sign_scope(scope: ScopeFile, private_key_path: Path) -> ScopeFile:
    """Return a copy of `scope` carrying a detached Ed25519 signature.

    The signer's public key is written *before* signing because it is part of the signed
    payload; signing first and stamping the key afterwards would produce a record that could
    never verify.
    """
    key = _load_private_key(private_key_path)
    signed = scope.model_copy(deep=True)
    signed.signature_alg = SIGNATURE_ALG
    # A record being signed now is signed under the payload shape this build verifies, whatever
    # version the file it came from declared. Leaving an old version in place would sign a payload
    # that omits the fields this build understands - a signature over less than the record says.
    signed.payload_version = PAYLOAD_VERSION
    signed.signer_public_key = _public_key_b64(key.public_key())
    signed.signature = None
    signed.signature = base64.b64encode(key.sign(_payload_bytes(signed))).decode("ascii")
    return signed


def verify_scope(scope: ScopeFile, public_key_path: Path | None) -> None:
    """Verify the record's signature or raise.

    A missing signature is a `ScopeError` (there is nothing to verify); a bad one is a
    `ScopeSignatureError`. When an anchor is configured the record's embedded key must
    match it, so a scope cannot smuggle in its own signing key alongside a signature.
    """
    if not scope.signature:
        raise ScopeError(
            f"scope {scope.scope_id} carries no signature; unverifiable authority is not authority"
        )
    if scope.signature_alg != SIGNATURE_ALG:
        raise ScopeError(
            f"scope {scope.scope_id} declares unsupported signature_alg {scope.signature_alg!r}"
        )
    try:
        signature = base64.b64decode(scope.signature.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ScopeSignatureError("scope signature is not valid base64") from exc
    if len(signature) != 64:
        raise ScopeSignatureError("scope signature is not a 64-byte Ed25519 signature")

    if public_key_path is not None:
        anchor = _load_public_key(public_key_path)
        embedded = _embedded_public_key_bytes(scope, required=False)
        if embedded is not None and embedded != _public_key_bytes(anchor):
            raise ScopeSignatureError(
                "scope was signed by a different key than the configured trust anchor"
            )
        key: Ed25519PublicKey = anchor
    else:
        embedded = _embedded_public_key_bytes(scope, required=True)
        assert embedded is not None  # required=True either yields a value or raises
        key = Ed25519PublicKey.from_public_bytes(embedded)

    try:
        key.verify(signature, _payload_bytes(scope))
    except InvalidSignature as exc:
        raise ScopeSignatureError(
            f"scope {scope.scope_id} failed signature verification; the record changed after signing"
        ) from exc


def load_scope(
    path: Path,
    *,
    public_key_path: Path | None = None,
    allow_unsigned: bool = False,
    now: datetime | None = None,
) -> ScopeFile:
    """Load a scope record, refusing anything that is not currently valid authority.

    Three independent refusals, all loud and typed, because each of them means the run must not
    reach the model at all:

    1. the file is missing or malformed (`ScopeError`);
    2. the signature is absent and unsigned scopes were not explicitly allowed, or present and
       not verifiable (`ScopeError` / `ScopeSignatureError`);
    3. the authorisation window does not cover `now` (`ScopeError`).

    `allow_unsigned` is for local development and fixture-driven tests only. It never
    downgrades a *present* signature: a signed-and-then-edited record is still refused.
    """
    p = Path(path)
    try:
        raw: Any = read_json(p)
    except FileNotFoundError as exc:
        raise ScopeError(f"scope file {p} does not exist") from exc
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ScopeError(f"scope file {p} could not be parsed: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeError(f"scope file {p} must contain a JSON object")

    try:
        scope = ScopeFile.model_validate(raw)
    except ValidationError as exc:
        raise ScopeError(f"scope file {p} is malformed: {exc.error_count()} field error(s)") from exc

    if scope.signature:
        verify_scope(scope, public_key_path)
    elif not allow_unsigned:
        raise ScopeError(
            f"scope {scope.scope_id} is unsigned and unsigned scopes were not allowed; "
            "refusing to start a run without recorded authority"
        )

    when = now if now is not None else utcnow()
    _require_aware(when, "the scope validity check timestamp")
    if not scope.window.covers(when):
        state = "expired" if when > scope.window.to else "not yet valid"
        raise ScopeError(
            f"scope {scope.scope_id} window is {state} at {iso(when)} "
            f"(authorised {iso(scope.window.from_at)} to {iso(scope.window.to)})"
        )
    return scope
