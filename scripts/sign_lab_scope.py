"""Sign a scope record with the Ed25519 key produced by ``scripts.gen_scope_keypair``.

A scope record is the authorisation for a run, not a configuration file with a polite comment:
the loader refuses to start a run whose signature is missing, malformed, or produced by a
different key. This script is the only place that turns an editable JSON file into that record,
and it does three things in an order that matters:

1. it validates paths *before* importing the signing code, so operator mistakes are reported as
   operator mistakes;
2. it imports ``generate_keypair``/``sign_scope``/``load_scope`` from ``harness.policy.scope``
   rather than reimplementing the payload, because two implementations of "what gets signed"
   would be two definitions of the authorisation boundary;
3. it **verifies the signature it just produced** before writing anything. A signature that is
   written but does not verify is worse than no signature at all, because downstream tooling
   treats the file as authorisation.

The signed record is written outside the repository by default: the authorisation artefact should
not live in the tree the agent can edit, or "signed scope" would mean "a file the agent could
rewrite along with everything else".

Usage (from the repository root)::

    python -m scripts.sign_lab_scope
    python -m scripts.sign_lab_scope --scope tests/fixtures/scope/lab_scope.json --out /tmp/lab.signed.json
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from scripts.gen_scope_keypair import (
    DEFAULT_PRIVATE_KEY,
    DEFAULT_PUBLIC_KEY,
    REPO_ROOT,
    assert_private_key_outside_repo,
)

#: The unsigned record that ships with the project. Signing it is the documented first step of
#: any run, which is why this is the default rather than a required argument.
DEFAULT_SCOPE = REPO_ROOT / "tests" / "fixtures" / "scope" / "lab_scope.json"


def _fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.sign_lab_scope",
        description="Sign a harness scope record with the offline Ed25519 scope key.",
    )
    parser.add_argument("--scope", type=Path, default=DEFAULT_SCOPE, help="unsigned scope JSON (default: %(default)s)")
    parser.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY,
        help="scope signing key; must be outside the repository (default: %(default)s)",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY,
        help="public key used to verify the signature before it is written (default: %(default)s)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="where to write the signed record (default: next to the keys, outside the repository)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Order matters: path sanity first, imports second. See the module docstring.
    private_path = assert_private_key_outside_repo(args.private_key)
    public_path = args.public_key.expanduser().resolve()
    scope_path = args.scope.expanduser().resolve()
    out_path = (args.out.expanduser().resolve() if args.out else private_path.parent / f"{scope_path.stem}.signed.json")

    if not scope_path.is_file():
        _fail(f"scope file not found: {scope_path}")
    if not private_path.is_file():
        _fail(
            f"scope signing key not found: {private_path}\n"
            f"       run `python -m scripts.gen_scope_keypair` first; the private key is never "
            f"read from inside the repository by design"
        )
    if not public_path.is_file():
        _fail(f"public key not found: {public_path} (needed to verify the signature before writing it)")

    from harness.policy.scope import load_scope, sign_scope, verify_scope
    from harness.util import atomic_write_json, sha256_hex

    # The input is expected to be unsigned; ``allow_unsigned`` is what makes re-signing an
    # existing record (after an edit) work without special-casing it. The window is still
    # checked here, so an expired authorisation fails now rather than at run start.
    scope = load_scope(scope_path, allow_unsigned=True)
    signed = sign_scope(scope, private_path)

    if not signed.signature:
        _fail("sign_scope returned a record without a signature; refusing to write it")
    verify_scope(signed, public_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out_path, signed.model_dump(mode="json"))

    print(f"scope_id:       {signed.scope_id}")
    print(f"authorized_by:  {signed.authorized_by}")
    print(f"window:         {signed.window.from_at.isoformat()} -> {signed.window.to.isoformat()}")
    print(f"aliases:        {', '.join(sorted(signed.aliases))}")
    print(f"signature alg:  {signed.signature_alg}")
    print(f"public key sha256: {sha256_hex(public_path.read_bytes())}")
    print(f"signed scope:   {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
