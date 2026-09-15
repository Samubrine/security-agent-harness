"""Generate the Ed25519 keypair that authorises every harness run.

The scope record is the project's authorisation artefact: no valid signature means the process
exits before the model is ever called (``docs/design/03-policy-and-safety.md`` section 2). That
only means something if the private key is genuinely out of reach of the agent and of the code
being investigated, which is why this script **refuses to write the private key inside the
repository**. A key next to the source is a key that a future refactor, a stray ``git add -A`` or
an agent with filesystem scope can read; the check turns that into a hard error instead of a
convention.

Key generation itself is not reimplemented here. ``harness.policy.scope.generate_keypair`` owns
the format and the algorithm, and this script is only an argument-parsing and safety wrapper
around it - two implementations of "generate a signing key" would be two definitions of the
trust root.

Usage (from the repository root)::

    python -m scripts.gen_scope_keypair
    python -m scripts.gen_scope_keypair --private-key ~/keys/scope.pem --public-key ~/keys/scope.pub
    python -m scripts.gen_scope_keypair --skip-if-exists   # used by `make scope`
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

#: Repository root, derived from this file's location rather than from the current directory, so
#: the containment check cannot be defeated by running the script from somewhere else.
REPO_ROOT = Path(__file__).resolve().parents[1]

#: The default location is outside the repository *and* outside the working tree the harness can
#: write to. ``$XDG_CONFIG_HOME`` is respected so the key does not have to sit in ``$HOME``.
DEFAULT_KEY_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "security-agent-harness"
DEFAULT_PRIVATE_KEY = DEFAULT_KEY_DIR / "scope_ed25519_private.pem"
DEFAULT_PUBLIC_KEY = DEFAULT_KEY_DIR / "scope_ed25519_public.pem"


def _fail(message: str) -> NoReturn:
    """Fail loudly and non-zero. Silent degradation is the wrong behaviour for keys."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def assert_private_key_outside_repo(path: Path) -> Path:
    """Return the resolved path, or refuse if it lands inside the repository.

    Resolved (not merely spelled) paths are compared so ``./scripts/../keys/x.pem`` cannot slip
    through, and a symlink pointing into the tree is caught by the same comparison.
    """
    resolved = path.expanduser().resolve()
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        _fail(
            f"refusing to write the scope signing private key inside the repository: {resolved}\n"
            f"       the authorisation key must stay out of everything the agent and the code "
            f"under investigation can reach (repo root: {REPO_ROOT})"
        )
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.gen_scope_keypair",
        description="Generate the Ed25519 keypair used to sign harness scope records.",
    )
    parser.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY,
        help="where to write the private key; must be outside the repository (default: %(default)s)",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY,
        help="where to write the public key (default: %(default)s)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing private key (rotates authority: every previously signed scope becomes unverifiable)",
    )
    parser.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="exit 0 without touching anything when the private key already exists (makes `make scope` idempotent)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Validation happens *before* the policy import on purpose: misuse of the key path must fail
    # for the reason the operator can act on, not behind an unrelated import error.
    private_path = assert_private_key_outside_repo(args.private_key)
    public_path = args.public_key.expanduser().resolve()
    if public_path == private_path:
        _fail("the public key path and the private key path must differ")

    if private_path.exists():
        if args.skip_if_exists:
            print(f"scope keypair already present, leaving it alone: {private_path}")
            return 0
        if not args.force:
            _fail(
                f"private key already exists: {private_path}\n"
                f"       re-run with --force to rotate it (this invalidates every scope record "
                f"signed with the old key) or --skip-if-exists to keep the current one"
            )

    from harness.policy.scope import generate_keypair  # imported late; see the note in main()
    from harness.util import sha256_hex

    private_path.parent.mkdir(parents=True, exist_ok=True)
    # 0700 on the directory and 0600 on the key: the key is the trust root, so it is not the
    # world-readable default that umask 022 would otherwise produce.
    os.chmod(private_path.parent, 0o700)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    generate_keypair(private_path, public_path)

    if not private_path.is_file() or private_path.stat().st_size == 0:
        _fail(f"key generation reported success but produced no private key at {private_path}")
    if not public_path.is_file() or public_path.stat().st_size == 0:
        _fail(f"key generation reported success but produced no public key at {public_path}")
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)

    fingerprint = sha256_hex(public_path.read_bytes())
    print(f"private key (never in the repo): {private_path}")
    print(f"public key:                      {public_path}")
    print(f"public key sha256:               {fingerprint}")
    print("next: python -m scripts.sign_lab_scope  (records the key fingerprint in the run report)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
