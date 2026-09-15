"""Deterministic primitives shared by every subsystem.

Everything here is pure and byte-exact on purpose: canonical JSON and SHA-256 are
what make artifacts immutable and the event log replayable.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ID_ALPHABET = "0123456789abcdef"


def utcnow() -> datetime:
    """Timezone-aware UTC now. All timestamps in the harness are aware UTC."""
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    """Canonical ISO-8601 rendering, always UTC with a trailing ``Z``."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime is not permitted in harness records")
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def new_id(prefix: str, nbytes: int = 6) -> str:
    """Return an opaque short id such as ``o-9f2c31ab``.

    Ids are random, not sequential: a model that can predict the next finding id is a
    model that can be tricked into referencing one that does not exist yet.
    """
    token = "".join(secrets.choice(_ID_ALPHABET) for _ in range(nbytes * 2))
    return f"{prefix}-{token}"


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace, UTF-8 preserved.

    Used for hashing events, artifacts metadata and proposals. Two structurally equal
    objects must produce identical strings or the hash chain is worthless.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default)


def _json_default(obj: Any) -> Any:
    from datetime import date
    from enum import Enum

    if isinstance(obj, datetime | date):
        return iso(obj) if isinstance(obj, datetime) else obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    raise TypeError(f"object of type {type(obj).__name__} is not JSON serializable")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def digest_short(digest: str, n: int = 12) -> str:
    """``sha256:abcdef...`` -> short human-facing form."""
    body = digest.split(":", 1)[-1]
    return body[:n]


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes atomically so a crashed run never leaves a half artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib_suppress():
            os.unlink(tmp)
        raise


class contextlib_suppress:
    """Tiny local stand-in for ``contextlib.suppress(OSError)``."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: Path, obj: Any, *, pretty: bool = True) -> None:
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=_json_default) if pretty else canonical_json(obj)
    atomic_write_text(path, payload + ("\n" if pretty else ""))


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append_jsonl(path: Path, obj: Any) -> None:
    """Append one canonical JSON line. Append-only by contract."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(canonical_json(obj) + "\n")
        fh.flush()


def read_jsonl(path: Path) -> list[Any]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def clamp_text(text: str, limit: int) -> str:
    """Bound a string for context inclusion without silently lying about length."""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + f"\n[...truncated {len(text) - limit} chars...]"


def estimate_tokens(text: str) -> int:
    """Conservative offline token estimate (~4 chars/token) used when no local
    tokenizer is configured. The ledger records which estimator produced a number."""
    return max(1, (len(text) + 3) // 4)


def strip_control_chars(text: str) -> str:
    """Remove ANSI escapes and control characters from untrusted payloads."""
    import re

    ansi = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
    text = ansi.sub("", text)
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def safe_relpath(root: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` under ``root`` or raise. Used by the artifact store and
    by filesystem-scoped providers to make path traversal a structural error."""
    root = Path(root).resolve()
    resolved = (root / Path(candidate).name).resolve() if not Path(candidate).is_absolute() else Path(candidate).resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError(f"path {resolved} escapes root {root}")
    return resolved
