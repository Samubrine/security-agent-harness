"""Evaluation harness: scenarios, ground truth, and the metrics computed over finished runs.

``eval`` is a development tool, not part of the shipped package (``pyproject.toml`` packages only
``src/harness``). It nevertheless reuses the harness primitives - canonical JSON, hashing, span
verification - instead of defining a second copy of them, because an evaluator that canonicalises
JSON differently from the thing it evaluates produces numbers that cannot be reconciled.

The ``src`` bootstrap below mirrors ``tests/conftest.py`` so ``python -m eval.runner`` works in a
bare checkout without an editable install. It is skipped entirely when ``harness`` already
resolves.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

if importlib.util.find_spec("harness") is None:  # pragma: no cover - depends on the environment
    _SRC = REPO_ROOT / "src"
    if _SRC.is_dir() and str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))

__all__ = ["REPO_ROOT"]
