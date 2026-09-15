"""A replay pass that *re-derives* a run's findings instead of re-reading them.

The question this module answers is not whether the run's ``findings.json`` agrees with itself,
but whether the observations the run recorded actually imply the findings it reported. Those are
completely different checks, and only the second one can fail for a run whose findings were edited
by hand, invented by a model, or produced by a pipeline that has since drifted.

So the pass re-runs the harness's own deterministic pipeline over the run's recorded observations -
``RuleEngine`` for rule claims, ``candidate_cves`` against a ``VulnerabilitySnapshot`` for version
matches, ``Correlator`` for cross-provider relations, and ``build_findings`` for the findings
themselves - and hashes the result with ``harness.util.canonical_json`` + ``sha256_text``.
``live_finding_digests`` are the same hashes over the recorded ``findings.json``. A faithful run
produces two maps that agree; a tampered or fabricated one does not.

Three deliberate normalisations make that comparison meaningful rather than decorative, and each
one exists because the alternative reports a mismatch for a run that is actually faithful:

* **Volatile identity is dropped.** Finding and claim ids come from ``harness.util.new_id``
  (``os.urandom``) and ``Finding.created_at`` from the wall clock, so no re-derivation can
  reproduce them. Hashing them would make every replay pass report a mismatch, which measures
  nothing at all.
* **Claim order inside a finding is canonicalised.** The live run adds a finding's claims as
  observations arrive, while ``observations.json`` is written with its keys sorted, so the same set
  of claims can be ordered differently on the two sides. The *set* of claims a finding rests on is
  the property worth checking; the order they happen to be listed in is not.
* **A statement that embeds a Python container literal has its keys sorted before hashing.** One
  rule template renders a dict (``{reason_counts}``), and the run's artefacts are written with
  ``sort_keys=True``, so the recorded statement preserves an insertion order that is not
  recoverable from the files. Sorting the container's keys compares the content of the statement
  rather than the accident of how it was serialised. Every other character of the statement - every
  number, every word - is still compared exactly.

The vulnerability snapshot is loaded from ``tests/fixtures/vuln/snapshot_2026-09.json`` by default.
That is a test fixture, and reaching into it from ``eval/`` is a deliberate, documented shortcut:
the eval scenarios run against the same fixture library the tests do. Pass ``snapshot_path`` to
point the pass at a different snapshot.
"""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.analysers.correlate import Correlator
from harness.analysers.cve_match import CveCandidate, VulnerabilitySnapshot, candidate_cves
from harness.analysers.rules import RuleEngine
from harness.findings.builder import build_findings
from harness.models import Finding, Observation
from harness.util import atomic_write_json, canonical_json, read_jsonl, sha256_text

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The snapshot the re-derivation matches versions against. A test fixture, by documented shortcut.
DEFAULT_SNAPSHOT_PATH = REPO_ROOT / "tests" / "fixtures" / "vuln" / "snapshot_2026-09.json"

_VOLATILE_FINDING_KEYS = frozenset({"id", "created_at"})
_VOLATILE_CLAIM_KEYS = frozenset({"id"})

#: A brace-delimited container literal inside a claim statement, e.g. ``{'a': 1, 'b': 2}``.
_CONTAINER_RE = re.compile(r"\{[^{}]*\}")


# ----------------------------------------------------------------------------------------------
# Result type
# ----------------------------------------------------------------------------------------------


@dataclass
class ReplayPass:
    """What one re-derivation of a run's findings found.

    ``replayed_finding_digests`` is keyed by the id the *run* recorded, because that is the only key
    space both sides can agree on (re-derived findings carry fresh random ids). A re-derived finding
    the run never recorded appears under an ``unmatched:`` key, so that it is visible as a mismatch
    instead of being silently dropped.
    """

    run_id: str
    replayed_finding_digests: dict[str, str] = field(default_factory=dict)
    live_finding_digests: dict[str, str] = field(default_factory=dict)
    rederived: int = 0
    observations_used: int = 0
    problems: list[str] = field(default_factory=list)

    def mismatched_keys(self) -> list[str]:
        """Ids whose two digests differ, plus ids that appear on only one side."""
        keys = sorted(set(self.live_finding_digests) | set(self.replayed_finding_digests))
        return [
            key
            for key in keys
            if self.live_finding_digests.get(key) != self.replayed_finding_digests.get(key)
        ]

    @property
    def ok(self) -> bool:
        """True only when the pass reproduced the recorded findings and raised no problem.

        The default is False: an empty pass - a directory with no observations - has not
        demonstrated fidelity, and a property whose default is fine is one nobody checks.
        """
        return bool(self.live_finding_digests) and not self.problems and not self.mismatched_keys()

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "rederived": self.rederived,
            "observations_used": self.observations_used,
            "recorded_findings": len(self.live_finding_digests),
            "mismatched": self.mismatched_keys(),
            "problems": list(self.problems),
        }


# ----------------------------------------------------------------------------------------------
# Canonicalisation
# ----------------------------------------------------------------------------------------------


def canonical_statement(text: str) -> str:
    """Sort the keys of any dict literal embedded in a claim statement.

    ``ast.literal_eval`` is used rather than ``eval`` because the text being parsed is run output:
    it is data, and a statement whose braces are not a literal is left exactly as it was found.
    Only the *order of keys* changes; the keys, the values and every other character of the
    statement are compared verbatim.
    """

    def _fix(match: re.Match[str]) -> str:
        body = match.group(0)
        try:
            value = ast.literal_eval(body)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return body
        if not isinstance(value, dict):
            return body
        try:
            items = sorted(value.items(), key=lambda kv: repr(kv[0]))
        except TypeError:
            return body
        return "{" + ", ".join(f"{key!r}: {val!r}" for key, val in items) + "}"

    return _CONTAINER_RE.sub(_fix, text)


def _normalise(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The comparable content of a finding: everything bar the identity that cannot be reproduced."""
    out = {key: value for key, value in payload.items() if key not in _VOLATILE_FINDING_KEYS}
    out["cve"] = sorted(str(item) for item in payload.get("cve") or [])
    out["cpe"] = sorted(str(item) for item in payload.get("cpe") or [])
    claims: list[dict[str, Any]] = []
    for claim in payload.get("claims") or []:
        if not isinstance(claim, Mapping):
            continue
        clean = {key: value for key, value in claim.items() if key not in _VOLATILE_CLAIM_KEYS}
        clean["statement"] = canonical_statement(str(clean.get("statement") or ""))
        clean["supports"] = sorted(str(item) for item in clean.get("supports") or [])
        clean["contradicts"] = sorted(str(item) for item in clean.get("contradicts") or [])
        claims.append(clean)
    claims.sort(key=canonical_json)
    out["claims"] = claims
    return out


def finding_digest(payload: Mapping[str, Any]) -> str:
    """Canonical hash of a finding's comparable content."""
    return sha256_text(canonical_json(_normalise(payload)))


def finding_structure(payload: Mapping[str, Any]) -> str:
    """Identity used to pair a recorded finding with its re-derived counterpart.

    The pairing key deliberately excludes prose and the volatile ids: it is the finding's shape -
    which rules produced claims over which observations, about which subject. A run whose findings
    keep the right shape but changed their wording therefore still pairs up, and is then caught by
    the digest comparison instead of being reported as a finding that vanished.
    """
    claims = []
    for claim in payload.get("claims") or []:
        if not isinstance(claim, Mapping):
            continue
        claims.append(
            {
                "rule_id": claim.get("rule_id"),
                "assertion": claim.get("assertion"),
                "supports": sorted(str(item) for item in claim.get("supports") or []),
                "contradicts": sorted(str(item) for item in claim.get("contradicts") or []),
            }
        )
    claims.sort(key=canonical_json)
    return canonical_json(
        {
            "title": payload.get("title"),
            "status": payload.get("status"),
            "severity": payload.get("severity"),
            "skill": payload.get("skill"),
            "run_id": payload.get("run_id"),
            "cve": sorted(str(item) for item in payload.get("cve") or []),
            "cpe": sorted(str(item) for item in payload.get("cpe") or []),
            "claims": claims,
        }
    )


@dataclass(frozen=True)
class _Row:
    """One finding on one side of the comparison."""

    key: str
    structure: str
    digest: str
    title: str


def _rows(payloads: Iterable[Mapping[str, Any]], *, fallback_prefix: str) -> list[_Row]:
    out: list[_Row] = []
    for index, payload in enumerate(payloads):
        key = payload.get("id")
        key = str(key) if isinstance(key, str) and key else f"{fallback_prefix}-{index}"
        out.append(
            _Row(
                key=key,
                structure=finding_structure(payload),
                digest=finding_digest(payload),
                title=str(payload.get("title") or ""),
            )
        )
    return out


def _pair(live: Sequence[_Row], replayed: Sequence[_Row]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Pair recorded and re-derived findings by shape, then compare their digests.

    Exact digest matches are paired first, so identical findings cannot be paired with a near-miss
    of the same shape. Whatever is left over within a shape is paired in a deterministic order and
    reported as a content difference.
    """
    live_groups: dict[str, list[_Row]] = defaultdict(list)
    replay_groups: dict[str, list[_Row]] = defaultdict(list)
    for row in live:
        live_groups[row.structure].append(row)
    for row in replayed:
        replay_groups[row.structure].append(row)

    live_map: dict[str, str] = {}
    replay_map: dict[str, str] = {}
    problems: list[str] = []

    for structure in sorted(set(live_groups) | set(replay_groups)):
        left = sorted(live_groups.get(structure, []), key=lambda row: (row.digest, row.key))
        right = sorted(replay_groups.get(structure, []), key=lambda row: (row.digest, row.key))

        for live_row in list(left):
            match = next((row for row in right if row.digest == live_row.digest), None)
            if match is None:
                continue
            left.remove(live_row)
            right.remove(match)
            live_map[live_row.key] = live_row.digest
            replay_map[live_row.key] = match.digest

        for live_row, replay_row in zip(left, right):
            live_map[live_row.key] = live_row.digest
            replay_map[live_row.key] = replay_row.digest
            problems.append(
                f"finding {live_row.key} ({live_row.title!r}) is shaped like a re-derivation of "
                f"this run's observations but its content differs: recorded digest "
                f"{live_row.digest[:12]}, re-derived {replay_row.digest[:12]}"
            )

        for live_row in left[len(right) :]:
            live_map[live_row.key] = live_row.digest
            problems.append(
                f"recorded finding {live_row.key} ({live_row.title!r}) was not re-derived from "
                "this run's observations"
            )
        for replay_row in right[len(left) :]:
            key = f"unmatched:{replay_row.digest[:12]}"
            replay_map[key] = replay_row.digest
            problems.append(
                "the re-derivation produced a finding this run never recorded "
                f"({replay_row.title!r}, digest {replay_row.digest[:12]}, keyed as {key})"
            )

    return live_map, replay_map, problems


# ----------------------------------------------------------------------------------------------
# Reading the run
# ----------------------------------------------------------------------------------------------


def _read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _records(value: Any, keys: Sequence[str]) -> list[dict[str, Any]] | None:
    """Accept both a bare list and a wrapping object; anything else is unreadable."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in keys:
            inner = value.get(key)
            if isinstance(inner, list):
                return [item for item in inner if isinstance(item, dict)]
    return None


def _run_identity(
    run_dir: Path, problems: list[str], recorded: Sequence[Mapping[str, Any]]
) -> tuple[str, str]:
    """Run id and skill, which ``build_findings`` needs and ``findings.json`` records."""
    meta = _read_json(run_dir / "run.json")
    run_id = ""
    skill = ""
    if isinstance(meta, dict):
        run_id = str(meta.get("run_id") or "")
        skill = str(meta.get("skill") or "")
    if not run_id:
        run_id = next((str(row.get("run_id")) for row in recorded if row.get("run_id")), "")
    if not skill:
        skill = next((str(row.get("skill")) for row in recorded if row.get("skill")), "")
    if not run_id:
        problems.append(f"run.json did not name a run id; the directory name {run_dir.name!r} was used")
        run_id = run_dir.name
    if not skill:
        problems.append("no skill was recorded, so re-derived findings carry an empty skill field")
    return run_id, skill


def _load_recorded_findings(run_dir: Path, problems: list[str]) -> list[dict[str, Any]]:
    """Recorded findings as JSON payloads, checked against the record they claim to be."""
    value = _read_json(run_dir / "findings.json")
    if value is None:
        problems.append("findings.json is missing or unreadable, so there is nothing to compare")
        return []
    rows = _records(value, ("findings", "items"))
    if rows is None:
        problems.append("findings.json is neither a list of findings nor an object carrying one")
        return []
    out: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        try:
            out.append(Finding.model_validate(row).model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001 - a malformed record is a problem, never a crash
            # The raw bytes are still hashed: a record edited into an invalid shape is exactly the
            # kind of tampering this pass exists to surface, and dropping it would hide the finding.
            problems.append(
                f"recorded finding at index {index} is not a valid Finding ({type(exc).__name__}); "
                "its raw payload was hashed instead"
            )
            out.append(dict(row))
    return out


def _load_observations(run_dir: Path, problems: list[str]) -> list[Observation]:
    """The run's observations, rebuilt as real records so the pipeline can consume them."""
    value = _read_json(run_dir / "observations.json")
    rows = _records(value, ("observations", "items"))
    if rows is None:
        rows = read_jsonl(run_dir / "observations.jsonl")
    if rows is None:
        problems.append(
            "no observations.json or observations.jsonl was recorded, so this run's findings "
            "cannot be re-derived from anything"
        )
        return []
    out: list[Observation] = []
    for row in rows:
        if not isinstance(row, dict):
            problems.append(f"observation entry {row!r} is not an object")
            continue
        try:
            out.append(Observation.model_validate(row))
        except Exception as exc:  # noqa: BLE001 - one unreadable observation must not stop the pass
            problems.append(
                f"observation {row.get('id')!r} is not a valid Observation "
                f"({type(exc).__name__}); it was excluded from the re-derivation"
            )
    return out


def _snapshot_candidates(
    observations: Sequence[Observation], snapshot_path: Path, problems: list[str]
) -> list[CveCandidate]:
    """Re-derive the version matches from the snapshot, then tie them to the run's own records.

    The candidate list is rebuilt from the *service* observations and the snapshot, never copied
    from the matcher's output: that is what makes "this CVE applies here" a statement the
    observations imply rather than one the run asserted. The recorded ``vulnerability_match``
    observation is then attached to the candidate it corresponds to, because that is the record the
    finding builder joins claims through - and any disagreement between the two, in either
    direction, is a problem rather than a silently accepted difference.
    """
    try:
        snapshot = VulnerabilitySnapshot.load(Path(snapshot_path))
    except Exception as exc:  # noqa: BLE001 - a missing snapshot is a reported gap, not a crash
        problems.append(f"vulnerability snapshot {snapshot_path} could not be loaded: {exc}")
        return []

    recorded: dict[tuple[str, str], str] = {}
    recorded_digests: set[str] = set()
    for obs in observations:
        if obs.kind != "vulnerability_match":
            continue
        value = obs.value or {}
        recorded.setdefault((str(value.get("cve") or ""), str(value.get("cpe") or "")), obs.id)
        if value.get("snapshot_digest"):
            recorded_digests.add(str(value["snapshot_digest"]))
    if recorded_digests and snapshot.digest not in recorded_digests:
        # The pass matched against a different snapshot than the run did, so a disagreement here
        # says nothing about the run. Naming it keeps that from being read as a finding.
        problems.append(
            f"the run matched against snapshot {sorted(recorded_digests)} but this pass used "
            f"{snapshot.digest}; version-match differences below are not attributable to the run"
        )

    candidates, _gaps = candidate_cves(observations, snapshot)
    out: list[CveCandidate] = []
    claimed: set[tuple[str, str]] = set()
    for candidate in candidates:
        key = (candidate.cve, candidate.cpe)
        matched_id = recorded.get(key)
        if matched_id is not None:
            claimed.add(key)
            # The matcher's own observation first, then the service observation it was derived
            # from - the same order runtime.loop uses, because the finding builder joins claims to
            # candidates through exactly these ids.
            candidate.observation_ids = [matched_id, *candidate.observation_ids]
        out.append(candidate)

    for key, observation_id in sorted(recorded.items()):
        if key not in claimed:
            problems.append(
                f"observation {observation_id} claims {key[0]} for {key[1]}, which the recorded "
                "snapshot does not yield for the version that was observed"
            )
    return out


# ----------------------------------------------------------------------------------------------
# The pass
# ----------------------------------------------------------------------------------------------


def rederive_findings(run_dir: Path, *, snapshot_path: Path = DEFAULT_SNAPSHOT_PATH) -> ReplayPass:
    """Re-run the harness's deterministic pipeline over a recorded run and compare the result.

    Never raises for any input, including a nonexistent or empty directory: an unreadable run is a
    pass that could not be completed, which belongs in ``problems`` where a metric can report it as
    ``not_measured``, rather than an exception that loses the rest of the evaluation.
    """
    run_dir = Path(run_dir)
    problems: list[str] = []
    recorded = _load_recorded_findings(run_dir, problems)
    run_id, skill = _run_identity(run_dir, problems, recorded)
    live_rows = _rows(recorded, fallback_prefix="recorded")

    observations = _load_observations(run_dir, problems)
    replay_rows: list[_Row] = []
    rederived = 0
    if observations:
        try:
            engine = RuleEngine()
            claims = engine.evaluate(observations)
            for rule_id, why in getattr(engine, "skipped", []):
                # A rule that could not fire is a skipped detection, not a quiet success.
                problems.append(f"rule {rule_id} was skipped while re-deriving: {why}")
            candidates = _snapshot_candidates(observations, Path(snapshot_path), problems)
            correlator = Correlator(run_id)
            correlations = correlator.add(observations)
            findings = build_findings(
                run_id=run_id,
                observations=observations,
                claims=claims,
                candidates=candidates,
                correlations=correlations,
                skill=skill,
            )
        except Exception as exc:  # noqa: BLE001 - the pass reports a failure instead of raising one
            problems.append(f"the re-derivation failed: {type(exc).__name__}: {exc}")
            findings = []
        rederived = len(findings)
        replay_rows = _rows(
            (finding.model_dump(mode="json") for finding in findings), fallback_prefix="rederived"
        )

    live_map, replay_map, pair_problems = _pair(live_rows, replay_rows)
    problems.extend(pair_problems)
    return ReplayPass(
        run_id=run_id,
        replayed_finding_digests=replay_map,
        live_finding_digests=live_map,
        rederived=rederived,
        observations_used=len(observations),
        problems=problems,
    )


def _read_replay_document(run_dir: Path) -> dict[str, Any]:
    """Whatever ``replay.json`` already holds, in a form the digest maps can be added to.

    A v1 run writes ``replay.json`` as JSONL records of the model and provider interactions. Those
    records are what makes a run offline-replayable, so the digest document keeps them verbatim
    under ``records`` rather than replacing them: an evaluation step must not destroy the artefact it
    is measuring. An already-augmented document is returned as it is, which makes the call
    idempotent.
    """
    path = run_dir / "replay.json"
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return value
    records: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"_unparsed": line[:2000]})
    return {"records": records} if records else {}


def augment_replay_json(run_dir: Path, *, snapshot_path: Path = DEFAULT_SNAPSHOT_PATH) -> ReplayPass:
    """Run the replay pass and write its result where the metrics read it. Returns the pass.

    The digest maps are written only when the run recorded findings, because two empty maps would
    make ``replay_fidelity`` report ``0.0`` for a run that has nothing to be faithful about; the
    metric's ``not_measured`` is the honest answer there.
    """
    run_dir = Path(run_dir)
    pass_ = rederive_findings(run_dir, snapshot_path=Path(snapshot_path))
    document = _read_replay_document(run_dir)
    if pass_.live_finding_digests or pass_.replayed_finding_digests:
        document["finding_digests"] = dict(pass_.live_finding_digests)
        document["replayed_finding_digests"] = dict(pass_.replayed_finding_digests)
    else:
        document.pop("finding_digests", None)
        document.pop("replayed_finding_digests", None)
    document["replay_pass"] = pass_.as_dict()
    atomic_write_json(run_dir / "replay.json", document)
    return pass_
