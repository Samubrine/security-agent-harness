"""Recording and offline replay.

Decision D24 separates ``replay`` from ``rerun``. Replay reconstructs the structured state of a
finished run from what was recorded, and it *verifies* rather than trusting: the event chain is
re-hashed, every evidence span is recomputed against the stored artifact bytes, and every
finding is re-run through the same validator that admitted it.

If a finding could be admitted by the live validator but not by replay, the provenance graph in
the report would be a claim rather than a proof. That is the failure this module exists to catch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from harness.artifacts import ArtifactStore
from harness.models import Finding, Observation, ReplayRecord
from harness.util import canonical_json, read_json, read_jsonl, sha256_text, utcnow


def _final_segment(events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The events belonging to the run whose state files are on disk.

    Running into a directory that already holds a run appends a second ``RUN_STARTED`` to the chain
    and overwrites the record files with the new run's state -- which is what the frozen evaluation
    fixture looks like. Only the events after the last ``RUN_STARTED`` describe those files;
    measuring them against an earlier segment would report every earlier attempt as missing.
    """
    start = 0
    for index, row in enumerate(events):
        if row.get("type") == "RUN_STARTED":
            start = index
    return list(events[start:])


def _witnessed(segment: Sequence[dict[str, Any]], event_type: str, key: str) -> dict[str, dict[str, Any]]:
    """Payloads of every ``event_type`` event in the segment, keyed by the record it names."""
    out: dict[str, dict[str, Any]] = {}
    for row in segment:
        if row.get("type") != event_type:
            continue
        data = row.get("data")
        if not isinstance(data, dict):
            continue
        record_id = data.get(key)
        if isinstance(record_id, str) and record_id:
            out[record_id] = data
    return out


def _string_list(value: Any) -> list[str]:
    """A recorded list of strings, or nothing at all if the field is not one."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


class ReplayWriter:
    """Append-only recording of model and provider interactions.

    Prompts are recorded verbatim because replay matches a re-rendered prompt against the
    recorded request digest; storing only a hash would make a mismatch undiagnosable.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def _write(self, record: ReplayRecord) -> None:
        from harness.util import append_jsonl

        append_jsonl(self.path, record.to_jsonl())
        self._count += 1

    def model(self, *, key: str, step: int, request: str, response: Any) -> ReplayRecord:
        record = ReplayRecord(
            kind="model",
            key=key,
            step=step,
            request_sha256=sha256_text(request),
            response=response,
            recorded_at=utcnow(),
            request_text=request,
        )
        self._write(record)
        return record

    def provider(self, *, key: str, step: int, request: dict[str, Any], response: Any) -> ReplayRecord:
        record = ReplayRecord(
            kind="provider",
            key=key,
            step=step,
            request_sha256=sha256_text(canonical_json(request)),
            response=response,
            recorded_at=utcnow(),
        )
        self._write(record)
        return record


class Replayer:
    """Reads a finished run directory and re-derives its structured state."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        if not (self.run_dir / "events.jsonl").exists():
            from harness.errors import ReplayError

            raise ReplayError(f"{self.run_dir} is not a run directory (no events.jsonl)")
        self.problems: list[str] = []
        run_meta = read_json(self.run_dir / "run.json") if (self.run_dir / "run.json").exists() else {}
        self.run_id = str(run_meta.get("run_id") or self.run_dir.name)
        self._observations: dict[str, Observation] = {}
        self._recorded_observation_ids: set[str] = set()
        self._findings: list[Finding] = []
        self._load_records()

    def _load_records(self) -> None:
        """Read the record files off disk. A row that will not reconstruct is reported, not raised.

        Called from the constructor and again from :meth:`verify`, because verification has to describe
        the bytes that are on disk now: a caller that edits ``observations.jsonl`` between the two must
        not be held to an in-memory copy of the file it replaced.

        Both copies of the observation set are read and reconciled *separately*. The runtime writes the
        same records as a JSONL working form and as a JSON array, and the evaluation harness scores the
        array - so a check that read one of them would pass while the file a metric is computed from
        said something else (R2-31). The one the runtime wrote (``observations.jsonl``) is what the
        accessors return; the other is checked against the chain like a record file in its own right.
        """
        self._observations = {}
        self._recorded_observation_ids = set()
        self._recorded_observation_digests: dict[str, str] = {}
        self._observation_files: list[tuple[str, list[dict[str, Any]]]] = []
        for name in ("observations.jsonl", "observations.json"):
            rows = self._rows_of(name)
            if rows is None:
                continue
            self._observation_files.append((name, rows))
            for row in rows:
                row_id = row.get("id") if isinstance(row, dict) else None
                if isinstance(row_id, str):
                    self._recorded_observation_ids.add(row_id)
                    self._recorded_observation_digests[row_id] = sha256_text(canonical_json(row))
                try:
                    observation = Observation.model_validate(row)
                except Exception as exc:  # noqa: BLE001 - the row is the problem, not the reader
                    self.problems.append(f"unreadable observation {row_id} in {name}: {exc}")
                    continue
                # The JSONL form wins when both are present: it is what the runtime wrote while the run
                # was happening, and the checks below compare each file against the chain anyway.
                self._observations.setdefault(observation.id, observation)
        self._findings = []
        findings_path = self.run_dir / "findings.json"
        if findings_path.exists():
            for row in read_json(findings_path):
                try:
                    self._findings.append(Finding.model_validate(row))
                except Exception as exc:  # noqa: BLE001
                    row_id = row.get("id") if isinstance(row, dict) else None
                    self.problems.append(f"unreadable finding {row_id}: {exc}")

    def _rows_of(self, name: str) -> list[dict[str, Any]] | None:
        """The record rows in one file, or ``None`` when the file is not there.

        A file that exists but does not hold a list of records is reported here rather than being read
        as an empty set: "no observations" and "an unreadable observations file" are different facts.
        """
        path = self.run_dir / name
        if not path.exists():
            return None
        if name.endswith(".jsonl"):
            rows = read_jsonl(path)
        else:
            value = read_json(path)
            if isinstance(value, dict):
                value = value.get("observations") or value.get("findings") or value.get("items")
            rows = value
        if not isinstance(rows, list):
            self.problems.append(f"{name} is not a list of records")
            return []
        return [row for row in rows if isinstance(row, dict)]

    def _observation_rows(self) -> list[dict[str, Any]]:
        """Every recorded observation, from the working form and from the array form.

        The runtime writes both, and the evaluation harness scores the *array*: a check that read only
        ``observations.jsonl`` would pass while the file a metric is computed from said something else
        (R2-31).
        """
        rows = [row for row in read_jsonl(self.run_dir / "observations.jsonl") if isinstance(row, dict)]
        array_path = self.run_dir / "observations.json"
        if array_path.exists():
            extra = read_json(array_path)
            if isinstance(extra, list):
                rows.extend(row for row in extra if isinstance(row, dict))
            else:
                self.problems.append("observations.json is not a list of records")
        return rows

    # -- accessors -------------------------------------------------------------------------

    @property
    def observations(self) -> dict[str, Observation]:
        return dict(self._observations)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def finding_digests(self) -> dict[str, str]:
        """Stable identity of each finding, independent of dict ordering."""
        return {f.id: sha256_text(canonical_json(f.model_dump(mode="json"))) for f in self._findings}

    # -- verification ----------------------------------------------------------------------

    def verify(self) -> bool:
        """Re-derive everything the run claims. Returns False and fills ``problems`` on any gap."""
        from harness.events import EventLog
        from harness.findings.validate import validate_finding

        self.problems = []
        self._load_records()
        log = EventLog(self.run_dir / "events.jsonl", self.run_id)
        try:
            log.verify_chain()
        except Exception as exc:  # noqa: BLE001 - chain break is reported, not raised to the caller
            self.problems.append(f"event chain did not verify: {exc}")
        # Reconciliation is attempted even after a chain break: a broken *link* does not stop the
        # lines from parsing, and the record files are exactly what is being questioned.
        try:
            chain = log.raw_events()
        except Exception as exc:  # noqa: BLE001
            self.problems.append(f"the event log could not be re-read for reconciliation: {exc}")
            chain = []
        self._reconcile_records(chain)

        store = ArtifactStore(self.run_dir, self.run_id)
        for obs in self._observations.values():
            for ref in obs.evidence:
                if not store.exists(ref.artifact):
                    self.problems.append(f"observation {obs.id} cites missing artifact {ref.artifact}")
                    continue
                if not store.verify_ref(ref):
                    self.problems.append(
                        f"observation {obs.id} has an evidence span that does not recompute "
                        f"({ref.artifact} bytes {ref.byte_start}:{ref.byte_end})"
                    )

        # Every artifact in the run, not only the ones a span happens to cite. A matcher's own
        # output is evidence for the run even when no observation points at it directly, and
        # content-addressing is only a guarantee if somebody re-checks the address.
        artifacts_dir = self.run_dir / "artifacts"
        if artifacts_dir.is_dir():
            for path in sorted(artifacts_dir.rglob("*")):
                if not path.is_file() or path.name.endswith(".meta.json"):
                    continue
                digest = f"sha256:{path.name}"
                if not store.verify_digest(digest):
                    self.problems.append(
                        f"artifact {digest[:19]} does not hash to the address it is filed under"
                    )

        for finding in self._findings:
            result = validate_finding(finding, observations=self._observations, store=store)
            if not result.ok:
                self.problems.append(f"finding {finding.id} fails re-validation: {'; '.join(result.violations)}")

        recorded = read_json(self.run_dir / "report.json") if (self.run_dir / "report.json").exists() else {}
        recorded_digests = (recorded.get("integrity") or {}).get("finding_digests") or {}
        if recorded_digests and recorded_digests != self.finding_digests():
            self.problems.append("finding digests differ from the ones recorded in report.json")

        return not self.problems

    # -- reconciliation against the chain ---------------------------------------------------

    def _reconcile_records(self, chain: Sequence[dict[str, Any]]) -> None:
        """Check the run's record files against the event chain (R2-31).

        Re-hashing artifacts and re-validating findings are both checks on the *same files the run
        wrote*: an ``observations.jsonl`` whose records were added, deleted or edited still verifies
        clean as long as the spans it cites recompute from the artifacts. The chain is the
        independent witness -- it is append-only and hash-linked, so a record that has no event
        behind it is a record the run never produced.

        What each direction can and cannot see, since the check is only worth its limits: an
        observation that no ``OBSERVATION_ADDED`` event witnesses, or one whose kind, provider or
        evidence differs from the event, is named here. Within one run segment the observation set
        only grows, so the comparison is exact in both directions. The finding set does *not* only
        grow -- a step re-derives it wholesale -- so a finding the chain witnessed and a later step
        dropped is legitimate, and deletions are caught instead by the count the final
        ``RUN_ENDED`` event records. Fields the chain does not carry (an observation's ``value``, a
        finding's claims) cannot be reconciled here at all; they are covered by the span and
        validator checks above.
        """
        segment = _final_segment(chain)
        if not segment:
            return
        self._reconcile_observations(segment)
        self._reconcile_findings(segment)

    def _reconcile_observations(self, segment: Sequence[dict[str, Any]]) -> None:
        witnessed = _witnessed(segment, "OBSERVATION_ADDED", "observation")
        for name, rows in self._observation_files:
            seen: set[str] = set()
            for row in rows:
                row_id = str(row.get("id") or "")
                if not row_id:
                    continue
                seen.add(row_id)
                data = witnessed.get(row_id)
                if data is None:
                    self.problems.append(
                        f"{name} records {row_id}, which no OBSERVATION_ADDED event in the final run "
                        f"segment witnesses"
                    )
                    continue
                self._mismatch("observation", row_id, "kind", row.get("kind"), data.get("kind"))
                self._mismatch("observation", row_id, "provider", row.get("provider"), data.get("provider"))
                evidence = row.get("evidence")
                artifacts = [
                    str(entry.get("artifact"))
                    for entry in evidence
                    if isinstance(entry, dict) and entry.get("artifact")
                ] if isinstance(evidence, list) else []
                self._mismatch("observation", row_id, "evidence", sorted(artifacts), sorted(_string_list(data.get("evidence"))))
                self._reconcile_record_digest(
                    "observation",
                    row_id,
                    data,
                    {row_id: sha256_text(canonical_json(row))},
                    source=name,
                )
            for observation_id in sorted(set(witnessed) - seen):
                self.problems.append(
                    f"the event chain witnesses observation {observation_id}, which {name} does not record"
                )

    def _reconcile_findings(self, segment: Sequence[dict[str, Any]]) -> None:
        witnessed = _witnessed(segment, "FINDING_ADDED", "finding")
        for finding in sorted(self._findings, key=lambda f: f.id):
            data = witnessed.get(finding.id)
            if data is None:
                self.problems.append(
                    f"findings.json records {finding.id}, which no FINDING_ADDED event in the final "
                    f"run segment witnesses"
                )
                continue
            self._mismatch("finding", finding.id, "title", finding.title, data.get("title"))
            self._mismatch("finding", finding.id, "status", finding.status, data.get("status"))
            self._mismatch(
                "finding",
                finding.id,
                "cve",
                sorted(finding.cve),
                sorted(_string_list(data.get("cve"))),
            )
            self._reconcile_record_digest(
                "finding",
                finding.id,
                data,
                {finding.id: sha256_text(canonical_json(finding.model_dump(mode="json")))},
            )
        ended = next((row for row in reversed(segment) if row.get("type") == "RUN_ENDED"), None)
        expected = (ended or {}).get("data", {}).get("findings")
        if isinstance(expected, int) and expected != len(self._findings):
            self.problems.append(
                f"the final RUN_ENDED event records {expected} findings, but findings.json records "
                f"{len(self._findings)}"
            )

    def _reconcile_record_digest(
        self,
        what: str,
        record_id: str,
        data: dict[str, Any],
        recorded: dict[str, str],
        *,
        source: str = "",
    ) -> None:
        """Compare the digest the chain records for a record with the record on disk.

        The event's own fields are a summary of what a record holds, not the record: an observation's
        value, taint and trust class reach no event field, so an edit to any of them used to replay
        clean. The digest is what covers those, and a run directory written before v1.2 carries none -
        for those, re-deriving findings from observations is the check that sees an edited value
        (`eval/replay_pass.py`), which this method deliberately does not attempt.
        """
        witnessed = data.get("record")
        if not isinstance(witnessed, str) or not witnessed:
            return
        subject = f"{record_id} in {source}" if source else record_id
        self._mismatch(what, subject, "record digest", recorded.get(record_id), witnessed)

    def _mismatch(self, what: str, record_id: str, field: str, recorded: Any, witnessed: Any) -> None:
        if recorded != witnessed:
            self.problems.append(
                f"{what} {record_id} was recorded with {field}={recorded!r}, but the event chain "
                f"witnesses {field}={witnessed!r}"
            )

    def report(self) -> dict[str, Any]:
        """A compact, machine-readable account of what replay was able to re-derive."""
        events = read_jsonl(self.run_dir / "events.jsonl")
        return {
            "run_id": self.run_id,
            "verified": self.verify(),
            "problems": list(self.problems),
            "event_count": len(events),
            "observation_count": len(self._observations),
            "finding_count": len(self._findings),
            "finding_digests": self.finding_digests(),
            "replay_has_no_network_calls": True,
        }
