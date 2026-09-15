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
from typing import Any

from harness.artifacts import ArtifactStore
from harness.models import Finding, Observation, ReplayRecord
from harness.util import canonical_json, read_json, read_jsonl, sha256_text, utcnow


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
        for row in read_jsonl(self.run_dir / "observations.jsonl"):
            try:
                obs = Observation.model_validate(row)
            except Exception as exc:  # noqa: BLE001
                self.problems.append(f"unreadable observation {row.get('id')}: {exc}")
                continue
            self._observations[obs.id] = obs
        self._findings: list[Finding] = []
        findings_path = self.run_dir / "findings.json"
        if findings_path.exists():
            for row in read_json(findings_path):
                try:
                    self._findings.append(Finding.model_validate(row))
                except Exception as exc:  # noqa: BLE001
                    self.problems.append(f"unreadable finding {row.get('id')}: {exc}")

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
        log = EventLog(self.run_dir / "events.jsonl", self.run_id)
        try:
            log.verify_chain()
        except Exception as exc:  # noqa: BLE001 - chain break is reported, not raised to the caller
            self.problems.append(f"event chain did not verify: {exc}")

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

        for finding in self._findings:
            result = validate_finding(finding, observations=self._observations, store=store)
            if not result.ok:
                self.problems.append(f"finding {finding.id} fails re-validation: {'; '.join(result.violations)}")

        recorded = read_json(self.run_dir / "report.json") if (self.run_dir / "report.json").exists() else {}
        recorded_digests = (recorded.get("integrity") or {}).get("finding_digests") or {}
        if recorded_digests and recorded_digests != self.finding_digests():
            self.problems.append("finding digests differ from the ones recorded in report.json")

        return not self.problems

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
