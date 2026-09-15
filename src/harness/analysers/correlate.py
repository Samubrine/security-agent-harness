"""Cross-provider reconciliation over normalised observations.

Decision D11 and design 01 section 8 are explicit that the correlator compares *values*, never
prose. That matters for two reasons:

* agreement and conflict become structured state a rule can cite, rather than a paragraph a reader
  has to trust;
* a conflict stays visible. The correlator never picks the answer from whichever provider responded
  last, because the failure mode this whole design guards against is a confident report whose two
  sources disagreed and nobody noticed.

Three relations are distinguishable, and the middle one is why this is not a simple equality test:

* **agreement** - two providers fill the same fields with the same values;
* **complement** - two providers fill *different* fields of the same subject (one saw the product,
  the other saw the version), which is corroboration and not a disagreement;
* **conflict** - two providers disagree about a field they both filled.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Sequence

from harness.models import Correlation, Observation
from harness.util import canonical_json, new_id

#: Only kinds where two providers describing the same subject is meaningful. Correlating, say, two
#: banners would report a conflict every time a service legitimately says something different to
#: two different probes, which would be noise rather than signal.
KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "service": ("target", "port", "protocol"),
    "host_state": ("target",),
    "vulnerability_match": ("cve", "cpe"),
    "auth_summary": ("target",),
    "http_summary": ("target",),
}

#: Fields that describe *who* observed something rather than *what* was observed. Excluded from the
#: comparison so that two providers agreeing about a port are not reported as disagreeing because
#: one recorded a scanner name.
PROVENANCE_FIELDS = frozenset(
    {"provider", "scanner", "observed_by", "execution", "parser", "method", "source"}
)


class Correlator:
    def __init__(self, run_id: str = "") -> None:
        self.run_id = run_id
        self._correlations: list[Correlation] = []

    def add(self, observations: Sequence[Observation]) -> list[Correlation]:
        """Correlate the observations supplied and return only the *new* correlations.

        Returning the delta rather than the whole set keeps the caller's event log honest: a
        correlation appears exactly once, when the second provider made it possible.
        """
        groups: dict[str, list[Observation]] = defaultdict(list)
        for observation in observations:
            key = self.key_for(observation)
            if key is not None:
                groups[key].append(observation)

        known = {c.key for c in self._correlations}
        fresh: list[Correlation] = []
        for key in sorted(groups):
            group = sorted(groups[key], key=lambda o: (o.provider, o.id))
            if len(group) < 2:
                continue
            relation, detail = self._classify(group)
            if key in known and self._unchanged(key, group):
                continue
            correlation = Correlation(
                id=new_id("cor"),
                run_id=self.run_id or group[0].run_id,
                key=key,
                observation_ids=[obs.id for obs in group],
                relation=relation,
                detail=detail,
            )
            fresh.append(correlation)
        self._correlations.extend(fresh)
        return fresh

    def correlations(self) -> list[Correlation]:
        return list(self._correlations)

    def conflicts(self) -> list[Correlation]:
        return [c for c in self._correlations if c.relation == "conflict"]

    def _unchanged(self, key: str, group: Sequence[Observation]) -> bool:
        existing = next((c for c in self._correlations if c.key == key), None)
        if existing is None:
            return False
        return existing.observation_ids == [obs.id for obs in group]

    @staticmethod
    def key_for(observation: Observation) -> str | None:
        """Identity of the subject two providers can agree or disagree about."""
        fields = KEY_FIELDS.get(observation.kind)
        if not fields:
            return None
        value = observation.value or {}
        parts = [observation.kind]
        for field in fields:
            parts.append(str(value.get(field, "?")))
            if value.get(field) in (None, "") and field in {"target", "cve"}:
                # A subject with no target cannot be corroborated; correlating on "?" would create
                # phantom agreements between unrelated observations.
                return None
        return "|".join(parts)

    def _classify(self, group: Sequence[Observation]) -> tuple[str, str]:
        providers = sorted({obs.provider for obs in group})
        values = [self._comparable(obs) for obs in group]

        shared_fields: set[str] = set()
        for value in values:
            shared_fields |= set(value)

        disagreements: list[str] = []
        for field in sorted(shared_fields):
            seen = [value[field] for value in values if field in value]
            if len(seen) > 1 and len({canonical_json(item) for item in seen}) > 1:
                disagreements.append(field)

        if not disagreements:
            covered = {field for value in values for field in value}
            if len({canonical_json(value) for value in values}) == 1:
                return "agreement", (
                    f"{len(providers)} providers ({', '.join(providers)}) report identical values"
                )
            return "complement", (
                f"{len(providers)} providers ({', '.join(providers)}) fill different fields of the "
                f"same subject: {', '.join(sorted(covered))}"
            )
        return "conflict", (
            f"providers ({', '.join(providers)}) disagree on {', '.join(disagreements)}; "
            "the conflict is preserved rather than resolved by preference"
        )

    @staticmethod
    def _comparable(observation: Observation) -> dict[str, Any]:
        return {
            key: value
            for key, value in (observation.value or {}).items()
            if key not in PROVENANCE_FIELDS
        }


def conflicting_keys(correlations: Iterable[Correlation]) -> set[str]:
    """Correlation keys currently in conflict, for the necessity gate's expansion decision."""
    return {c.key for c in correlations if c.relation == "conflict"}
