"""Offline CPE/version matching against a snapshot-stamped vulnerability database.

Decision D8 makes vulnerability mapping deterministic, for three reasons that matter more than
they might look:

* **A model cannot invent a CVE.** A reported CVE must be present in the recorded snapshot, so
  hallucination is not mitigated by prompting, it is structurally impossible.
* **A missing match is not a clean bill of health.** Absence of an entry means the snapshot has
  nothing to say, and this module returns a gap rather than an empty list a report could render as
  "not vulnerable".
* **The comparison is a tuple, not a string.** 8.2p1 sorts below 9.3p2 because versions are
  compared as numeric tuples, so a distro suffix cannot accidentally land inside the wrong range.

Everything here runs against local data. There is no network call in this module, which is what
lets the evaluation harness produce identical candidates on a machine with no internet access.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from harness.errors import ConfigError
from harness.models import EvidenceGap, Observation
from harness.util import new_id, sha256_json

#: Severity is a fixed rubric over CVSS (decision D6), never a model's opinion. One function means
#: two runs matching the same score cannot disagree about how bad it is.
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)

#: A version is a run of numbers with an optional trailing pre-release marker such as OpenSSH's
#: "p1". The numeric head is what is comparable; a distro build label after it says nothing about
#: which upstream range a binary falls in.
_VERSION_HEAD = re.compile(
    r"^\s*v?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>(?:p|pl|rc|b|a)\.?\d+)?", re.IGNORECASE
)


def severity_from_cvss(cvss: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if cvss >= threshold:
            return label
    return "info"


def parse_cpe(cpe: str) -> tuple[str, str, str, str] | None:
    """Normalise a CPE 2.2 URI or a CPE 2.3 string to (part, vendor, product, version).

    nmap emits the 2.2 URI form while vulnerability data is usually 2.3. Accepting only one form
    would mean the matcher silently finds nothing for exactly the input nmap produces.
    """
    if not cpe:
        return None
    value = cpe.strip()
    if value.startswith("cpe:2.3:"):
        fields = value.split(":")[2:]
    elif value.startswith("cpe:/"):
        fields = value[len("cpe:/") :].split(":")
    elif value.startswith("cpe:"):
        fields = value[len("cpe:") :].split(":")
    else:
        return None
    if len(fields) < 3:
        return None
    part = (fields[0] or "").strip() or "a"
    vendor = (fields[1] or "").strip().lower()
    product = (fields[2] or "").strip().lower()
    version = (fields[3] if len(fields) > 3 else "").strip()
    if version in {"*", "-"}:
        version = ""
    if not vendor or not product:
        return None
    return part, vendor, product, version


def version_key(version: str) -> tuple[int, ...] | None:
    """Comparable form of a version string, or None when it cannot be compared.

    None is the load-bearing return value: an unparsable version must produce no candidate rather
    than a default that could fall inside every range.
    """
    if not version:
        return None
    match = _VERSION_HEAD.match(version)
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group("numbers").split("."))
    suffix = match.group("suffix")
    if suffix:
        numbers = numbers + (int(re.sub(r"[^0-9]", "", suffix)),)
    return numbers


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Tuple comparison with zero padding, so 8.2 and 8.2.0 compare equal."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left == padded_right:
        return 0
    return -1 if padded_left < padded_right else 1


@dataclass
class CveCandidate:
    """One version match, carrying the observation it was derived from.

    observation_ids is not decoration: the finding built from this candidate cites that
    observation, and the observation cites artifact bytes. Drop the field and the match becomes an
    assertion with no way to check it.
    """

    cve: str
    cpe: str
    product: str
    version: str
    cvss: float
    severity: str
    summary: str
    matched_on: str
    observation_ids: list[str] = field(default_factory=list)


class VulnerabilitySnapshot:
    """An immutable, digest-stamped set of version-range entries.

    The digest is what makes "this CVE came from the snapshot" a checkable statement: a finding
    records it, and the validator refuses a CVE whose snapshot is not the one the run loaded.
    """

    def __init__(
        self,
        *,
        snapshot_id: str,
        entries: list[dict[str, Any]],
        source: str = "",
        generated_at: str = "",
    ) -> None:
        self.snapshot_id = snapshot_id
        self.entries = entries
        self.source = source
        self.generated_at = generated_at
        self.digest = "sha256:" + sha256_json({"snapshot_id": snapshot_id, "entries": entries})

    @classmethod
    def load(cls, path: Path) -> VulnerabilitySnapshot:
        path = Path(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"vulnerability snapshot {path} could not be read: {exc}") from exc
        entries_raw = payload.get("entries")
        if not isinstance(entries_raw, list) or not entries_raw:
            raise ConfigError(f"vulnerability snapshot {path} contains no entries")
        entries: list[dict[str, Any]] = []
        for index, raw in enumerate(entries_raw):
            if not isinstance(raw, dict):
                raise ConfigError(f"snapshot {path} entry {index} is not an object")
            missing = {"cve", "vendor", "product"} - set(raw)
            if missing:
                raise ConfigError(
                    f"snapshot {path} entry {index} is missing {sorted(missing)}; an entry without "
                    "a vendor or product can never match"
                )
            entries.append(
                {
                    "cve": str(raw["cve"]),
                    "vendor": str(raw["vendor"]).lower(),
                    "product": str(raw["product"]).lower(),
                    "version_start_including": raw.get("version_start_including"),
                    "version_end_excluding": raw.get("version_end_excluding"),
                    "cvss": float(raw.get("cvss") or 0.0),
                    "severity": str(raw.get("severity") or ""),
                    "summary": str(raw.get("summary") or ""),
                    "cwe": list(raw.get("cwe") or []),
                }
            )
        return cls(
            snapshot_id=str(payload.get("snapshot_id") or path.stem),
            entries=entries,
            source=str(payload.get("source") or ""),
            generated_at=str(payload.get("generated_at") or ""),
        )

    def match(
        self, cpes: Sequence[str], versions: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        """Entries whose range contains the observed version for the same vendor and product."""
        out: list[dict[str, Any]] = []
        for cpe in cpes:
            parsed = parse_cpe(cpe)
            if parsed is None:
                continue
            _, vendor, product, cpe_version = parsed
            version = (versions or {}).get(cpe) or cpe_version
            key = version_key(version)
            if key is None:
                continue
            for entry in self.entries:
                if entry["vendor"] != vendor or entry["product"] != product:
                    continue
                if not self._in_range(key, entry):
                    continue
                out.append({**entry, "matched_cpe": cpe, "matched_version": version})
        return out

    @staticmethod
    def _in_range(version: tuple[int, ...], entry: dict[str, Any]) -> bool:
        start = version_key(str(entry.get("version_start_including") or ""))
        end = version_key(str(entry.get("version_end_excluding") or ""))
        if start is not None and _compare(version, start) < 0:
            return False
        if end is not None and _compare(version, end) >= 0:
            return False
        return True

    def entries_for(self, product: str) -> list[dict[str, Any]]:
        """Every entry naming a product, matched or not. Used by the evaluation harness to score
        recall against what the snapshot could have found, not only against what it did."""
        wanted = product.lower()
        return [entry for entry in self.entries if entry["product"] == wanted]


def cpe_from_observation(obs: Observation) -> str | None:
    """The CPE a service observation carries, if any.

    A missing CPE is a real coverage gap: without it there is nothing to compare, and admitting
    that is more useful than inventing a product name from a free-text service string.
    """
    value = obs.value or {}
    cpe = value.get("cpe")
    if isinstance(cpe, str) and cpe.strip():
        return cpe.strip()
    candidates = value.get("cpes")
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return None


def extract_cpes(observations: Iterable[Observation]) -> list[str]:
    return [cpe for cpe in (cpe_from_observation(obs) for obs in observations) if cpe]


def candidate_cves(
    observations: Sequence[Observation],
    snapshot: VulnerabilitySnapshot,
    *,
    min_cvss: float = 0.0,
) -> tuple[list[CveCandidate], list[EvidenceGap]]:
    """Match every service observation against the snapshot.

    Candidates and gaps are returned together because the two honest answers to "what do we know
    about versions?" are "these CVEs" and "these services we could not map". Returning only the
    first would make unmapped services invisible in the report.
    """
    candidates: list[CveCandidate] = []
    gaps: list[EvidenceGap] = []
    seen: set[tuple[str, str]] = set()

    for obs in observations:
        if obs.kind != "service":
            continue
        value = obs.value or {}
        label = _service_label(value)
        cpe = cpe_from_observation(obs)
        if cpe is None:
            gaps.append(
                _gap(
                    obs,
                    "no_cpe",
                    f"service {label} was fingerprinted without a CPE, so no version range could be "
                    "checked; this is missing coverage, not an absence of vulnerabilities",
                )
            )
            continue
        parsed = parse_cpe(cpe)
        if parsed is None:
            gaps.append(
                _gap(obs, "no_cpe", f"CPE {cpe!r} for {label} is not a form this matcher can read")
            )
            continue
        version = str(value.get("version") or parsed[3]).strip()
        if version_key(version) is None:
            gaps.append(
                _gap(
                    obs,
                    "no_cpe",
                    f"service {label} has version {version!r}, which is not comparable to a snapshot "
                    "range; no candidate is reported rather than guessing",
                )
            )
            continue
        for hit in snapshot.match([cpe], {cpe: version}):
            cvss = float(hit.get("cvss") or 0.0)
            if cvss < min_cvss:
                continue
            key = (str(hit["cve"]), cpe)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                CveCandidate(
                    cve=str(hit["cve"]),
                    cpe=cpe,
                    product=str(hit["product"]),
                    version=version,
                    cvss=cvss,
                    severity=severity_from_cvss(cvss),
                    summary=str(hit.get("summary") or ""),
                    matched_on=str(hit.get("version_start_including") or "*"),
                    observation_ids=[obs.id],
                )
            )
    candidates.sort(key=lambda c: (-c.cvss, c.cve))
    return candidates, gaps


def _service_label(value: dict[str, Any]) -> str:
    product = value.get("product") or value.get("service") or "unknown"
    version = value.get("version") or ""
    suffix = f" {version}" if version else ""
    port = value.get("port")
    return f"{product}{suffix} on port {port}" if port is not None else f"{product}{suffix}"


def _gap(obs: Observation, kind: str, impact: str) -> EvidenceGap:
    value = obs.value or {}
    scope = {
        "observation": obs.id,
        "target": value.get("target"),
        "port": value.get("port"),
        "product": value.get("product"),
    }
    return EvidenceGap(
        id=new_id("g"),
        run_id=obs.run_id,
        kind=kind,  # type: ignore[arg-type]
        scope=scope,
        impact=impact,
        capability="vulnerability.match",
    )
