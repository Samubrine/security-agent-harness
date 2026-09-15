"""Tests for the content-addressed artifact store and the provenance log.

Two properties matter enough to be asserted directly:

* bytes on disk are the bytes that were written, and their address proves it -- so a rewritten
  artifact or repointed metadata is refused rather than parsed;
* an evidence span is recomputable, so a claim whose span was edited (or whose offsets shifted)
  fails verification instead of silently citing different bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.artifacts import ArtifactStore, ProvenanceLog
from harness.errors import BudgetExhausted, EvidenceError
from harness.util import sha256_hex

RUN_ID = "run-artifacts-0001"


def new_store(tmp_path: Path, *, max_bytes: int = 32 * 1024 * 1024) -> ArtifactStore:
    return ArtifactStore(tmp_path / "run", RUN_ID, max_bytes=max_bytes)


def artifact_path(root: Path, digest: str) -> Path:
    hexd = digest.split(":", 1)[1]
    return root / "artifacts" / hexd[:2] / hexd


def meta_path(root: Path, digest: str) -> Path:
    return artifact_path(root, digest).with_name(f"{digest.split(':', 1)[1]}.meta.json")


BANNER = (
    b"<?xml version=\"1.0\"?><nmaprun><host><address addr=\"10.77.0.11\"/><ports>"
    b"<port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\" "
    b"product=\"OpenSSH\" version=\"8.2p1\"/></port></ports></host></nmaprun>"
)


# ---------------------------------------------------------------------------------------------
# Storage contract
# ---------------------------------------------------------------------------------------------


def test_put_uses_the_content_addressed_layout(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    hexd = sha256_hex(BANNER)

    assert meta.digest == f"sha256:{hexd}"
    assert meta.byte_length == len(BANNER)
    assert artifact_path(tmp_path / "run", meta.digest).is_file()
    assert artifact_path(tmp_path / "run", meta.digest).parent.name == hexd[:2]
    assert meta_path(tmp_path / "run", meta.digest).is_file()
    assert meta.run_id == RUN_ID
    assert meta.taint == "T2"
    assert meta.created_at.tzinfo is not None


def test_artifact_bytes_survive_a_round_trip_byte_identically(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    payload = bytes(range(256)) * 3 + b"\x00\xff\xfe" + "banner \u2014 OpenSSH".encode("utf-8")
    meta = store.put(payload, media_type="application/octet-stream", producer="mcp:scanner-a")

    assert store.get(meta.digest) == payload
    assert store.exists(meta.digest) is True
    assert store.meta(meta.digest).byte_length == len(payload)


def test_put_text_stores_utf8_and_declares_a_text_media_type(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    text = "failed password for invalid user root\n"
    meta = store.put_text(text, producer="native:logfile")

    assert meta.media_type.startswith("text/plain")
    assert store.get(meta.digest) == text.encode("utf-8")


def test_identical_bytes_are_stored_once_and_keep_the_first_producers_metadata(tmp_path: Path) -> None:
    """Idempotency is an integrity property: a later writer must not be able to relabel evidence
    that is already addressed by its content."""
    root = tmp_path / "run"
    store = new_store(tmp_path)
    first = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap", taint="T2")
    second = store.put(BANNER, media_type="text/plain", producer="mcp:liar", taint="T0")

    assert second == first
    stored = sorted(p.name for p in (root / "artifacts").rglob("*") if p.is_file())
    assert stored == [first.digest.split(":")[1], f"{first.digest.split(':')[1]}.meta.json"]


def test_two_different_payloads_never_collide_to_the_same_digest(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    payloads = [
        b"",
        b"\x00",
        b"OpenSSH_8.2p1",
        b"OpenSSH_8.2p2",
        b"OpenSSH_8.2p1 ",
        b"a" * 512 + b"b",
        b"a" * 513,
    ]
    digests = [store.put(p, media_type="application/octet-stream", producer="t").digest for p in payloads]

    assert len(set(digests)) == len(payloads)
    for payload, digest in zip(payloads, digests, strict=True):
        assert store.get(digest) == payload


def test_put_rejects_blank_media_type_or_producer(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    with pytest.raises(ValueError):
        store.put(b"x", media_type="", producer="native:nmap")
    with pytest.raises(ValueError):
        store.put(b"x", media_type="text/plain", producer="")


# ---------------------------------------------------------------------------------------------
# Adversarial: refuse bytes that do not match their address
# ---------------------------------------------------------------------------------------------


def test_rewriting_an_artifact_makes_it_unreadable(tmp_path: Path) -> None:
    root = tmp_path / "run"
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")

    artifact_path(root, meta.digest).write_bytes(b"<nmaprun>nothing to see here</nmaprun>")

    with pytest.raises(EvidenceError):
        store.get(meta.digest)


def test_metadata_cannot_be_repointed_at_another_artifacts_bytes(tmp_path: Path) -> None:
    root = tmp_path / "run"
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")

    row = json.loads(meta_path(root, meta.digest).read_text(encoding="utf-8"))
    row["digest"] = f"sha256:{'0' * 64}"
    meta_path(root, meta.digest).write_text(json.dumps(row), encoding="utf-8")

    with pytest.raises(EvidenceError):
        store.meta(meta.digest)


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "sha256",
        "sha256:",
        "sha256:abcd",
        f"sha256:{'0' * 63}",
        f"sha256:{'g' * 64}",
        "sha256:" + "A" * 64,  # uppercase is not the canonical form
        "sha256:../../etc/passwd",
        f"../../{'0' * 32}",
        "md5:0123456789abcdef0123456789abcdef",
    ],
)
def test_a_digest_is_a_typed_token_not_a_path(tmp_path: Path, digest: str) -> None:
    store = new_store(tmp_path)
    for call in (store.get, store.meta, store.exists):
        with pytest.raises(EvidenceError):
            call(digest)


def test_get_reports_a_missing_artifact_distinctly(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    missing = f"sha256:{'1' * 64}"
    with pytest.raises(EvidenceError):
        store.get(missing)
    assert store.exists(missing) is False


# ---------------------------------------------------------------------------------------------
# Byte budget
# ---------------------------------------------------------------------------------------------


def test_a_single_artifact_over_the_byte_budget_is_refused(tmp_path: Path) -> None:
    store = new_store(tmp_path, max_bytes=16)
    with pytest.raises(BudgetExhausted) as excinfo:
        store.put(b"x" * 17, media_type="text/plain", producer="native:nmap")
    assert "max_artifact_bytes" in str(excinfo.value)
    assert not (tmp_path / "run" / "artifacts").exists()


def test_the_byte_budget_is_cumulative_across_puts(tmp_path: Path) -> None:
    store = new_store(tmp_path, max_bytes=64)
    store.put(b"a" * 40, media_type="text/plain", producer="native:nmap")

    with pytest.raises(BudgetExhausted) as excinfo:
        store.put(b"b" * 40, media_type="text/plain", producer="native:nmap")
    assert "max_artifact_bytes" in str(excinfo.value)


def test_re_putting_stored_bytes_does_not_spend_the_budget_twice(tmp_path: Path) -> None:
    store = new_store(tmp_path, max_bytes=64)
    payload = b"a" * 64
    first = store.put(payload, media_type="text/plain", producer="native:nmap")

    assert store.put(payload, media_type="text/plain", producer="native:nmap") == first


def test_the_byte_budget_survives_re_opening_the_store(tmp_path: Path) -> None:
    """A budget that resets when the process does is not a budget."""
    store = new_store(tmp_path, max_bytes=64)
    store.put(b"a" * 60, media_type="text/plain", producer="native:nmap")

    reopened = new_store(tmp_path, max_bytes=64)
    with pytest.raises(BudgetExhausted):
        reopened.put(b"b" * 10, media_type="text/plain", producer="native:nmap")


# ---------------------------------------------------------------------------------------------
# Evidence spans
# ---------------------------------------------------------------------------------------------


def test_ref_records_the_hash_of_the_exact_slice(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    start = BANNER.index(b"OpenSSH")
    ref = store.ref(meta.digest, byte_start=start, byte_end=start + 12, locator="banner", line_start=1, line_end=1)

    assert ref.artifact == meta.digest
    assert ref.media_type == "application/nmap+xml"
    assert ref.taint == "T3"  # anything a tool returned is attacker-reachable data
    # Independently recomputed here rather than by calling the model's own helper, so the test can
    # actually fail if the span that was hashed is the wrong slice.
    expected = sha256_hex(BANNER[start : start + 12].decode("utf-8", errors="replace").encode("utf-8"))
    assert ref.span_sha256 == expected
    assert store.verify_ref(ref) is True


def test_a_caller_can_choose_a_lower_taint_but_the_default_is_hostile(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    meta = store.put_text("lab-nginx access log line\n", producer="native:logfile")
    ref = store.ref(meta.digest, byte_start=0, byte_end=5, taint="T2")
    assert store.verify_ref(ref) is True


def test_ref_refuses_spans_that_do_not_exist_in_the_artifact(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    for start, end in [(-1, 4), (0, len(BANNER) + 1), (10, 5)]:
        with pytest.raises(EvidenceError):
            store.ref(meta.digest, byte_start=start, byte_end=end)


def test_a_mutated_evidence_ref_fails_verification(tmp_path: Path) -> None:
    """The claim under test: changing the bytes a finding cites is detectable."""
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    ref = store.ref(meta.digest, byte_start=0, byte_end=40)
    assert store.verify_ref(ref) is True

    forged = ref.model_copy(update={"span_sha256": f"sha256:{'0' * 64}"})
    assert store.verify_ref(forged) is False

    shifted = ref.model_copy(update={"byte_start": 1, "byte_end": 41})
    assert store.verify_ref(shifted) is False

    emptied = ref.model_copy(update={"span_sha256": ""})
    assert store.verify_ref(emptied) is False


def test_verification_returns_false_rather_than_raising_when_it_cannot_decide(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    ref = store.ref(meta.digest, byte_start=0, byte_end=8)

    assert store.verify_ref(ref.model_copy(update={"artifact": f"sha256:{'2' * 64}"})) is False
    assert store.verify_ref(ref.model_copy(update={"artifact": "not-a-digest"})) is False
    assert store.verify_ref(ref.model_copy(update={"byte_end": 10**9})) is False


def test_a_span_into_a_rewritten_artifact_does_not_verify(tmp_path: Path) -> None:
    root = tmp_path / "run"
    store = new_store(tmp_path)
    meta = store.put(BANNER, media_type="application/nmap+xml", producer="native:nmap")
    ref = store.ref(meta.digest, byte_start=0, byte_end=8)

    artifact_path(root, meta.digest).write_bytes(b"X" * len(BANNER))
    assert store.verify_ref(ref) is False  # never raises, never claims success


# ---------------------------------------------------------------------------------------------
# Provenance log
# ---------------------------------------------------------------------------------------------


def test_provenance_triples_round_trip_with_extra_fields(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path / "provenance.jsonl")
    log.add("obs-1", "derived_from", "sha256:abc", span="0-12", provider="native:nmap")
    log.add("claim-1", "supports", "obs-1")

    triples = log.triples()
    assert [t["relation"] for t in triples] == ["derived_from", "supports"]
    assert triples[0]["span"] == "0-12"
    assert triples[0]["provider"] == "native:nmap"
    assert triples[0]["subject"] == "obs-1"
    assert triples[1]["object"] == "obs-1"
    assert all(t["at"].endswith("Z") for t in triples)


def test_provenance_log_is_append_only_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "provenance.jsonl"
    ProvenanceLog(path).add("exec-1", "produced", "sha256:abc")
    reopened = ProvenanceLog(path)
    reopened.add("exec-1", "produced", "sha256:def")

    assert [t["object"] for t in reopened.triples()] == ["sha256:abc", "sha256:def"]
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_provenance_triples_must_be_complete(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path / "provenance.jsonl")
    with pytest.raises(ValueError):
        log.add("", "derived_from", "sha256:abc")
    with pytest.raises(ValueError):
        log.add("obs-1", "", "sha256:abc")
    with pytest.raises(ValueError):
        log.add("obs-1", "derived_from", "")
    assert log.triples() == []


def test_provenance_extra_fields_may_not_shadow_the_triple(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path / "provenance.jsonl")
    with pytest.raises(ValueError):
        # `at` is the timestamp the log itself records; an extra field must not overwrite it.
        log.add("obs-1", "derived_from", "sha256:abc", at="1999-01-01T00:00:00Z")
    assert log.triples() == []
