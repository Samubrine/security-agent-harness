"""Tests for provider-side egress (INTERFACES.md 6.2, invariant 12).

The adversarial cases are the point. The audit's finding was that a component was allowed to
grade itself: ``requires_network_egress`` is the provider's own claim, and policy consumed it as
fact, so a remote transport registered as "no egress" was treated as a local source. Every test
below is written to fail if the verdict can be influenced by that claim, by a DNS name mistaken
for a local host, or by an endpoint nobody could classify.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from harness.errors import EgressViolation
from harness.models import EgressAssessment, ProviderSpec
from harness.policy import egress as egress_mod
from harness.policy.egress import (
    REASON_DECLARATION_MISMATCH,
    REASON_EGRESS_ENABLED,
    REASON_ENDPOINT_LOCAL,
    REASON_ENDPOINT_PUBLIC,
    REASON_ENDPOINT_UNKNOWN,
    REASON_LOCAL_EXECUTION,
    REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT,
    REASON_PERMITTED,
    REASON_NOT_PERMITTED,
    assess_provider_egress,
    classify_endpoint,
    classify_prompt_content,
    redact_for_egress,
    require_permitted,
)

PUBLIC_IPV4 = "http://8.8.8.8:11434/v1"
PUBLIC_IPV6 = "https://[2606:4700:4700::1111]:443/v1"
DNS_NAME = "vuln-svc.internal:8080"


def _spec(**overrides):
    """A real ``ProviderSpec``: the transport fact lives in the record, not in loose kwargs."""
    base = dict(
        id="mcp-vuln-remote",
        kind="mcp",
        capabilities=["vuln.lookup"],
        output_media_type="application/json",
        parser="trivy-json",
        risk="MEDIUM",
        trust_class="external_provider",
        requires_network_egress=True,
        transport="remote_service",
        endpoint="https://vuln-svc.example.com:8443/v1",
    )
    base.update(overrides)
    return ProviderSpec(**base)


def _assess(spec: ProviderSpec, *, egress_enabled: bool = False) -> EgressAssessment:
    """The wiring the contract names: transport is a harness fact, declaration is a claim."""
    return assess_provider_egress(
        spec.id,
        endpoint=spec.endpoint,
        declared_requires_egress=spec.requires_network_egress,
        egress_enabled=egress_enabled,
        local_subprocess=(spec.transport == "local_subprocess"),
    )


# ---------------------------------------------------------------------------------------------
# classify_endpoint
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "127.0.0.1",
        "127.0.0.2",  # 127.0.0.0/8 is loopback in its entirety, not just .1
        "127.255.255.254",
        "127.0.0.0",
        "127.5.5.5",
        "localhost",
        "LOCALHOST",
        "localhost:11434",
        "http://localhost:11434/v1",
        "::1",
        "[::1]:8080",
        "http://[::1]:8080/v1",
    ],
)
def test_loopback_forms(endpoint: str) -> None:
    assert classify_endpoint(endpoint) == "loopback"


@pytest.mark.parametrize(
    "endpoint",
    [
        "10.77.0.11:22",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.5",
        "169.254.169.254",  # link-local, and the cloud metadata address
        "fd00::1",
        "fe80::1",
        "http://10.77.0.11:9200/_cluster/health",
    ],
)
def test_private_forms(endpoint: str) -> None:
    assert classify_endpoint(endpoint) == "private"


@pytest.mark.parametrize(
    "endpoint",
    [
        "8.8.8.8",
        "8.8.8.8:53",
        PUBLIC_IPV4,
        PUBLIC_IPV6,
        DNS_NAME,
        "vuln-svc.internal",
        "mcp.example.com:8443",
        "https://api.vendor.test/v1/scan",
        "ssh://10.77.0.9@public-relay.example.com:22",
    ],
)
def test_public_forms(endpoint: str) -> None:
    assert classify_endpoint(endpoint) == "public"


def test_a_dns_name_is_never_treated_as_local() -> None:
    # This is the bug being fixed. Nothing here resolves a name, so all this module can know is
    # that a name which is not the literal ``localhost`` points somewhere off this host.
    assert classify_endpoint("vuln-svc.internal:8080") == "public"
    assert classify_endpoint("vuln-svc.local") == "public"
    assert classify_endpoint("internal") == "public"
    assert classify_endpoint("localhost.internal") == "public"
    # A trailing dot makes it a fully-qualified DNS name, not the loopback token. Failing closed
    # costs a refused call; failing open would cost the run.
    assert classify_endpoint("localhost.") == "public"


@pytest.mark.parametrize("endpoint", [None, "", "   ", "\t\n", "not a host!!", "http://", "://x"])
def test_unparsable_input_is_unknown(endpoint: str | None) -> None:
    assert classify_endpoint(endpoint) == "unknown"


@pytest.mark.parametrize(
    "endpoint",
    [
        "localhost\n8.8.8.8",  # smuggling a second authority must not read as loopback
        "127.0.0.1 8.8.8.8",
        "8.8.8.8:abc",  # a malformed port is not repaired into a host
        "[::1",
        "[]",
    ],
)
def test_multi_token_or_malformed_input_is_unknown_not_local(endpoint: str) -> None:
    assert classify_endpoint(endpoint) == "unknown"


def test_near_miss_numeric_hosts_do_not_become_loopback() -> None:
    # 2130706433 is 127.0.0.1 in decimal and 127.1 is a shorthand; neither is an address literal
    # this module accepts, so both fail closed rather than being reinterpreted into loopback.
    for endpoint in ("2130706433", "0x7f000001", "127.1", "999.1.1.1"):
        assert classify_endpoint(endpoint) in {"public", "unknown"}


def test_the_module_never_resolves_a_name() -> None:
    # Resolution is the bug, not just a slow path. Importing a resolver at all invites a later
    # caller to use it, so the module is required to contain no such name.
    source = Path(egress_mod.__file__).read_text(encoding="utf-8")
    assert "socket" not in source
    assert "getaddrinfo" not in source
    assert "gethostbyname" not in source
    assert "import dns" not in source


# ---------------------------------------------------------------------------------------------
# assess_provider_egress - the permission table
# ---------------------------------------------------------------------------------------------


def test_the_permission_table_is_a_table_not_a_formula() -> None:
    # Pins all four rows. The tempting one-liner ``not required or enabled`` is wrong: it permits
    # ``unknown``, which is exactly what a component grading itself would want.
    rows = {
        "loopback": (False, True),
        "private": (False, True),
        "public": (True, False),
        "unknown": (False, False),
    }
    endpoints = {
        "loopback": "127.0.0.1",
        "private": "10.77.0.11",
        "public": "8.8.8.8",
        "unknown": "not a host!!",
    }
    for klass, (required, permitted_without_egress) in rows.items():
        got = assess_provider_egress("p", endpoint=endpoints[klass], egress_enabled=False)
        assert got.endpoint_class == klass
        assert got.egress_actually_required is required
        assert got.permitted is permitted_without_egress


def test_unknown_is_refused_without_egress_enabled() -> None:
    for endpoint in (None, "", "not a host!!"):
        got = assess_provider_egress("p", endpoint=endpoint, egress_enabled=False)
        assert got.endpoint_class == "unknown"
        assert got.permitted is False
        with pytest.raises(EgressViolation):
            require_permitted(got)


@pytest.mark.parametrize("endpoint", [None, "", "not a host!!", "8.8.8.8", DNS_NAME])
def test_explicit_egress_enabled_permits_public_and_unknown(endpoint: str | None) -> None:
    got = assess_provider_egress("p", endpoint=endpoint, egress_enabled=True)
    assert got.permitted is True
    assert REASON_EGRESS_ENABLED in got.reasons
    require_permitted(got)


def test_local_subprocess_is_permitted_even_with_egress_disabled() -> None:
    got = assess_provider_egress("nmap", endpoint=None, local_subprocess=True, egress_enabled=False)
    assert got.endpoint_class == "loopback"
    assert got.egress_actually_required is False
    assert got.permitted is True
    assert REASON_LOCAL_EXECUTION in got.reasons
    require_permitted(got)


def test_local_subprocess_with_a_public_endpoint_is_permitted_but_flagged() -> None:
    # The contract makes local execution loopback by construction. A contradictory endpoint is
    # permitted but cannot pass unremarked, so an auditor sees the impossible pair.
    got = assess_provider_egress(
        "nmap", endpoint=PUBLIC_IPV4, local_subprocess=True, egress_enabled=False
    )
    assert got.endpoint_class == "loopback"
    assert got.permitted is True
    assert got.endpoint == PUBLIC_IPV4
    assert REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT in got.reasons


# ---------------------------------------------------------------------------------------------
# assess_provider_egress - the declaration is only evidence about the declarer
# ---------------------------------------------------------------------------------------------


def test_declared_false_with_a_public_endpoint_is_refused() -> None:
    # The exact audit finding: the provider says "no egress" and the endpoint says otherwise.
    got = assess_provider_egress(
        "mcp-remote", endpoint=PUBLIC_IPV4, declared_requires_egress=False, egress_enabled=False
    )
    assert got.endpoint_class == "public"
    assert got.egress_actually_required is True
    assert got.permitted is False
    assert got.declaration_mismatch is True
    assert REASON_DECLARATION_MISMATCH in got.reasons


def test_declared_false_never_makes_a_public_name_local() -> None:
    got = assess_provider_egress(
        "mcp-remote", endpoint=DNS_NAME, declared_requires_egress=False, egress_enabled=False
    )
    assert got.endpoint_class == "public"
    assert got.permitted is False


def test_declaration_mismatch_is_recorded_even_when_permitted() -> None:
    # Declaring egress over a loopback endpoint is a mismatch too, and it is kept even though the
    # call is allowed, because policy's risk computation used the declaration.
    got = assess_provider_egress(
        "native", endpoint="127.0.0.1:9200", declared_requires_egress=True, egress_enabled=False
    )
    assert got.permitted is True
    assert got.egress_actually_required is False
    assert REASON_DECLARATION_MISMATCH in got.reasons

    enabled = assess_provider_egress(
        "mcp-remote", endpoint=PUBLIC_IPV4, declared_requires_egress=False, egress_enabled=True
    )
    assert enabled.permitted is True
    assert REASON_DECLARATION_MISMATCH in enabled.reasons


def test_matching_declarations_carry_no_mismatch_reason() -> None:
    honest = assess_provider_egress(
        "mcp-remote", endpoint=PUBLIC_IPV4, declared_requires_egress=True, egress_enabled=True
    )
    assert honest.declaration_mismatch is False
    assert REASON_DECLARATION_MISMATCH not in honest.reasons
    local = assess_provider_egress(
        "native", endpoint="127.0.0.1", declared_requires_egress=False, egress_enabled=False
    )
    assert REASON_DECLARATION_MISMATCH not in local.reasons


def test_locally_executed_provider_never_reports_a_transport_mismatch() -> None:
    # nmap declares requires_network_egress=True while running as a plain local process: it
    # reaches out to a *target*, which is a scope question, not a transport lie. Flagging it here
    # would fire on every nmap run and teach an operator to ignore the reason.
    for declared in (True, False):
        got = assess_provider_egress(
            "nmap",
            endpoint=None,
            declared_requires_egress=declared,
            egress_enabled=False,
            local_subprocess=True,
        )
        assert got.permitted is True
        assert REASON_DECLARATION_MISMATCH not in got.reasons
        assert got.declared_by_provider is declared  # still echoed for the record


def test_declared_by_provider_is_never_trusted_for_the_verdict() -> None:
    # Whatever the claim, the class comes from the endpoint alone.
    for declared in (True, False):
        got = assess_provider_egress(
            "mcp-remote", endpoint=PUBLIC_IPV4, declared_requires_egress=declared
        )
        assert got.endpoint_class == "public"
        assert got.egress_actually_required is True
        assert got.permitted is False


# ---------------------------------------------------------------------------------------------
# require_permitted
# ---------------------------------------------------------------------------------------------


def test_require_permitted_names_the_provider_and_the_class() -> None:
    got = assess_provider_egress("mcp-vuln-remote", endpoint=PUBLIC_IPV4, egress_enabled=False)
    with pytest.raises(EgressViolation) as excinfo:
        require_permitted(got)
    message = str(excinfo.value)
    assert "mcp-vuln-remote" in message
    assert "public" in message


def test_require_permitted_returns_none_when_permitted() -> None:
    assert require_permitted(assess_provider_egress("p", endpoint="127.0.0.1")) is None


def test_a_tampered_assessment_cannot_assert_its_way_past_the_table() -> None:
    # permitted=True with a refused class and no egress-enabled evidence is internally
    # inconsistent. It cannot be produced by assess_provider_egress, so it is refused.
    forged = EgressAssessment(
        provider="mcp-remote",
        endpoint=PUBLIC_IPV4,
        endpoint_class="public",
        egress_actually_required=True,
        permitted=True,
        reasons=[],
    )
    with pytest.raises(EgressViolation):
        require_permitted(forged)


def test_a_consistent_assessment_still_passes() -> None:
    honest = assess_provider_egress(
        "mcp-remote", endpoint=PUBLIC_IPV4, declared_requires_egress=True, egress_enabled=True
    )
    require_permitted(honest)


def test_endpoint_class_is_constrained_by_the_record_itself() -> None:
    with pytest.raises(ValidationError):
        EgressAssessment(provider="p", endpoint_class="somewhere-off-host")


# ---------------------------------------------------------------------------------------------
# ProviderSpec-driven cases (INTERFACES.md 6.2, transport amendment)
# ---------------------------------------------------------------------------------------------


def test_remote_service_with_a_public_endpoint_is_refused() -> None:
    spec = _spec(endpoint=PUBLIC_IPV4, requires_network_egress=True)
    got = _assess(spec)
    assert got.endpoint_class == "public"
    assert got.permitted is False
    with pytest.raises(EgressViolation):
        require_permitted(got)


def test_remote_service_that_declares_no_egress_is_still_refused() -> None:
    # The original bug: the declaration changes nothing.
    spec = _spec(endpoint=PUBLIC_IPV4, requires_network_egress=False)
    got = _assess(spec)
    assert got.permitted is False
    assert got.egress_actually_required is True
    assert got.declared_by_provider is False
    assert REASON_DECLARATION_MISMATCH in got.reasons


def test_remote_service_with_no_endpoint_is_unknown_and_refused() -> None:
    # A remote transport that cannot be classified is not local.
    spec = _spec(transport="remote_service", endpoint=None)
    got = _assess(spec)
    assert got.endpoint_class == "unknown"
    assert got.permitted is False
    assert _assess(spec, egress_enabled=True).permitted is True


def test_local_subprocess_spec_declaring_egress_is_permitted_without_a_mismatch() -> None:
    # nmap: reaches a target, calls no remote service.
    spec = _spec(
        id="nmap",
        kind="native",
        capabilities=["net.raw"],
        requires_network_egress=True,
        transport="local_subprocess",
        endpoint=None,
        trust_class="local_tool",
        risk="HIGH",
    )
    got = _assess(spec)
    assert got.permitted is True
    assert got.endpoint_class == "loopback"
    assert got.egress_actually_required is False
    assert got.declared_by_provider is True
    assert REASON_DECLARATION_MISMATCH not in got.reasons
    assert REASON_LOCAL_EXECUTION in got.reasons
    require_permitted(got)


def test_a_remote_service_bound_to_loopback_is_permitted() -> None:
    # A self-hosted transport on this host is genuinely local, decided from the endpoint rather
    # than from the declaration.
    assert _assess(_spec(endpoint="http://127.0.0.1:11434/v1")).permitted is True
    assert _assess(_spec(endpoint="http://[::1]:8443/v1")).permitted is True


def test_a_local_subprocess_spec_carrying_a_remote_endpoint_is_flagged() -> None:
    # Defaults are local_subprocess + endpoint None, so a remote endpoint on a local process is
    # a contradiction in the record and must say so even though the contract permits the call.
    default = _spec(endpoint=None)
    assert default.transport == "remote_service"
    assert default.endpoint is None
    local = _spec(transport="local_subprocess", endpoint=DNS_NAME, requires_network_egress=False)
    got = _assess(local)
    assert got.endpoint_class == "loopback"
    assert got.permitted is True
    assert REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT in got.reasons


# ---------------------------------------------------------------------------------------------
# classify_prompt_content / redact_for_egress
# ---------------------------------------------------------------------------------------------

DIGEST = "sha256:" + "a1b2c3d4" * 8
MEM_REF = "mem-9f2c31ab77c1"
RUN_ID = "run-9f2c31ab77c1"


def test_empty_text_recognises_nothing() -> None:
    assert classify_prompt_content("") == []
    assert classify_prompt_content("a perfectly ordinary sentence") == []
    assert redact_for_egress("") == ("", 0)


def test_each_marker_class_is_recognised() -> None:
    assert classify_prompt_content(f"artifact {DIGEST} here") == ["artifact_digest"]
    assert classify_prompt_content(f"reference {MEM_REF} here") == ["memory_reference"]
    assert classify_prompt_content(f"run {RUN_ID} produced this") == ["run_identifier"]
    assert classify_prompt_content("read MEMORY.md first") == ["memory_section"]
    assert classify_prompt_content("read BASELINE.md first") == ["memory_section"]
    assert classify_prompt_content("byte_start 0 byte_end 812") == ["evidence_span"]
    assert classify_prompt_content("artifact:sha256:deadbeef#0-812") == ["evidence_span"]


def test_classes_are_sorted_and_deduplicated() -> None:
    text = " ".join([DIGEST, DIGEST, MEM_REF, RUN_ID, "MEMORY.md", "byte_start"])
    assert classify_prompt_content(text) == [
        "artifact_digest",
        "evidence_span",
        "memory_reference",
        "memory_section",
        "run_identifier",
    ]


def test_near_miss_markers_are_not_claimed_as_safe() -> None:
    # A digest of the wrong length, or non-hex "hex", is not a digest. That is a false negative
    # whose only remedy is the caveat pinned below: nothing recognised is not the same as nothing
    # sensitive, which is why egress is decided from the endpoint and not from this list.
    assert classify_prompt_content("sha256:" + "a" * 63) == []
    assert classify_prompt_content("sha256:" + "z" * 64) == []
    assert classify_prompt_content("mem-notreallyhex") == []


def test_the_docstring_says_an_empty_list_is_not_a_certificate() -> None:
    source = Path(egress_mod.__file__).read_text(encoding="utf-8")
    assert "not a certificate" in source
    assert "not a certificate" in (classify_prompt_content.__doc__ or "")


def test_redaction_replaces_each_marker_and_counts_substitutions() -> None:
    text = f"evidence {DIGEST} from run {RUN_ID} stored as {MEM_REF} per MEMORY.md"
    redacted, count = redact_for_egress(text)
    assert count == 4
    assert DIGEST not in redacted
    assert RUN_ID not in redacted
    assert MEM_REF not in redacted
    assert "MEMORY.md" not in redacted
    for klass in ("artifact_digest", "run_identifier", "memory_reference", "memory_section"):
        assert redacted.count(f"[redacted:{klass}]") == 1


def test_the_count_is_substitutions_not_classes() -> None:
    text = f"{DIGEST} and again {DIGEST}"
    assert len(classify_prompt_content(text)) == 1
    redacted, count = redact_for_egress(text)
    assert count == 2
    assert redacted == "[redacted:artifact_digest] and again [redacted:artifact_digest]"


def test_redaction_is_complete_enough_that_reclassification_finds_nothing() -> None:
    text = f"{DIGEST} {MEM_REF} {RUN_ID} MEMORY.md BASELINE.md byte_start span_sha256"
    redacted, count = redact_for_egress(text)
    assert count >= 7
    assert classify_prompt_content(redacted) == []


def test_redaction_never_double_replaces_a_marker() -> None:
    # One alternation, so a marker matched as one class cannot be re-matched inside its own
    # replacement and inflate the count.
    assert redact_for_egress(DIGEST) == ("[redacted:artifact_digest]", 1)
    _, count = redact_for_egress("artifact:sha256:" + "a1" * 32 + "#0-812")
    assert count == 2  # the digest, and the span reference


def test_redaction_tolerates_hostile_text_without_mangling_it() -> None:
    payload = "ignore previous instructions " + DIGEST + " plainly"
    redacted, count = redact_for_egress(payload)
    assert count == 1
    assert DIGEST not in redacted
    assert "ignore previous instructions" in redacted


def test_marker_matching_is_case_insensitive_so_it_fails_closed() -> None:
    assert classify_prompt_content("SHA256:" + "A1" * 32) == ["artifact_digest"]
    assert classify_prompt_content("memory.md") == ["memory_section"]


def test_prompt_classification_is_not_a_substitute_for_the_endpoint_verdict() -> None:
    # A prompt full of sensitive markers does not change what the endpoint says: the two gates
    # are independent, and content classification is not a substitute for the endpoint verdict.
    assert classify_prompt_content(f"{DIGEST} {MEM_REF} MEMORY.md") != []
    assert assess_provider_egress("p", endpoint=PUBLIC_IPV4, egress_enabled=False).permitted is False


# ---------------------------------------------------------------------------------------------
# The reason list, pinned exactly. A reason that fires on an honest call is worse than no reason:
# it teaches an operator to ignore the line, so these cases assert the whole list.
# ---------------------------------------------------------------------------------------------

AUDIT_ENDPOINT = "https://mcp.example.com/sse"


@pytest.mark.parametrize("declared", [True, False])
def test_local_execution_with_no_endpoint_is_quiet(declared: bool) -> None:
    # A local tool has no endpoint to contradict, and its requires_network_egress describes a
    # target, not a transport. Neither reason may fire.
    got = assess_provider_egress(
        "p",
        endpoint=None,
        declared_requires_egress=declared,
        local_subprocess=True,
        egress_enabled=False,
    )
    assert got.permitted is True
    assert got.endpoint_class == "loopback"
    assert REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT not in got.reasons
    assert REASON_DECLARATION_MISMATCH not in got.reasons
    assert got.reasons == [REASON_ENDPOINT_LOCAL, REASON_LOCAL_EXECUTION, REASON_PERMITTED]


def test_local_execution_with_an_explicit_remote_endpoint_is_flagged() -> None:
    # The contradiction this reason exists for: the harness runs the process locally *and* names
    # a remote service. Permitted per the contract, but never silent.
    got = assess_provider_egress(
        "p", endpoint=AUDIT_ENDPOINT, declared_requires_egress=False, local_subprocess=True
    )
    assert got.permitted is True
    assert REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT in got.reasons
    assert got.reasons == [
        REASON_ENDPOINT_LOCAL,
        REASON_LOCAL_EXECUTION,
        REASON_LOCAL_EXECUTION_PUBLIC_ENDPOINT,
        REASON_PERMITTED,
    ]


def test_a_remote_provider_declaring_itself_local_is_refused_for_the_audit_case() -> None:
    # The original audit finding, at the endpoint the reviewer reproduced it with: the endpoint
    # decides, the declaration only supplies the evidence that it lied.
    got = assess_provider_egress(
        "mcp-remote", endpoint=AUDIT_ENDPOINT, declared_requires_egress=False, local_subprocess=False
    )
    assert got.endpoint_class == "public"
    assert got.egress_actually_required is True
    assert got.permitted is False
    assert got.declaration_mismatch is True
    assert got.reasons == [
        REASON_ENDPOINT_PUBLIC,
        REASON_DECLARATION_MISMATCH,
        REASON_NOT_PERMITTED,
    ]


def test_no_endpoint_on_a_remote_transport_is_unknown_without_a_mismatch() -> None:
    # Both sides agree that no service egress is described, so there is nothing to report beyond
    # the refusal itself - the class, not the declaration, is what refuses the call.
    got = assess_provider_egress(
        "mcp-remote", endpoint=None, declared_requires_egress=False, local_subprocess=False
    )
    assert got.endpoint_class == "unknown"
    assert got.permitted is False
    assert got.declaration_mismatch is False
    assert got.reasons == [REASON_ENDPOINT_UNKNOWN, REASON_NOT_PERMITTED]


def test_a_declaration_of_egress_on_an_unclassifiable_endpoint_is_reported() -> None:
    # Even here the mismatch is recorded: the provider says a service is reached, the derived fact
    # (unknown) says the class implies no egress, and an auditor needs to see that disagreement
    # rather than only the refusal.
    got = assess_provider_egress(
        "mcp-remote", endpoint=None, declared_requires_egress=True, local_subprocess=False
    )
    assert got.permitted is False
    assert got.reasons == [
        REASON_ENDPOINT_UNKNOWN,
        REASON_DECLARATION_MISMATCH,
        REASON_NOT_PERMITTED,
    ]
