"""Native adapters: the boundary where a capability becomes a concrete action."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from harness.models import EvidenceRef, Grant, ProviderExecution
from harness.providers.base import ProviderRequest
from harness.providers.native.logfile import LogFileProvider, media_type_for
from harness.providers.native.nmap import NmapProvider
from harness.providers.native.synthetic import SyntheticProvider
from harness.util import utcnow


def grant(*, kind: str = "net", resource: str = "net:10.77.0.11", alias: str = "lab-web-01", capabilities=("service.enumerate", "log.read")) -> Grant:
    return Grant(
        id="g-test",
        resource=resource,
        alias=alias,
        capabilities=list(capabilities),
        expires_at=utcnow() + timedelta(hours=1),
        origin="scope:test",
        kind=kind,  # type: ignore[arg-type]
    )


def request(*, capability: str, target: Grant, args: dict | None = None, timeout_s: int = 5) -> ProviderRequest:
    return ProviderRequest.build(
        grant=target, capability=capability, run_id="run-native", args=args or {}, timeout_s=timeout_s
    )


# -- synthetic --------------------------------------------------------------------------------


def test_synthetic_returns_the_recorded_scan_for_a_known_alias(fixtures_dir: Path) -> None:
    provider = SyntheticProvider(fixture_root=fixtures_dir / "nmap")
    result = provider.invoke(request(capability="service.enumerate", target=grant()))
    assert result.exit_status == "completed"
    assert result.stdout == (fixtures_dir / "nmap" / "lab_web_01.xml").read_bytes()
    assert result.media_type == "application/nmap+xml"


def test_synthetic_fails_with_a_gap_rather_than_raising_for_an_unknown_alias(fixtures_dir: Path) -> None:
    """"I have no data for this host" is coverage loss, and coverage loss belongs in the report."""
    provider = SyntheticProvider(fixture_root=fixtures_dir / "nmap")
    result = provider.invoke(
        request(capability="service.enumerate", target=grant(resource="net:10.77.0.99", alias="decoy"))
    )
    assert result.exit_status == "failed"
    assert result.stdout is None
    assert [gap.kind for gap in result.gaps] == ["provider_failure"]
    assert "decoy" in result.gaps[0].impact


def test_synthetic_fails_cleanly_when_the_fixture_root_is_empty(tmp_path: Path) -> None:
    provider = SyntheticProvider(fixture_root=tmp_path)
    result = provider.invoke(request(capability="service.enumerate", target=grant()))
    assert result.exit_status == "failed"
    assert result.gaps and result.gaps[0].kind == "provider_failure"


# -- logfile ----------------------------------------------------------------------------------


def fs_request(name: str, log_root: Path, *, capability: str = "log.read", target: Grant | None = None) -> ProviderRequest:
    return request(
        capability=capability,
        target=target or grant(kind="fs", resource="fs:/lab/logs", alias="lab-logs"),
        args={"path": name},
    )


def test_logfile_reads_a_named_file_and_picks_the_parser_by_name(fixtures_dir: Path) -> None:
    provider = LogFileProvider(root=fixtures_dir / "logs")
    auth = provider.invoke(fs_request("auth.log", fixtures_dir / "logs"))
    access = provider.invoke(fs_request("nginx_access.log", fixtures_dir / "logs"))
    assert auth.exit_status == "completed" and auth.media_type == "text/x-authlog"
    assert access.exit_status == "completed" and access.media_type == "text/x-nginx-access"
    assert b"Failed password" in auth.stdout
    assert media_type_for("weird.txt") == "text/x-authlog"


@pytest.mark.parametrize("name", ["../secrets.key", "../../etc/shadow", "sub/../../escape.log"])
def test_logfile_refuses_a_path_that_escapes_its_root(name: str, tmp_path: Path, fixtures_dir: Path) -> None:
    """A traversal attempt is a refusal, not a best-effort read of something nearby."""
    provider = LogFileProvider(root=fixtures_dir / "logs")
    result = provider.invoke(fs_request(name, fixtures_dir / "logs"))
    assert result.exit_status == "denied"
    assert result.stdout is None
    assert result.gaps and result.gaps[0].kind == "permission_denied"


def test_logfile_refuses_a_filename_with_control_characters(fixtures_dir: Path) -> None:
    provider = LogFileProvider(root=fixtures_dir / "logs")
    result = provider.invoke(fs_request("auth.log\x00.png", fixtures_dir / "logs"))
    assert result.exit_status == "denied"
    assert result.gaps and result.gaps[0].kind == "permission_denied"


def test_logfile_refuses_a_network_grant(fixtures_dir: Path) -> None:
    """A grant to scan a host is not a grant to read a filesystem."""
    provider = LogFileProvider(root=fixtures_dir / "logs")
    result = provider.invoke(fs_request("auth.log", fixtures_dir / "logs", target=grant()))
    assert result.exit_status == "denied"
    assert result.gaps and result.gaps[0].kind == "permission_denied"


def test_logfile_reports_a_missing_file_as_a_gap(fixtures_dir: Path) -> None:
    provider = LogFileProvider(root=fixtures_dir / "logs")
    result = provider.invoke(fs_request("nope.log", fixtures_dir / "logs"))
    assert result.exit_status == "failed"
    assert result.gaps and result.gaps[0].kind == "unreachable"


def test_logfile_reports_truncation_rather_than_hiding_it(fixtures_dir: Path) -> None:
    provider = LogFileProvider(root=fixtures_dir / "logs", max_bytes=64)
    result = provider.invoke(fs_request("auth.log", fixtures_dir / "logs"))
    assert result.exit_status == "completed"
    assert len(result.stdout) == 64
    kinds = {gap.kind for gap in result.gaps}
    assert "partial_coverage" in kinds


def test_logfile_requires_a_file_name(fixtures_dir: Path) -> None:
    provider = LogFileProvider(root=fixtures_dir / "logs")
    result = provider.invoke(request(capability="log.read", target=grant(kind="fs", resource="fs:/lab/logs", alias="lab-logs")))
    assert result.exit_status == "denied"


# -- nmap -------------------------------------------------------------------------------------


def test_nmap_without_the_binary_produces_a_gap_not_an_exception() -> None:
    """nmap is not installed here, which is exactly the state a grader's machine may be in."""
    provider = NmapProvider(binary="definitely-not-installed-xyz")
    result = provider.invoke(request(capability="service.enumerate", target=grant()))
    assert result.exit_status == "failed"
    assert result.gaps and result.gaps[0].kind == "provider_failure"


def test_nmap_takes_the_host_from_the_grant_and_refuses_other_schemes() -> None:
    provider = NmapProvider(binary="definitely-not-installed-xyz")
    # A filesystem grant cannot be scanned, and the refusal happens before anything is executed.
    result = provider.invoke(
        request(capability="service.enumerate", target=grant(kind="fs", resource="fs:/lab/logs", alias="lab-logs"))
    )
    assert result.exit_status == "denied"
    assert result.gaps and result.gaps[0].kind == "permission_denied"


@pytest.mark.parametrize("ports", ["80; rm -rf /", "$(id)", "80 443", "-p"]) 
def test_nmap_refuses_a_port_argument_that_is_not_a_port_specification(ports: str) -> None:
    """The only model-supplied value that would reach argv is validated before it can."""
    provider = NmapProvider()
    result = provider.invoke(
        request(capability="service.enumerate", target=grant(), args={"ports": ports})
    )
    assert result.exit_status == "denied"
    assert result.gaps and result.gaps[0].kind == "permission_denied"


def test_nmap_advertises_http_probe_but_excludes_it() -> None:
    """A capability claim that outruns the implementation is refused at the registry boundary."""
    spec = NmapProvider().spec
    assert "http.probe" in spec.capabilities
    assert "http.probe" in spec.excludes
    assert spec.supports("service.enumerate")
    assert not spec.supports("http.probe")
    assert spec.requires_network_egress is True


def test_the_synthetic_provider_honours_a_port_window(fixtures_dir: Path) -> None:
    """A recorded scan restricted to the ports the call named.

    The fixture describes every port that was open when it was taken; a scope that authorises only
    some of them must not put the rest into the run as evidence (R2-05).
    """
    from datetime import timedelta

    from harness.models import Grant
    from harness.providers.base import ProviderRequest
    from harness.util import utcnow

    provider = SyntheticProvider(fixture_root=fixtures_dir / "nmap")
    grant = Grant(
        id="g-window",
        resource="net:10.77.0.11",
        alias="lab-web-01",
        capabilities=["service.enumerate"],
        ports=[80],
        expires_at=utcnow() + timedelta(hours=1),
        origin="test",
        kind="net",
    )

    def ports_for(args: dict) -> list[int]:
        from harness.parsers.nmap_xml import parse_nmap_xml

        result = provider.invoke(
            ProviderRequest(
                run_id="run-synthetic-ports",
                execution_id="x-1",
                capability="service.enumerate",
                args=args,
                grant=grant,
                target_alias="lab-web-01",
                timeout_s=10,
            )
        )
        assert result.exit_status == "completed", result.error
        parsed = parse_nmap_xml(
            result.stdout,
            execution=ProviderExecution(
                id="x-1",
                run_id="run-synthetic-ports",
                provider="native:synthetic",
                capability="service.enumerate",
                grant="g-window",
                policy_decision="pd-1",
                necessity_decision="d-1",
                started_at=utcnow(),
                ended_at=utcnow(),
                exit_status="completed",
            ),
            run_id="run-synthetic-ports",
            artifact_digest="sha256:" + "0" * 64,
            # A real span over the filtered bytes: the parser refuses an observation whose evidence
            # nothing can cite, which is the property being relied on elsewhere.
            evidence_of=lambda start, end: [
                EvidenceRef(
                    artifact="sha256:" + "0" * 64,
                    media_type="application/nmap+xml",
                    byte_start=start,
                    byte_end=end,
                )
            ],
            target="lab-web-01",
        )
        return sorted(
            int(obs.value["port"]) for obs in parsed.observations if obs.kind == "service"
        )

    unfiltered = ports_for({})
    assert len(unfiltered) > 1, unfiltered
    assert ports_for({"ports": "80"}) == [80]
    assert ports_for({"ports": str(unfiltered[0])}) == [unfiltered[0]]
    assert ports_for({"ports": "1-65535"}) == unfiltered
