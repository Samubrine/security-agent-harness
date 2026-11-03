"""The MCP extension path, end to end: a real MCP server process registered from a config file,
called only with a human's approval, and its answer corroborated against the scan.

What these tests pin down:

* an MCP server is added with data (config/mcp_servers.json), not with harness code;
* a MEDIUM-risk third-party server is routed to a human under ``--strict``, and a run with no
  approver fails closed (the evidence it would have produced is recorded as a gap);
* "independent" really means a different trust class: the second provider for a corroborated
  conclusion is the MCP server, not a second local scanner;
* the scan and the inventory name the same machine differently (address vs alias) and are still
  compared, so agreement and the Tomcat version conflict are both recorded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from harness.analysers.correlate import Correlator
from harness.errors import ConfigError
from harness.models import ProviderSpec
from harness.providers.mcp.config import close_all, load_mcp_providers
from harness.runtime.runner import execute_run

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = REPO_ROOT / "mcp_servers" / "asset_inventory.py"
SHIPPED_CONFIG = REPO_ROOT / "config" / "mcp_servers.json"


def _config(tmp_path: Path, **override) -> Path:
    entry = {
        "id": "mcp:asset-inventory",
        "command": [sys.executable, str(SERVER)],
        "capabilities": {"service.enumerate": "inventory_services"},
        "risk": "MEDIUM",
        "trust_class": "local_mcp",
    }
    entry.update(override)
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"servers": [entry]}), encoding="utf-8")
    return path


def _events(run_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def test_the_shipped_config_starts_the_shipped_server() -> None:
    providers = load_mcp_providers(SHIPPED_CONFIG, root=REPO_ROOT)
    try:
        assert [p.spec.id for p in providers] == ["mcp:asset-inventory"]
        spec = providers[0].spec
        assert spec.capabilities == ["service.enumerate"]
        assert spec.risk == "MEDIUM"
        assert spec.trust_class == "local_mcp"
        assert spec.kind == "mcp"
    finally:
        close_all(providers)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"id": "inventory"}, "must start with 'mcp:'"),
        ({"capabilities": {"service.enumerate": "no_such_tool"}}, "does not advertise"),
        ({"risk": "SPICY"}, "risk must be one of"),
        ({"command": []}, "command must be a non-empty list"),
    ],
)
def test_a_bad_server_entry_is_a_config_error(tmp_path: Path, override: dict, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_mcp_providers(_config(tmp_path, **override), root=REPO_ROOT)


def test_corroboration_picks_a_second_trust_class_not_a_second_local_tool() -> None:
    from harness.providers.necessity import NecessityGate

    def spec(pid: str, trust: str, risk: str = "LOW") -> ProviderSpec:
        return ProviderSpec(
            id=pid, kind="native" if pid.startswith("native") else "mcp", capabilities=["service.enumerate"],
            input_schema={"type": "object"}, output_media_type="x", parser="p", risk=risk,
            trust_class=trust, requires_network_egress=False, timeout_s=10, idempotent=True, description="",
        )

    ranked = [spec("native:synthetic", "local_tool"), spec("native:nmap", "local_tool"), spec("mcp:inv", "local_mcp", "MEDIUM")]
    assert [s.id for s in NecessityGate._diverse(ranked, 2)] == ["native:synthetic", "mcp:inv"]
    # One trust class only: the plain ranked choice.
    assert [s.id for s in NecessityGate._diverse(ranked[:2], 2)] == ["native:synthetic", "native:nmap"]


def test_the_correlator_treats_an_alias_and_its_address_as_one_machine() -> None:
    from harness.models import Observation

    def service(provider: str, target: str, version: str) -> Observation:
        # Only the fields the correlator reads; the full record is validated elsewhere.
        return Observation.model_construct(
            id=f"o-{provider}-{version}", run_id="r", kind="service", provider=provider,
            value={"target": target, "port": 8080, "protocol": "tcp", "product": "Apache Tomcat", "version": version},
        )

    plain = Correlator("r")
    assert plain.add([service("native:a", "10.77.0.11", "9.0.30"), service("mcp:b", "lab-web-01", "9.0.31")]) == []

    aliased = Correlator("r", aliases={"lab-web-01": "net:10.77.0.11"})
    [conflict] = aliased.add([service("native:a", "10.77.0.11", "9.0.30"), service("mcp:b", "lab-web-01", "9.0.31")])
    assert conflict.key == "service|lab-web-01|8080|tcp"
    assert conflict.relation == "conflict"


@pytest.mark.integration
def test_without_an_approver_the_inventory_is_not_called(lab_environment, tmp_path: Path) -> None:
    artifacts = execute_run(lab_environment.request(
        objective="Check lab-web-01 versions against the inventory.", skill="version_check",
        run_id="run-vc-deny", target_alias="lab-web-01", strict=True, mcp_config=_config(tmp_path),
    ))
    events = _events(artifacts.run_dir)
    asked = [e for e in events if e["type"] == "APPROVAL_REQUESTED"]
    assert [e["data"]["provider"] for e in asked] == ["mcp:asset-inventory"]
    assert not [e for e in events if e["type"] == "PROVIDER_STARTED" and e["data"]["provider"] == "mcp:asset-inventory"]
    gaps = [json.loads(line) for line in (artifacts.run_dir / "gaps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert "rejected_by_user" in {g["kind"] for g in gaps}


@pytest.mark.integration
def test_with_approval_the_scan_and_inventory_are_compared(lab_environment, tmp_path: Path) -> None:
    artifacts = execute_run(lab_environment.request(
        objective="Check lab-web-01 versions against the inventory.", skill="version_check",
        run_id="run-vc-yes", target_alias="lab-web-01", strict=True, mcp_config=_config(tmp_path),
        approval_mode="scripted", approval_answers=(True,),
    ))
    assert artifacts.summary.status == "completed"
    rows = [json.loads(line) for line in (artifacts.run_dir / "correlations.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    relations = {row["key"]: row["relation"] for row in rows}
    assert relations["service|lab-web-01|22|tcp"] == "agreement"
    assert relations["service|lab-web-01|80|tcp"] == "agreement"
    # The inventory says Tomcat was patched to 9.0.31; the scan still sees 9.0.30.
    assert relations["service|lab-web-01|8080|tcp"] == "conflict"
