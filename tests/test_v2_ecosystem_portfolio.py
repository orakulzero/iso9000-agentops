"""Comprehensive verification tests for Multi-Repository Ecosystem Portfolio Certifier (REQ-ISO-205).

Under Agile V (arXiv:2602.20684) and ISO 9001:2015 / ISO/IEC 42001:2023:
Validates:
- certify_ecosystem_portfolio aggregation across 10+ ecosystem stations
- RFC 6962 binary Merkle tree root calculation over repository certificates
- HMAC-SHA256 portfolio signature and tamper detection
- ISO/IEC 42001 Annex A Statement of Applicability control count enforcement (>= 20 controls)
- Rejection of non-conformant repositories, high FMEA RPN (> 400), or low RTM coverage (< 0.85)
- Standalone SVG badge rendering and OASIS SARIF 2.1.0 compliance reports
- CLI subcommand 'certify-portfolio' and MCP tool 'iso_certify_portfolio' (< 64 chars)
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from iso9000_agentops.certificate import (
        certify_ecosystem_portfolio,
        export_portfolio_sarif_report,
        render_portfolio_badge_svg,
    )
except ImportError:

    def certify_ecosystem_portfolio(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import certify_ecosystem_portfolio as fn

        return fn(*args, **kwargs)

    def render_portfolio_badge_svg(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import render_portfolio_badge_svg as fn

        return fn(*args, **kwargs)

    def export_portfolio_sarif_report(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import export_portfolio_sarif_report as fn

        return fn(*args, **kwargs)


def _make_dummy_hash(seed: str) -> str:
    """Generate a deterministic 64-char hex SHA-256 hash for tests."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _make_sample_repo_report(
    repo_name: str,
    *,
    status: str = "CERTIFIED",
    rtm_coverage: float = 1.0,
    max_rpn: int = 120,
    overall_risk: str = "L2",
    tests_passed: int = 50,
    tests_total: int = 50,
    soa_controls: int = 24,
) -> dict[str, Any]:
    """Construct a schema-valid repository verification report fixture."""
    merkle_root = _make_dummy_hash(f"merkle-{repo_name}")
    gate1_hmac = _make_dummy_hash(f"gate1-{repo_name}")
    cert_sig = _make_dummy_hash(f"sig-{repo_name}")

    certificate = {
        "certificate_id": f"CERT-{repo_name}-v2.0.0",
        "status": status,
        "standards": [
            "ISO 9001:2015",
            "ISO/IEC 42001:2023",
            "Agile V (arXiv:2602.20684)",
        ],
        "baseline_id": f"BASE-{repo_name}",
        "version": "2.0.0",
        "rtm_compliant": status == "CERTIFIED" and rtm_coverage >= 0.85,
        "rtm_coverage": rtm_coverage,
        "max_rpn": max_rpn,
        "overall_risk_level": overall_risk,
        "merkle_root": merkle_root,
        "gate1_hmac": gate1_hmac,
        "tests_passed": tests_passed,
        "tests_total": tests_total,
        "certificate_signature": cert_sig,
    }

    rtm_report = {
        "compliant": status == "CERTIFIED" and rtm_coverage >= 0.85,
        "coverage_ratio": rtm_coverage,
        "requirements": ["REQ-001", "REQ-002"],
        "orphan_requirements": [] if status == "CERTIFIED" else ["REQ-ORPHAN"],
        "unimplemented_requirements": [] if status == "CERTIFIED" else ["REQ-UNIMPL"],
        "gold_plated_symbols": [],
    }

    fmea_report = {
        "max_rpn": max_rpn,
        "overall_risk_level": overall_risk,
        "critical_modes": ["FM-01"] if (max_rpn > 400 or overall_risk == "L4") else [],
        "modes": [
            {
                "id": "FM-01",
                "name": "Component failure",
                "rpn": max_rpn,
                "risk_level": overall_risk,
                "action_required": max_rpn > 400,
            }
        ],
    }

    soa_report = {
        "standard": "ISO/IEC 42001:2023",
        "soa_version": "2.0.0",
        "controls_total": 38,
        "controls_implemented": soa_controls,
        "controls": [
            {"id": f"A.{i}", "implemented": i <= soa_controls}
            for i in range(1, 39)
        ],
    }

    return {
        "repository": repo_name,
        "version": "2.0.0",
        "certificate": certificate,
        "rtm_report": rtm_report,
        "fmea_report": fmea_report,
        "soa": soa_report,
    }


def _make_10_station_portfolio() -> dict[str, dict[str, Any]]:
    """Generate reports for all 10 non-video stations in Antigravity v2.0.0."""
    stations = [
        "iso9000-agentops",
        "agy-computer-use",
        "agy-golden-stack",
        "agy-brain-memory",
        "agy-doctor-mux",
        "agy-lsrpc-bridge",
        "pe-reversing-lab",
        "eskd-vision-station",
        "agy-secret-shield",
        "agy-federation-mesh",
    ]
    return {stn: _make_sample_repo_report(stn) for stn in stations}


# ============================================================================
# 1. REQ-ISO-205: Ecosystem Portfolio Certification & Invariants
# ============================================================================


def test_req205_portfolio_all_repos_certified_success() -> None:
    """REQ-ISO-205: Full 10-repository portfolio with conformant stations is CERTIFIED."""
    portfolio_reports = _make_10_station_portfolio()

    result = certify_ecosystem_portfolio(
        portfolio_name="Antigravity Ecosystem",
        version="2.0.0",
        repository_reports=portfolio_reports,
        secret="test-portfolio-secret",
    )

    assert isinstance(result, dict)
    assert result["portfolio_name"] == "Antigravity Ecosystem"
    assert result["version"] == "2.0.0"
    assert result["status"] == "CERTIFIED"
    assert result["repositories_certified"] == 10
    assert result["repositories_total"] == 10
    assert result["mean_rtm_coverage"] == 1.0
    assert result["max_fmea_rpn"] <= 400
    assert result["critical_fmea_count"] == 0
    assert result["iso42001_soa_controls_implemented"] >= 20

    # Verify cryptographic tokens
    assert isinstance(result["portfolio_merkle_root"], str)
    assert len(result["portfolio_merkle_root"]) == 64
    assert isinstance(result["portfolio_signature"], str)
    assert len(result["portfolio_signature"]) == 64

    # Verify badge and SARIF artifacts
    assert "badge_svg" in result
    assert "<svg" in result["badge_svg"]
    assert "#2ea44f" in result["badge_svg"]
    assert "CERTIFIED" in result["badge_svg"]

    assert "sarif_report" in result
    assert result["sarif_report"]["version"] == "2.1.0"
    assert len(result["sarif_report"]["runs"]) >= 1


def test_req205_portfolio_rejects_non_conformant_repo() -> None:
    """REQ-ISO-205: Portfolio status becomes NON_CONFORMANT when any repository fails certification."""
    portfolio_reports = _make_10_station_portfolio()
    # Mark one repository as NON_CONFORMANT
    portfolio_reports["agy-secret-shield"] = _make_sample_repo_report(
        "agy-secret-shield",
        status="NON_CONFORMANT",
        rtm_coverage=0.60,
    )

    result = certify_ecosystem_portfolio(
        portfolio_name="Antigravity Ecosystem",
        version="2.0.0",
        repository_reports=portfolio_reports,
        secret="test-portfolio-secret",
    )

    assert result["status"] == "NON_CONFORMANT"
    assert result["repositories_certified"] == 9
    assert result["repositories_total"] == 10
    assert "#d73a49" in result["badge_svg"]
    assert "NON_CONFORMANT" in result["badge_svg"]

    # SARIF report must contain error results
    sarif = result["sarif_report"]
    errors = [
        item
        for run in sarif.get("runs", [])
        for item in run.get("results", [])
        if item.get("level") == "error"
    ]
    assert len(errors) >= 1


def test_req205_portfolio_rejects_high_fmea_rpn() -> None:
    """REQ-ISO-205: Portfolio is rejected if any station exceeds max RPN threshold of 400."""
    portfolio_reports = _make_10_station_portfolio()
    # Inject a critical FMEA failure mode into pe-reversing-lab
    portfolio_reports["pe-reversing-lab"] = _make_sample_repo_report(
        "pe-reversing-lab",
        max_rpn=480,
        overall_risk="L4",
    )

    result = certify_ecosystem_portfolio(
        portfolio_name="Antigravity Ecosystem",
        version="2.0.0",
        repository_reports=portfolio_reports,
        secret="test-portfolio-secret",
    )

    assert result["status"] == "NON_CONFORMANT"
    assert result["max_fmea_rpn"] == 480
    assert result["critical_fmea_count"] >= 1


def test_req205_portfolio_rejects_low_rtm_coverage() -> None:
    """REQ-ISO-205: Portfolio is rejected if ecosystem mean RTM coverage falls below 0.85."""
    portfolio_reports = _make_10_station_portfolio()
    # Lower RTM coverage across several repositories so mean < 0.85
    for name in ("iso9000-agentops", "agy-computer-use", "agy-golden-stack", "pe-reversing-lab"):
        portfolio_reports[name] = _make_sample_repo_report(
            name,
            rtm_coverage=0.70,
        )

    result = certify_ecosystem_portfolio(
        portfolio_name="Antigravity Ecosystem",
        version="2.0.0",
        repository_reports=portfolio_reports,
        secret="test-portfolio-secret",
    )

    assert result["mean_rtm_coverage"] < 0.85
    assert result["status"] == "NON_CONFORMANT"


def test_req205_portfolio_rejects_insufficient_soa_controls() -> None:
    """REQ-ISO-205: Portfolio requires at least 20 implemented ISO/IEC 42001 Annex A controls."""
    portfolio_reports = _make_10_station_portfolio()
    for name in portfolio_reports:
        portfolio_reports[name]["soa"]["controls_implemented"] = 14

    result = certify_ecosystem_portfolio(
        portfolio_name="Antigravity Ecosystem",
        version="2.0.0",
        repository_reports=portfolio_reports,
        secret="test-portfolio-secret",
    )

    assert result["iso42001_soa_controls_implemented"] < 20
    assert result["status"] == "NON_CONFORMANT"


def test_req205_portfolio_merkle_root_determinism_and_sensitivity() -> None:
    """REQ-ISO-205: RFC 6962 Merkle tree root is deterministic and sensitive to any single modification."""
    portfolio_a = _make_10_station_portfolio()
    portfolio_b = copy.deepcopy(portfolio_a)

    res_a = certify_ecosystem_portfolio("Ecosystem", "2.0.0", portfolio_a, secret="sec-1")
    res_b = certify_ecosystem_portfolio("Ecosystem", "2.0.0", portfolio_b, secret="sec-1")

    assert res_a["portfolio_merkle_root"] == res_b["portfolio_merkle_root"]

    # Modify one repository certificate in portfolio_b
    portfolio_b["agy-brain-memory"]["certificate"]["tests_passed"] = 999
    res_b_mutated = certify_ecosystem_portfolio("Ecosystem", "2.0.0", portfolio_b, secret="sec-1")

    assert res_a["portfolio_merkle_root"] != res_b_mutated["portfolio_merkle_root"]


def test_req205_portfolio_hmac_signature_verification_and_tamper_detection() -> None:
    """REQ-ISO-205: Portfolio HMAC signature verifies correctly and detects field tampering."""
    portfolio = _make_10_station_portfolio()
    secret = "production-grade-hmac-secret-iso9000"

    cert = certify_ecosystem_portfolio("Ecosystem", "2.0.0", portfolio, secret=secret)
    original_sig = cert["portfolio_signature"]

    # Re-compute expected HMAC
    filtered = {k: v for k, v in cert.items() if k != "portfolio_signature"}
    canonical = json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    assert original_sig == expected_sig

    # Tampering with status must invalidate HMAC
    tampered_cert = copy.deepcopy(cert)
    tampered_cert["status"] = "CERTIFIED" if cert["status"] != "CERTIFIED" else "NON_CONFORMANT"
    tampered_canonical = json.dumps(
        {k: v for k, v in tampered_cert.items() if k != "portfolio_signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    tampered_sig = hmac.new(secret.encode("utf-8"), tampered_canonical, hashlib.sha256).hexdigest()
    assert tampered_sig != original_sig


def test_req205_render_portfolio_badge_svg_certified_and_rejected() -> None:
    """REQ-ISO-205: Standalone SVG compliance badge renders correctly for both statuses."""
    cert_ok = {
        "portfolio_name": "Antigravity",
        "version": "2.0.0",
        "status": "CERTIFIED",
        "mean_rtm_coverage": 1.0,
        "repositories_certified": 10,
        "repositories_total": 10,
    }
    svg_ok = render_portfolio_badge_svg(cert_ok)
    assert isinstance(svg_ok, str)
    assert "<svg" in svg_ok and "</svg>" in svg_ok
    assert "#2ea44f" in svg_ok
    assert "CERTIFIED" in svg_ok
    assert "v2.0.0" in svg_ok

    cert_fail = copy.deepcopy(cert_ok)
    cert_fail["status"] = "NON_CONFORMANT"
    svg_fail = render_portfolio_badge_svg(cert_fail)
    assert "#d73a49" in svg_fail
    assert "NON_CONFORMANT" in svg_fail


def test_req205_export_portfolio_sarif_report_structure() -> None:
    """REQ-ISO-205: Portfolio SARIF 2.1.0 report complies with OASIS SARIF specifications."""
    portfolio_reports = _make_10_station_portfolio()
    # Add a failure so SARIF contains non-empty results
    portfolio_reports["eskd-vision-station"]["rtm_report"]["unimplemented_requirements"] = ["REQ-ESKD-999"]
    portfolio_reports["eskd-vision-station"]["certificate"]["status"] = "NON_CONFORMANT"

    sarif = export_portfolio_sarif_report(portfolio_reports, tool_version="2.0.0")

    assert isinstance(sarif, dict)
    assert sarif.get("$schema") == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif.get("version") == "2.1.0"
    assert "runs" in sarif and len(sarif["runs"]) >= 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "iso9000-agentops"
    assert driver["version"] == "2.0.0"
    assert len(driver["rules"]) >= 3


def test_req205_cli_certify_portfolio_subcommand(tmp_path: Path) -> None:
    """REQ-ISO-205: CLI 'certify-portfolio' command processes JSON input and outputs certified artifacts."""
    from iso9000_agentops.cli import run_cli

    portfolio = _make_10_station_portfolio()
    input_file = tmp_path / "portfolio_reports.json"
    input_file.write_text(json.dumps(portfolio), encoding="utf-8")

    out_file = tmp_path / "portfolio_certificate.json"

    res = run_cli(
        [
            "--workspace",
            str(tmp_path),
            "certify-portfolio",
            "--portfolio-json",
            str(input_file),
            "--name",
            "Antigravity Ecosystem",
            "--version",
            "2.0.0",
            "--output",
            str(out_file),
            "--secret",
            "cli-test-secret",
        ]
    )

    cert = res.get("portfolio_certificate", res)
    assert cert.get("status") == "CERTIFIED"
    assert out_file.is_file()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["status"] == "CERTIFIED"
    assert len(saved["portfolio_signature"]) == 64


def test_req205_mcp_tool_iso_certify_portfolio_registration_and_dispatch(
    tmp_path: Path,
) -> None:
    """REQ-ISO-205: MCP tool 'iso_certify_portfolio' enforces <64-char limit and executes cleanly."""
    from iso9000_agentops.mcp_server import MCP_TOOLS, handle_mcp_request

    # Check 64-character naming constraint
    tool_name = "iso_certify_portfolio"
    assert len(tool_name) < 64
    composite_name = f"mcp_iso9000_agentops_iso9000_{tool_name}"
    assert len(composite_name) < 64

    matching_tools = [t for t in MCP_TOOLS if t["name"] == tool_name]
    assert len(matching_tools) == 1
    spec = matching_tools[0]
    assert "portfolio_name" in spec["inputSchema"]["properties"]
    assert "repository_reports" in spec["inputSchema"]["properties"]

    portfolio = _make_10_station_portfolio()
    resp = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {
                    "portfolio_name": "MCP Ecosystem",
                    "version": "2.0.0",
                    "repository_reports": portfolio,
                    "secret": "mcp-secret",
                },
            },
        },
        workspace=tmp_path,
    )

    assert resp.get("result", {}).get("isError") is False
    content = resp["result"]["content"][0]["text"]
    cert = json.loads(content)
    assert cert["status"] == "CERTIFIED"
    assert cert["repositories_total"] == 10


def test_req205_top_level_exports_and_version_alignment() -> None:
    """REQ-ISO-205: Top-level exports certify_ecosystem_portfolio and version is strictly 2.0.0."""
    import iso9000_agentops

    assert hasattr(iso9000_agentops, "__version__")
    assert iso9000_agentops.__version__ == "2.0.0"

    assert hasattr(iso9000_agentops, "certify_ecosystem_portfolio")
    assert "certify_ecosystem_portfolio" in getattr(iso9000_agentops, "__all__", [])


def test_req205_adversarial_empty_and_malformed_inputs() -> None:
    """REQ-ISO-205: Empty repository dictionary or invalid payload is handled safely."""
    # Empty portfolio dictionary must yield NON_CONFORMANT or raise ValueError
    try:
        res = certify_ecosystem_portfolio("Empty", "2.0.0", {})
        assert res["status"] == "NON_CONFORMANT"
        assert res["repositories_total"] == 0
    except ValueError:
        pass

    # Malformed non-dict report values
    malformed = {"bad_repo": "invalid string not dict"}  # type: ignore[dict-item]
    try:
        res2 = certify_ecosystem_portfolio("Malformed", "2.0.0", malformed)
        assert res2["status"] == "NON_CONFORMANT"
    except (ValueError, TypeError):
        pass


@settings(max_examples=15, deadline=None)
@given(
    coverage=st.floats(min_value=0.0, max_value=1.0),
    max_rpn=st.integers(min_value=1, max_value=1000),
    num_repos=st.integers(min_value=1, max_value=8),
)
def test_req205_hypothesis_portfolio_certification_invariants(
    coverage: float, max_rpn: int, num_repos: int
) -> None:
    """REQ-ISO-205: Hypothesis property test asserting status is CERTIFIED iff all conditions met."""
    repos: dict[str, dict[str, Any]] = {}
    for i in range(num_repos):
        repos[f"repo_{i}"] = _make_sample_repo_report(
            f"repo_{i}",
            rtm_coverage=coverage,
            max_rpn=max_rpn,
            overall_risk="L4" if max_rpn > 400 else "L2",
        )

    res = certify_ecosystem_portfolio(
        "Hypothesis Portfolio",
        "2.0.0",
        repos,
        secret="hyp-secret",
    )

    assert isinstance(res["portfolio_merkle_root"], str)
    assert len(res["portfolio_merkle_root"]) == 64
    assert res["repositories_total"] == num_repos

    if coverage >= 0.85 and max_rpn <= 400:
        assert res["status"] == "CERTIFIED"
    else:
        assert res["status"] == "NON_CONFORMANT"
