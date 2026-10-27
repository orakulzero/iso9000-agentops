"""Comprehensive unit and property-based tests for v2.0.0 ISO 9001:2015, ISO/IEC 42001:2023 & Agile V Suite.

Validates:
- REQ-ISO-201: Bidirectional Agile V Requirements Traceability Matrix (iso9000_agentops.traceability)
- REQ-ISO-202: ISO/IEC 42001:2023 AIMS & ISO 31000 FMEA Risk Engine (iso9000_agentops.aims_42001)
- REQ-ISO-203: Cryptographic Quality Certificate, SVG Badge & OASIS SARIF 2.1.0 (iso9000_agentops.certificate)
- REQ-ISO-204: Package Version 2.0.0, Top-Level Exports, CLI (rtm, fmea, certify), MCP Tools (<64 chars), and Plugin Metadata
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from iso9000_agentops.traceability import (
        build_requirements_traceability_matrix,
        extract_code_req_links,
        extract_test_req_links,
        render_rtm_markdown,
    )
except ImportError:

    def extract_code_req_links(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.traceability import extract_code_req_links as fn

        return fn(*args, **kwargs)

    def extract_test_req_links(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.traceability import extract_test_req_links as fn

        return fn(*args, **kwargs)

    def build_requirements_traceability_matrix(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.traceability import (
            build_requirements_traceability_matrix as fn,
        )

        return fn(*args, **kwargs)

    def render_rtm_markdown(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.traceability import render_rtm_markdown as fn

        return fn(*args, **kwargs)


try:
    from iso9000_agentops.aims_42001 import (
        assess_failure_modes,
        compute_fmea_rpn,
        generate_iso42001_soa,
    )
except ImportError:

    def compute_fmea_rpn(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.aims_42001 import compute_fmea_rpn as fn

        return fn(*args, **kwargs)

    def assess_failure_modes(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.aims_42001 import assess_failure_modes as fn

        return fn(*args, **kwargs)

    def generate_iso42001_soa(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.aims_42001 import generate_iso42001_soa as fn

        return fn(*args, **kwargs)


try:
    from iso9000_agentops.certificate import (
        export_sarif_report,
        issue_quality_certificate,
        render_compliance_badge_svg,
        verify_quality_certificate,
    )
except ImportError:

    def issue_quality_certificate(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import issue_quality_certificate as fn

        return fn(*args, **kwargs)

    def verify_quality_certificate(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import verify_quality_certificate as fn

        return fn(*args, **kwargs)

    def render_compliance_badge_svg(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import render_compliance_badge_svg as fn

        return fn(*args, **kwargs)

    def export_sarif_report(*args: Any, **kwargs: Any) -> Any:
        from iso9000_agentops.certificate import export_sarif_report as fn

        return fn(*args, **kwargs)


# ============================================================================
# 1. REQ-ISO-201: Bidirectional Agile V Requirements Traceability Matrix
# ============================================================================


def test_req201_extract_code_req_links_module_class_function_method(
    tmp_path: Path,
) -> None:
    """REQ-ISO-201: Extract module, class, function, and method symbols with REQ IDs."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    mod_file = src_dir / "billing.py"
    mod_file.write_text(
        '"""Billing service module implementing REQ-BILL-100."""\n\n'
        "class InvoiceEngine:\n"
        '    """Handles invoice lifecycle (REQ-BILL-101)."""\n\n'
        "    def calculate_total(self, amount: float) -> float:\n"
        '        """Compute total with tax for REQ-BILL-102."""\n'
        "        return amount * 1.2\n\n"
        "def issue_receipt(invoice_id: str) -> str:\n"
        "    # Inline requirement link: REQ-BILL-103\n"
        "    return f'RCPT-{invoice_id}'\n",
        encoding="utf-8",
    )

    links = extract_code_req_links(src_dir)
    assert isinstance(links, list)
    assert len(links) >= 4

    by_symbol = {item["symbol"]: item for item in links}
    assert "InvoiceEngine" in by_symbol
    assert by_symbol["InvoiceEngine"]["kind"] == "class"
    assert "REQ-BILL-101" in by_symbol["InvoiceEngine"]["req_ids"]
    assert by_symbol["InvoiceEngine"]["line"] >= 1

    method_key = (
        "InvoiceEngine.calculate_total"
        if "InvoiceEngine.calculate_total" in by_symbol
        else "calculate_total"
    )
    assert method_key in by_symbol
    assert by_symbol[method_key]["kind"] in ("method", "function")
    assert "REQ-BILL-102" in by_symbol[method_key]["req_ids"]

    assert "issue_receipt" in by_symbol
    assert by_symbol["issue_receipt"]["kind"] == "function"
    assert "REQ-BILL-103" in by_symbol["issue_receipt"]["req_ids"]


def test_req201_extract_code_req_links_deduplication_and_sorting(
    tmp_path: Path,
) -> None:
    """REQ-ISO-201: Verify extracted REQ IDs are deduplicated and sorted ascending."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "core.py").write_text(
        "def process_event() -> None:\n"
        '    """Implements REQ-Z-99, REQ-A-01, and REQ-Z-99 again."""\n'
        "    # Also touches REQ-M-50\n"
        "    return None\n",
        encoding="utf-8",
    )

    links = extract_code_req_links(src_dir)
    fn_links = [item for item in links if item["symbol"] == "process_event"]
    assert len(fn_links) == 1
    assert fn_links[0]["req_ids"] == ["REQ-A-01", "REQ-M-50", "REQ-Z-99"]


def test_req201_extract_test_req_links_decorators_docstrings_comments(
    tmp_path: Path,
) -> None:
    """REQ-ISO-201: Extract test links from @pytest.mark.req, docstrings, and comments."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_billing.py").write_text(
        "import pytest\n\n"
        '@pytest.mark.req("REQ-001", "REQ-002")\n'
        "def test_decorated_reqs() -> None:\n"
        "    assert True\n\n"
        "def test_docstring_req() -> None:\n"
        '    """Verifies REQ-003 behavior under load."""\n'
        "    assert True\n\n"
        "class TestSuite:\n"
        "    def test_comment_req(self) -> None:\n"
        "        # Validates REQ-004 edge case\n"
        "        assert True\n",
        encoding="utf-8",
    )

    links = extract_test_req_links(tests_dir)
    assert len(links) == 3
    by_name = {item["test_name"].split(".")[-1]: item for item in links}

    assert by_name["test_decorated_reqs"]["req_ids"] == ["REQ-001", "REQ-002"]
    assert by_name["test_docstring_req"]["req_ids"] == ["REQ-003"]
    assert by_name["test_comment_req"]["req_ids"] == ["REQ-004"]


def test_req201_extract_code_req_links_syntax_error_resilience(
    tmp_path: Path,
) -> None:
    """REQ-ISO-201: AST extractor gracefully skips broken syntax files without crashing."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (src_dir / "valid.py").write_text(
        'def healthy_fn() -> int:\n    """REQ-OK-01"""\n    return 1\n',
        encoding="utf-8",
    )

    links = extract_code_req_links(src_dir)
    symbols = {item["symbol"] for item in links}
    assert "healthy_fn" in symbols


def test_req201_build_rtm_full_compliance_and_evidence_units(tmp_path: Path) -> None:
    """REQ-ISO-201: Build bidirectional RTM with 100% implementation, verification, and evidence."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    (src_dir / "auth.py").write_text(
        "def login_user() -> bool:\n"
        '    """Authenticate user per REQ-001."""\n'
        "    return True\n\n"
        "def audit_access() -> bool:\n"
        '    """Record access log per REQ-002."""\n'
        "    return True\n",
        encoding="utf-8",
    )
    (tests_dir / "test_auth.py").write_text(
        "def test_login_user() -> None:\n"
        '    """Verify REQ-001."""\n'
        "    assert True\n\n"
        "def test_audit_access() -> None:\n"
        '    """Verify REQ-002."""\n'
        "    assert True\n",
        encoding="utf-8",
    )

    evidence = [
        {
            "evidence_id": "EV-001",
            "requirement_ids": ["REQ-001", "REQ-002"],
            "stdout_sha256": "a" * 64,
        }
    ]
    rtm = build_requirements_traceability_matrix(
        requirements=["(REQ-001) User authentication", {"id": "REQ-002", "text": "Audit logging"}],
        source_root=src_dir,
        tests_root=tests_dir,
        evidence_units=evidence,
    )

    assert rtm["requirements"] == ["REQ-001", "REQ-002"]
    assert rtm["compliant"] is True
    assert rtm["coverage_ratio"] == 1.0
    assert rtm["orphan_requirements"] == []
    assert rtm["unimplemented_requirements"] == []
    assert rtm["untraced_tests"] == []
    assert rtm["gold_plated_symbols"] == []

    for req_id in ("REQ-001", "REQ-002"):
        fwd = rtm["forward_trace"][req_id]
        assert fwd["req_id"] == req_id
        assert fwd["implemented"] is True
        assert fwd["verified"] is True
        assert len(fwd["code_symbols"]) >= 1
        assert len(fwd["test_names"]) >= 1
        assert ("a" * 64) in fwd["evidence_hashes"] or "EV-001" in fwd["evidence_hashes"]


def test_req201_build_rtm_orphan_and_unimplemented_detection(tmp_path: Path) -> None:
    """REQ-ISO-201: Detect orphan (untested) and unimplemented requirements accurately."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    (src_dir / "service.py").write_text(
        'def fn_one() -> None:\n    """REQ-001"""\n    pass\n\n'
        'def fn_two() -> None:\n    """REQ-002"""\n    pass\n',
        encoding="utf-8",
    )
    (tests_dir / "test_service.py").write_text(
        'def test_one() -> None:\n    """REQ-001"""\n    pass\n\n'
        'def test_three() -> None:\n    """REQ-003"""\n    pass\n',
        encoding="utf-8",
    )

    rtm = build_requirements_traceability_matrix(
        requirements=["REQ-001", "REQ-002", "REQ-003", "REQ-004"],
        source_root=src_dir,
        tests_root=tests_dir,
    )

    # REQ-001: code + test (implemented & verified)
    # REQ-002: code only (orphan requirement - no test)
    # REQ-003: test only (unimplemented requirement - no code)
    # REQ-004: neither (both orphan and unimplemented)
    assert rtm["orphan_requirements"] == ["REQ-002", "REQ-004"]
    assert rtm["unimplemented_requirements"] == ["REQ-003", "REQ-004"]
    assert rtm["coverage_ratio"] == pytest.approx(0.25)
    assert rtm["compliant"] is False


def test_req201_build_rtm_gold_plated_symbols_and_untraced_tests(
    tmp_path: Path,
) -> None:
    """REQ-ISO-201: Flag public unlinked symbols as gold-plating while ignoring private helpers."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    (src_dir / "module.py").write_text(
        'def traced_api() -> int:\n    """Implements REQ-100."""\n    return _private_helper()\n\n'
        "def _private_helper() -> int:\n    return 42\n\n"
        "def speculative_gold_plated_fn() -> str:\n    return 'unrequested'\n\n"
        "class GoldPlatedWidget:\n    pass\n",
        encoding="utf-8",
    )
    (tests_dir / "test_module.py").write_text(
        'def test_traced() -> None:\n    """REQ-100"""\n    assert True\n\n'
        "def test_mystery_untraced() -> None:\n    assert True\n",
        encoding="utf-8",
    )

    rtm = build_requirements_traceability_matrix(
        requirements=["REQ-100"],
        source_root=src_dir,
        tests_root=tests_dir,
    )

    assert "speculative_gold_plated_fn" in rtm["gold_plated_symbols"]
    assert "GoldPlatedWidget" in rtm["gold_plated_symbols"]
    assert "_private_helper" not in rtm["gold_plated_symbols"]
    assert "traced_api" not in rtm["gold_plated_symbols"]
    assert "test_mystery_untraced" in rtm["untraced_tests"]


def test_req201_build_rtm_empty_requirements_edge_case(tmp_path: Path) -> None:
    """REQ-ISO-201: Empty requirement list yields coverage_ratio 1.0 and compliant True."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    rtm = build_requirements_traceability_matrix(
        requirements=[],
        source_root=src_dir,
        tests_root=tests_dir,
    )
    assert rtm["requirements"] == []
    assert rtm["coverage_ratio"] == 1.0
    assert rtm["compliant"] is True
    assert rtm["orphan_requirements"] == []
    assert rtm["unimplemented_requirements"] == []


def test_req201_backward_trace_mapping(tmp_path: Path) -> None:
    """REQ-ISO-201: Verify backward_trace maps code_to_reqs and test_to_reqs accurately."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    (src_dir / "engine.py").write_text(
        'def run_engine() -> None:\n    """Covers REQ-010 and REQ-020."""\n    pass\n',
        encoding="utf-8",
    )
    (tests_dir / "test_engine.py").write_text(
        'def test_run_engine() -> None:\n    """Verifies REQ-010 and REQ-020."""\n    pass\n',
        encoding="utf-8",
    )

    rtm = build_requirements_traceability_matrix(
        requirements=["REQ-010", "REQ-020"],
        source_root=src_dir,
        tests_root=tests_dir,
    )
    code_to_reqs = rtm["backward_trace"]["code_to_reqs"]
    test_to_reqs = rtm["backward_trace"]["test_to_reqs"]

    assert code_to_reqs["run_engine"] == ["REQ-010", "REQ-020"]
    assert test_to_reqs["test_run_engine"] == ["REQ-010", "REQ-020"]


def test_req201_render_rtm_markdown_table_and_metrics(tmp_path: Path) -> None:
    """REQ-ISO-201: Render Markdown RTM report containing table columns and summary metrics."""
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()

    (src_dir / "app.py").write_text(
        'def handle_req() -> None:\n    """REQ-001"""\n    pass\n\n'
        "def extra_untraced() -> None:\n    pass\n",
        encoding="utf-8",
    )
    (tests_dir / "test_app.py").write_text(
        'def test_handle_req() -> None:\n    """REQ-001"""\n    pass\n',
        encoding="utf-8",
    )

    rtm = build_requirements_traceability_matrix(
        requirements=["REQ-001", "REQ-002"],
        source_root=src_dir,
        tests_root=tests_dir,
    )
    md = render_rtm_markdown(rtm)

    assert "REQ-ID" in md
    assert "Code Symbols" in md
    assert "Tests" in md
    assert "Status" in md
    assert "REQ-001" in md
    assert "REQ-002" in md
    assert "handle_req" in md
    assert "test_handle_req" in md
    assert "extra_untraced" in md


@settings(max_examples=25, deadline=None)
@given(
    req_nums=st.lists(st.integers(min_value=1, max_value=8), unique=True, max_size=6),
    code_nums=st.lists(st.integers(min_value=1, max_value=8), unique=True, max_size=6),
    test_nums=st.lists(st.integers(min_value=1, max_value=8), unique=True, max_size=6),
)
def test_req201_hypothesis_rtm_invariants(
    req_nums: list[int], code_nums: list[int], test_nums: list[int]
) -> None:
    """REQ-ISO-201: Hypothesis property check for RTM coverage bounds, subset invariants, and compliance."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_str:
        base = Path(tmp_str)
        src_dir = base / "src"
        tests_dir = base / "tests"
        src_dir.mkdir()
        tests_dir.mkdir()

        reqs = [f"REQ-{n:03d}" for n in req_nums]
        code_lines = [
            f'def fn_{n}() -> int:\n    """Implements REQ-{n:03d}."""\n    return {n}\n'
            for n in code_nums
        ]
        test_lines = [
            f'def test_{n}() -> None:\n    """Verifies REQ-{n:03d}."""\n    assert True\n'
            for n in test_nums
        ]
        (src_dir / "mod.py").write_text("\n".join(code_lines) or "# empty\n", encoding="utf-8")
        (tests_dir / "test_mod.py").write_text(
            "\n".join(test_lines) or "# empty\n", encoding="utf-8"
        )

        rtm = build_requirements_traceability_matrix(
            requirements=reqs,
            source_root=src_dir,
            tests_root=tests_dir,
        )

        assert 0.0 <= rtm["coverage_ratio"] <= 1.0
        req_set = set(rtm["requirements"])
        orphan_set = set(rtm["orphan_requirements"])
        unimpl_set = set(rtm["unimplemented_requirements"])

        assert orphan_set.issubset(req_set)
        assert unimpl_set.issubset(req_set)
        expected_compliant = len(orphan_set) == 0 and len(unimpl_set) == 0
        assert rtm["compliant"] is expected_compliant


# ============================================================================
# 2. REQ-ISO-202: ISO/IEC 42001:2023 AIMS & ISO 31000 FMEA Risk Engine
# ============================================================================


def test_req202_compute_fmea_rpn_exact_tier_boundaries() -> None:
    """REQ-ISO-202: Verify exact RPN computation and risk tier boundaries L0..L4."""
    # L0: RPN <= 40 (and S < 9)
    r_l0_min = compute_fmea_rpn(1, 1, 1)
    assert r_l0_min["rpn"] == 1
    assert r_l0_min["risk_level"] == "L0"
    assert r_l0_min["action_required"] is False

    r_l0_max = compute_fmea_rpn(4, 2, 5)
    assert r_l0_max["rpn"] == 40
    assert r_l0_max["risk_level"] == "L0"
    assert r_l0_max["action_required"] is False

    # L1: 41 <= RPN <= 100 (and S < 9)
    r_l1_min = compute_fmea_rpn(7, 2, 3)
    assert r_l1_min["rpn"] == 42
    assert r_l1_min["risk_level"] == "L1"
    assert r_l1_min["action_required"] is False

    r_l1_max = compute_fmea_rpn(5, 4, 5)
    assert r_l1_max["rpn"] == 100
    assert r_l1_max["risk_level"] == "L1"
    assert r_l1_max["action_required"] is False

    # L2: 101 <= RPN <= 200 (and S < 9)
    r_l2 = compute_fmea_rpn(6, 3, 6)
    assert r_l2["rpn"] == 108
    assert r_l2["risk_level"] == "L2"
    assert r_l2["action_required"] is True

    # L3: 201 <= RPN <= 400 (and S < 9)
    r_l3 = compute_fmea_rpn(7, 5, 6)
    assert r_l3["rpn"] == 210
    assert r_l3["risk_level"] == "L3"
    assert r_l3["action_required"] is True

    # L4: RPN > 400
    r_l4 = compute_fmea_rpn(8, 7, 8)
    assert r_l4["rpn"] == 448
    assert r_l4["risk_level"] == "L4"
    assert r_l4["action_required"] is True


def test_req202_compute_fmea_rpn_high_severity_override_to_l4() -> None:
    """REQ-ISO-202: Severity >= 9 escalates directly to L4 and action_required True regardless of RPN."""
    r_sev9 = compute_fmea_rpn(9, 1, 1)
    assert r_sev9["rpn"] == 9
    assert r_sev9["risk_level"] == "L4"
    assert r_sev9["action_required"] is True

    r_sev10 = compute_fmea_rpn(10, 1, 1)
    assert r_sev10["rpn"] == 10
    assert r_sev10["risk_level"] == "L4"
    assert r_sev10["action_required"] is True


def test_req202_compute_fmea_rpn_required_controls_populated() -> None:
    """REQ-ISO-202: Verify required_controls list is returned and non-empty for elevated risk levels."""
    for sev, occ, det in [(4, 3, 4), (6, 4, 5), (8, 6, 6), (9, 2, 2)]:
        res = compute_fmea_rpn(sev, occ, det)
        assert isinstance(res["required_controls"], list)
        assert len(res["required_controls"]) >= 1


def test_req202_compute_fmea_rpn_out_of_bounds_raises_value_error() -> None:
    """REQ-ISO-202: Out-of-range S, O, or D outside [1, 10] raises ValueError."""
    invalid_triplets = [
        (0, 5, 5),
        (11, 5, 5),
        (5, 0, 5),
        (5, 11, 5),
        (5, 5, 0),
        (5, 5, 11),
        (-1, 2, 3),
    ]
    for s, o, d in invalid_triplets:
        with pytest.raises(ValueError):
            compute_fmea_rpn(s, o, d)


def test_req202_assess_failure_modes_sorting_and_critical_extraction() -> None:
    """REQ-ISO-202: Assess multiple failure modes, sort descending by RPN, and list critical_modes."""
    modes = [
        {"id": "FM-001", "name": "Minor cache miss", "severity": 2, "occurrence": 3, "detection": 4},
        {"id": "FM-002", "name": "Self-grading test tamper", "severity": 8, "occurrence": 5, "detection": 7},
        {"id": "FM-003", "name": "Catastrophic key leak", "severity": 9, "occurrence": 1, "detection": 2},
    ]
    report = assess_failure_modes(modes)

    assert [m["id"] for m in report["modes"]] == ["FM-002", "FM-001", "FM-003"]
    assert report["max_rpn"] == 280
    assert report["mean_rpn"] == pytest.approx((24 + 280 + 18) / 3.0)
    assert report["overall_risk_level"] == "L4"
    assert set(report["critical_modes"]) == {"FM-002", "FM-003"}


def test_req202_assess_failure_modes_empty_list() -> None:
    """REQ-ISO-202: Empty failure modes list returns zeroed metrics and L0 risk."""
    report = assess_failure_modes([])
    assert report["modes"] == []
    assert report["max_rpn"] == 0
    assert report["mean_rpn"] == 0.0
    assert report["overall_risk_level"] == "L0"
    assert report["critical_modes"] == []


def test_req202_generate_iso42001_soa_controls_and_satisfaction() -> None:
    """REQ-ISO-202: Generate ISO/IEC 42001:2023 Statement of Applicability with mandatory Annex A controls."""
    baseline = {
        "baseline_id": "BL-20261027-L2",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {
            "solvable": True,
            "completeness_covered": True,
            "non_redundant": True,
        },
        "artifact_scope": {
            "allowed_paths": ["src/**", "tests/**"],
            "forbidden_paths": [".env*"],
        },
    }
    fmea_summary = assess_failure_modes(
        [{"id": "FM-01", "name": "Drift", "severity": 4, "occurrence": 3, "detection": 3}]
    )
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}

    soa = generate_iso42001_soa(baseline, fmea_summary=fmea_summary, rtm_summary=rtm_summary)
    assert soa["standard"] == "ISO/IEC 42001:2023"
    assert soa["baseline_id"] == "BL-20261027-L2"
    assert soa["risk_level"] == "L2"
    assert soa["all_controls_satisfied"] is True

    control_map = {c["control_id"]: c for c in soa["controls"]}
    required_ids = {"A.6.2.2", "A.6.2.4", "A.7.4", "A.8.3", "A.9.3", "A.10.2"}
    assert required_ids.issubset(set(control_map.keys()))

    for cid in required_ids:
        ctrl = control_map[cid]
        assert ctrl["applicable"] is True
        assert ctrl["implemented"] is True
        assert isinstance(ctrl["title"], str) and len(ctrl["title"]) > 0
        assert isinstance(ctrl["evidence"], str) and len(ctrl["evidence"]) > 0


def test_req202_generate_iso42001_soa_unsatisfied_when_unsealed_or_noncompliant() -> None:
    """REQ-ISO-202: SoA reports all_controls_satisfied False when Gate 1 is unapproved or RTM is non-compliant."""
    unapproved_baseline = {
        "baseline_id": "BL-UNSEALED",
        "risk_level": "L3",
        "human_gate_1_approved": False,
    }
    soa = generate_iso42001_soa(
        unapproved_baseline,
        fmea_summary={"overall_risk_level": "L3", "critical_modes": ["FM-1"]},
        rtm_summary={"compliant": False, "coverage_ratio": 0.5},
    )
    assert soa["all_controls_satisfied"] is False
    assert any(not c["implemented"] for c in soa["controls"])


@settings(max_examples=40, deadline=None)
@given(
    s1=st.integers(min_value=1, max_value=10),
    s2=st.integers(min_value=1, max_value=10),
    o1=st.integers(min_value=1, max_value=10),
    o2=st.integers(min_value=1, max_value=10),
    d1=st.integers(min_value=1, max_value=10),
    d2=st.integers(min_value=1, max_value=10),
)
def test_req202_hypothesis_fmea_rpn_monotonicity(
    s1: int, s2: int, o1: int, o2: int, d1: int, d2: int
) -> None:
    """REQ-ISO-202: Hypothesis monotonicity property for FMEA RPN and risk level ordering."""
    low_s, high_s = min(s1, s2), max(s1, s2)
    low_o, high_o = min(o1, o2), max(o1, o2)
    low_d, high_d = min(d1, d2), max(d1, d2)

    res_low = compute_fmea_rpn(low_s, low_o, low_d)
    res_high = compute_fmea_rpn(high_s, high_o, high_d)

    tier_rank = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4}
    assert 1 <= res_low["rpn"] <= res_high["rpn"] <= 1000
    assert tier_rank[res_low["risk_level"]] <= tier_rank[res_high["risk_level"]]


@settings(max_examples=25, deadline=None)
@given(
    bad_val=st.one_of(
        st.integers(max_value=0),
        st.integers(min_value=11),
    ),
    pos=st.integers(min_value=0, max_value=2),
)
def test_req202_hypothesis_fmea_rpn_invalid_inputs(bad_val: int, pos: int) -> None:
    """REQ-ISO-202: Hypothesis test proving any out-of-range integer raises ValueError."""
    args = [5, 5, 5]
    args[pos] = bad_val
    with pytest.raises(ValueError):
        compute_fmea_rpn(args[0], args[1], args[2])


# ============================================================================
# 3. REQ-ISO-203: Cryptographic Quality Certificate, SVG Badge & SARIF 2.1.0
# ============================================================================


def test_req203_issue_and_verify_quality_certificate_certified() -> None:
    """REQ-ISO-203: Issue CERTIFIED quality certificate and verify HMAC-SHA256 signature."""
    rtm_report = {"compliant": True, "coverage_ratio": 1.0}
    fmea_report = {"max_rpn": 72, "overall_risk_level": "L1"}
    merkle_root = "a" * 64
    gate1_hmac = "b" * 64

    cert = issue_quality_certificate(
        baseline_id="BL-20261027-CERT",
        version="2.0.0",
        rtm_report=rtm_report,
        fmea_report=fmea_report,
        merkle_root=merkle_root,
        gate1_hmac=gate1_hmac,
        tests_passed=68,
        tests_total=68,
        secret="unit-test-secret-key",
    )

    assert cert["status"] == "CERTIFIED"
    assert cert["standards"] == [
        "ISO 9001:2015",
        "ISO/IEC 42001:2023",
        "Agile V (arXiv:2602.20684)",
    ]
    assert cert["baseline_id"] == "BL-20261027-CERT"
    assert cert["version"] == "2.0.0"
    assert cert["rtm_coverage"] == 1.0
    assert cert["max_rpn"] == 72
    assert cert["merkle_root"] == merkle_root
    assert cert["gate1_hmac"] == gate1_hmac
    assert cert["tests_passed"] == 68
    assert cert["tests_total"] == 68
    assert isinstance(cert["certificate_signature"], str)
    assert len(cert["certificate_signature"]) == 64

    assert verify_quality_certificate(cert, secret="unit-test-secret-key") is True


def test_req203_issue_quality_certificate_non_conformant_conditions() -> None:
    """REQ-ISO-203: Verify every non-conformant condition yields status NON_CONFORMANT."""
    base_kwargs: dict[str, Any] = {
        "baseline_id": "BL-20261027-NC",
        "version": "2.0.0",
        "rtm_report": {"compliant": True, "coverage_ratio": 1.0},
        "fmea_report": {"max_rpn": 80, "overall_risk_level": "L1"},
        "merkle_root": "c" * 64,
        "gate1_hmac": "d" * 64,
        "tests_passed": 50,
        "tests_total": 50,
        "secret": "nc-secret",
    }

    # 1. RTM non-compliant
    kw1 = copy.deepcopy(base_kwargs)
    kw1["rtm_report"]["compliant"] = False
    c1 = issue_quality_certificate(**kw1)
    assert c1["status"] == "NON_CONFORMANT"
    assert verify_quality_certificate(c1, secret="nc-secret") is True

    # 2. Failing test
    kw2 = copy.deepcopy(base_kwargs)
    kw2["tests_passed"] = 49
    c2 = issue_quality_certificate(**kw2)
    assert c2["status"] == "NON_CONFORMANT"

    # 3. Zero total tests
    kw3 = copy.deepcopy(base_kwargs)
    kw3["tests_passed"] = 0
    kw3["tests_total"] = 0
    c3 = issue_quality_certificate(**kw3)
    assert c3["status"] == "NON_CONFORMANT"

    # 4. Invalid Merkle root length
    kw4 = copy.deepcopy(base_kwargs)
    kw4["merkle_root"] = "short"
    c4 = issue_quality_certificate(**kw4)
    assert c4["status"] == "NON_CONFORMANT"

    # 5. Invalid Gate 1 HMAC length
    kw5 = copy.deepcopy(base_kwargs)
    kw5["gate1_hmac"] = ""
    c5 = issue_quality_certificate(**kw5)
    assert c5["status"] == "NON_CONFORMANT"

    # 6. Unmitigated L4 FMEA risk
    kw6 = copy.deepcopy(base_kwargs)
    kw6["fmea_report"]["overall_risk_level"] = "L4"
    c6 = issue_quality_certificate(**kw6)
    assert c6["status"] == "NON_CONFORMANT"


def test_req203_verify_quality_certificate_detects_field_and_secret_tampering() -> None:
    """REQ-ISO-203: Any modification to signed certificate fields or secret invalidates verification."""
    cert = issue_quality_certificate(
        baseline_id="BL-TAMPER",
        version="2.0.0",
        rtm_report={"compliant": True, "coverage_ratio": 1.0},
        fmea_report={"max_rpn": 50, "overall_risk_level": "L1"},
        merkle_root="1" * 64,
        gate1_hmac="2" * 64,
        tests_passed=10,
        tests_total=10,
        secret="correct-secret",
    )
    assert verify_quality_certificate(cert, secret="correct-secret") is True
    assert verify_quality_certificate(cert, secret="wrong-secret") is False

    for field, mutated_value in [
        ("status", "NON_CONFORMANT"),
        ("rtm_coverage", 0.5),
        ("max_rpn", 999),
        ("merkle_root", "f" * 64),
        ("gate1_hmac", "f" * 64),
        ("tests_passed", 9),
        ("tests_total", 11),
        ("version", "1.0.0"),
    ]:
        tampered = copy.deepcopy(cert)
        tampered[field] = mutated_value
        assert verify_quality_certificate(tampered, secret="correct-secret") is False, (
            f"Tampering field {field!r} was not detected"
        )


def test_req203_verify_quality_certificate_malformed_or_missing_fields() -> None:
    """REQ-ISO-203: Malformed or empty certificate dicts return False safely."""
    assert verify_quality_certificate({}) is False
    assert verify_quality_certificate({"certificate_signature": "0" * 64}) is False


def test_req203_render_compliance_badge_svg_certified_and_non_conformant() -> None:
    """REQ-ISO-203: Render valid SVG compliance badge for both CERTIFIED and NON_CONFORMANT states."""
    cert_ok = issue_quality_certificate(
        baseline_id="BL-SVG-OK",
        version="2.0.0",
        rtm_report={"compliant": True, "coverage_ratio": 1.0},
        fmea_report={"max_rpn": 30, "overall_risk_level": "L0"},
        merkle_root="a" * 64,
        gate1_hmac="b" * 64,
        tests_passed=40,
        tests_total=40,
    )
    svg_ok = render_compliance_badge_svg(cert_ok)
    assert svg_ok.strip().startswith("<svg")
    assert svg_ok.strip().endswith("</svg>")
    assert "2.0.0" in svg_ok
    assert "CERTIFIED" in svg_ok
    assert "#2ea44f" in svg_ok.lower() or "#3fb950" in svg_ok.lower()

    cert_nc = copy.deepcopy(cert_ok)
    cert_nc["status"] = "NON_CONFORMANT"
    svg_nc = render_compliance_badge_svg(cert_nc)
    assert svg_nc.strip().startswith("<svg")
    assert svg_nc.strip().endswith("</svg>")
    assert "NON-CONFORMANT" in svg_nc or "NON_CONFORMANT" in svg_nc
    assert "#d73a49" in svg_nc.lower() or "#cb2431" in svg_nc.lower()


def test_req203_export_sarif_report_clean_conformant() -> None:
    """REQ-ISO-203: Export OASIS SARIF 2.1.0 report with zero results when fully conformant."""
    sarif = export_sarif_report(
        rtm_report={
            "orphan_requirements": [],
            "unimplemented_requirements": [],
            "gold_plated_symbols": [],
        },
        fmea_report={"critical_modes": [], "modes": []},
        oss_audit_report={"passed": True},
        tool_version="2.0.0",
    )
    assert sarif["version"] == "2.1.0"
    assert str(sarif["$schema"]).endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "iso9000-agentops"
    assert driver["version"] == "2.0.0"
    assert sarif["runs"][0]["results"] == []


def test_req203_export_sarif_report_populates_all_violation_categories() -> None:
    """REQ-ISO-203: Export SARIF 2.1.0 findings for orphan reqs, unimplemented reqs, gold-plating, FMEA, and OSS audit."""
    sarif = export_sarif_report(
        rtm_report={
            "orphan_requirements": ["REQ-ORPHAN-01"],
            "unimplemented_requirements": ["REQ-UNIMPL-02"],
            "gold_plated_symbols": ["unrequested_feature"],
        },
        fmea_report={
            "critical_modes": ["FM-CRIT-99"],
            "modes": [
                {
                    "id": "FM-CRIT-99",
                    "name": "Unbounded retry loop",
                    "rpn": 320,
                    "risk_level": "L3",
                    "action_required": True,
                }
            ],
        },
        oss_audit_report={
            "passed": False,
            "cyrillic_violations": ["src/bad.py"],
        },
        tool_version="2.0.0",
    )
    results = sarif["runs"][0]["results"]
    assert len(results) >= 5
    serialized = json.dumps(results)
    assert "REQ-ORPHAN-01" in serialized
    assert "REQ-UNIMPL-02" in serialized
    assert "unrequested_feature" in serialized
    assert "FM-CRIT-99" in serialized


@settings(max_examples=25, deadline=None)
@given(
    passed=st.integers(min_value=1, max_value=500),
    rpn=st.integers(min_value=1, max_value=350),
    secret=st.text(min_size=4, max_size=32, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"),
)
def test_req203_hypothesis_certificate_tamper_resistance(
    passed: int, rpn: int, secret: str
) -> None:
    """REQ-ISO-203: Hypothesis property proving certificate verification detects any mutation."""
    cert = issue_quality_certificate(
        baseline_id="BL-HYP",
        version="2.0.0",
        rtm_report={"compliant": True, "coverage_ratio": 1.0},
        fmea_report={"max_rpn": rpn, "overall_risk_level": "L2"},
        merkle_root="a" * 64,
        gate1_hmac="b" * 64,
        tests_passed=passed,
        tests_total=passed,
        secret=secret,
    )
    assert cert["status"] == "CERTIFIED"
    assert verify_quality_certificate(cert, secret=secret) is True
    assert verify_quality_certificate(cert, secret=secret + "x") is False

    mutated = copy.deepcopy(cert)
    mutated["tests_passed"] = passed + 1
    assert verify_quality_certificate(mutated, secret=secret) is False


# ============================================================================
# 4. REQ-ISO-204: Version 2.0.0, Exports, CLI, MCP Tools (<64 chars), Metadata
# ============================================================================


def test_req204_version_2_0_0_across_package_pyproject_and_plugin_json() -> None:
    """REQ-ISO-204: Verify version 2.0.0 is synchronized across package, pyproject.toml, and plugin.json."""
    import iso9000_agentops

    assert iso9000_agentops.__version__ == "2.0.0"

    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.0.0"' in pyproject_text

    plugin_json_path = REPO_ROOT / "plugin.json"
    assert plugin_json_path.is_file(), "plugin.json must exist at repository root"
    plugin_meta = json.loads(plugin_json_path.read_text(encoding="utf-8"))
    assert plugin_meta.get("version") == "2.0.0"


def test_req204_top_level_exports_complete() -> None:
    """REQ-ISO-204: Verify all v2.0.0 functions are exported in iso9000_agentops.__all__."""
    import iso9000_agentops

    expected_exports = (
        "extract_code_req_links",
        "extract_test_req_links",
        "build_requirements_traceability_matrix",
        "render_rtm_markdown",
        "compute_fmea_rpn",
        "assess_failure_modes",
        "generate_iso42001_soa",
        "issue_quality_certificate",
        "verify_quality_certificate",
        "render_compliance_badge_svg",
        "export_sarif_report",
    )
    all_list = getattr(iso9000_agentops, "__all__", [])
    for sym in expected_exports:
        assert hasattr(iso9000_agentops, sym), f"Missing top-level attribute: {sym}"
        assert sym in all_list, f"Missing from __all__: {sym}"


def test_req204_mcp_initialize_version_2_0_0(tmp_path: Path) -> None:
    """REQ-ISO-204: Verify MCP initialize reports server version 2.0.0."""
    from iso9000_agentops.mcp_server import handle_mcp_request

    resp = handle_mcp_request(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        workspace=tmp_path,
    )
    assert resp["result"]["serverInfo"]["version"] == "2.0.0"


def test_req204_mcp_tools_list_includes_v2_tools_and_enforces_64_char_limit(
    tmp_path: Path,
) -> None:
    """REQ-ISO-204: MCP tools/list exposes v2 tools and all tool names are <= 64 characters."""
    from iso9000_agentops.mcp_server import handle_mcp_request

    resp = handle_mcp_request(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        workspace=tmp_path,
    )
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}

    for required_tool in (
        "iso9000_traceability_matrix",
        "iso9000_fmea_42001_assess",
        "iso9000_issue_certificate",
    ):
        assert required_tool in names, f"Missing MCP tool: {required_tool}"

    for tool in tools:
        assert len(tool["name"]) <= 64, f"Tool name exceeds 64 chars: {tool['name']}"
        assert "inputSchema" in tool


def test_req204_mcp_tool_call_traceability_matrix(tmp_path: Path) -> None:
    """REQ-ISO-204: Execute iso9000_traceability_matrix via MCP tools/call."""
    from iso9000_agentops.mcp_server import handle_mcp_request

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "mod.py").write_text(
        'def do_work() -> int:\n    """Implements REQ-001."""\n    return 1\n',
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_mod.py").write_text(
        'def test_do_work() -> None:\n    """Verifies REQ-001."""\n    assert True\n',
        encoding="utf-8",
    )

    handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "iso9000_init_baseline",
                "arguments": {"request": "(REQ-001) Do work", "risk_level": "L1", "offline": True},
            },
        },
        workspace=tmp_path,
    )

    resp = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "iso9000_traceability_matrix",
                "arguments": {},
            },
        },
        workspace=tmp_path,
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    rtm = payload.get("rtm", payload)
    assert rtm["compliant"] is True
    assert rtm["coverage_ratio"] == 1.0


def test_req204_mcp_tool_call_fmea_42001_assess(tmp_path: Path) -> None:
    """REQ-ISO-204: Execute iso9000_fmea_42001_assess via MCP tools/call."""
    from iso9000_agentops.mcp_server import handle_mcp_request

    handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "iso9000_init_baseline",
                "arguments": {"request": "(REQ-001) Assess risk", "risk_level": "L1", "offline": True},
            },
        },
        workspace=tmp_path,
    )

    resp = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "iso9000_fmea_42001_assess",
                "arguments": {
                    "modes": [
                        {
                            "id": "FM-10",
                            "name": "Prompt drift",
                            "severity": 5,
                            "occurrence": 3,
                            "detection": 4,
                        }
                    ]
                },
            },
        },
        workspace=tmp_path,
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    fmea_part = payload.get("fmea", payload)
    assert fmea_part["max_rpn"] == 60
    assert "soa" in payload or "standard" in payload


def test_req204_mcp_tool_call_issue_certificate(tmp_path: Path) -> None:
    """REQ-ISO-204: Execute iso9000_issue_certificate via MCP tools/call on a compliant workspace."""
    from iso9000_agentops.mcp_server import handle_mcp_request

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "core.py").write_text(
        'def run_core() -> bool:\n    """Implements REQ-001."""\n    return True\n',
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_core.py").write_text(
        'def test_run_core() -> None:\n    """Verifies REQ-001."""\n    assert True\n',
        encoding="utf-8",
    )

    handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "iso9000_init_baseline",
                "arguments": {"request": "(REQ-001) Core feature", "risk_level": "L2", "offline": True},
            },
        },
        workspace=tmp_path,
    )
    handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {"name": "iso9000_approve_gate1", "arguments": {}},
        },
        workspace=tmp_path,
    )
    handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "iso9000_verify_oracle",
                "arguments": {"cmd": 'python -c "import sys; sys.exit(0)"'},
            },
        },
        workspace=tmp_path,
    )

    resp = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {"name": "iso9000_issue_certificate", "arguments": {}},
        },
        workspace=tmp_path,
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    cert = payload.get("certificate", payload)
    assert cert["status"] == "CERTIFIED"
    assert len(cert["certificate_signature"]) == 64


def test_req204_cli_rtm_subcommand(tmp_path: Path) -> None:
    """REQ-ISO-204: CLI 'rtm' subcommand computes RTM and writes .supergraph artifacts."""
    from iso9000_agentops.cli import run_cli

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "item.py").write_text(
        'def create_item() -> str:\n    """Implements REQ-001."""\n    return "ok"\n',
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_item.py").write_text(
        'def test_create_item() -> None:\n    """Verifies REQ-001."""\n    assert True\n',
        encoding="utf-8",
    )

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "(REQ-001) Create item",
            "--risk",
            "L1",
            "--offline",
        ]
    )
    res = run_cli(["--workspace", str(tmp_path), "rtm"])
    rtm = res.get("rtm", res)
    assert rtm["compliant"] is True
    assert rtm["coverage_ratio"] == 1.0


def test_req204_cli_fmea_subcommand(tmp_path: Path) -> None:
    """REQ-ISO-204: CLI 'fmea' subcommand computes FMEA RPN profile and ISO/IEC 42001 SoA."""
    from iso9000_agentops.cli import run_cli

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "(REQ-001) FMEA check",
            "--risk",
            "L1",
            "--offline",
        ]
    )
    res = run_cli(["--workspace", str(tmp_path), "fmea"])
    fmea_data = res.get("fmea", res)
    assert "max_rpn" in fmea_data
    assert "overall_risk_level" in fmea_data
    assert "soa" in res or "controls" in res


def test_req204_cli_certify_subcommand_end_to_end(tmp_path: Path) -> None:
    """REQ-ISO-204: CLI 'certify' subcommand runs full certification and writes badge + SARIF."""
    from iso9000_agentops.cli import run_cli

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "feature.py").write_text(
        'def run_feature() -> int:\n    """Implements REQ-001."""\n    return 200\n',
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_feature.py").write_text(
        'def test_run_feature() -> None:\n    """Verifies REQ-001."""\n    assert True\n',
        encoding="utf-8",
    )

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "(REQ-001) Build feature",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    run_cli(["--workspace", str(tmp_path), "approve-gate1"])
    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "verify",
            "--cmd",
            'python -c "import sys; sys.exit(0)"',
        ]
    )

    res = run_cli(["--workspace", str(tmp_path), "certify"])
    cert = res.get("certificate", res)
    assert cert["status"] == "CERTIFIED"
    assert len(cert["certificate_signature"]) == 64

    sg = tmp_path / ".supergraph"
    assert (sg / "quality_certificate.json").is_file()
    assert (sg / "compliance_badge.svg").is_file()
    assert (sg / "compliance_report.sarif.json").is_file()


def test_req204_self_traceability_on_iso9000_agentops_repo() -> None:
    """REQ-ISO-204: Verify iso9000-agentops repository itself satisfies REQ-ISO-201..204 traceability."""
    rtm = build_requirements_traceability_matrix(
        requirements=["REQ-ISO-201", "REQ-ISO-202", "REQ-ISO-203", "REQ-ISO-204"],
        source_root=REPO_ROOT / "iso9000_agentops",
        tests_root=REPO_ROOT / "tests",
    )
    assert rtm["requirements"] == [
        "REQ-ISO-201",
        "REQ-ISO-202",
        "REQ-ISO-203",
        "REQ-ISO-204",
    ]
    assert rtm["orphan_requirements"] == []
    assert rtm["unimplemented_requirements"] == []
    assert rtm["coverage_ratio"] == 1.0
    assert rtm["compliant"] is True
