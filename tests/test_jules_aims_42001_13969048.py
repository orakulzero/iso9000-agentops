"""Tests for iso9000_agentops.aims_42001.

Validates:
- FMEA RPN computations (edge cases, bound limits)
- _validate_sod_value input boundary enforcement 
- Failure mode risk categorization & critical mode identification
- ISO/IEC 42001:2023 SoA logic paths
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (REPO_ROOT / "src", REPO_ROOT):
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    assess_failure_modes,
    compute_fmea_rpn,
    generate_iso42001_soa,
)

# ---------------------------------------------------------------------------
# _validate_sod_value tests
# ---------------------------------------------------------------------------


def test_validate_sod_value_valid() -> None:
    """Test valid SOD values."""
    assert _validate_sod_value("severity", 1) == 1
    assert _validate_sod_value("occurrence", 5) == 5
    assert _validate_sod_value("detection", 10) == 10


def test_validate_sod_value_out_of_bounds() -> None:
    """Test out of bounds inputs for SOD values."""
    with pytest.raises(ValueError, match="between 1 and 10 inclusive"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="between 1 and 10 inclusive"):
        _validate_sod_value("test", 11)


@pytest.mark.parametrize("invalid_type_val", [
    "5",
    5.0,
    True,
    None,
    [5],
])
def test_validate_sod_value_invalid_types(invalid_type_val: Any) -> None:
    """Test invalid types for SOD values."""
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", invalid_type_val)


# ---------------------------------------------------------------------------
# compute_fmea_rpn tests
# ---------------------------------------------------------------------------


def test_compute_fmea_rpn_l0() -> None:
    """Test RPN resulting in L0."""
    result = compute_fmea_rpn(1, 1, 1)
    assert result["rpn"] == 1
    assert result["risk_level"] == "L0"
    assert not result["action_required"]
    assert result["required_controls"] == ["A.6.2.2: AI system lifecycle documentation"]


def test_compute_fmea_rpn_l1() -> None:
    """Test RPN resulting in L1."""
    result = compute_fmea_rpn(2, 4, 6)
    assert result["rpn"] == 48
    assert result["risk_level"] == "L1"
    assert not result["action_required"]
    assert len(result["required_controls"]) == 2


def test_compute_fmea_rpn_l2() -> None:
    """Test RPN resulting in L2."""
    result = compute_fmea_rpn(5, 5, 5)
    assert result["rpn"] == 125
    assert result["risk_level"] == "L2"
    assert result["action_required"]
    assert len(result["required_controls"]) == 4


def test_compute_fmea_rpn_l3() -> None:
    """Test RPN resulting in L3."""
    result = compute_fmea_rpn(6, 6, 6)
    assert result["rpn"] == 216
    assert result["risk_level"] == "L3"
    assert result["action_required"]
    assert len(result["required_controls"]) == 5


def test_compute_fmea_rpn_l4_by_rpn() -> None:
    """Test RPN resulting in L4 via overall score > 400."""
    result = compute_fmea_rpn(8, 8, 8)
    assert result["rpn"] == 512
    assert result["risk_level"] == "L4"
    assert result["action_required"]
    assert len(result["required_controls"]) == 6


def test_compute_fmea_rpn_l4_by_severity() -> None:
    """Test RPN resulting in L4 due to severity >= 9, even with low RPN."""
    result = compute_fmea_rpn(9, 1, 1)
    assert result["rpn"] == 9
    assert result["risk_level"] == "L4"
    assert result["action_required"]


# ---------------------------------------------------------------------------
# assess_failure_modes tests
# ---------------------------------------------------------------------------


def test_assess_failure_modes_empty() -> None:
    """Test assessing empty sequence."""
    result = assess_failure_modes([])
    assert result["modes"] == []
    assert result["max_rpn"] == 0
    assert result["mean_rpn"] == 0.0
    assert result["overall_risk_level"] == "L0"
    assert result["critical_modes"] == []


def test_assess_failure_modes_single_critical() -> None:
    """Test assessing a single critical failure mode."""
    modes = [{"id": "FM-999", "name": "Catastrophic Failure", "severity": 10, "occurrence": 1, "detection": 1}]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 1
    assert result["max_rpn"] == 10
    assert result["overall_risk_level"] == "L4"
    assert result["critical_modes"] == ["FM-999"]
    assert result["modes"][0]["action_required"] is True


def test_assess_failure_modes_multiple_sorting() -> None:
    """Test that failure modes are sorted descending by RPN and multiple modes aggregate correctly."""
    modes = [
        {"id": "FM-01", "severity": 2, "occurrence": 2, "detection": 2}, # RPN 8
        {"id": "FM-02", "severity": 7, "occurrence": 7, "detection": 7}, # RPN 343, L3
        {"id": "FM-03", "severity": 5, "occurrence": 5, "detection": 5}, # RPN 125, L2
    ]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 3
    # Check sorting
    assert result["modes"][0]["id"] == "FM-02"
    assert result["modes"][1]["id"] == "FM-03"
    assert result["modes"][2]["id"] == "FM-01"

    assert result["max_rpn"] == 343
    # 8 + 343 + 125 = 476 / 3 = 158.666...
    assert result["mean_rpn"] == pytest.approx(158.666, 0.01)
    assert result["overall_risk_level"] == "L3"
    assert set(result["critical_modes"]) == {"FM-02", "FM-03"}

    # Check defaults applied correctly
    assert result["modes"][2]["name"] == "Unnamed failure mode"


def test_assess_failure_modes_defaults() -> None:
    """Test that default values are applied when not provided."""
    modes = [{}]
    result = assess_failure_modes(modes)
    assert result["modes"][0]["id"] == "FM-001"
    assert result["modes"][0]["name"] == "Unnamed failure mode"
    assert result["modes"][0]["rpn"] == 1


# ---------------------------------------------------------------------------
# generate_iso42001_soa tests
# ---------------------------------------------------------------------------


def test_generate_iso42001_soa_all_compliant() -> None:
    """Test SoA generation with full compliance."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64, # 64-char seal
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea = {"overall_risk_level": "L2"}
    rtm = {"compliant": True, "coverage_ratio": 1.0}

    soa = generate_iso42001_soa(baseline, fmea, rtm)
    assert soa["all_controls_satisfied"] is True
    assert soa["baseline_id"] == "BL-001"


def test_generate_iso42001_soa_non_compliant_due_to_seal() -> None:
    """Test SoA generation failing due to missing/invalid HMAC seal for L2+."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short-seal", # Invalid seal length
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    
    soa = generate_iso42001_soa(baseline, fmea_summary=None, rtm_summary=None)
    assert soa["all_controls_satisfied"] is False
    # Check A.9.3 control
    gate_control = next(c for c in soa["controls"] if c["control_id"] == "A.9.3")
    assert gate_control["implemented"] is False


def test_generate_iso42001_soa_l0_no_seal_needed() -> None:
    """Test SoA generation for L0/L1 where seal isn't strictly checked if gate1 approved."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short-seal", # Doesn't matter for L0
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    
    soa = generate_iso42001_soa(baseline)
    gate_control = next(c for c in soa["controls"] if c["control_id"] == "A.9.3")
    assert gate_control["implemented"] is True


def test_generate_iso42001_soa_fmea_l4() -> None:
    """Test SoA generation failing due to unacceptable L4 risk."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea = {"overall_risk_level": "L4"}
    
    soa = generate_iso42001_soa(baseline, fmea_summary=fmea)
    assert soa["all_controls_satisfied"] is False
    fmea_control = next(c for c in soa["controls"] if c["control_id"] == "A.8.3")
    assert fmea_control["implemented"] is False


def test_generate_iso42001_soa_aop_invalid() -> None:
    """Test SoA generation failing due to invalid AOP validation."""
    baseline = {
        "baseline_id": "BL-001",
        "aop_validation": {"solvable": False, "completeness_covered": True},
    }
    
    soa = generate_iso42001_soa(baseline)
    assert soa["all_controls_satisfied"] is False
    req_control = next(c for c in soa["controls"] if c["control_id"] == "A.6.2.2")
    assert req_control["implemented"] is False


def test_generate_iso42001_soa_rtm_invalid() -> None:
    """Test SoA generation failing due to invalid RTM summary."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "",
    }
    rtm = {"compliant": False, "coverage_ratio": 0.5}
    
    soa = generate_iso42001_soa(baseline, rtm_summary=rtm)
    assert soa["all_controls_satisfied"] is False
    rtm_control = next(c for c in soa["controls"] if c["control_id"] == "A.6.2.4")
    assert rtm_control["implemented"] is False
