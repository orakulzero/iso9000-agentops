"""Tests for iso9000_agentops.aims_42001."""

import pytest
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (REPO_ROOT / "src", REPO_ROOT):
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
)

def test_validate_sod_value_valid():
    """Test valid SOD values."""
    assert _validate_sod_value("severity", 1) == 1
    assert _validate_sod_value("severity", 5) == 5
    assert _validate_sod_value("severity", 10) == 10

def test_validate_sod_value_invalid_type():
    """Test invalid type SOD values."""
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", "5")
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", 5.5)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", True)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", None)

def test_validate_sod_value_out_of_bounds():
    """Test out of bounds SOD values."""
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", 11)

def test_compute_fmea_rpn_l0():
    """Test compute_fmea_rpn for L0 risk tier."""
    result = compute_fmea_rpn(1, 1, 1)
    assert result["rpn"] == 1
    assert result["risk_level"] == "L0"
    assert result["action_required"] is False
    assert result["required_controls"] == ["A.6.2.2: AI system lifecycle documentation"]

def test_compute_fmea_rpn_l1():
    """Test compute_fmea_rpn for L1 risk tier."""
    result = compute_fmea_rpn(5, 3, 3)
    assert result["rpn"] == 45
    assert result["risk_level"] == "L1"
    assert result["action_required"] is False
    assert "A.6.2.4: AI system verification and validation specification" in result["required_controls"]

def test_compute_fmea_rpn_l2():
    """Test compute_fmea_rpn for L2 risk tier."""
    result = compute_fmea_rpn(5, 5, 5)
    assert result["rpn"] == 125
    assert result["risk_level"] == "L2"
    assert result["action_required"] is True

def test_compute_fmea_rpn_l3():
    """Test compute_fmea_rpn for L3 risk tier."""
    result = compute_fmea_rpn(8, 6, 5)
    assert result["rpn"] == 240
    assert result["risk_level"] == "L3"
    assert result["action_required"] is True

def test_compute_fmea_rpn_l4_by_rpn():
    """Test compute_fmea_rpn for L4 risk tier by RPN value > 400."""
    result = compute_fmea_rpn(8, 8, 8)
    assert result["rpn"] == 512
    assert result["risk_level"] == "L4"
    assert result["action_required"] is True

def test_compute_fmea_rpn_l4_by_severity():
    """Test compute_fmea_rpn for L4 risk tier by severity >= 9."""
    result = compute_fmea_rpn(9, 1, 1)
    assert result["rpn"] == 9
    assert result["risk_level"] == "L4"
    assert result["action_required"] is True

def test_assess_failure_modes_empty():
    """Test assess_failure_modes with empty list."""
    result = assess_failure_modes([])
    assert result["modes"] == []
    assert result["max_rpn"] == 0
    assert result["mean_rpn"] == 0.0
    assert result["overall_risk_level"] == "L0"
    assert result["critical_modes"] == []

def test_assess_failure_modes_single():
    """Test assess_failure_modes with a single mode."""
    modes = [{"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 2, "detection": 2}]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 1
    assert result["max_rpn"] == 8
    assert result["mean_rpn"] == 8.0
    assert result["overall_risk_level"] == "L0"
    assert result["critical_modes"] == []

def test_assess_failure_modes_multiple():
    """Test assess_failure_modes with multiple modes, checking sorting and aggregation."""
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"id": "FM-02", "name": "Mode 2", "severity": 9, "occurrence": 1, "detection": 1}, # RPN 9, L4
        {"id": "FM-03", "name": "Mode 3", "severity": 5, "occurrence": 5, "detection": 5}, # RPN 125, L2
    ]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 3
    # Check sorting by RPN descending
    assert result["modes"][0]["id"] == "FM-03" # RPN 125
    assert result["modes"][1]["id"] == "FM-02" # RPN 9
    assert result["modes"][2]["id"] == "FM-01" # RPN 8

    assert result["max_rpn"] == 125
    assert result["mean_rpn"] == (125 + 9 + 8) / 3.0
    assert result["overall_risk_level"] == "L4"
    assert set(result["critical_modes"]) == {"FM-02", "FM-03"}

def test_assess_failure_modes_missing_fields():
    """Test assess_failure_modes with missing optional fields."""
    modes = [{}] # Should default to FM-001, Unnamed, 1, 1, 1
    result = assess_failure_modes(modes)
    assert result["modes"][0]["id"] == "FM-001"
    assert result["modes"][0]["name"] == "Unnamed failure mode"
    assert result["modes"][0]["rpn"] == 1

def test_generate_iso42001_soa_default():
    """Test generate_iso42001_soa with default baseline."""
    result = generate_iso42001_soa({})
    assert result["baseline_id"] == "BL-DEFAULT"
    assert result["risk_level"] == "L2"
    assert result["all_controls_satisfied"] is False # Because human_gate_1_approved is False

def test_generate_iso42001_soa_l0_satisfied():
    """Test generate_iso42001_soa with L0 risk level, all satisfied."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    result = generate_iso42001_soa(baseline)
    assert result["all_controls_satisfied"] is True

def test_generate_iso42001_soa_l2_requires_seal():
    """Test generate_iso42001_soa with L2 risk level, requiring a 64-char seal."""
    baseline_no_seal = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short-seal",
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    result_no_seal = generate_iso42001_soa(baseline_no_seal)
    assert result_no_seal["all_controls_satisfied"] is False

    baseline_with_seal = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64, # 64 char seal
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    result_with_seal = generate_iso42001_soa(baseline_with_seal)
    assert result_with_seal["all_controls_satisfied"] is True

def test_generate_iso42001_soa_fmea_l4_fails():
    """Test generate_iso42001_soa fails if FMEA is L4."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea_summary = {"overall_risk_level": "L4"}
    result = generate_iso42001_soa(baseline, fmea_summary=fmea_summary)
    assert result["all_controls_satisfied"] is False

def test_generate_iso42001_soa_rtm_not_compliant():
    """Test generate_iso42001_soa fails if RTM is not compliant."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    rtm_summary = {"compliant": False, "coverage_ratio": 0.5}
    result = generate_iso42001_soa(baseline, rtm_summary=rtm_summary)
    assert result["all_controls_satisfied"] is False

def test_generate_iso42001_soa_aop_not_ok():
    """Test generate_iso42001_soa fails if AOP is not solvable or covered."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "aop_validation": {"solvable": False, "completeness_covered": True},
    }
    result = generate_iso42001_soa(baseline)
    assert result["all_controls_satisfied"] is False
