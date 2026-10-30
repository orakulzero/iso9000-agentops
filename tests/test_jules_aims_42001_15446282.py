"""Tests for ISO/IEC 42001:2023 AIMS and FMEA logic."""
from __future__ import annotations

import pytest
from pathlib import Path
import sys

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

def test_validate_sod_value_valid() -> None:
    """Test valid SOD values are accepted."""
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 5) == 5
    assert _validate_sod_value("test", 10) == 10

def test_validate_sod_value_invalid_types() -> None:
    """Test invalid types raise ValueError."""
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", "5")
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", 5.0)
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", None)

def test_validate_sod_value_invalid_bounds() -> None:
    """Test out of bounds integers raise ValueError."""
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 11)
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn_l0() -> None:
    """Test RPN calculation for L0 risk."""
    res = compute_fmea_rpn(1, 1, 1)
    assert res["rpn"] == 1
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert len(res["required_controls"]) == 1

def test_compute_fmea_rpn_l1() -> None:
    """Test RPN calculation for L1 risk."""
    # 41 <= rpn <= 100
    res = compute_fmea_rpn(5, 3, 3)
    assert res["rpn"] == 45
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False
    assert len(res["required_controls"]) == 2

def test_compute_fmea_rpn_l2() -> None:
    """Test RPN calculation for L2 risk."""
    # 101 <= rpn <= 200
    res = compute_fmea_rpn(5, 5, 5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True
    assert len(res["required_controls"]) == 4

def test_compute_fmea_rpn_l3() -> None:
    """Test RPN calculation for L3 risk."""
    # 201 <= rpn <= 400
    res = compute_fmea_rpn(7, 6, 5)
    assert res["rpn"] == 210
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True
    assert len(res["required_controls"]) == 5

def test_compute_fmea_rpn_l4() -> None:
    """Test RPN calculation for L4 risk."""
    # rpn > 400 or severity >= 9
    res1 = compute_fmea_rpn(8, 8, 8)
    assert res1["rpn"] == 512
    assert res1["risk_level"] == "L4"
    assert res1["action_required"] is True
    assert len(res1["required_controls"]) == 6

    # Severity 9, even if RPN is low
    res2 = compute_fmea_rpn(9, 1, 1)
    assert res2["rpn"] == 9
    assert res2["risk_level"] == "L4"

def test_assess_failure_modes_empty() -> None:
    """Test assessing an empty list of failure modes."""
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes_valid() -> None:
    """Test assessing multiple failure modes."""
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 3, "detection": 2}, # RPN=12 (L0)
        {"id": "FM-02", "name": "Mode 2", "severity": 6, "occurrence": 5, "detection": 4}, # RPN=120 (L2)
        {"id": "FM-03", "name": "Mode 3", "severity": 9, "occurrence": 1, "detection": 1}, # RPN=9 (L4 due to S=9)
    ]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 3
    # Sorted by RPN desc
    assert res["modes"][0]["id"] == "FM-02" # 120
    assert res["modes"][1]["id"] == "FM-01" # 12
    assert res["modes"][2]["id"] == "FM-03" # 9

    assert res["max_rpn"] == 120
    assert res["mean_rpn"] == (120 + 12 + 9) / 3
    assert res["overall_risk_level"] == "L4"
    assert res["critical_modes"] == ["FM-02", "FM-03"] # L2+ are critical

def test_generate_iso42001_soa_default() -> None:
    """Test SoA generation with default baseline."""
    baseline = {}
    res = generate_iso42001_soa(baseline)
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    
    # Defaults lead to not all satisfied
    assert res["all_controls_satisfied"] is False

def test_generate_iso42001_soa_all_satisfied() -> None:
    """Test SoA generation where all controls are satisfied."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64, # 64 length seal
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea_summary = {"overall_risk_level": "L2"}
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}
    
    res = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert res["all_controls_satisfied"] is True
    assert all(c["implemented"] for c in res["controls"])

def test_generate_iso42001_soa_l0_oversight() -> None:
    """Test SoA generation for L0 risk level where seal is not required for oversight."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "", # Empty seal
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    res = generate_iso42001_soa(baseline)
    # Finding A.9.3
    oversight_control = next(c for c in res["controls"] if c["control_id"] == "A.9.3")
    assert oversight_control["implemented"] is True

def test_generate_iso42001_soa_fmea_l4() -> None:
    """Test SoA generation where FMEA is L4 causing failure in A.8.3."""
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64, 
    }
    fmea_summary = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline, fmea_summary)
    fmea_control = next(c for c in res["controls"] if c["control_id"] == "A.8.3")
    assert fmea_control["implemented"] is False
    assert res["all_controls_satisfied"] is False
