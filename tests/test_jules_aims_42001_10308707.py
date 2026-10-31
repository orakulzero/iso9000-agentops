"""Tests for ISO/IEC 42001:2023 AIMS & ISO 31000 FMEA Risk Engine."""

import sys
from pathlib import Path

import pytest

# Add src and current directory to sys.path to resolve imports correctly
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
    """Test _validate_sod_value with valid inputs."""
    for val in range(1, 11):
        assert _validate_sod_value("test", val) == val

def test_validate_sod_value_invalid_type():
    """Test _validate_sod_value with invalid types."""
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\], got .*"):
        _validate_sod_value("test", "1")
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\], got True"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\], got 1.5"):
        _validate_sod_value("test", 1.5)
        
def test_validate_sod_value_invalid_range():
    """Test _validate_sod_value with invalid range values."""
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive, got 0"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive, got 11"):
        _validate_sod_value("test", 11)
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive, got -5"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn_l0():
    """Test compute_fmea_rpn resulting in L0."""
    result = compute_fmea_rpn(2, 2, 2)
    assert result["rpn"] == 8
    assert result["risk_level"] == "L0"
    assert result["action_required"] is False
    assert result["required_controls"] == ["A.6.2.2: AI system lifecycle documentation"]
    assert result["severity"] == 2
    assert result["occurrence"] == 2
    assert result["detection"] == 2
    
def test_compute_fmea_rpn_l1():
    """Test compute_fmea_rpn resulting in L1."""
    result = compute_fmea_rpn(5, 3, 3)
    assert result["rpn"] == 45
    assert result["risk_level"] == "L1"
    assert result["action_required"] is False
    assert "A.6.2.4: AI system verification and validation specification" in result["required_controls"]

def test_compute_fmea_rpn_l2():
    """Test compute_fmea_rpn resulting in L2."""
    result = compute_fmea_rpn(5, 5, 5)
    assert result["rpn"] == 125
    assert result["risk_level"] == "L2"
    assert result["action_required"] is True
    assert "A.9.3: Human oversight Gate 1 HMAC-SHA256 seal" in result["required_controls"]

def test_compute_fmea_rpn_l3():
    """Test compute_fmea_rpn resulting in L3."""
    result = compute_fmea_rpn(7, 6, 5)
    assert result["rpn"] == 210
    assert result["risk_level"] == "L3"
    assert result["action_required"] is True
    assert "A.8.3: External reporting and OASIS SARIF 2.1.0 audit" in result["required_controls"]

def test_compute_fmea_rpn_l4_by_rpn():
    """Test compute_fmea_rpn resulting in L4 by high RPN."""
    result = compute_fmea_rpn(8, 8, 8)
    assert result["rpn"] == 512
    assert result["risk_level"] == "L4"
    assert result["action_required"] is True
    assert "A.10.2: Strict Test-Designer / Build-Agent role isolation and Planarian rollback" in result["required_controls"]

def test_compute_fmea_rpn_l4_by_severity():
    """Test compute_fmea_rpn resulting in L4 by high severity."""
    # Even with low RPN, severity >= 9 triggers L4
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

def test_assess_failure_modes_multiple():
    """Test assess_failure_modes with multiple modes."""
    modes = [
        {"id": "FM-001", "name": "Mode A", "severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"id": "FM-002", "name": "Mode B", "severity": 8, "occurrence": 8, "detection": 8}, # RPN 512, L4
        {"severity": 5, "occurrence": 5, "detection": 5} # RPN 125, L2, missing ID and name
    ]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 3
    # Should be sorted by RPN descending
    assert result["modes"][0]["id"] == "FM-002"
    assert result["modes"][0]["rpn"] == 512
    assert result["modes"][1]["id"] == "FM-003" # Auto-generated ID
    assert result["modes"][1]["name"] == "Unnamed failure mode"
    assert result["modes"][1]["rpn"] == 125
    assert result["modes"][2]["id"] == "FM-001"
    assert result["modes"][2]["rpn"] == 8
    
    assert result["max_rpn"] == 512
    assert result["mean_rpn"] == (512 + 125 + 8) / 3
    assert result["overall_risk_level"] == "L4"
    assert set(result["critical_modes"]) == {"FM-002", "FM-003"} # L4 and L2 require action

def test_generate_iso42001_soa_default():
    """Test generate_iso42001_soa with default baseline and None summaries."""
    baseline = {}
    result = generate_iso42001_soa(baseline)
    assert result["standard"] == "ISO/IEC 42001:2023"
    assert result["baseline_id"] == "BL-DEFAULT"
    assert result["risk_level"] == "L2"
    # gate1_approved is False by default, so L2 fails oversight_ok
    # A.9.3 requires gate1_approved and seal_len=64 for L2+
    
    # Check specific controls
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.6.2.2"]["implemented"] is True # baseline_id "BL-DEFAULT" is truthy, default aop_ok is True
    assert controls["A.6.2.4"]["implemented"] is True # default rtm_ok is True if None
    assert controls["A.7.4"]["implemented"] is True
    assert controls["A.8.3"]["implemented"] is True # default fmea_ok is True (L0 != L4)
    assert controls["A.9.3"]["implemented"] is False # gate1_approved is False
    assert controls["A.10.2"]["implemented"] is True
    
    assert result["all_controls_satisfied"] is False

def test_generate_iso42001_soa_satisfied():
    """Test generate_iso42001_soa where all controls are satisfied."""
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "l3",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64, # 64 chars
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    fmea_summary = {"overall_risk_level": "L3"}
    rtm_summary = {"compliant": True, "coverage_ratio": 0.95}
    
    result = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert result["risk_level"] == "L3"
    assert result["all_controls_satisfied"] is True
    
def test_generate_iso42001_soa_oversight_logic_l0_l1():
    """Test generate_iso42001_soa oversight_ok logic for L0/L1."""
    # L0/L1 only need gate1_approved, don't need valid seal length
    baseline = {
        "risk_level": "L1",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short" # not 64 chars
    }
    result = generate_iso42001_soa(baseline)
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.9.3"]["implemented"] is True
    
def test_generate_iso42001_soa_aop_fail():
    """Test generate_iso42001_soa failing AOP validation."""
    baseline = {
        "baseline_id": "BL-001",
        "aop_validation": {"solvable": False, "completeness_covered": True}
    }
    result = generate_iso42001_soa(baseline)
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.6.2.2"]["implemented"] is False

def test_generate_iso42001_soa_rtm_fail():
    """Test generate_iso42001_soa failing RTM."""
    baseline = {"baseline_id": "BL-001"}
    rtm_summary = {"compliant": False, "coverage_ratio": 0.5}
    result = generate_iso42001_soa(baseline, rtm_summary=rtm_summary)
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.6.2.4"]["implemented"] is False
    
def test_generate_iso42001_soa_fmea_fail():
    """Test generate_iso42001_soa failing FMEA (L4)."""
    baseline = {"baseline_id": "BL-001"}
    fmea_summary = {"overall_risk_level": "L4"}
    result = generate_iso42001_soa(baseline, fmea_summary=fmea_summary)
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.8.3"]["implemented"] is False

def test_generate_iso42001_soa_aop_completeness_fail():
    """Test generate_iso42001_soa failing AOP completeness_covered."""
    baseline = {
        "baseline_id": "BL-001",
        "aop_validation": {"solvable": True, "completeness_covered": False}
    }
    result = generate_iso42001_soa(baseline)
    controls = {c["control_id"]: c for c in result["controls"]}
    assert controls["A.6.2.2"]["implemented"] is False

def test_assess_failure_modes_missing_keys():
    """Test assess_failure_modes with missing keys to trigger defaults."""
    modes = [{}]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 1
    assert result["modes"][0]["id"] == "FM-001"
    assert result["modes"][0]["name"] == "Unnamed failure mode"
    assert result["modes"][0]["rpn"] == 1
    assert result["modes"][0]["risk_level"] == "L0"
    
def test_assess_failure_modes_highest_tier():
    """Test assess_failure_modes updates highest tier correctly."""
    modes = [
        {"severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"severity": 5, "occurrence": 5, "detection": 5} # RPN 125, L2
    ]
    result = assess_failure_modes(modes)
    assert result["overall_risk_level"] == "L2"

def test_compute_fmea_rpn_boundaries():
    """Test compute_fmea_rpn with boundary values."""
    # Boundary: rpn == 400 -> L3 (since rpn > 400 is L4)
    # severity=8 to avoid s >= 9 L4 override
    res = compute_fmea_rpn(8, 10, 5)
    assert res["rpn"] == 400
    assert res["risk_level"] == "L3"
    
    # Boundary: rpn == 200 -> L2 (since rpn >= 201 is L3)
    res = compute_fmea_rpn(8, 5, 5)
    assert res["rpn"] == 200
    assert res["risk_level"] == "L2"
    
    # Boundary: rpn == 100 -> L1 (since rpn >= 101 is L2)
    res = compute_fmea_rpn(4, 5, 5)
    assert res["rpn"] == 100
    assert res["risk_level"] == "L1"
    
    # Boundary: rpn == 40 -> L0 (since rpn >= 41 is L1)
    res = compute_fmea_rpn(4, 5, 2)
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    
    # Boundary: s == 9 -> L4 (even if RPN is low)
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
