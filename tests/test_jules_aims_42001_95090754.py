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

def test_validate_sod_value():
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 10) == 10
    
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", 1.5)
        
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", True)
        
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", "5")
        
    with pytest.raises(ValueError, match="between 1 and 10 inclusive"):
        _validate_sod_value("test", 0)
        
    with pytest.raises(ValueError, match="between 1 and 10 inclusive"):
        _validate_sod_value("test", 11)

def test_compute_fmea_rpn():
    # L0
    res = compute_fmea_rpn(1, 1, 1)
    assert res["rpn"] == 1
    assert res["risk_level"] == "L0"
    assert not res["action_required"]
    
    res = compute_fmea_rpn(2, 4, 5) # 40
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    
    # L1
    res = compute_fmea_rpn(1, 6, 7) # 42
    assert res["rpn"] == 42
    assert res["risk_level"] == "L1"
    assert not res["action_required"]
    
    # L2
    res = compute_fmea_rpn(4, 5, 6) # 120
    assert res["rpn"] == 120
    assert res["risk_level"] == "L2"
    assert res["action_required"]
    
    # L3
    res = compute_fmea_rpn(6, 6, 6) # 216
    assert res["rpn"] == 216
    assert res["risk_level"] == "L3"
    
    # L4
    res = compute_fmea_rpn(7, 8, 8) # 448
    assert res["rpn"] == 448
    assert res["risk_level"] == "L4"
    
    # L4 due to severity >= 9
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
    
def test_assess_failure_modes():
    # Empty
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    
    # Default values and sorting
    modes = [
        {"id": "FM-001", "name": "Mode 1", "severity": 2, "occurrence": 4, "detection": 5}, # RPN 40
        {"id": "FM-002", "name": "Mode 2", "severity": 6, "occurrence": 6, "detection": 6}, # RPN 216 -> L3
        {} # Missing keys, should default to 1,1,1 -> RPN 1 -> L0
    ]
    res = assess_failure_modes(modes)
    assert res["overall_risk_level"] == "L3"
    assert res["max_rpn"] == 216
    assert res["mean_rpn"] == (216 + 40 + 1) / 3
    assert len(res["critical_modes"]) == 1
    assert res["critical_modes"][0] == "FM-002"
    
    assert res["modes"][0]["id"] == "FM-002"
    assert res["modes"][1]["id"] == "FM-001"
    assert res["modes"][2]["id"] == "FM-003"
    assert res["modes"][2]["name"] == "Unnamed failure mode"
    assert res["modes"][2]["rpn"] == 1

def test_generate_iso42001_soa():
    # Basic baseline
    res = generate_iso42001_soa({})
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert not res["all_controls_satisfied"]
    
    # Satisfied L0/L1
    baseline_l1 = {
        "baseline_id": "BL-1",
        "risk_level": "L1",
        "human_gate_1_approved": True,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    res = generate_iso42001_soa(baseline_l1)
    assert res["all_controls_satisfied"]
    
    # L2 with full requirements
    baseline_l2 = {
        "baseline_id": "BL-2",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    fmea_summary = {"overall_risk_level": "L2"}
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}
    res = generate_iso42001_soa(baseline_l2, fmea_summary, rtm_summary)
    assert res["all_controls_satisfied"]
    
    # Missing RTM, failing FMEA (L4)
    baseline_fail = {
        "baseline_id": "BL-FAIL",
        "risk_level": "L3",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 63, # Wrong len
    }
    fmea_summary_fail = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline_fail, fmea_summary_fail)
    assert not res["all_controls_satisfied"]
