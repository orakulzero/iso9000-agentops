from __future__ import annotations

import pytest
from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
)

def test_validate_sod_value_valid():
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 5) == 5
    assert _validate_sod_value("test", 10) == 10

def test_validate_sod_value_invalid_types():
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", "5")
    
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", 5.0)

    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", True)

def test_validate_sod_value_out_of_bounds():
    with pytest.raises(ValueError, match="between 1 and 10"):
        _validate_sod_value("test", 0)
        
    with pytest.raises(ValueError, match="between 1 and 10"):
        _validate_sod_value("test", 11)
        
    with pytest.raises(ValueError, match="between 1 and 10"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn_tiers():
    # L0: RPN <= 40 and S < 9
    res_l0 = compute_fmea_rpn(1, 1, 1)
    assert res_l0["rpn"] == 1
    assert res_l0["risk_level"] == "L0"
    assert not res_l0["action_required"]
    
    # L1: 41 <= RPN <= 100 and S < 9
    res_l1 = compute_fmea_rpn(5, 5, 2)
    assert res_l1["rpn"] == 50
    assert res_l1["risk_level"] == "L1"
    assert not res_l1["action_required"]
    
    # L2: 101 <= RPN <= 200 and S < 9
    res_l2 = compute_fmea_rpn(5, 5, 5)
    assert res_l2["rpn"] == 125
    assert res_l2["risk_level"] == "L2"
    assert res_l2["action_required"]
    
    # L3: 201 <= RPN <= 400 and S < 9
    res_l3 = compute_fmea_rpn(8, 8, 4)
    assert res_l3["rpn"] == 256
    assert res_l3["risk_level"] == "L3"
    assert res_l3["action_required"]
    
    # L4: RPN > 400
    res_l4_1 = compute_fmea_rpn(8, 8, 8)
    assert res_l4_1["rpn"] == 512
    assert res_l4_1["risk_level"] == "L4"
    assert res_l4_1["action_required"]
    
    # L4: S >= 9
    res_l4_2 = compute_fmea_rpn(9, 1, 1)
    assert res_l4_2["rpn"] == 9
    assert res_l4_2["risk_level"] == "L4"
    assert res_l4_2["action_required"]

def test_compute_fmea_rpn_invalid_inputs():
    with pytest.raises(ValueError):
        compute_fmea_rpn(11, 1, 1)
    with pytest.raises(ValueError):
        compute_fmea_rpn(1, 0, 1)
    with pytest.raises(ValueError):
        compute_fmea_rpn(1, 1, "1")

def test_assess_failure_modes_empty():
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes_multiple():
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"id": "FM-02", "name": "Mode 2", "severity": 5, "occurrence": 5, "detection": 5}, # RPN 125, L2, action_required
        {"id": "FM-03", "name": "Mode 3", "severity": 9, "occurrence": 1, "detection": 1}, # RPN 9, L4, action_required
    ]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 3
    
    # Check sorting
    assert res["modes"][0]["id"] == "FM-02" # RPN 125
    assert res["modes"][1]["id"] == "FM-03" # RPN 9
    assert res["modes"][2]["id"] == "FM-01" # RPN 8
    
    assert res["max_rpn"] == 125
    assert res["mean_rpn"] == (125 + 9 + 8) / 3.0
    assert res["overall_risk_level"] == "L4"
    assert "FM-02" in res["critical_modes"]
    assert "FM-03" in res["critical_modes"]
    assert "FM-01" not in res["critical_modes"]

def test_assess_failure_modes_missing_properties():
    # Will default to severity=1, occurrence=1, detection=1
    modes = [{}]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 1
    assert res["modes"][0]["id"] == "FM-001"
    assert res["modes"][0]["name"] == "Unnamed failure mode"
    assert res["modes"][0]["rpn"] == 1
    assert res["max_rpn"] == 1

def test_generate_iso42001_soa_defaults():
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    
    # oversight_ok for L2 requires gate1_approved AND len(gate_seal) == 64
    # With defaults: gate1_approved=False, gate_seal="", so oversight_ok=False
    oversight_ctrl = next(c for c in res["controls"] if c["control_id"] == "A.9.3")
    assert not oversight_ctrl["implemented"]
    
    assert not res["all_controls_satisfied"]

def test_generate_iso42001_soa_all_satisfied():
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea_summary = {"overall_risk_level": "L2"}
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}
    
    res = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    
    assert res["all_controls_satisfied"]
    
def test_generate_iso42001_soa_l0_oversight():
    # For L0, oversight_ok only requires gate1_approved
    baseline = {
        "baseline_id": "BL-002",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short", # Does not matter for L0
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    res = generate_iso42001_soa(baseline)
    oversight_ctrl = next(c for c in res["controls"] if c["control_id"] == "A.9.3")
    assert oversight_ctrl["implemented"]

def test_generate_iso42001_soa_fmea_l4_fails():
    baseline = {
        "baseline_id": "BL-003",
        "risk_level": "L4",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea_summary = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline, fmea_summary)
    
    # fmea_ok = fmea_risk != "L4", so A.8.3 should fail
    fmea_ctrl = next(c for c in res["controls"] if c["control_id"] == "A.8.3")
    assert not fmea_ctrl["implemented"]
    assert not res["all_controls_satisfied"]

def test_generate_iso42001_soa_rtm_fails():
    baseline = {
        "baseline_id": "BL-004",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    rtm_summary = {"compliant": False, "coverage_ratio": 0.5}
    res = generate_iso42001_soa(baseline, rtm_summary=rtm_summary)
    
    rtm_ctrl = next(c for c in res["controls"] if c["control_id"] == "A.6.2.4")
    assert not rtm_ctrl["implemented"]
    assert not res["all_controls_satisfied"]

def test_generate_iso42001_soa_aop_fails():
    baseline = {
        "baseline_id": "BL-005",
        "aop_validation": {"solvable": False},
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    res = generate_iso42001_soa(baseline)
    
    aop_ctrl = next(c for c in res["controls"] if c["control_id"] == "A.6.2.2")
    assert not aop_ctrl["implemented"]
    assert not res["all_controls_satisfied"]
