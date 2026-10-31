import pytest
from pathlib import Path
import sys

# Setup sys.path to be able to import iso9000_agentops
REPO_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (REPO_ROOT / "src", REPO_ROOT):
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
    _CONTROLS_BY_TIER
)

def test_validate_sod_value_valid():
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 10) == 10
    assert _validate_sod_value("test", 5) == 5

def test_validate_sod_value_invalid_types():
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", False)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", 5.0)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", "5")

def test_validate_sod_value_out_of_bounds():
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 11)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn_l0():
    # 40 or less -> L0 (s=4, o=2, d=5 -> 40)
    res = compute_fmea_rpn(4, 2, 5)
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert res["required_controls"] == _CONTROLS_BY_TIER["L0"]

def test_compute_fmea_rpn_l1():
    # 41 to 100 -> L1 (s=5, o=9, d=1 -> 45)
    res = compute_fmea_rpn(5, 9, 1)
    assert res["rpn"] == 45
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False
    assert res["required_controls"] == _CONTROLS_BY_TIER["L1"]

    res2 = compute_fmea_rpn(5, 5, 4) # 100
    assert res2["rpn"] == 100
    assert res2["risk_level"] == "L1"

def test_compute_fmea_rpn_l2():
    # 101 to 200 -> L2 (s=5, o=5, d=5 -> 125)
    res = compute_fmea_rpn(5, 5, 5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True
    assert res["required_controls"] == _CONTROLS_BY_TIER["L2"]

    res2 = compute_fmea_rpn(5, 8, 5) # 200
    assert res2["rpn"] == 200
    assert res2["risk_level"] == "L2"

def test_compute_fmea_rpn_l3():
    # 201 to 400 -> L3 (s=5, o=5, d=9 -> 225)
    res = compute_fmea_rpn(5, 5, 9)
    assert res["rpn"] == 225
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True
    assert res["required_controls"] == _CONTROLS_BY_TIER["L3"]

    res2 = compute_fmea_rpn(8, 5, 10) # 400
    assert res2["rpn"] == 400
    assert res2["risk_level"] == "L3"

def test_compute_fmea_rpn_l4_by_rpn():
    # > 400 -> L4 (s=8, o=8, d=7 -> 448)
    res = compute_fmea_rpn(8, 8, 7)
    assert res["rpn"] == 448
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    assert res["required_controls"] == _CONTROLS_BY_TIER["L4"]

def test_compute_fmea_rpn_l4_by_severity():
    # severity >= 9 -> L4 (s=9, o=1, d=1 -> 9)
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    assert res["required_controls"] == _CONTROLS_BY_TIER["L4"]
    
    res2 = compute_fmea_rpn(10, 1, 1)
    assert res2["rpn"] == 10
    assert res2["risk_level"] == "L4"

def test_assess_failure_modes_empty():
    res = assess_failure_modes([])
    assert res == {
        "modes": [],
        "max_rpn": 0,
        "mean_rpn": 0.0,
        "overall_risk_level": "L0",
        "critical_modes": [],
    }

def test_assess_failure_modes_defaults_and_sorting():
    modes = [
        {"severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"severity": 5, "occurrence": 5, "detection": 5}, # RPN 125, L2
        {"id": "CUSTOM-1", "name": "Custom", "severity": 8, "occurrence": 5, "detection": 10}, # RPN 400, L3
    ]
    res = assess_failure_modes(modes)
    assert res["max_rpn"] == 400
    assert res["mean_rpn"] == (8 + 125 + 400) / 3.0
    assert res["overall_risk_level"] == "L3"
    
    # Sorting by RPN desc
    assert res["modes"][0]["rpn"] == 400
    assert res["modes"][1]["rpn"] == 125
    assert res["modes"][2]["rpn"] == 8

    # Default IDs and Names
    assert res["modes"][0]["id"] == "CUSTOM-1"
    assert res["modes"][0]["name"] == "Custom"
    
    # original list had index 1 for 125, index 0 for 8. So index is 1+1=2, 0+1=1 for defaults
    assert res["modes"][1]["id"] == "FM-002"
    assert res["modes"][1]["name"] == "Unnamed failure mode"
    assert res["modes"][2]["id"] == "FM-001"
    
    # Critical modes
    assert set(res["critical_modes"]) == {"CUSTOM-1", "FM-002"}

def test_generate_iso42001_soa_defaults():
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    
    # A.6.2.2: bool(baseline_id) and aop_ok (default True) -> True
    # A.6.2.4: rtm_ok (default True if None) -> True
    # A.7.4: True
    # A.8.3: fmea_ok (default fmea_risk != L4 -> True) -> True
    # A.9.3: oversight_ok (risk_level L2 -> gate1_approved and len(seal)==64 -> False and False) -> False
    # A.10.2: True
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert controls["A.6.2.2"] is True
    assert controls["A.6.2.4"] is True
    assert controls["A.8.3"] is True
    assert controls["A.9.3"] is False
    assert res["all_controls_satisfied"] is False

def test_generate_iso42001_soa_fully_compliant():
    res = generate_iso42001_soa(
        baseline={
            "baseline_id": "BL-123",
            "risk_level": "L3",
            "human_gate_1_approved": True,
            "gate_seal_hmac": "a" * 64,
            "aop_validation": {"solvable": True, "completeness_covered": True}
        },
        fmea_summary={"overall_risk_level": "L3"},
        rtm_summary={"compliant": True, "coverage_ratio": 1.0}
    )
    assert res["baseline_id"] == "BL-123"
    assert res["risk_level"] == "L3"
    assert res["all_controls_satisfied"] is True
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert all(controls.values())

def test_generate_iso42001_soa_non_compliant_fmea():
    res = generate_iso42001_soa(
        baseline={},
        fmea_summary={"overall_risk_level": "L4"}
    )
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert controls["A.8.3"] is False
    assert res["all_controls_satisfied"] is False

def test_generate_iso42001_soa_oversight_ok_low_risk():
    # If L0 or L1, just gate1_approved is enough (no seal length requirement)
    res = generate_iso42001_soa(
        baseline={
            "risk_level": "L1",
            "human_gate_1_approved": True,
            "gate_seal_hmac": "short"
        }
    )
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert controls["A.9.3"] is True

def test_generate_iso42001_soa_aop_validation_false():
    res = generate_iso42001_soa(
        baseline={
            "aop_validation": {"solvable": False}
        }
    )
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert controls["A.6.2.2"] is False

def test_generate_iso42001_soa_rtm_summary_false():
    res = generate_iso42001_soa(
        baseline={},
        rtm_summary={"compliant": False}
    )
    controls = {c["control_id"]: c["implemented"] for c in res["controls"]}
    assert controls["A.6.2.4"] is False
