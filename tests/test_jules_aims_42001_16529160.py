import sys
from pathlib import Path

# Add the repository root to sys.path so we can import iso9000_agentops
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
)

def test_validate_sod_value_valid():
    assert _validate_sod_value("severity", 1) == 1
    assert _validate_sod_value("occurrence", 5) == 5
    assert _validate_sod_value("detection", 10) == 10

def test_validate_sod_value_invalid_types():
    with pytest.raises(ValueError, match="severity must be an integer"):
        _validate_sod_value("severity", "5")
    with pytest.raises(ValueError, match="occurrence must be an integer"):
        _validate_sod_value("occurrence", 5.0)
    with pytest.raises(ValueError, match="detection must be an integer"):
        _validate_sod_value("detection", True)

def test_validate_sod_value_out_of_bounds():
    with pytest.raises(ValueError, match="severity must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", 0)
    with pytest.raises(ValueError, match="occurrence must be between 1 and 10 inclusive"):
        _validate_sod_value("occurrence", 11)
    with pytest.raises(ValueError, match="detection must be between 1 and 10 inclusive"):
        _validate_sod_value("detection", -5)

def test_compute_fmea_rpn():
    # Test L4 (s >= 9)
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True

    # Test L4 (rpn > 400)
    res = compute_fmea_rpn(8, 8, 7)
    assert res["rpn"] == 448
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True

    # Test L3 (201 <= rpn <= 400)
    res = compute_fmea_rpn(8, 5, 6)
    assert res["rpn"] == 240
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True

    # Test L2 (101 <= rpn <= 200)
    res = compute_fmea_rpn(5, 5, 5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True

    # Test L1 (41 <= rpn <= 100)
    res = compute_fmea_rpn(4, 3, 4)
    assert res["rpn"] == 48
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False

    # Test L0 (rpn <= 40)
    res = compute_fmea_rpn(2, 2, 2)
    assert res["rpn"] == 8
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert "A.6.2.2: AI system lifecycle documentation" in res["required_controls"]

def test_assess_failure_modes_empty():
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes_multiple():
    modes = [
        {"id": "FM-001", "name": "Minor bug", "severity": 2, "occurrence": 2, "detection": 2}, # RPN = 8 (L0)
        {"id": "FM-002", "name": "Major failure", "severity": 5, "occurrence": 5, "detection": 5}, # RPN = 125 (L2)
        {"id": "FM-003", "name": "Critical failure", "severity": 9, "occurrence": 2, "detection": 2}, # RPN = 36 (L4 due to s=9)
    ]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 3
    # Sorted by RPN descending (125, 36, 8)
    assert res["modes"][0]["id"] == "FM-002"
    assert res["modes"][1]["id"] == "FM-003"
    assert res["modes"][2]["id"] == "FM-001"
    assert res["max_rpn"] == 125
    assert res["mean_rpn"] == (125 + 36 + 8) / 3.0
    assert res["overall_risk_level"] == "L4"
    assert set(res["critical_modes"]) == {"FM-002", "FM-003"}

def test_assess_failure_modes_defaults():
    # Test missing fields to ensure defaults apply
    res = assess_failure_modes([{}])
    assert len(res["modes"]) == 1
    assert res["modes"][0]["id"] == "FM-001"
    assert res["modes"][0]["name"] == "Unnamed failure mode"
    assert res["modes"][0]["severity"] == 1
    assert res["modes"][0]["occurrence"] == 1
    assert res["modes"][0]["detection"] == 1
    assert res["max_rpn"] == 1
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_generate_iso42001_soa_defaults():
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert res["all_controls_satisfied"] is False

    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.6.2.2"]["implemented"] is True
    assert controls["A.6.2.4"]["implemented"] is True
    assert controls["A.7.4"]["implemented"] is True
    assert controls["A.8.3"]["implemented"] is True
    assert controls["A.9.3"]["implemented"] is False  # oversight_ok is False
    assert controls["A.10.2"]["implemented"] is True

def test_generate_iso42001_soa_all_satisfied():
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    fmea_summary = {"overall_risk_level": "L2"}
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}

    res = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert res["all_controls_satisfied"] is True
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.9.3"]["implemented"] is True
    assert controls["A.6.2.2"]["implemented"] is True
    assert controls["A.6.2.4"]["implemented"] is True

def test_generate_iso42001_soa_fmea_fail():
    baseline = {
        "baseline_id": "BL-001",
        "risk_level": "L4",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    fmea_summary = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline, fmea_summary)
    assert res["all_controls_satisfied"] is False
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.8.3"]["implemented"] is False

def test_generate_iso42001_soa_oversight_logic():
    # If L0/L1, gate1_approved is enough
    baseline_l1 = {
        "risk_level": "L1",
        "human_gate_1_approved": True,
    }
    res_l1 = generate_iso42001_soa(baseline_l1)
    controls_l1 = {c["control_id"]: c for c in res_l1["controls"]}
    assert controls_l1["A.9.3"]["implemented"] is True

    # If L2+, gate_seal_hmac must be len 64
    baseline_l2_fail = {
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short",
    }
    res_l2_fail = generate_iso42001_soa(baseline_l2_fail)
    controls_l2_fail = {c["control_id"]: c for c in res_l2_fail["controls"]}
    assert controls_l2_fail["A.9.3"]["implemented"] is False

    baseline_l2_pass = {
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "b" * 64,
    }
    res_l2_pass = generate_iso42001_soa(baseline_l2_pass)
    controls_l2_pass = {c["control_id"]: c for c in res_l2_pass["controls"]}
    assert controls_l2_pass["A.9.3"]["implemented"] is True
