from __future__ import annotations

import pytest
import sys
from pathlib import Path

# Add repo root and src/ to sys.path like sample test
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
    assert _validate_sod_value("severity", 1) == 1
    assert _validate_sod_value("severity", 5) == 5
    assert _validate_sod_value("severity", 10) == 10

def test_validate_sod_value_invalid_type():
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", "5")
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", 5.5)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", True)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("severity", None)

def test_validate_sod_value_out_of_bounds():
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", -1)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("severity", 11)


def test_compute_fmea_rpn_l0():
    result = compute_fmea_rpn(1, 1, 1)
    assert result["rpn"] == 1
    assert result["risk_level"] == "L0"
    assert result["action_required"] is False
    assert len(result["required_controls"]) == 1

def test_compute_fmea_rpn_l1():
    result = compute_fmea_rpn(4, 5, 2)
    assert result["rpn"] == 40
    assert result["risk_level"] == "L0"

    result = compute_fmea_rpn(4, 5, 3)
    assert result["rpn"] == 60
    assert result["risk_level"] == "L1"
    assert result["action_required"] is False
    assert len(result["required_controls"]) == 2

def test_compute_fmea_rpn_l2():
    result = compute_fmea_rpn(5, 5, 4)
    assert result["rpn"] == 100
    assert result["risk_level"] == "L1"

    result = compute_fmea_rpn(5, 5, 5)
    assert result["rpn"] == 125
    assert result["risk_level"] == "L2"
    assert result["action_required"] is True
    assert len(result["required_controls"]) == 4

def test_compute_fmea_rpn_l3():
    result = compute_fmea_rpn(5, 8, 5)
    assert result["rpn"] == 200
    assert result["risk_level"] == "L2"

    result = compute_fmea_rpn(7, 6, 5)
    assert result["rpn"] == 210
    assert result["risk_level"] == "L3"
    assert result["action_required"] is True
    assert len(result["required_controls"]) == 5

def test_compute_fmea_rpn_l4():
    result = compute_fmea_rpn(8, 10, 5)
    assert result["rpn"] == 400
    assert result["risk_level"] == "L3"

    result = compute_fmea_rpn(8, 10, 6)
    assert result["rpn"] == 480
    assert result["risk_level"] == "L4"
    assert result["action_required"] is True
    assert len(result["required_controls"]) == 6

def test_compute_fmea_rpn_severity_override_l4():
    # RPN is only 9 * 1 * 1 = 9, but severity is 9
    result = compute_fmea_rpn(9, 1, 1)
    assert result["rpn"] == 9
    assert result["risk_level"] == "L4"
    assert result["action_required"] is True

def test_assess_failure_modes_empty():
    result = assess_failure_modes([])
    assert result["modes"] == []
    assert result["max_rpn"] == 0
    assert result["mean_rpn"] == 0.0
    assert result["overall_risk_level"] == "L0"
    assert result["critical_modes"] == []

def test_assess_failure_modes_valid():
    modes = [
        {"id": "F1", "severity": 2, "occurrence": 2, "detection": 2},
        {"severity": 9, "occurrence": 1, "detection": 1},
        {"name": "Some mode", "severity": 5, "occurrence": 5, "detection": 5}
    ]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 3
    assert result["max_rpn"] == 125
    # mean = (8 + 9 + 125) / 3 = 142 / 3 = 47.333...
    assert pytest.approx(result["mean_rpn"]) == 47.333333333333336
    assert result["overall_risk_level"] == "L4"
    
    # Critical modes check: Mode 2 (sev=9) is L4 so action required, Mode 3 (rpn=125) is L2 so action required
    assert len(result["critical_modes"]) == 2
    
    assert result["modes"][0]["rpn"] == 125 # highest rpn first
    assert result["modes"][1]["rpn"] == 9
    assert result["modes"][2]["rpn"] == 8

def test_assess_failure_modes_default_values():
    modes = [{}]
    result = assess_failure_modes(modes)
    assert len(result["modes"]) == 1
    assert result["modes"][0]["rpn"] == 1
    assert result["modes"][0]["severity"] == 1
    assert result["modes"][0]["occurrence"] == 1
    assert result["modes"][0]["detection"] == 1
    assert result["modes"][0]["id"] == "FM-001"
    assert result["modes"][0]["name"] == "Unnamed failure mode"
    assert result["modes"][0]["risk_level"] == "L0"
    assert result["overall_risk_level"] == "L0"

def test_generate_iso42001_soa_default():
    result = generate_iso42001_soa({})
    assert result["standard"] == "ISO/IEC 42001:2023"
    assert result["baseline_id"] == "BL-DEFAULT"
    assert result["risk_level"] == "L2"
    assert result["all_controls_satisfied"] is False

    controls = result["controls"]
    assert len(controls) == 6
    assert controls[0]["implemented"] is True

    # rtm_ok = True by default.
    assert controls[1]["implemented"] is True

    # A.7.4 implemented = True
    assert controls[2]["implemented"] is True

    # fmea_ok = True by default since fmea_risk="L0"
    assert controls[3]["implemented"] is True

    # oversight_ok = False by default since risk_level="L2", gate1_approved=False
    assert controls[4]["implemented"] is False

    # A.10.2 implemented = True
    assert controls[5]["implemented"] is True


def test_generate_iso42001_soa_fully_compliant():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    fmea_summary = {"overall_risk_level": "L3"}
    rtm_summary = {"compliant": True, "coverage_ratio": 0.95}

    result = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert result["all_controls_satisfied"] is True
    assert all(c["implemented"] for c in result["controls"])

def test_generate_iso42001_soa_aop_failure():
    baseline = {
        "aop_validation": {"solvable": False}
    }
    result = generate_iso42001_soa(baseline)
    assert result["controls"][0]["implemented"] is False
    assert result["all_controls_satisfied"] is False

def test_generate_iso42001_soa_rtm_failure():
    rtm_summary = {"compliant": False}
    result = generate_iso42001_soa({}, rtm_summary=rtm_summary)
    assert result["controls"][1]["implemented"] is False

def test_generate_iso42001_soa_fmea_l4_failure():
    fmea_summary = {"overall_risk_level": "L4"}
    result = generate_iso42001_soa({}, fmea_summary=fmea_summary)
    assert result["controls"][3]["implemented"] is False

def test_generate_iso42001_soa_l1_oversight_ok():
    baseline = {
        "risk_level": "L1",
        "human_gate_1_approved": True,
        "gate_seal_hmac": ""
    }
    result = generate_iso42001_soa(baseline)
    # L1 only needs human_gate_1_approved=True
    assert result["controls"][4]["implemented"] is True

def test_generate_iso42001_soa_l2_oversight_fail():
    baseline = {
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short"
    }
    result = generate_iso42001_soa(baseline)
    # L2 needs 64 char seal
    assert result["controls"][4]["implemented"] is False
