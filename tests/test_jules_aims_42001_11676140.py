from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (REPO_ROOT / "src", REPO_ROOT):
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa
)


def test_validate_sod_value_valid():
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 10) == 10
    assert _validate_sod_value("test", 5) == 5

def test_validate_sod_value_invalid_types():
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", "1")
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", 5.0)
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", False)
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_sod_value("test", None)

def test_validate_sod_value_out_of_bounds():
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", -1)
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 11)


def test_compute_fmea_rpn_levels():
    # L0
    # rpn <= 40, s < 9
    res = compute_fmea_rpn(4, 5, 2) # rpn = 40
    assert res["risk_level"] == "L0"
    assert res["rpn"] == 40
    assert not res["action_required"]
    assert res["severity"] == 4

    # L1
    # rpn >= 41, rpn <= 100, s < 9
    res = compute_fmea_rpn(5, 5, 2) # rpn = 50
    assert res["risk_level"] == "L1"

    res = compute_fmea_rpn(1, 10, 5) # rpn = 50
    assert res["risk_level"] == "L1"

    res = compute_fmea_rpn(10, 2, 2) # rpn=40 but s=10 -> L4!
    assert res["risk_level"] == "L4"

    # L2
    # rpn >= 101, rpn <= 200, s < 9
    res = compute_fmea_rpn(5, 5, 5) # rpn = 125
    assert res["risk_level"] == "L2"
    assert res["action_required"]

    # L3
    # rpn >= 201, rpn <= 400, s < 9
    res = compute_fmea_rpn(8, 6, 5) # rpn = 240
    assert res["risk_level"] == "L3"

    res = compute_fmea_rpn(8, 10, 5) # rpn = 400
    assert res["risk_level"] == "L3"
    
    # L4 (rpn > 400)
    res = compute_fmea_rpn(7, 8, 8) # rpn = 448
    assert res["risk_level"] == "L4"

    # L4 (severity >= 9)
    res = compute_fmea_rpn(9, 1, 1) # rpn = 9
    assert res["risk_level"] == "L4"
    assert res["rpn"] == 9
    
    # Test boundary of required_controls
    assert "A.10.2: Strict Test-Designer / Build-Agent role isolation and Planarian rollback" in res["required_controls"]


def test_assess_failure_modes_empty():
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []


def test_assess_failure_modes_logic():
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 2, "detection": 2}, # rpn = 8 (L0)
        {"severity": 5, "occurrence": 5, "detection": 5}, # rpn = 125 (L2) - missing id/name
        {"id": "FM-99", "name": "Crit", "severity": 9, "occurrence": 1, "detection": 1}, # rpn = 9 (L4)
    ]
    res = assess_failure_modes(modes)
    
    # Should be sorted by rpn desc
    assert len(res["modes"]) == 3
    assert res["modes"][0]["rpn"] == 125
    assert res["modes"][1]["rpn"] == 9
    assert res["modes"][2]["rpn"] == 8
    
    assert res["modes"][1]["id"] == "FM-99"
    
    # default id/name for second item
    # Since it's the second in input array, idx=1, so f"FM-002"
    assert res["modes"][0]["id"] == "FM-002"
    assert res["modes"][0]["name"] == "Unnamed failure mode"
    
    assert res["max_rpn"] == 125
    assert abs(res["mean_rpn"] - (125 + 9 + 8) / 3.0) < 0.001
    assert res["overall_risk_level"] == "L4"
    assert "FM-002" in res["critical_modes"]
    assert "FM-99" in res["critical_modes"]
    assert "FM-01" not in res["critical_modes"]


def test_generate_iso42001_soa_default():
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert not res["all_controls_satisfied"]
    
def test_generate_iso42001_soa_fully_compliant():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    rtm_summary = {"compliant": True, "coverage_ratio": 1.0}
    fmea_summary = {"overall_risk_level": "L2"}
    
    res = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert res["all_controls_satisfied"] is True
    assert res["baseline_id"] == "BL-123"
    assert res["risk_level"] == "L2"

def test_generate_iso42001_soa_missing_hmac_seal():
    # For L2, needs 64-char seal
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 63, # too short
    }
    res = generate_iso42001_soa(baseline)
    assert res["all_controls_satisfied"] is False
    
    # A.9.3 is human oversight
    c = next(c for c in res["controls"] if c["control_id"] == "A.9.3")
    assert not c["implemented"]

def test_generate_iso42001_soa_l0_no_hmac_needed():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "", 
    }
    res = generate_iso42001_soa(baseline)
    assert res["all_controls_satisfied"] is True

def test_generate_iso42001_soa_fmea_l4():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
    }
    fmea = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline, fmea_summary=fmea)
    assert res["all_controls_satisfied"] is False
    c = next(c for c in res["controls"] if c["control_id"] == "A.8.3")
    assert not c["implemented"]

def test_generate_iso42001_soa_aop_failure():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
        "aop_validation": {"solvable": False, "completeness_covered": True}
    }
    res = generate_iso42001_soa(baseline)
    assert res["all_controls_satisfied"] is False
    c = next(c for c in res["controls"] if c["control_id"] == "A.6.2.2")
    assert not c["implemented"]

def test_generate_iso42001_soa_rtm_failure():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L0",
        "human_gate_1_approved": True,
    }
    rtm = {"compliant": False, "coverage_ratio": 0.5}
    res = generate_iso42001_soa(baseline, rtm_summary=rtm)
    assert res["all_controls_satisfied"] is False
    c = next(c for c in res["controls"] if c["control_id"] == "A.6.2.4")
    assert not c["implemented"]
