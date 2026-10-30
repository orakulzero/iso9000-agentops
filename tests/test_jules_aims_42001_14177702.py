"""Tests for iso9000_agentops.aims_42001."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
    _CONTROLS_BY_TIER,
)

def test_validate_sod_value_valid() -> None:
    for i in range(1, 11):
        assert _validate_sod_value("test", i) == i

def test_validate_sod_value_invalid_types() -> None:
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", True)
    
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", False)

    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", "5")
        
    with pytest.raises(ValueError, match="test must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", 5.0)

def test_validate_sod_value_invalid_range() -> None:
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 0)
        
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 11)
        
    with pytest.raises(ValueError, match="test must be between 1 and 10 inclusive"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn() -> None:
    # L0
    res = compute_fmea_rpn(1, 1, 1)
    assert res["rpn"] == 1
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert res["required_controls"] == _CONTROLS_BY_TIER["L0"]
    
    res = compute_fmea_rpn(4, 5, 2)
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"

    # L1 (41 to 100)
    res = compute_fmea_rpn(4, 5, 3)
    assert res["rpn"] == 60
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False

    # L2 (101 to 200)
    res = compute_fmea_rpn(5, 5, 5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True

    # L3 (201 to 400)
    res = compute_fmea_rpn(8, 8, 4)
    assert res["rpn"] == 256
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True
    
    res = compute_fmea_rpn(7, 7, 7)
    assert res["rpn"] == 343
    assert res["risk_level"] == "L3"

    # L4 (rpn > 400 or severity >= 9)
    res = compute_fmea_rpn(8, 8, 8)
    assert res["rpn"] == 512
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    
    # Severity >= 9 check
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"

    res = compute_fmea_rpn(10, 2, 2)
    assert res["rpn"] == 40
    assert res["risk_level"] == "L4"


def test_assess_failure_modes_empty() -> None:
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes() -> None:
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 2, "occurrence": 2, "detection": 2}, # rpn=8, L0
        {"id": "FM-02", "name": "Mode 2", "severity": 9, "occurrence": 1, "detection": 1}, # rpn=9, L4, action required
        {"id": "FM-03", "name": "Mode 3", "severity": 5, "occurrence": 5, "detection": 5}, # rpn=125, L2, action required
        {"severity": 3, "occurrence": 4, "detection": 4} # rpn=48, L1. Default id="FM-004", name="Unnamed failure mode"
    ]
    
    res = assess_failure_modes(modes)
    assert res["max_rpn"] == 125
    assert res["mean_rpn"] == (8 + 9 + 125 + 48) / 4.0
    assert res["overall_risk_level"] == "L4"
    assert set(res["critical_modes"]) == {"FM-02", "FM-03"}
    
    assert len(res["modes"]) == 4
    # Sorting descending by rpn: FM-03 (125), FM-004 (48), FM-02 (9), FM-01 (8)
    assert res["modes"][0]["id"] == "FM-03"
    assert res["modes"][1]["id"] == "FM-004"
    assert res["modes"][1]["name"] == "Unnamed failure mode"
    assert res["modes"][2]["id"] == "FM-02"
    assert res["modes"][3]["id"] == "FM-01"


def test_generate_iso42001_soa_defaults() -> None:
    res = generate_iso42001_soa({})
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert res["all_controls_satisfied"] is False
    
    # A.6.2.2 (implemented: baseline_id and aop_ok) -> True (default aop_ok is True)
    # A.6.2.4 (implemented: rtm_ok) -> True (default rtm_summary=None)
    # A.7.4 (implemented: True) -> True
    # A.8.3 (implemented: fmea_ok) -> True (default fmea_risk="L0")
    # A.9.3 (implemented: oversight_ok) -> False (L2 requires gate1_approved=True and gate_seal len=64, here gate1_approved=False)
    # A.10.2 (implemented: True) -> True
    
    implemented = [c["implemented"] for c in res["controls"]]
    assert implemented == [True, True, True, True, False, True]


def test_generate_iso42001_soa_fmea_ok() -> None:
    res = generate_iso42001_soa({}, fmea_summary={"overall_risk_level": "L4"})
    # A.8.3 should be false
    assert res["controls"][3]["implemented"] is False


def test_generate_iso42001_soa_oversight() -> None:
    # L0/L1 only needs gate1_approved
    res = generate_iso42001_soa({"risk_level": "L1", "human_gate_1_approved": True})
    assert res["controls"][4]["implemented"] is True
    
    # L2+ needs gate_seal length 64
    res = generate_iso42001_soa({"risk_level": "L2", "human_gate_1_approved": True, "gate_seal_hmac": "a" * 64})
    assert res["controls"][4]["implemented"] is True
    
    res = generate_iso42001_soa({"risk_level": "L2", "human_gate_1_approved": True, "gate_seal_hmac": "short"})
    assert res["controls"][4]["implemented"] is False


def test_generate_iso42001_soa_aop_rtm() -> None:
    # aop not solvable
    res = generate_iso42001_soa({"aop_validation": {"solvable": False}})
    assert res["controls"][0]["implemented"] is False
    
    # rtm compliant = False
    res = generate_iso42001_soa({}, rtm_summary={"compliant": False})
    assert res["controls"][1]["implemented"] is False

def test_generate_iso42001_soa_all_satisfied() -> None:
    res = generate_iso42001_soa(
        baseline={
            "baseline_id": "BL-TEST",
            "risk_level": "L2",
            "human_gate_1_approved": True,
            "gate_seal_hmac": "a" * 64,
            "aop_validation": {"solvable": True, "completeness_covered": True}
        },
        fmea_summary={"overall_risk_level": "L2"},
        rtm_summary={"compliant": True, "coverage_ratio": 1.0}
    )
    assert res["all_controls_satisfied"] is True
