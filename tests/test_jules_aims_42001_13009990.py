"""Tests for ISO/IEC 42001:2023 AIMS and ISO 31000 FMEA Risk Engine (REQ-ISO-202)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

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
    for i in range(1, 11):
        assert _validate_sod_value("test", i) == i

def test_validate_sod_value_out_of_bounds() -> None:
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 11)

def test_validate_sod_value_invalid_types() -> None:
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", 5.5)
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", "5")
    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", None)

def test_compute_fmea_rpn_l0() -> None:
    # RPN <= 40
    res = compute_fmea_rpn(2, 4, 5) # 40
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert "A.6.2.2: AI system lifecycle documentation" in res["required_controls"]

def test_compute_fmea_rpn_l1() -> None:
    # 41 <= RPN <= 100
    res = compute_fmea_rpn(5, 3, 3) # 45
    assert res["rpn"] == 45
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False
    assert "A.6.2.4: AI system verification and validation specification" in res["required_controls"]

def test_compute_fmea_rpn_l2() -> None:
    # 101 <= RPN <= 200
    res = compute_fmea_rpn(5, 5, 5) # 125
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True
    assert "A.7.4: Data and W3C PROV-DM provenance quality" in res["required_controls"]

def test_compute_fmea_rpn_l3() -> None:
    # 201 <= RPN <= 400
    res = compute_fmea_rpn(8, 6, 5) # 240
    assert res["rpn"] == 240
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True
    assert "A.8.3: External reporting and OASIS SARIF 2.1.0 audit" in res["required_controls"]

def test_compute_fmea_rpn_l4_by_rpn() -> None:
    # RPN > 400
    res = compute_fmea_rpn(8, 8, 8) # 512
    assert res["rpn"] == 512
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    assert "A.10.2: Strict Test-Designer / Build-Agent role isolation and Planarian rollback" in res["required_controls"]

def test_compute_fmea_rpn_l4_by_severity() -> None:
    # Severity >= 9, even if RPN <= 400
    res = compute_fmea_rpn(9, 1, 1) # 9
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True

def test_assess_failure_modes_empty() -> None:
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes_various() -> None:
    modes = [
        {"id": "FM-A", "severity": 2, "occurrence": 2, "detection": 2}, # RPN 8, L0
        {"id": "FM-B", "severity": 9, "occurrence": 1, "detection": 1}, # RPN 9, L4
        {"severity": 5, "occurrence": 5, "detection": 5}, # No ID/Name, RPN 125, L2
    ]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 3
    # Sorted by RPN descending: 125 (L2), 9 (L4), 8 (L0)
    assert res["modes"][0]["rpn"] == 125
    assert res["modes"][1]["rpn"] == 9
    assert res["modes"][2]["rpn"] == 8
    
    assert res["modes"][0]["id"] == "FM-003" # Auto-generated ID for 3rd item (index 2 in original list, but sorted to index 0)
    assert res["modes"][0]["name"] == "Unnamed failure mode"
    
    assert res["max_rpn"] == 125
    assert abs(res["mean_rpn"] - (125+9+8)/3.0) < 1e-6
    assert res["overall_risk_level"] == "L4" # Because of FM-B
    assert "FM-B" in res["critical_modes"]
    assert "FM-003" in res["critical_modes"]
    assert "FM-A" not in res["critical_modes"]

def test_generate_iso42001_soa_defaults() -> None:
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert res["all_controls_satisfied"] is False # Because human oversight L2 requires gate1_approved and seal_len 64

def test_generate_iso42001_soa_all_satisfied_l2() -> None:
    baseline = {
        "baseline_id": "BL-CUSTOM",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    rtm = {"compliant": True, "coverage_ratio": 1.0}
    fmea = {"overall_risk_level": "L3"}
    res = generate_iso42001_soa(baseline, fmea, rtm)
    assert res["all_controls_satisfied"] is True
    assert res["baseline_id"] == "BL-CUSTOM"

def test_generate_iso42001_soa_l4_fmea_fail() -> None:
    baseline = {
        "baseline_id": "BL-CUSTOM",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    fmea = {"overall_risk_level": "L4"} # A.8.3 fail
    res = generate_iso42001_soa(baseline, fmea)
    assert res["all_controls_satisfied"] is False

def test_generate_iso42001_soa_l0_oversight_no_seal() -> None:
    # For L0 or L1, oversight is OK just if gate1_approved=True (seal not req)
    baseline = {
        "risk_level": "l0", # tests upper casing
        "human_gate_1_approved": True,
        "gate_seal_hmac": "", # Empty seal
    }
    res = generate_iso42001_soa(baseline)
    # A.8.3 and A.6.2.2 and A.6.2.4 defaults pass when args missing
    # But A.6.2.2 requires bool(baseline_id) which is True for default BL-DEFAULT
    # Wait, gate oversight should be OK
    # aop ok by default
    assert res["all_controls_satisfied"] is True

def test_generate_iso42001_soa_rtm_fail() -> None:
    baseline = {
        "baseline_id": "BL-CUSTOM",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    rtm = {"compliant": False, "coverage_ratio": 0.5} # Fail A.6.2.4
    res = generate_iso42001_soa(baseline, rtm_summary=rtm)
    assert res["all_controls_satisfied"] is False

def test_generate_iso42001_soa_aop_fail() -> None:
    baseline = {
        "baseline_id": "BL-CUSTOM",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": False, "completeness_covered": True},
    }
    res = generate_iso42001_soa(baseline)
    assert res["all_controls_satisfied"] is False
