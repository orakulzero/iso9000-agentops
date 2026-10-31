import pytest
import sys
from pathlib import Path
import dataclasses
from typing import Any

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
    for val in range(1, 11):
        assert _validate_sod_value("test", val) == val

def test_validate_sod_value_invalid_type() -> None:
    with pytest.raises(ValueError, match="must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", "5")
    with pytest.raises(ValueError, match="must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", 5.0)
    with pytest.raises(ValueError, match="must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", True)
    with pytest.raises(ValueError, match="must be an integer in \\[1, 10\\]"):
        _validate_sod_value("test", None)

def test_validate_sod_value_out_of_bounds() -> None:
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 0)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", 11)
    with pytest.raises(ValueError, match="must be between 1 and 10 inclusive"):
        _validate_sod_value("test", -1)

def test_compute_fmea_rpn_l0() -> None:
    # rpn <= 40 and severity < 9
    # e.g., 2 * 4 * 5 = 40
    res = compute_fmea_rpn(severity=2, occurrence=4, detection=5)
    assert res["severity"] == 2
    assert res["occurrence"] == 4
    assert res["detection"] == 5
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False
    assert res["required_controls"] == ["A.6.2.2: AI system lifecycle documentation"]

def test_compute_fmea_rpn_l1() -> None:
    # 41 <= rpn <= 100
    res = compute_fmea_rpn(severity=5, occurrence=3, detection=3)
    assert res["rpn"] == 45
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False
    assert "A.6.2.4: AI system verification and validation specification" in res["required_controls"]

def test_compute_fmea_rpn_l2() -> None:
    # 101 <= rpn <= 200
    res = compute_fmea_rpn(severity=5, occurrence=5, detection=5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True
    assert "A.7.4: Data and W3C PROV-DM provenance quality" in res["required_controls"]
    assert "A.9.3: Human oversight Gate 1 HMAC-SHA256 seal" in res["required_controls"]

def test_compute_fmea_rpn_l3() -> None:
    # 201 <= rpn <= 400
    res = compute_fmea_rpn(severity=8, occurrence=6, detection=5)
    assert res["rpn"] == 240
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True
    assert "A.8.3: External reporting and OASIS SARIF 2.1.0 audit" in res["required_controls"]

def test_compute_fmea_rpn_l4_by_rpn() -> None:
    # rpn > 400
    res = compute_fmea_rpn(severity=8, occurrence=8, detection=8)
    assert res["rpn"] == 512
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    assert "A.10.2: Strict Test-Designer / Build-Agent role isolation and Planarian rollback" in res["required_controls"]

def test_compute_fmea_rpn_l4_by_severity() -> None:
    # severity >= 9, even if rpn <= 400
    res = compute_fmea_rpn(severity=9, occurrence=1, detection=1)
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

def test_assess_failure_modes_multiple() -> None:
    modes = [
        {"id": "FM-01", "name": "Minor bug", "severity": 2, "occurrence": 2, "detection": 2}, # rpn 8, L0
        {"id": "FM-02", "name": "Major bug", "severity": 5, "occurrence": 5, "detection": 5}, # rpn 125, L2, critical
        {"id": "FM-03", "name": "Critical bug", "severity": 9, "occurrence": 2, "detection": 2}, # rpn 36, L4, critical
    ]
    res = assess_failure_modes(modes)
    
    assert len(res["modes"]) == 3
    # check sorting descending by rpn
    assert res["modes"][0]["id"] == "FM-02" # rpn 125
    assert res["modes"][1]["id"] == "FM-03" # rpn 36
    assert res["modes"][2]["id"] == "FM-01" # rpn 8

    assert res["max_rpn"] == 125
    assert res["mean_rpn"] == (125 + 36 + 8) / 3.0
    assert res["overall_risk_level"] == "L4"
    assert set(res["critical_modes"]) == {"FM-02", "FM-03"}

def test_assess_failure_modes_defaults() -> None:
    modes = [{}]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 1
    m = res["modes"][0]
    assert m["id"] == "FM-001"
    assert m["name"] == "Unnamed failure mode"
    assert m["severity"] == 1
    assert m["occurrence"] == 1
    assert m["detection"] == 1
    assert m["rpn"] == 1
    assert res["max_rpn"] == 1
    assert res["mean_rpn"] == 1.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_generate_iso42001_soa_defaults() -> None:
    baseline = {}
    res = generate_iso42001_soa(baseline)
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert res["all_controls_satisfied"] is False # gate_seal_hmac is missing for L2

def test_generate_iso42001_soa_all_satisfied() -> None:
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True}
    }
    fmea_summary = {"overall_risk_level": "L3"}
    rtm_summary = {"compliant": True, "coverage_ratio": 0.95}

    res = generate_iso42001_soa(baseline, fmea_summary, rtm_summary)
    assert res["all_controls_satisfied"] is True
    assert res["baseline_id"] == "BL-123"

def test_generate_iso42001_soa_fmea_l4() -> None:
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
    }
    fmea_summary = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline, fmea_summary)
    assert res["all_controls_satisfied"] is False
    
    # check that A.8.3 is not implemented
    for c in res["controls"]:
        if c["control_id"] == "A.8.3":
            assert c["implemented"] is False
            assert c["evidence"] == "ISO 31000 FMEA overall_risk_level=L4"

def test_generate_iso42001_soa_oversight_fails_l2() -> None:
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L2",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short" # not 64 chars
    }
    res = generate_iso42001_soa(baseline)
    assert res["all_controls_satisfied"] is False

    for c in res["controls"]:
        if c["control_id"] == "A.9.3":
            assert c["implemented"] is False

def test_generate_iso42001_soa_oversight_ok_l1() -> None:
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L1",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "short" # length doesn't matter for L1
    }
    res = generate_iso42001_soa(baseline)
    # A.9.3 should be implemented
    for c in res["controls"]:
        if c["control_id"] == "A.9.3":
            assert c["implemented"] is True
