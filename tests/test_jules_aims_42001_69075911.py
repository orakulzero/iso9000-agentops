import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from iso9000_agentops.aims_42001 import (
    _validate_sod_value,
    compute_fmea_rpn,
    assess_failure_modes,
    generate_iso42001_soa,
    _CONTROLS_BY_TIER,
)

def test_validate_sod_value():
    assert _validate_sod_value("test", 1) == 1
    assert _validate_sod_value("test", 5) == 5
    assert _validate_sod_value("test", 10) == 10

    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", 1.5)

    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", True)

    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", "5")

    with pytest.raises(ValueError, match="must be an integer in"):
        _validate_sod_value("test", None)

    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 0)

    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", 11)

    with pytest.raises(ValueError, match="must be between 1 and 10"):
        _validate_sod_value("test", -5)

def test_compute_fmea_rpn_levels():
    # L4 based on severity >= 9
    res = compute_fmea_rpn(9, 1, 1)
    assert res["rpn"] == 9
    assert res["risk_level"] == "L4"
    assert res["action_required"] is True
    assert res["required_controls"] == _CONTROLS_BY_TIER["L4"]

    res = compute_fmea_rpn(10, 2, 2)
    assert res["risk_level"] == "L4"

    # L4 based on rpn > 400
    res = compute_fmea_rpn(8, 8, 8)
    assert res["rpn"] == 512
    assert res["risk_level"] == "L4"

    # L3 based on rpn >= 201
    res = compute_fmea_rpn(8, 6, 5)
    assert res["rpn"] == 240
    assert res["risk_level"] == "L3"
    assert res["action_required"] is True

    # L2 based on rpn >= 101
    res = compute_fmea_rpn(5, 5, 5)
    assert res["rpn"] == 125
    assert res["risk_level"] == "L2"
    assert res["action_required"] is True

    # L1 based on rpn >= 41
    res = compute_fmea_rpn(4, 4, 3)
    assert res["rpn"] == 48
    assert res["risk_level"] == "L1"
    assert res["action_required"] is False

    res = compute_fmea_rpn(8, 5, 1)
    assert res["rpn"] == 40
    assert res["risk_level"] == "L0"
    assert res["action_required"] is False

def test_compute_fmea_rpn_validation():
    with pytest.raises(ValueError):
        compute_fmea_rpn(11, 1, 1)
    with pytest.raises(ValueError):
        compute_fmea_rpn(5, 0, 5)
    with pytest.raises(ValueError):
        compute_fmea_rpn(5, 5, "5")

def test_assess_failure_modes_empty():
    res = assess_failure_modes([])
    assert res["modes"] == []
    assert res["max_rpn"] == 0
    assert res["mean_rpn"] == 0.0
    assert res["overall_risk_level"] == "L0"
    assert res["critical_modes"] == []

def test_assess_failure_modes():
    modes = [
        {"id": "FM-01", "name": "Mode 1", "severity": 4, "occurrence": 4, "detection": 3}, # RPN=48, L1
        {"id": "FM-02", "name": "Mode 2", "severity": 8, "occurrence": 6, "detection": 5}, # RPN=240, L3, critical
        {"severity": 9, "occurrence": 1, "detection": 1}, # RPN=9, L4, critical, default ID/name
    ]
    res = assess_failure_modes(modes)
    assert len(res["modes"]) == 3
    assert res["max_rpn"] == 240
    assert res["mean_rpn"] == (240 + 48 + 9) / 3.0
    assert res["overall_risk_level"] == "L4"
    assert set(res["critical_modes"]) == {"FM-02", "FM-003"}

    # Checking sorting (descending by RPN)
    assert res["modes"][0]["id"] == "FM-02"
    assert res["modes"][0]["rpn"] == 240
    assert res["modes"][1]["id"] == "FM-01"
    assert res["modes"][1]["rpn"] == 48
    assert res["modes"][2]["id"] == "FM-003"
    assert res["modes"][2]["rpn"] == 9
    assert res["modes"][2]["name"] == "Unnamed failure mode"

def test_generate_iso42001_soa_defaults():
    res = generate_iso42001_soa({})
    assert res["standard"] == "ISO/IEC 42001:2023"
    assert res["baseline_id"] == "BL-DEFAULT"
    assert res["risk_level"] == "L2"
    assert not res["all_controls_satisfied"]

    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.6.2.2"]["implemented"] is True
    assert controls["A.6.2.4"]["implemented"] is True  # default rtm_ok=True if None
    assert controls["A.8.3"]["implemented"] is True    # default fmea_ok=True if None (L0 != L4)
    assert controls["A.9.3"]["implemented"] is False   # L2 needs seal 64 chars

def test_generate_iso42001_soa_full_compliance():
    baseline = {
        "baseline_id": "BL-123",
        "risk_level": "L3",
        "human_gate_1_approved": True,
        "gate_seal_hmac": "a" * 64,
        "aop_validation": {"solvable": True, "completeness_covered": True},
    }
    fmea = {"overall_risk_level": "L3"}
    rtm = {"compliant": True, "coverage_ratio": 0.95}

    res = generate_iso42001_soa(baseline, fmea, rtm)
    assert res["all_controls_satisfied"] is True
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.9.3"]["implemented"] is True

def test_generate_iso42001_soa_various_failures():
    # fail AOP validation
    baseline1 = {
        "baseline_id": "BL-123",
        "aop_validation": {"solvable": False},
        "risk_level": "L1",
        "human_gate_1_approved": True, # L1 only needs approval, no seal
    }
    res = generate_iso42001_soa(baseline1)
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.6.2.2"]["implemented"] is False
    assert controls["A.9.3"]["implemented"] is True
    assert res["all_controls_satisfied"] is False

    # fail RTM
    baseline2 = {"human_gate_1_approved": True, "gate_seal_hmac": "a"*64, "risk_level": "L2"}
    rtm = {"compliant": False, "coverage_ratio": 0.5}
    res = generate_iso42001_soa(baseline2, rtm_summary=rtm)
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.6.2.4"]["implemented"] is False

    # fail FMEA
    fmea = {"overall_risk_level": "L4"}
    res = generate_iso42001_soa(baseline2, fmea_summary=fmea)
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.8.3"]["implemented"] is False

    # fail seal length for L2+
    baseline3 = {"human_gate_1_approved": True, "gate_seal_hmac": "short_seal", "risk_level": "L2"}
    res = generate_iso42001_soa(baseline3)
    controls = {c["control_id"]: c for c in res["controls"]}
    assert controls["A.9.3"]["implemented"] is False
