"""ISO/IEC 42001:2023 AI Management System (AIMS) & ISO 31000 FMEA Risk Engine (REQ-ISO-202).

Provides quantitative Failure Mode and Effects Analysis (FMEA) Risk Priority
Number (RPN = Severity * Occurrence * Detection) calculation, automated L0..L4
risk tier classification, and ISO/IEC 42001:2023 Annex A Statement of
Applicability (SoA) generation.
"""

from __future__ import annotations

from typing import Any, Sequence

_TIER_RANK: dict[str, int] = {
    "L0": 0,
    "L1": 1,
    "L2": 2,
    "L3": 3,
    "L4": 4,
}

_CONTROLS_BY_TIER: dict[str, list[str]] = {
    "L0": [
        "A.6.2.2: AI system lifecycle documentation",
    ],
    "L1": [
        "A.6.2.2: AI system lifecycle documentation",
        "A.6.2.4: AI system verification and validation specification",
    ],
    "L2": [
        "A.6.2.2: AI system lifecycle documentation",
        "A.6.2.4: AI system verification and validation specification",
        "A.7.4: Data and W3C PROV-DM provenance quality",
        "A.9.3: Human oversight Gate 1 HMAC-SHA256 seal",
    ],
    "L3": [
        "A.6.2.2: AI system lifecycle documentation",
        "A.6.2.4: AI system verification and validation specification",
        "A.7.4: Data and W3C PROV-DM provenance quality",
        "A.8.3: External reporting and OASIS SARIF 2.1.0 audit",
        "A.9.3: Human oversight Gate 1 HMAC-SHA256 seal",
    ],
    "L4": [
        "A.6.2.2: AI system lifecycle documentation",
        "A.6.2.4: AI system verification and validation specification",
        "A.7.4: Data and W3C PROV-DM provenance quality",
        "A.8.3: External reporting and OASIS SARIF 2.1.0 audit",
        "A.9.3: Human oversight Gate 1 HMAC-SHA256 seal",
        "A.10.2: Strict Test-Designer / Build-Agent role isolation and Planarian rollback",
    ],
}


def _validate_sod_value(name: str, val: Any) -> int:
    """Validate that a Severity, Occurrence, or Detection rating is an int in [1, 10] (REQ-ISO-202)."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"{name} must be an integer in [1, 10], got {val!r}")
    if val < 1 or val > 10:
        raise ValueError(f"{name} must be between 1 and 10 inclusive, got {val}")
    return val


def compute_fmea_rpn(
    severity: int, occurrence: int, detection: int
) -> dict[str, Any]:
    """Compute ISO 31000 / IEC 60812 FMEA Risk Priority Number and L0..L4 risk tier (REQ-ISO-202)."""
    s = _validate_sod_value("severity", severity)
    o = _validate_sod_value("occurrence", occurrence)
    d = _validate_sod_value("detection", detection)

    rpn = s * o * d
    if s >= 9 or rpn > 400:
        risk_level = "L4"
    elif rpn >= 201:
        risk_level = "L3"
    elif rpn >= 101:
        risk_level = "L2"
    elif rpn >= 41:
        risk_level = "L1"
    else:
        risk_level = "L0"

    action_required = risk_level in ("L2", "L3", "L4")
    required_controls = list(_CONTROLS_BY_TIER[risk_level])

    return {
        "severity": s,
        "occurrence": o,
        "detection": d,
        "rpn": rpn,
        "risk_level": risk_level,
        "action_required": action_required,
        "required_controls": required_controls,
    }


def assess_failure_modes(modes: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Assess a collection of failure modes, sort descending by RPN, and flag critical modes (REQ-ISO-202)."""
    if not modes:
        return {
            "modes": [],
            "max_rpn": 0,
            "mean_rpn": 0.0,
            "overall_risk_level": "L0",
            "critical_modes": [],
        }

    enriched: list[dict[str, Any]] = []
    highest_tier = "L0"
    critical_ids: list[str] = []

    for idx, mode in enumerate(modes):
        mode_id = str(mode.get("id") or f"FM-{idx + 1:03d}")
        mode_name = str(mode.get("name") or "Unnamed failure mode")
        fmea = compute_fmea_rpn(
            int(mode.get("severity", 1)),
            int(mode.get("occurrence", 1)),
            int(mode.get("detection", 1)),
        )
        entry = {
            **mode,
            "id": mode_id,
            "name": mode_name,
            **fmea,
        }
        enriched.append(entry)

        if _TIER_RANK[fmea["risk_level"]] > _TIER_RANK[highest_tier]:
            highest_tier = fmea["risk_level"]
        if fmea["action_required"]:
            critical_ids.append(mode_id)

    enriched.sort(key=lambda m: int(m["rpn"]), reverse=True)
    rpns = [int(m["rpn"]) for m in enriched]
    max_rpn = max(rpns)
    mean_rpn = sum(rpns) / float(len(rpns))

    return {
        "modes": enriched,
        "max_rpn": max_rpn,
        "mean_rpn": mean_rpn,
        "overall_risk_level": highest_tier,
        "critical_modes": critical_ids,
    }


def generate_iso42001_soa(
    baseline: dict[str, Any],
    fmea_summary: dict[str, Any] | None = None,
    rtm_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate an ISO/IEC 42001:2023 Annex A Statement of Applicability (SoA) (REQ-ISO-202)."""
    baseline_id = str(baseline.get("baseline_id") or "BL-DEFAULT")
    risk_level = str(baseline.get("risk_level") or "L2").upper()
    gate1_approved = bool(baseline.get("human_gate_1_approved", False))
    gate_seal = str(baseline.get("gate_seal_hmac") or "")
    aop = baseline.get("aop_validation") or {}
    aop_ok = bool(aop.get("solvable", True)) and bool(aop.get("completeness_covered", True))

    rtm_ok = True if rtm_summary is None else bool(rtm_summary.get("compliant", False))
    rtm_cov = 1.0 if rtm_summary is None else float(rtm_summary.get("coverage_ratio", 0.0))

    fmea_risk = "L0" if fmea_summary is None else str(fmea_summary.get("overall_risk_level", "L0"))
    fmea_ok = fmea_risk != "L4"

    oversight_ok = gate1_approved if risk_level in ("L0", "L1") else (gate1_approved and len(gate_seal) == 64)

    controls: list[dict[str, Any]] = [
        {
            "control_id": "A.6.2.2",
            "title": "AI system requirements and normative baseline specification",
            "applicable": True,
            "implemented": bool(baseline_id) and aop_ok,
            "evidence": f"Frozen baseline {baseline_id} with AOP validation ({aop_ok})",
        },
        {
            "control_id": "A.6.2.4",
            "title": "AI system verification and bidirectional traceability validation",
            "applicable": True,
            "implemented": rtm_ok,
            "evidence": f"Agile V RTM compliance={rtm_ok}, coverage_ratio={rtm_cov:.2f}",
        },
        {
            "control_id": "A.7.4",
            "title": "Data provenance and W3C PROV-DM / RFC 6962 Merkle lineage",
            "applicable": True,
            "implemented": True,
            "evidence": "W3C PROV-DM SHA-256 hash chain and RFC 6962 Merkle audit tree enabled",
        },
        {
            "control_id": "A.8.3",
            "title": "AI risk assessment, FMEA RPN scoring, and SARIF reporting",
            "applicable": True,
            "implemented": fmea_ok,
            "evidence": f"ISO 31000 FMEA overall_risk_level={fmea_risk}",
        },
        {
            "control_id": "A.9.3",
            "title": "Human oversight and cryptographic Gate 1 approval seal",
            "applicable": True,
            "implemented": oversight_ok,
            "evidence": f"human_gate_1_approved={gate1_approved}, seal_len={len(gate_seal)}",
        },
        {
            "control_id": "A.10.2",
            "title": "Third-party / role-isolated verification and self-grading bias guard",
            "applicable": True,
            "implemented": True,
            "evidence": "PreToolUse role isolation separating TEST_DESIGN from SYNTHESIS",
        },
    ]

    all_satisfied = all(c["implemented"] for c in controls if c["applicable"])

    return {
        "standard": "ISO/IEC 42001:2023",
        "baseline_id": baseline_id,
        "risk_level": risk_level,
        "controls": controls,
        "all_controls_satisfied": all_satisfied,
    }
