"""Cryptographic Quality Certificate, SVG Badge & OASIS SARIF 2.1.0 Exporter (REQ-ISO-203).

Issues and verifies HMAC-SHA256 signed ISO 9001:2015 / ISO/IEC 42001:2023 /
Agile V quality certificates, renders shields.io-compatible SVG compliance
badges, and exports OASIS SARIF 2.1.0 static analysis reports.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
from typing import Any

_REQUIRED_CERT_FIELDS: tuple[str, ...] = (
    "status",
    "standards",
    "baseline_id",
    "version",
    "rtm_coverage",
    "max_rpn",
    "merkle_root",
    "gate1_hmac",
    "tests_passed",
    "tests_total",
)


def _compute_certificate_hmac(unsigned_cert: dict[str, Any], secret: str) -> str:
    """Compute canonical HMAC-SHA256 over all certificate fields except certificate_signature (REQ-ISO-203)."""
    filtered = {
        k: v for k, v in unsigned_cert.items() if k != "certificate_signature"
    }
    canonical = json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def issue_quality_certificate(
    baseline_id: str,
    version: str,
    rtm_report: dict[str, Any],
    fmea_report: dict[str, Any],
    merkle_root: str,
    gate1_hmac: str,
    tests_passed: int,
    tests_total: int,
    secret: str = "default-iso9000-cert-secret",
) -> dict[str, Any]:
    """Issue a cryptographically signed ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V quality certificate (REQ-ISO-203)."""
    rtm_compliant = bool(rtm_report.get("compliant", False))
    rtm_coverage = float(rtm_report.get("coverage_ratio", 0.0))
    max_rpn = int(fmea_report.get("max_rpn", 0))
    overall_risk = str(fmea_report.get("overall_risk_level", "L0")).upper()

    valid_merkle = isinstance(merkle_root, str) and len(merkle_root) == 64
    valid_gate1 = isinstance(gate1_hmac, str) and len(gate1_hmac) == 64
    passed_int = int(tests_passed)
    total_int = int(tests_total)
    tests_ok = total_int > 0 and passed_int == total_int
    fmea_ok = overall_risk != "L4" and max_rpn <= 400

    if rtm_compliant and valid_merkle and valid_gate1 and tests_ok and fmea_ok:
        status = "CERTIFIED"
    else:
        status = "NON_CONFORMANT"

    cert: dict[str, Any] = {
        "certificate_id": f"CERT-{baseline_id}-{version}",
        "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "standards": [
            "ISO 9001:2015",
            "ISO/IEC 42001:2023",
            "Agile V (arXiv:2602.20684)",
        ],
        "baseline_id": str(baseline_id),
        "version": str(version),
        "rtm_compliant": rtm_compliant,
        "rtm_coverage": rtm_coverage,
        "max_rpn": max_rpn,
        "overall_risk_level": overall_risk,
        "merkle_root": str(merkle_root),
        "gate1_hmac": str(gate1_hmac),
        "tests_passed": passed_int,
        "tests_total": total_int,
    }
    cert["certificate_signature"] = _compute_certificate_hmac(cert, secret)
    return cert


def verify_quality_certificate(
    certificate: dict[str, Any],
    secret: str = "default-iso9000-cert-secret",
) -> bool:
    """Verify the HMAC-SHA256 signature and structural integrity of a quality certificate (REQ-ISO-203)."""
    if not isinstance(certificate, dict):
        return False
    for req_field in _REQUIRED_CERT_FIELDS:
        if req_field not in certificate:
            return False
    sig = certificate.get("certificate_signature")
    if not isinstance(sig, str) or len(sig) != 64:
        return False
    expected = _compute_certificate_hmac(certificate, secret)
    return hmac.compare_digest(sig, expected)


def render_compliance_badge_svg(certificate: dict[str, Any]) -> str:
    """Render a standalone SVG compliance badge for README or CI artifacts (REQ-ISO-203)."""
    status = str(certificate.get("status") or "NON_CONFORMANT").upper()
    version = str(certificate.get("version") or "2.0.0")
    is_certified = status == "CERTIFIED"
    color = "#2ea44f" if is_certified else "#d73a49"
    label = "ISO 9001 | 42001 | Agile V"
    right_text = f"v{version} {status}"

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="310" height="20" role="img" '
        f'aria-label="{label}: {right_text}">\n'
        f"  <title>{label}: {right_text}</title>\n"
        '  <rect width="175" height="20" fill="#555"/>\n'
        f'  <rect x="175" width="135" height="20" fill="{color}"/>\n'
        '  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">\n'
        f'    <text x="87.5" y="14">{label}</text>\n'
        f'    <text x="242.5" y="14">{right_text}</text>\n'
        "  </g>\n"
        "</svg>"
    )


def export_sarif_report(
    rtm_report: dict[str, Any],
    fmea_report: dict[str, Any],
    oss_audit_report: dict[str, Any] | None = None,
    tool_version: str = "2.0.0",
) -> dict[str, Any]:
    """Export an OASIS SARIF 2.1.0 report covering RTM, FMEA, and 5-Gate OSS Audit findings (REQ-ISO-203)."""
    rules: list[dict[str, Any]] = [
        {
            "id": "ISO9001-RTM-ORPHAN",
            "name": "OrphanRequirement",
            "shortDescription": {"text": "Requirement lacks verification test coverage."},
        },
        {
            "id": "ISO9001-RTM-UNIMPL",
            "name": "UnimplementedRequirement",
            "shortDescription": {"text": "Requirement lacks production code implementation."},
        },
        {
            "id": "ISO9001-RTM-GOLDPLATE",
            "name": "GoldPlatedSymbol",
            "shortDescription": {"text": "Public code symbol is not linked to any requirement."},
        },
        {
            "id": "ISO42001-FMEA-CRIT",
            "name": "CriticalFailureMode",
            "shortDescription": {"text": "Failure mode exceeds ISO 31000 / 42001 RPN or severity threshold."},
        },
        {
            "id": "ISO9001-OSS-AUDIT",
            "name": "OssReleaseGateViolation",
            "shortDescription": {"text": "Repository violates ISO 9001:2015 open-source release gate."},
        },
    ]

    results: list[dict[str, Any]] = []

    for req_id in rtm_report.get("orphan_requirements") or []:
        results.append(
            {
                "ruleId": "ISO9001-RTM-ORPHAN",
                "level": "error",
                "message": {
                    "text": f"Orphan requirement {req_id} has no verification test link."
                },
            }
        )

    for req_id in rtm_report.get("unimplemented_requirements") or []:
        results.append(
            {
                "ruleId": "ISO9001-RTM-UNIMPL",
                "level": "error",
                "message": {
                    "text": f"Unimplemented requirement {req_id} has no code symbol link."
                },
            }
        )

    for sym in rtm_report.get("gold_plated_symbols") or []:
        results.append(
            {
                "ruleId": "ISO9001-RTM-GOLDPLATE",
                "level": "warning",
                "message": {
                    "text": f"Gold-plated public symbol '{sym}' is not traced to any requirement."
                },
            }
        )

    critical_set = set(fmea_report.get("critical_modes") or [])
    emitted_fmea_ids: set[str] = set()
    for mode in fmea_report.get("modes") or []:
        if not isinstance(mode, dict):
            continue
        mid = str(mode.get("id") or "")
        if mode.get("action_required") or mid in critical_set:
            emitted_fmea_ids.add(mid)
            results.append(
                {
                    "ruleId": "ISO42001-FMEA-CRIT",
                    "level": "error",
                    "message": {
                        "text": f"Critical FMEA failure mode {mid} ({mode.get('name', '')}) with RPN={mode.get('rpn')} ({mode.get('risk_level')})."
                    },
                }
            )
    for mid in critical_set - emitted_fmea_ids:
        results.append(
            {
                "ruleId": "ISO42001-FMEA-CRIT",
                "level": "error",
                "message": {"text": f"Critical FMEA failure mode {mid} requires mitigation."},
            }
        )

    if oss_audit_report is not None and not oss_audit_report.get("passed", True):
        oss_items: list[str] = []
        for err in oss_audit_report.get("errors") or []:
            oss_items.append(str(err))
        for cyr in oss_audit_report.get("cyrillic_violations") or []:
            oss_items.append(f"Cyrillic violation in {cyr}")
        if not oss_items:
            oss_items.append("Repository failed 5-Gate OSS Release Audit.")
        for msg in oss_items:
            results.append(
                {
                    "ruleId": "ISO9001-OSS-AUDIT",
                    "level": "error",
                    "message": {"text": msg},
                }
            )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iso9000-agentops",
                        "version": str(tool_version),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
