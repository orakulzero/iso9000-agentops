"""Locked Agile V verification tests for Google Elephant-Goldfish Model (EGM) and Spec Drift Detector."""

from __future__ import annotations

from pathlib import Path
import pytest

from iso9000_agentops.egm_goldfish import (
    EGM_RUBRIC_STAGES,
    GoldfishReviewPacket,
    GoldfishZeroContextBuilder,
)
from iso9000_agentops.egm_drift_detector import (
    SpecCodeDriftDetector,
    SpecDriftReport,
)


SAMPLE_SPEC_MARKDOWN = """# Feature Overview & Architecture
## Goals
Deliver deterministic zero-context Goldfish review packets and AST drift auditing.
## System Architecture
High-level component flow separating Elephant planning from Goldfish review.

# Detailed Design & Implementation Plan
## Module Signatures
Implement `GoldfishZeroContextBuilder` and `SpecCodeDriftDetector` in `iso9000_agentops/egm_goldfish.py`.
## Verification Plan
Run pytest suite across all 4 rubric stages.
"""


def test_goldfish_semantic_boundaries_and_packet_builder() -> None:
    """Verify semantic boundary discovery and zero-context packet construction.

    @requirement("REQ-ISO-EGM-01")
    """
    assert EGM_RUBRIC_STAGES == (
        "zoom_out",
        "comprehension",
        "design_critic",
        "implementation_readiness",
    )

    builder = GoldfishZeroContextBuilder()
    boundaries = builder.discover_semantic_boundaries(SAMPLE_SPEC_MARKDOWN)
    assert "feature_range" in boundaries
    assert "detailed_range" in boundaries

    f_start, f_end = boundaries["feature_range"]
    d_start, d_end = boundaries["detailed_range"]
    assert 1 <= f_start <= f_end < d_start <= d_end

    chat_history = [
        {"role": "user", "content": "SECRET_ELEPHANT_CHAT_BIAS_98765"},
        {"role": "assistant", "content": "We agreed to skip validation earlier."},
    ]
    ref_files = {"iso9000_agentops/sample.py": "class Sample:\n    pass\n"}

    packets = builder.build_review_packets(
        spec_markdown=SAMPLE_SPEC_MARKDOWN,
        referenced_files=ref_files,
        conversation_history=chat_history,
    )
    assert len(packets) == 4
    assert tuple(p.stage for p in packets) == EGM_RUBRIC_STAGES

    for pkt in packets:
        assert isinstance(pkt, GoldfishReviewPacket)
        assert pkt.chat_history_stripped is True
        assert pkt.feature_range_lines == (f_start, f_end)
        assert pkt.detailed_range_lines == (d_start, d_end)
        assert pkt.referenced_files == ref_files
        assert len(pkt.rubric_checklist) >= 2
        assert "SECRET_ELEPHANT_CHAT_BIAS_98765" not in pkt.spec_markdown
        assert all("SECRET_ELEPHANT_CHAT_BIAS_98765" not in item for item in pkt.rubric_checklist)

    with pytest.raises(ValueError):
        builder.build_review_packets("   \n\t  ")


def test_goldfish_findings_deduplication_and_shootdown_gate() -> None:
    """Verify Goldfish shootdown deduplication, severity sorting, and approval gate.

    @requirement("REQ-ISO-EGM-01")
    """
    builder = GoldfishZeroContextBuilder()
    raw_findings = [
        {
            "stage": "design_critic",
            "target": "GoldfishZeroContextBuilder",
            "issue": "Missing empty spec guard",
            "severity": "major",
        },
        {
            "stage": "  DESIGN_CRITIC ",
            "target": "goldfishzerocontextbuilder",
            "issue": "missing empty spec guard",
            "severity": "major",
        },
        {
            "stage": "comprehension",
            "target": "Spec section 2",
            "issue": "Minor typo in heading",
            "severity": "minor",
        },
        {
            "stage": "zoom_out",
            "target": "Architecture",
            "issue": "Circular dependency with core bus",
            "severity": "critical",
        },
    ]

    summary = builder.synthesize_goldfish_findings(raw_findings)
    assert summary["total_unique_findings"] == 3
    assert summary["blocking_count"] == 2
    assert summary["approved_for_implementation"] is False
    severities = [item["severity"] for item in summary["findings"]]
    assert severities == ["critical", "major", "minor"]

    minor_only = builder.synthesize_goldfish_findings(
        [{"stage": "comprehension", "target": "Doc", "issue": "Nitpick", "severity": "minor"}]
    )
    assert minor_only["blocking_count"] == 0
    assert minor_only["approved_for_implementation"] is True


def test_spec_code_drift_detector_in_sync_and_out_of_sync(tmp_path: Path) -> None:
    """Verify AST-based Spec-to-Code drift detection for files, symbols, and signatures.

    @requirement("REQ-ISO-DRIFT-01")
    """
    pkg_dir = tmp_path / "iso9000_agentops"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    mod_file = pkg_dir / "engine_sample.py"
    mod_file.write_text(
        "class DriftEngine:\n"
        "    def evaluate_node(self, node_id: str, strict_mode: bool = True) -> bool:\n"
        "        return bool(node_id) and strict_mode\n\n"
        "def compute_metric(alpha: int, beta: int) -> int:\n"
        "    return alpha + beta\n",
        encoding="utf-8",
    )

    detector = SpecCodeDriftDetector()
    valid_spec = (
        "# Spec\n"
        "Implemented in `iso9000_agentops/engine_sample.py`.\n"
        "Provides `DriftEngine`, `evaluate_node(node_id, strict_mode)`, and `compute_metric(alpha, beta)`.\n"
    )
    ok_report = detector.audit_spec_against_repo(valid_spec, tmp_path)
    assert isinstance(ok_report, SpecDriftReport)
    assert ok_report.in_sync is True
    assert ok_report.missing_files == []
    assert ok_report.missing_symbols == []
    assert ok_report.signature_mismatches == []
    assert ok_report.checked_files_count >= 1
    assert ok_report.checked_symbols_count >= 3

    drifted_spec = (
        "# Drifted Spec\n"
        "Files: `iso9000_agentops/engine_sample.py` and `iso9000_agentops/missing_module.py`.\n"
        "Symbols: `DriftEngine`, `MissingValidator`, and `compute_metric(alpha, wrong_arg)`.\n"
    )
    bad_report = detector.audit_spec_against_repo(drifted_spec, tmp_path)
    assert bad_report.in_sync is False
    assert "iso9000_agentops/missing_module.py" in bad_report.missing_files
    assert "MissingValidator" in bad_report.missing_symbols
    assert any("compute_metric" in item for item in bad_report.signature_mismatches)
