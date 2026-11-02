"""Locked Agile V (P30) Verification Suite for Flaky Test Bifurcator & Non-Determinism Quarantine.

Requirement Traceability:
- REQ-ISO-FLAKY-01: Flaky Test Bifurcator & Non-Determinism Quarantine (`flaky_test_bifurcator.py`)

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V Role Separation.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from iso9000_agentops.flaky_test_bifurcator import (  # noqa: E402
    FlakyClassification,
    FlakyTestBifurcator,
)


def test_deterministic_failure_classified_as_code_regression() -> None:
    """REQ-ISO-FLAKY-01: Verify consistent failures across reruns are classified as DETERMINISTIC_REGRESSION."""
    bif = FlakyTestBifurcator()
    cls = bif.classify_test_runs(
        node_id="tests/test_core.py::test_math",
        exit_codes=[1, 1, 1],
        output_logs=["AssertionError: 2 != 3"] * 3,
    )
    assert isinstance(cls, FlakyClassification)
    assert cls.node_id == "tests/test_core.py::test_math"
    assert cls.classification == "DETERMINISTIC_REGRESSION"
    assert cls.is_flaky is False
    assert cls.allow_self_healing_code_patch is True


def test_mixed_pass_fail_bifurcation_classified_as_flaky_quarantine() -> None:
    """REQ-ISO-FLAKY-01: Verify mixed pass/fail outcomes across reruns are classified as FLAKY_NON_DETERMINISTIC."""
    bif = FlakyTestBifurcator()
    cls = bif.classify_test_runs(
        node_id="tests/test_network.py::test_webhook",
        exit_codes=[1, 0, 0],
        output_logs=["AssertionError: timing drift", "1 passed", "1 passed"],
    )
    assert isinstance(cls, FlakyClassification)
    assert cls.classification == "FLAKY_NON_DETERMINISTIC"
    assert cls.is_flaky is True
    assert cls.allow_self_healing_code_patch is False


def test_transient_environment_signature_detected_in_log() -> None:
    """REQ-ISO-FLAKY-01: Verify transient OS/socket signatures set transient_env_signature and RETRY_ISOLATED_SANDBOX."""
    bif = FlakyTestBifurcator()
    for signature in ("Address already in use", "ConnectionResetError", "TimedOut"):
        cls = bif.classify_test_runs(
            node_id="tests/test_server.py::test_bind",
            exit_codes=[1, 1],
            output_logs=[f"OSError: {signature}", f"OSError: {signature}"],
        )
        assert cls.transient_env_signature is True
        assert cls.recommended_action == "RETRY_ISOLATED_SANDBOX"
        assert cls.allow_self_healing_code_patch is False


def test_all_passing_runs_classified_as_healthy() -> None:
    """REQ-ISO-FLAKY-01: Verify all-zero exit codes classify test run as HEALTHY."""
    bif = FlakyTestBifurcator()
    cls = bif.classify_test_runs(
        node_id="tests/test_core.py::test_ok",
        exit_codes=[0, 0],
        output_logs=["1 passed", "1 passed"],
    )
    assert cls.classification == "HEALTHY"
    assert cls.is_flaky is False
    assert cls.allow_self_healing_code_patch is False


def test_quarantine_registry_tracks_flaky_node_ids() -> None:
    """REQ-ISO-FLAKY-01: Verify quarantine registry records only flaky node_ids."""
    bif = FlakyTestBifurcator()
    cls_flaky = bif.classify_test_runs(
        node_id="tests/test_flaky.py::test_race",
        exit_codes=[1, 0, 0],
        output_logs=["fail", "pass", "pass"],
    )
    cls_det = bif.classify_test_runs(
        node_id="tests/test_det.py::test_bug",
        exit_codes=[1, 1, 1],
        output_logs=["AssertionError"] * 3,
    )
    bif.record_classification(cls_flaky)
    bif.record_classification(cls_det)

    quarantined = bif.get_quarantined_tests()
    assert "tests/test_flaky.py::test_race" in quarantined
    assert "tests/test_det.py::test_bug" not in quarantined


def test_req_iso_flaky_01_traceability_and_english_hygiene() -> None:
    """REQ-ISO-FLAKY-01: Verify flaky_test_bifurcator.py contains REQ-ISO-FLAKY-01 and 0 Cyrillic characters."""
    target_file = REPO_ROOT / "iso9000_agentops" / "flaky_test_bifurcator.py"
    assert target_file.is_file(), f"Missing target module: {target_file}"
    content = target_file.read_text(encoding="utf-8")
    assert "REQ-ISO-FLAKY-01" in content
    for ch in content:
        code = ord(ch)
        assert not (0x0400 <= code <= 0x04FF), f"Cyrillic character found: {ch!r}"
