"""Flaky Test Bifurcator & Non-Determinism Quarantine Engine (REQ-ISO-FLAKY-01).

Distinguishes deterministic code regressions from non-deterministic flaky tests
and transient OS/network environment failures so self-healing agents never
corrupt production logic attempting to patch a race condition or port conflict.

Requirement Traceability:
- REQ-ISO-FLAKY-01: Flaky Test Bifurcator & Non-Determinism Quarantine
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Sequence

TRANSIENT_ENV_SIGNATURES = (
    "Address already in use",
    "ConnectionResetError",
    "TimedOut",
    "EADDRINUSE",
    "ConnectionRefusedError",
    "Temporary failure in name resolution",
)


@dataclass(frozen=True)
class FlakyClassification:
    """Result of bifurcating multi-run test execution telemetry (REQ-ISO-FLAKY-01)."""

    node_id: str
    classification: str
    is_flaky: bool
    allow_self_healing_code_patch: bool
    transient_env_signature: bool = False
    recommended_action: str = "NONE"
    exit_codes: list[int] = field(default_factory=list)


class FlakyTestBifurcator:
    """Bifurcates test runs into healthy, flaky, transient-env, or deterministic regression (REQ-ISO-FLAKY-01)."""

    def __init__(self, transient_signatures: Sequence[str] = TRANSIENT_ENV_SIGNATURES) -> None:
        self._transient_signatures: tuple[str, ...] = tuple(transient_signatures)
        self._quarantined_node_ids: set[str] = set()

    def _has_transient_signature(self, logs: Sequence[str]) -> bool:
        """Return True if any log entry matches a known transient OS/socket signature."""
        for log_entry in logs:
            for sig in self._transient_signatures:
                if sig in log_entry:
                    return True
        return False

    def classify_test_runs(
        self,
        node_id: str,
        exit_codes: Sequence[int],
        output_logs: Sequence[str],
    ) -> FlakyClassification:
        """Classify a sequence of test execution attempts for a given pytest node_id (REQ-ISO-FLAKY-01)."""
        codes = [int(c) for c in exit_codes]
        if not codes or all(c == 0 for c in codes):
            return FlakyClassification(
                node_id=node_id,
                classification="HEALTHY",
                is_flaky=False,
                allow_self_healing_code_patch=False,
                transient_env_signature=False,
                recommended_action="PROCEED",
                exit_codes=codes,
            )

        if self._has_transient_signature(output_logs):
            return FlakyClassification(
                node_id=node_id,
                classification="TRANSIENT_ENV_FAILURE",
                is_flaky=False,
                allow_self_healing_code_patch=False,
                transient_env_signature=True,
                recommended_action="RETRY_ISOLATED_SANDBOX",
                exit_codes=codes,
            )

        has_pass = any(c == 0 for c in codes)
        has_fail = any(c != 0 for c in codes)
        if has_pass and has_fail:
            return FlakyClassification(
                node_id=node_id,
                classification="FLAKY_NON_DETERMINISTIC",
                is_flaky=True,
                allow_self_healing_code_patch=False,
                transient_env_signature=False,
                recommended_action="QUARANTINE_FLAKY_TEST",
                exit_codes=codes,
            )

        return FlakyClassification(
            node_id=node_id,
            classification="DETERMINISTIC_REGRESSION",
            is_flaky=False,
            allow_self_healing_code_patch=True,
            transient_env_signature=False,
            recommended_action="SELF_HEAL_CODE_PATCH",
            exit_codes=codes,
        )

    def record_classification(self, classification: FlakyClassification) -> None:
        """Record a test classification and add flaky tests to the quarantine registry (REQ-ISO-FLAKY-01)."""
        if classification.is_flaky or classification.classification == "FLAKY_NON_DETERMINISTIC":
            self._quarantined_node_ids.add(classification.node_id)

    def get_quarantined_tests(self) -> list[str]:
        """Return sorted list of quarantined flaky test node_ids (REQ-ISO-FLAKY-01)."""
        return sorted(self._quarantined_node_ids)
