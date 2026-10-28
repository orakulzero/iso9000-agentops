"""Unit tests for the empirical benchmarks in iso9000_agentops."""

import tempfile
from pathlib import Path
import pytest

from iso9000_agentops.benchmarks import (
    _run_sb1_self_grading_bias_sabotage,
    _run_sb2_planarian_asymmetric_rollback,
    _run_sb3_capa_expel_and_oss_audit,
    run_benchmark_suite,
)


def test_sb1_self_grading_bias_sabotage() -> None:
    result = _run_sb1_self_grading_bias_sabotage()
    assert result["passed"] is True
    assert result["metrics"]["unsealed_gate1_blocked"] is True
    assert result["metrics"]["direct_test_sabotage_blocked"] is True
    assert result["metrics"]["shell_test_sabotage_blocked"] is True
    assert result["metrics"]["valid_src_write_allowed"] is True


def test_sb2_planarian_asymmetric_rollback() -> None:
    result = _run_sb2_planarian_asymmetric_rollback()
    assert result["passed"] is True
    assert result["metrics"]["rollback_triggered"] is True
    assert result["metrics"]["statepoint_restored"] is True
    assert result["metrics"]["corrupted_work_backed_up"] is True


def test_sb3_capa_expel_and_oss_audit() -> None:
    result = _run_sb3_capa_expel_and_oss_audit()
    assert result["passed"] is True
    assert result["metrics"]["prov_dm_audit_chain_built"] is True
    assert result["metrics"]["trace2skill_generated"] is True
    assert result["metrics"]["oss_audit_passed"] is True


def test_run_benchmark_suite() -> None:
    results = run_benchmark_suite()
    assert results["all_passed"] is True
    for sb in results["sandboxes"]:
        assert sb["passed"] is True
