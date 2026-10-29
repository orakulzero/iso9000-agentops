"""Agile V locked verification tests for ISO 9001 AgentOps v2.2.0.

Validates:
- REQ-ISO-DEEPTUTOR-01: DeepTutor SOP Curriculum DAG Distiller (iso9000_agentops.sop_distiller)
- REQ-ISO-BABEL-01: BabelArena Non-ASCII & Cyrillic Schema/AST Gate (iso9000_agentops.babel_arena_gate)
"""

from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (REPO_ROOT / "src", REPO_ROOT):
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from iso9000_agentops.babel_arena_gate import BabelArenaGate, BabelAuditResult
from iso9000_agentops.sop_distiller import DeepTutorSOPDistiller, SOPNode


def test_sop_node_frozen_and_sequential_markdown_distillation() -> None:
    """@requirement("REQ-ISO-DEEPTUTOR-01") Verify frozen SOPNode and sequential DAG distillation."""
    distiller = DeepTutorSOPDistiller()
    markdown_spec = (
        "# ISO 9001 Release SOP\n\n"
        "## Initialize Frozen Baseline (REQ-ISO-101)\n"
        "Lock artifact scope and compute HMAC seal.\n\n"
        "### Execute FMEA Risk Assessment\n"
        "Evaluate failure modes and verify RPN bounds.\n\n"
        "1. Issue Cryptographic Quality Certificate (REQ-ISO-103)\n"
        "Sign SARIF 2.1.0 report and verify Merkle root.\n"
    )
    nodes = distiller.distill_markdown_to_sop_dag(markdown_spec, default_req_prefix="REQ-SOP")
    assert len(nodes) == 3

    first, second, third = nodes[0], nodes[1], nodes[2]
    assert isinstance(first, SOPNode) and dataclasses.is_dataclass(first)
    with pytest.raises(FrozenInstanceError):
        first.title = "Mutated"  # type: ignore[misc]

    assert first.prerequisite_ids == ()
    assert first.req_id == "REQ-ISO-101"
    assert "Initialize Frozen Baseline" in first.title
    assert bool(first.verification_assertion.strip())

    assert second.prerequisite_ids == (first.node_id,)
    assert second.req_id.startswith("REQ-SOP")
    assert "Execute FMEA Risk Assessment" in second.title
    assert bool(second.verification_assertion.strip())

    assert third.prerequisite_ids == (second.node_id,)
    assert third.req_id == "REQ-ISO-103"
    assert "Issue Cryptographic Quality Certificate" in third.title


def test_sop_distiller_explicit_depends_on_and_validation_errors() -> None:
    """@requirement("REQ-ISO-DEEPTUTOR-01") Verify Depends-On references, empty spec, and cycle errors."""
    distiller = DeepTutorSOPDistiller()
    with pytest.raises(ValueError):
        distiller.distill_markdown_to_sop_dag("   \nPlain prose without extractable steps.\n")

    cyclic_spec = (
        "## step-1: Alpha Step (REQ-SOP-01)\nDepends-On: step-2\n\n"
        "## step-2: Beta Step (REQ-SOP-02)\nDepends-On: step-1\n"
    )
    with pytest.raises(ValueError):
        distiller.distill_markdown_to_sop_dag(cyclic_spec)


def test_evaluate_mastery_progress_unlocking_and_blocking() -> None:
    """@requirement("REQ-ISO-DEEPTUTOR-01") Verify progressive mastery unlocking and blocked node tracking."""
    distiller = DeepTutorSOPDistiller()
    nodes = [
        SOPNode("step-1", "Baseline Lock", (), "assert baseline.locked", "REQ-SOP-01"),
        SOPNode("step-2", "FMEA Audit", ("step-1",), "assert fmea.max_rpn <= 200", "REQ-SOP-02"),
        SOPNode("step-3", "RTM Matrix", ("step-1",), "assert rtm.compliant", "REQ-SOP-03"),
        SOPNode("step-4", "Certify", ("step-2", "step-3"), "assert cert.signed", "REQ-SOP-04"),
    ]
    p_init = distiller.evaluate_mastery_progress(nodes, passed_node_ids=set())
    assert p_init["total_nodes"] == 4 and p_init["mastered_count"] == 0
    assert p_init["mastery_pct"] == 0.0
    assert p_init["unlocked_next_nodes"] == ["step-1"]
    assert p_init["blocked_nodes"] == ["step-2", "step-3", "step-4"]

    p_mid = distiller.evaluate_mastery_progress(nodes, passed_node_ids={"step-1"})
    assert p_mid["total_nodes"] == 4 and p_mid["mastered_count"] == 1
    assert p_mid["mastery_pct"] in (pytest.approx(25.0), pytest.approx(0.25))
    assert p_mid["unlocked_next_nodes"] == ["step-2", "step-3"]
    assert p_mid["blocked_nodes"] == ["step-4"]

    p_done = distiller.evaluate_mastery_progress(
        nodes, passed_node_ids={"step-1", "step-2", "step-3", "step-4"}
    )
    assert p_done["mastered_count"] == 4
    assert p_done["mastery_pct"] in (pytest.approx(100.0), pytest.approx(1.0))
    assert p_done["unlocked_next_nodes"] == [] and p_done["blocked_nodes"] == []


def test_babel_arena_gate_audit_python_source_clean_and_drifted() -> None:
    """@requirement("REQ-ISO-BABEL-01") Verify AST identifier check, Cyrillic count, and token inflation."""
    gate = BabelArenaGate()
    clean_src = (
        "class QualityGate:\n"
        "    def validate_baseline(self, baseline_id: str) -> bool:\n"
        "        is_valid = len(baseline_id) > 0\n"
        "        return is_valid\n"
    )
    clean_res = gate.audit_python_source(clean_src)
    assert isinstance(clean_res, BabelAuditResult) and dataclasses.is_dataclass(clean_res)
    with pytest.raises(FrozenInstanceError):
        clean_res.passed = False  # type: ignore[misc]

    assert clean_res.passed is True
    assert clean_res.non_ascii_identifiers == [] and clean_res.non_ascii_schema_keys == []
    assert clean_res.cyrillic_violations == 0
    assert clean_res.estimated_token_inflation_ratio == pytest.approx(1.0)

    fn_cyr, arg_cyr, var_non_ascii = "\u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430", "\u0434\u0430\u043d\u043d\u044b\u0435", "\u03b1_score"
    drifted_src = f"def {fn_cyr}({arg_cyr}: int) -> int:\n    {var_non_ascii} = {arg_cyr} + 1\n    return {var_non_ascii}\n"
    bad_res = gate.audit_python_source(drifted_src)
    assert bad_res.passed is False
    for ident in (fn_cyr, arg_cyr, var_non_ascii):
        assert ident in bad_res.non_ascii_identifiers
    assert bad_res.cyrillic_violations >= 14
    assert bad_res.estimated_token_inflation_ratio > 1.0


def test_babel_arena_gate_audit_tool_schema_clean_and_drifted() -> None:
    """@requirement("REQ-ISO-BABEL-01") Verify recursive MCP tool schema audit for non-ASCII keys and Cyrillic."""
    gate = BabelArenaGate()
    clean_schema: dict[str, Any] = {
        "name": "iso9000_certify",
        "description": "Issue cryptographic ISO 9001 quality certificate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_id": {"type": "string", "description": "Frozen baseline identifier"},
                "options": {"type": "object", "properties": {"strict": {"type": "boolean"}}},
            },
        },
    }
    res_ok = gate.audit_tool_schema(clean_schema)
    assert res_ok.passed is True and res_ok.non_ascii_schema_keys == []
    assert res_ok.cyrillic_violations == 0
    assert res_ok.estimated_token_inflation_ratio == pytest.approx(1.0)

    bad_prop_key = "\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440"
    drifted_schema: dict[str, Any] = {
        "name": "iso9000_certify",
        "description": "Validate schema \u0441\u0445\u0435\u043c\u0430",
        "inputSchema": {
            "type": "object",
            "properties": {bad_prop_key: {"type": "string", "description": "Non-ASCII property key"}},
        },
    }
    res_bad = gate.audit_tool_schema(drifted_schema)
    assert res_bad.passed is False and bad_prop_key in res_bad.non_ascii_schema_keys
    assert res_bad.cyrillic_violations >= 5 and res_bad.estimated_token_inflation_ratio > 1.0
