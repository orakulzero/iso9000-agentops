"""Comprehensive unit and property-based tests for v1.2.0 capabilities:

1. W3C PROV-DM SHA-256 Hash Chain Builder and Tamper Verifier (crypto_guard.py)
2. Diff-Tour v1 Markdown Renderer and Weighted Risk Scorer (diff_tour.py)
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from iso9000_agentops.crypto_guard import (
    build_prov_hash_chain,
    verify_prov_hash_chain,
)
from iso9000_agentops.diff_tour import (
    REVIEW_DIMENSIONS,
    SeniorReviewDimension,
    build_diff_tour,
    compute_diff_tour_risk_score,
    render_diff_tour_markdown,
)


# ===========================================================================
# 1. W3C PROV-DM SHA-256 Hash Chain Tests
# ===========================================================================

def test_build_prov_hash_chain_basic() -> None:
    activities: list[dict[str, Any]] = [
        {"id": "act-1", "phase": "E1_BASELINE", "status": "APPROVED"},
        {"id": "act-2", "phase": "E2_PLANNING", "status": "IN_PROGRESS"},
        {"id": "act-3", "phase": "E3_SYNTHESIS", "status": "COMPLETED"},
    ]
    chain = build_prov_hash_chain(activities)

    assert len(chain) == 3
    assert chain[0]["prev_hash"] == ""
    assert len(chain[0]["entry_hash"]) == 64
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]
    assert len(chain[1]["entry_hash"]) == 64
    assert chain[2]["prev_hash"] == chain[1]["entry_hash"]
    assert len(chain[2]["entry_hash"]) == 64

    # Verify chain
    result = verify_prov_hash_chain(chain)
    assert result["valid"] is True
    assert result["chain_length"] == 3
    assert result["tampered_indices"] == []
    assert result["head_hash"] == chain[-1]["entry_hash"]


def test_build_prov_hash_chain_with_initial_prev_hash() -> None:
    genesis = "0" * 64
    activities: list[dict[str, Any]] = [
        {"id": "act-1", "action": "CREATE_PROJECT"},
        {"id": "act-2", "action": "INIT_REPO"},
    ]
    chain = build_prov_hash_chain(activities, initial_prev_hash=genesis)

    assert chain[0]["prev_hash"] == genesis
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]

    # Verify with matching initial hash
    res_valid = verify_prov_hash_chain(chain, initial_prev_hash=genesis)
    assert res_valid["valid"] is True
    assert res_valid["head_hash"] == chain[1]["entry_hash"]

    # Verify with mismatched initial hash
    res_invalid = verify_prov_hash_chain(chain, initial_prev_hash="f" * 64)
    assert res_invalid["valid"] is False
    assert 0 in res_invalid["tampered_indices"]


def test_build_prov_hash_chain_immutability() -> None:
    original: list[dict[str, Any]] = [
        {"id": "act-1", "payload": "immutable-data"},
        {"id": "act-2", "payload": "second-entry", "prev_hash": "stale", "entry_hash": "stale"},
    ]
    snapshot = copy.deepcopy(original)
    chain = build_prov_hash_chain(original)

    # Original inputs must not be modified in-place
    assert original == snapshot
    # Chain must contain correct computed hashes, stripping old ones
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]
    assert chain[1]["entry_hash"] != "stale"


def test_verify_prov_hash_chain_detects_payload_tampering() -> None:
    activities: list[dict[str, Any]] = [
        {"step": 1, "actor": "Auditor", "decision": "ACCEPT"},
        {"step": 2, "actor": "Developer", "decision": "SUBMIT"},
        {"step": 3, "actor": "Gatekeeper", "decision": "SEAL"},
    ]
    chain = build_prov_hash_chain(activities)

    # Tamper payload at index 1
    tampered_chain = [dict(c) for c in chain]
    tampered_chain[1]["decision"] = "REJECT"  # Silently changed payload

    res = verify_prov_hash_chain(tampered_chain)
    assert res["valid"] is False
    assert 1 in res["tampered_indices"]


def test_verify_prov_hash_chain_detects_hash_break() -> None:
    activities: list[dict[str, Any]] = [
        {"step": 1, "content": "alpha"},
        {"step": 2, "content": "beta"},
        {"step": 3, "content": "gamma"},
    ]
    chain = build_prov_hash_chain(activities)

    # Tamper entry_hash at index 0
    tampered = [dict(c) for c in chain]
    tampered[0]["entry_hash"] = "a" * 64

    res = verify_prov_hash_chain(tampered)
    assert res["valid"] is False
    # Both index 0 (hash mismatch) and index 1 (prev_hash mismatch) are caught
    assert 0 in res["tampered_indices"]
    assert 1 in res["tampered_indices"]


def test_verify_prov_hash_chain_empty_and_corrupt() -> None:
    # Empty chain
    res_empty = verify_prov_hash_chain([])
    assert res_empty["valid"] is True
    assert res_empty["chain_length"] == 0
    assert res_empty["tampered_indices"] == []
    assert res_empty["head_hash"] == ""

    # Malformed non-hex or short hashes
    corrupt_chain = [{"prev_hash": "", "entry_hash": "not-a-valid-64-char-hex"}]
    res_corrupt = verify_prov_hash_chain(corrupt_chain)
    assert res_corrupt["valid"] is False
    assert 0 in res_corrupt["tampered_indices"]


# ===========================================================================
# 2. Hypothesis Property-Based Testing for Hash Chains
# ===========================================================================

activity_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"),
    values=st.one_of(st.integers(), st.booleans(), st.text(max_size=30)),
    min_size=1,
    max_size=5,
)

@settings(max_examples=40, deadline=None)
@given(activities=st.lists(activity_strategy, min_size=1, max_size=10))
def test_hypothesis_prov_hash_chain_integrity(activities: list[dict[str, Any]]) -> None:
    chain = build_prov_hash_chain(activities)
    verification = verify_prov_hash_chain(chain)

    assert verification["valid"] is True
    assert verification["chain_length"] == len(activities)
    assert verification["tampered_indices"] == []
    assert verification["head_hash"] == chain[-1]["entry_hash"]

    # Tampering test: modify first key of first item
    tampered = [dict(entry) for entry in chain]
    tampered[0]["__injected_tamper__"] = 999999
    tampered_verification = verify_prov_hash_chain(tampered)

    assert tampered_verification["valid"] is False
    assert 0 in tampered_verification["tampered_indices"]


# ===========================================================================
# 3. Diff-Tour Markdown Renderer Tests
# ===========================================================================

def test_render_diff_tour_markdown_complete() -> None:
    tour_data = {
        "version": 1,
        "title": "Authentication Refactor Review",
        "description": "Walkthrough of cryptographic session tokens and cookie rotation.",
        "steps": [
            {
                "title": "Token Hash Verification",
                "file": "src/auth/session.py",
                "line_start": 45,
                "line_end": 52,
                "dimension": "L4_TRUST",
                "epistemic_basis": "fact",
                "description": "Validates HMAC-SHA256 signature on inbound session tokens.",
                "asks": ["Confirm key derivation adheres to RFC 2104."],
            },
            {
                "title": "Negative Error Path",
                "file": "src/auth/session.py",
                "line_start": 60,
                "line_end": 68,
                "dimension": "L2_FAILURE",
                "epistemic_basis": "inferred",
                "question": True,
                "description": "Does the session revocation trigger immediate cache invalidation?",
                "asks": ["Check redis timeout configuration.", "Inspect fallback retry loop."],
            },
        ],
    }

    markdown = render_diff_tour_markdown(tour_data)

    assert "# Authentication Refactor Review" in markdown
    assert "Walkthrough of cryptographic session tokens" in markdown
    assert "### Step 1: Token Hash Verification (`src/auth/session.py:45-52`)" in markdown
    assert "- **File Anchor**: `src/auth/session.py:45-52`" in markdown
    assert "- **Dimension**: `L4_TRUST`" in markdown
    assert "- **Epistemic Basis**: [FACT]" in markdown
    assert "Validates HMAC-SHA256 signature" in markdown
    assert "Confirm key derivation adheres to RFC 2104." in markdown

    assert "### Step 2: Negative Error Path (`src/auth/session.py:60-68`)" in markdown
    assert "- **Dimension**: `L2_FAILURE`" in markdown
    assert "- **Epistemic Basis**: [INFERRED]" in markdown
    assert "- **Question**: Yes (Verification Challenge)" in markdown
    assert "- Check redis timeout configuration." in markdown
    assert "- Inspect fallback retry loop." in markdown


def test_render_diff_tour_markdown_empty_steps() -> None:
    tour_data = {
        "title": "Empty Tour",
        "description": "A tour with zero steps.",
        "steps": [],
    }
    markdown = render_diff_tour_markdown(tour_data)

    assert "# Empty Tour" in markdown
    assert "A tour with zero steps." in markdown
    assert "_No review steps provided in tour._" in markdown


def test_render_diff_tour_markdown_invalid_input() -> None:
    assert "Invalid Diff-Tour" in render_diff_tour_markdown(None)  # type: ignore
    assert "Invalid Diff-Tour" in render_diff_tour_markdown("string")  # type: ignore


# ===========================================================================
# 4. Diff-Tour Weighted Risk Scorer Tests
# ===========================================================================

def test_compute_diff_tour_risk_score_pass() -> None:
    # Tour covering all 8 Senior Review Dimensions with all facts
    all_dims = sorted(list(REVIEW_DIMENSIONS))
    steps = [
        {
            "file": f"src/module_{i}.py",
            "line_start": 1,
            "line_end": 10,
            "dimension": dim,
            "epistemic_basis": "fact",
            "description": f"Verified implementation for dimension {dim}.",
        }
        for i, dim in enumerate(all_dims)
    ]

    tour = build_diff_tour(title="Complete 8-Dimension Tour", steps=steps)
    res = compute_diff_tour_risk_score(tour)

    assert res["verdict"] == "PASS"
    assert res["score"] == 100.0
    assert res["dimension_coverage"] == 1.0
    assert len(res["covered_dimensions"]) == 8
    assert res["missing_dimensions"] == []
    assert res["step_count"] == 8
    assert res["epistemic_counts"] == {"fact": 8, "inferred": 0, "opinion": 0}


def test_compute_diff_tour_risk_score_hold() -> None:
    # Tour covering 4 of 8 dimensions (50% coverage) with facts
    steps = [
        {"dimension": "L1_PROMISES", "epistemic_basis": "fact"},
        {"dimension": "L2_FAILURE", "epistemic_basis": "fact"},
        {"dimension": "L3_OPERATIONS", "epistemic_basis": "fact"},
        {"dimension": "L4_TRUST", "epistemic_basis": "fact"},
    ]
    tour = build_diff_tour(title="Partial Coverage Tour", steps=steps)
    res = compute_diff_tour_risk_score(tour)

    # Breadth: 4/8 * 60 = 30.0. Epistemic: 1.0 * 40 = 40.0. Total = 70.0.
    assert 50.0 <= res["score"] < 75.0
    assert res["verdict"] == "HOLD"
    assert res["dimension_coverage"] == 0.5
    assert len(res["covered_dimensions"]) == 4
    assert len(res["missing_dimensions"]) == 4


def test_compute_diff_tour_risk_score_block() -> None:
    # Tour covering 1 dimension with opinions
    steps = [
        {"dimension": "L8_AI_TRAPS", "epistemic_basis": "opinion"},
    ]
    tour = build_diff_tour(title="Inadequate Tour", steps=steps)
    res = compute_diff_tour_risk_score(tour)

    # Breadth: 1/8 * 60 = 7.5. Epistemic: 0.3 * 40 = 12.0. Total = 19.5.
    assert res["score"] < 50.0
    assert res["verdict"] == "BLOCK"
    assert res["dimension_coverage"] == 0.125
    assert res["epistemic_counts"]["opinion"] == 1


def test_compute_diff_tour_risk_score_empty() -> None:
    tour = build_diff_tour(title="Empty Tour", steps=[])
    res = compute_diff_tour_risk_score(tour)

    assert res["score"] == 0.0
    assert res["dimension_coverage"] == 0.0
    assert res["verdict"] == "BLOCK"
    assert res["covered_dimensions"] == []
    assert len(res["missing_dimensions"]) == 8
    assert res["step_count"] == 0
    assert res["epistemic_counts"] == {"fact": 0, "inferred": 0, "opinion": 0}


def test_compute_diff_tour_risk_score_invalid_input() -> None:
    res = compute_diff_tour_risk_score(None)  # type: ignore
    assert res["score"] == 0.0
    assert res["verdict"] == "BLOCK"
    assert res["step_count"] == 0
