"""Comprehensive tests for diff_tour.py and Senior Review Dimensions."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from iso9000_agentops.diff_tour import (
    REVIEW_DIMENSIONS,
    SeniorReviewDimension,
    VALID_EPISTEMIC_BASES,
    build_diff_tour,
    clear_git_blob_cache,
    drop_revealing_asks,
    validate_diff_tour,
    verify_git_reference,
)


def test_senior_review_dimensions_completeness() -> None:
    expected_dimensions = {
        "L1_PROMISES",
        "L2_FAILURE",
        "L3_OPERATIONS",
        "L4_TRUST",
        "L5_SCALE",
        "L6_DESIGN",
        "L7_TESTS",
        "L8_AI_TRAPS",
    }
    assert REVIEW_DIMENSIONS == expected_dimensions
    assert len(SeniorReviewDimension) == 8
    for dim in expected_dimensions:
        assert SeniorReviewDimension(dim) is not None


def test_epistemic_bases_completeness() -> None:
    assert VALID_EPISTEMIC_BASES == {"fact", "inferred", "opinion"}


def test_drop_revealing_asks_algorithm() -> None:
    tour = {
        "title": "Security & Architecture Review",
        "steps": [
            {
                "file": "src/main.py",
                "line_start": 1,
                "line_end": 5,
                "dimension": "L1_PROMISES",
                "epistemic_basis": "fact",
                "description": "Initial setup step.",
                "asks": ["Notice anything in step 0?"],
            },
            {
                "file": "src/main.py",
                "line_start": 6,
                "line_end": 10,
                "dimension": "L2_FAILURE",
                "epistemic_basis": "inferred",
                "description": "Step right before question.",
                "asks": ["What does the timeout handler do?"],
            },
            {
                "file": "src/main.py",
                "line_start": 11,
                "line_end": 15,
                "dimension": "L4_TRUST",
                "epistemic_basis": "opinion",
                "description": "Assessment question step.",
                "question": True,
                "asks": ["Is the HMAC key secret enough?"],
            },
            {
                "file": "src/main.py",
                "line_start": 16,
                "line_end": 20,
                "dimension": "L5_SCALE",
                "epistemic_basis": "fact",
                "description": "Follow-up step.",
                "asks": ["Can this withstand 10k QPS?"],
            },
        ],
    }

    sanitized = drop_revealing_asks(tour)

    # Original tour remains untouched (immutable deepcopy)
    assert "asks" in tour["steps"][1]
    assert "asks" in tour["steps"][2]

    # In sanitized tour:
    # Step 2 has question=True, so Step 2 AND Step 1 must have 'asks' stripped!
    assert "asks" in sanitized["steps"][0]
    assert "asks" not in sanitized["steps"][1]
    assert "asks" not in sanitized["steps"][2]
    assert "asks" in sanitized["steps"][3]


def test_validate_diff_tour_valid() -> None:
    tour = build_diff_tour(
        title="v1.1.0 Core Stack Tour",
        description="Verification of review dimensions",
        steps=[
            {
                "file": "pyproject.toml",
                "line_start": 1,
                "line_end": 10,
                "dimension": "L1_PROMISES",
                "epistemic_basis": "fact",
                "description": "Verified package metadata and dependencies.",
            },
            {
                "file": "iso9000_agentops/diff_tour.py",
                "line_start": 10,
                "line_end": 25,
                "dimension": "L8_AI_TRAPS",
                "epistemic_basis": "inferred",
                "description": "Checking for potential self-grading bias traps.",
            },
        ],
    )
    res = validate_diff_tour(tour)
    assert res["valid"] is True
    assert len(res["errors"]) == 0
    assert res["step_count"] == 2


def test_validate_diff_tour_invalid_dimensions_and_epistemic() -> None:
    invalid_tour = {
        "title": "Invalid Tour",
        "steps": [
            {
                "file": "foo.py",
                "line_start": 5,
                "line_end": 10,
                "dimension": "L9_UNKNOWN",
                "epistemic_basis": "speculation",
                "description": "Invalid dimension and epistemic basis.",
            },
            {
                "file": "",
                "line_start": 10,
                "line_end": 5,
                "dimension": "L1_PROMISES",
                "epistemic_basis": "fact",
                "description": "Invalid line range and empty file.",
            },
        ],
    }
    res = validate_diff_tour(invalid_tour)
    assert res["valid"] is False
    assert any("invalid dimension" in err for err in res["errors"])
    assert any("invalid or missing epistemic_basis" in err for err in res["errors"])
    assert any("missing or empty 'file'" in err for err in res["errors"])
    assert any("cannot be less than line_start" in err for err in res["errors"])

    with pytest.raises(ValueError, match="Diff-Tour validation failed"):
        validate_diff_tour(invalid_tour, strict=True)


def test_git_reference_checker_real_repo() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    clear_git_blob_cache()

    # Valid check on pyproject.toml
    res = verify_git_reference(repo_root, "HEAD", "pyproject.toml", 1, 5)
    assert res["valid"] is True
    assert res["total_lines"] >= 10
    assert res["line_count"] == 5

    # Out-of-bounds line numbers
    res_oob = verify_git_reference(repo_root, "HEAD", "pyproject.toml", 1, 999999)
    assert res_oob["valid"] is False
    assert res_oob["error"] == "LINE_BOUNDS_OUT_OF_RANGE"

    # Line start < 1
    res_zero = verify_git_reference(repo_root, "HEAD", "pyproject.toml", 0, 5)
    assert res_zero["valid"] is False
    assert res_zero["error"] == "LINE_BOUNDS_OUT_OF_RANGE"

    # Non-existent file
    res_nf = verify_git_reference(repo_root, "HEAD", "non_existent_file_xyz_123.py", 1, 5)
    assert res_nf["valid"] is False
    assert res_nf["error"] == "FILE_OR_REF_NOT_FOUND"


def test_validate_diff_tour_with_git_check() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    tour = build_diff_tour(
        title="Git Bound Verification",
        steps=[
            {
                "file": "pyproject.toml",
                "line_start": 1,
                "line_end": 5,
                "dimension": "L1_PROMISES",
                "epistemic_basis": "fact",
                "description": "Git bounds verified.",
            }
        ],
    )
    res = validate_diff_tour(tour, repo_root=repo_root, check_git=True, git_ref="HEAD")
    assert res["valid"] is True
