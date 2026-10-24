"""Diff-Tour v1 specification and Senior Engineer Review Dimensions (ISO 9001:2015)."""

from __future__ import annotations

import copy
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1. The 8 Senior Engineer Review Dimensions
# ---------------------------------------------------------------------------

class SeniorReviewDimension(str, Enum):
    """Eight Senior Review Dimensions for rigorous software audit."""

    L1_PROMISES = "L1_PROMISES"    # Scope fidelity, PR description vs diff, acceptance criteria
    L2_FAILURE = "L2_FAILURE"      # Error paths, timeouts, exceptions, resource leaks, degradation
    L3_OPERATIONS = "L3_OPERATIONS"  # Observability, structured logs, telemetry, rollback, health
    L4_TRUST = "L4_TRUST"          # Security boundaries, crypto seals, secret leaks, permissions
    L5_SCALE = "L5_SCALE"          # Performance, latency bounds, memory, locks, BigInt bounds
    L6_DESIGN = "L6_DESIGN"        # Modularity, coupling, DRY/KISS/YAGNI, portability
    L7_TESTS = "L7_TESTS"          # Coverage, mutation tests, mock fidelity, adversarial cases
    L8_AI_TRAPS = "L8_AI_TRAPS"    # Self-grading bias, hallucinated APIs, tautologies, dead code


REVIEW_DIMENSIONS: set[str] = {dim.value for dim in SeniorReviewDimension}

REVIEW_DIMENSION_DESCRIPTIONS: dict[str, str] = {
    SeniorReviewDimension.L1_PROMISES.value: "Scope fidelity and acceptance criteria fulfillment.",
    SeniorReviewDimension.L2_FAILURE.value: "Negative branches, network errors, timeouts, resource leaks.",
    SeniorReviewDimension.L3_OPERATIONS.value: "Observability, structured logging, audit trails, rollback.",
    SeniorReviewDimension.L4_TRUST.value: "Security boundaries, cryptographic seals, secret protection.",
    SeniorReviewDimension.L5_SCALE.value: "Performance under load, latency bounds, memory, concurrency.",
    SeniorReviewDimension.L6_DESIGN.value: "Architecture modularity, interface coupling, clean design.",
    SeniorReviewDimension.L7_TESTS.value: "Business logic coverage, adversarial test cases, mock fidelity.",
    SeniorReviewDimension.L8_AI_TRAPS.value: "Self-grading bias, hallucinated symbols, tautological asserts.",
}

# ---------------------------------------------------------------------------
# 2. Epistemic Basis
# ---------------------------------------------------------------------------

VALID_EPISTEMIC_BASES: set[str] = {"fact", "inferred", "opinion"}


# ---------------------------------------------------------------------------
# 3. Git Reference In-Memory Cache
# ---------------------------------------------------------------------------

_GIT_BLOB_CACHE: dict[tuple[str, str, str], str] = {}


def clear_git_blob_cache() -> None:
    """Clear the in-memory git blob cache."""
    _GIT_BLOB_CACHE.clear()


# ---------------------------------------------------------------------------
# 4. Zero-Hallucination Git Reference Checker
# ---------------------------------------------------------------------------

def verify_git_reference(
    repo_root: Path | str,
    git_ref: str,
    file_path: str,
    line_start: int,
    line_end: int,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Verify that a referenced file exists at git_ref and line bounds are valid.

    Executes git show <git_ref>:<file_path> to prevent hallucinated references.
    """
    root = Path(repo_root).resolve()
    normalized_path = file_path.replace("\\", "/").lstrip("/")

    cache_key = (str(root), git_ref, normalized_path)
    content: str | None = None

    if use_cache and cache_key in _GIT_BLOB_CACHE:
        content = _GIT_BLOB_CACHE[cache_key]
    else:
        cmd = ["git", "show", f"{git_ref}:{normalized_path}"]
        try:
            res = subprocess.run(
                cmd,
                cwd=str(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
            if res.returncode != 0:
                return {
                    "valid": False,
                    "error": "FILE_OR_REF_NOT_FOUND",
                    "message": f"Git object not found: '{git_ref}:{normalized_path}' (code {res.returncode}): {res.stderr.strip()}",
                }
            content = res.stdout
            if use_cache:
                _GIT_BLOB_CACHE[cache_key] = content
        except Exception as exc:
            return {
                "valid": False,
                "error": "GIT_COMMAND_FAILED",
                "message": f"Failed to execute git show: {exc}",
            }

    lines = content.splitlines()
    total_lines = len(lines)

    if line_start < 1 or line_end < line_start or line_end > total_lines:
        return {
            "valid": False,
            "error": "LINE_BOUNDS_OUT_OF_RANGE",
            "message": f"Line bounds [{line_start}, {line_end}] invalid for file with {total_lines} lines.",
            "total_lines": total_lines,
            "line_start": line_start,
            "line_end": line_end,
        }

    return {
        "valid": True,
        "error": None,
        "total_lines": total_lines,
        "line_count": line_end - line_start + 1,
    }


# ---------------------------------------------------------------------------
# 5. drop_revealing_asks Algorithm
# ---------------------------------------------------------------------------

def drop_revealing_asks(tour_data: dict[str, Any]) -> dict[str, Any]:
    """Strip 'asks' on question steps and their immediate preceding steps.

    Prevents spoiling assessment questions during review walkthroughs.
    """
    sanitized = copy.deepcopy(tour_data)
    steps = sanitized.get("steps") or []
    indices_to_strip: set[int] = set()

    for idx, step in enumerate(steps):
        if isinstance(step, dict) and step.get("question") is True:
            indices_to_strip.add(idx)
            if idx > 0:
                indices_to_strip.add(idx - 1)

    for idx in indices_to_strip:
        if idx < len(steps) and isinstance(steps[idx], dict):
            steps[idx].pop("asks", None)

    sanitized["steps"] = steps
    return sanitized


# ---------------------------------------------------------------------------
# 6. Diff-Tour Schema Validation
# ---------------------------------------------------------------------------

def validate_diff_tour(
    tour_data: dict[str, Any],
    repo_root: Path | str | None = None,
    check_git: bool = False,
    git_ref: str = "HEAD",
    strict: bool = False,
) -> dict[str, Any]:
    """Validate a diff-tour v1 payload against schema and review dimensions."""
    errors: list[str] = []

    if not isinstance(tour_data, dict):
        msg = "Tour payload must be a JSON dictionary."
        if strict:
            raise ValueError(msg)
        return {"valid": False, "errors": [msg], "tour": tour_data}

    title = tour_data.get("title")
    if not title or not isinstance(title, str) or not title.strip():
        errors.append("Tour must contain a non-empty 'title' string.")

    steps = tour_data.get("steps")
    if steps is None or not isinstance(steps, list):
        errors.append("Tour must contain a 'steps' list.")
        steps = []

    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"Step #{idx} must be a dictionary.")
            continue

        # File reference
        file_path = step.get("file") or step.get("file_path")
        if not file_path or not isinstance(file_path, str) or not file_path.strip():
            errors.append(f"Step #{idx}: missing or empty 'file' path.")

        # Line bounds
        line_start = step.get("line_start")
        line_end = step.get("line_end")
        if line_start is None and "line" in step:
            line_start = step["line"]
            line_end = step.get("line_end", line_start)

        if line_start is None or line_end is None:
            errors.append(f"Step #{idx}: missing line bounds ('line_start', 'line_end').")
        else:
            try:
                ls = int(line_start)
                le = int(line_end)
                if ls < 1:
                    errors.append(f"Step #{idx}: line_start must be >= 1 (got {ls}).")
                if le < ls:
                    errors.append(f"Step #{idx}: line_end ({le}) cannot be less than line_start ({ls}).")
            except (ValueError, TypeError):
                errors.append(f"Step #{idx}: line bounds must be integers.")

        # Review dimension
        dimension = step.get("dimension") or step.get("review_dimension")
        if not dimension or dimension not in REVIEW_DIMENSIONS:
            errors.append(
                f"Step #{idx}: invalid dimension '{dimension}'. "
                f"Must be one of {sorted(REVIEW_DIMENSIONS)}."
            )

        # Epistemic basis
        basis = step.get("epistemic_basis")
        if not basis or basis not in VALID_EPISTEMIC_BASES:
            errors.append(
                f"Step #{idx}: invalid or missing epistemic_basis '{basis}'. "
                f"Must be one of {sorted(VALID_EPISTEMIC_BASES)}."
            )

        # Description / comment
        desc = step.get("description") or step.get("comment") or step.get("body")
        if not desc or not isinstance(desc, str) or not desc.strip():
            errors.append(f"Step #{idx}: step must include a non-empty description.")

        # Optional git reference verification
        if check_git and repo_root and file_path and line_start is not None and line_end is not None:
            try:
                ls = int(line_start)
                le = int(line_end)
                if ls >= 1 and le >= ls:
                    git_res = verify_git_reference(repo_root, git_ref, str(file_path), ls, le)
                    if not git_res.get("valid"):
                        errors.append(
                            f"Step #{idx}: git reference verification failed: {git_res.get('message')}"
                        )
            except Exception as e:
                errors.append(f"Step #{idx}: git check error: {e}")

    is_valid = len(errors) == 0

    if not is_valid and strict:
        raise ValueError(f"Diff-Tour validation failed: {'; '.join(errors)}")

    return {
        "valid": is_valid,
        "errors": errors,
        "step_count": len(steps),
        "tour": tour_data,
    }


# ---------------------------------------------------------------------------
# 7. Helper: Build Structured Diff Tour
# ---------------------------------------------------------------------------

def build_diff_tour(
    title: str,
    description: str = "",
    steps: list[dict[str, Any]] | None = None,
    version: int = 1,
) -> dict[str, Any]:
    """Construct a standardized diff-tour v1 dictionary."""
    return {
        "version": version,
        "title": title,
        "description": description,
        "steps": steps or [],
    }
