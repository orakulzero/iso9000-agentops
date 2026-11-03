"""Speculative Dual-Tree AST Parity & Patch Verification Oracle (REQ-ISO-DUALTREE-01).

Verifies AST symbol parity, bidirectional requirement tag preservation, syntax
validity, and non-empty line retention (>= 95% on modules with >= 20 lines)
between a baseline source tree and a speculative candidate patch tree before
permitting autonomous merge.

Requirement Traceability:
- REQ-ISO-DUALTREE-01: Dual-Tree AST Parity & Speculative Patch Verification Oracle
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

REQ_TAG_PATTERN = re.compile(r"\bREQ-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")


def _count_non_empty_lines(source: str) -> int:
    """Count non-empty, non-whitespace lines in a source string (REQ-ISO-DUALTREE-01)."""
    return sum(1 for line in source.splitlines() if line.strip())


def _extract_top_level_symbols(tree: ast.Module) -> set[str]:
    """Extract top-level class and function names from a parsed AST module (REQ-ISO-DUALTREE-01)."""
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.add(node.name)
    return symbols


def _extract_req_tags(source: str) -> set[str]:
    """Extract all REQ-* identifier tags from a source string (REQ-ISO-DUALTREE-01)."""
    return set(REQ_TAG_PATTERN.findall(source))


class DualTreeVerificationOracle:
    """Evaluates AST parity and dual-tree test health for speculative patches (REQ-ISO-DUALTREE-01)."""

    def __init__(
        self,
        min_retention_ratio: float = 0.95,
        min_lines_for_retention_gate: int = 20,
    ) -> None:
        """Initialize the dual-tree verification oracle thresholds (REQ-ISO-DUALTREE-01)."""
        self.min_retention_ratio = float(min_retention_ratio)
        self.min_lines_for_retention_gate = int(min_lines_for_retention_gate)

    def compare_ast_trees(
        self,
        baseline_files: Mapping[str, str],
        mutated_files: Mapping[str, str],
    ) -> dict[str, Any]:
        """Compare baseline and mutated source trees for AST symbol, REQ tag, syntax, and line parity (REQ-ISO-DUALTREE-01)."""
        missing_symbols: set[str] = set()
        missing_req_tags: set[str] = set()
        syntax_errors: list[str] = []
        file_retentions: list[float] = []
        retention_gate_failed = False

        all_paths = sorted(set(baseline_files.keys()) | set(mutated_files.keys()))
        for path in all_paths:
            base_src = baseline_files.get(path, "")
            mut_src = mutated_files.get(path)

            base_reqs = _extract_req_tags(base_src)
            base_lines = _count_non_empty_lines(base_src)

            base_symbols: set[str] = set()
            if base_src:
                try:
                    base_tree = ast.parse(base_src, filename=path)
                    base_symbols = _extract_top_level_symbols(base_tree)
                except SyntaxError as exc:
                    syntax_errors.append(f"baseline:{path}:{exc.lineno}:{exc.msg}")

            if mut_src is None:
                missing_symbols.update(base_symbols)
                missing_req_tags.update(base_reqs)
                file_retentions.append(0.0 if base_lines > 0 else 1.0)
                if base_lines >= self.min_lines_for_retention_gate:
                    retention_gate_failed = True
                continue

            mut_reqs = _extract_req_tags(mut_src)
            missing_req_tags.update(base_reqs - mut_reqs)

            mut_lines = _count_non_empty_lines(mut_src)
            ratio = (float(mut_lines) / float(base_lines)) if base_lines > 0 else 1.0
            file_retentions.append(ratio)
            if base_lines >= self.min_lines_for_retention_gate and ratio < self.min_retention_ratio:
                retention_gate_failed = True

            try:
                mut_tree = ast.parse(mut_src, filename=path)
                mut_symbols = _extract_top_level_symbols(mut_tree)
                missing_symbols.update(base_symbols - mut_symbols)
            except SyntaxError as exc:
                syntax_errors.append(f"{path}:{exc.lineno}:{exc.msg}")
                missing_symbols.update(base_symbols)

        overall_retention = min(file_retentions) if file_retentions else 1.0
        parity_passed = (
            len(missing_symbols) == 0
            and len(missing_req_tags) == 0
            and len(syntax_errors) == 0
            and not retention_gate_failed
        )

        return {
            "parity_passed": parity_passed,
            "missing_symbols": sorted(missing_symbols),
            "missing_req_tags": sorted(missing_req_tags),
            "syntax_errors": syntax_errors,
            "retention_ratio": round(overall_retention, 6),
        }

    def evaluate_speculative_patch(
        self,
        baseline_files: Mapping[str, str],
        candidate_patch_files: Mapping[str, str],
        test_evaluator: Callable[[Mapping[str, str]], bool] | None = None,
    ) -> dict[str, Any]:
        """Run dual-tree verification across baseline and candidate patch trees and issue a SHA-256 receipt (REQ-ISO-DUALTREE-01)."""
        baseline_syntax_ok = True
        for path, src in baseline_files.items():
            try:
                ast.parse(src, filename=path)
            except SyntaxError:
                baseline_syntax_ok = False
                break

        baseline_eval_ok = True if test_evaluator is None else bool(test_evaluator(baseline_files))
        baseline_healthy = baseline_syntax_ok and baseline_eval_ok

        parity_report = self.compare_ast_trees(baseline_files, candidate_patch_files)
        if not parity_report["parity_passed"]:
            candidate_healthy = False
        else:
            candidate_healthy = (
                True if test_evaluator is None else bool(test_evaluator(candidate_patch_files))
            )

        verdict = (
            "APPROVE_MERGE"
            if (baseline_healthy and candidate_healthy and parity_report["parity_passed"])
            else "REJECT_ROLLBACK"
        )

        receipt_payload = {
            "baseline_files_sha256": {
                k: hashlib.sha256(v.encode("utf-8")).hexdigest()
                for k, v in sorted(baseline_files.items())
            },
            "candidate_files_sha256": {
                k: hashlib.sha256(v.encode("utf-8")).hexdigest()
                for k, v in sorted(candidate_patch_files.items())
            },
            "baseline_healthy": baseline_healthy,
            "candidate_healthy": candidate_healthy,
            "parity_passed": parity_report["parity_passed"],
            "verdict": verdict,
        }
        receipt_sha256 = hashlib.sha256(
            json.dumps(receipt_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return {
            "verdict": verdict,
            "baseline_healthy": baseline_healthy,
            "candidate_healthy": candidate_healthy,
            "ast_parity": parity_report,
            "oracle_receipt_sha256": receipt_sha256,
        }
