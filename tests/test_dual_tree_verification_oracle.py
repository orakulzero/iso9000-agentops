"""Locked Agile V (P30) Verification Suite for Dual-Tree Verification Oracle.

Requirement Traceability:
- REQ-ISO-DUALTREE-01: Dual-Tree AST Parity & Speculative Patch Verification Oracle (`dual_tree_verification_oracle.py`)

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V Role Separation.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from iso9000_agentops.dual_tree_verification_oracle import (  # noqa: E402
    DualTreeVerificationOracle,
)


def _build_baseline_source() -> str:
    """Construct a valid >= 20 non-empty line Python module with symbols and REQ tags."""
    lines = [
        '"""Authentication service module (REQ-AUTH-01, REQ-AUTH-02)."""',
        "from __future__ import annotations",
        "class TokenValidator:",
        '    """REQ-AUTH-01: Token validator class."""',
        "    def __init__(self, secret: str) -> None:",
        "        self.secret = secret",
        "    def check_prefix(self, token: str) -> bool:",
        "        return token.startswith('tok_')",
        "def validate_token(token: str, secret: str) -> bool:",
        '    """REQ-AUTH-01: Validate authentication token."""',
        "    validator = TokenValidator(secret)",
        "    if not validator.check_prefix(token):",
        "        return False",
        "    return len(token) > len(secret)",
        "def refresh_session(session_id: str) -> str:",
        '    """REQ-AUTH-02: Refresh active session identifier."""',
        "    cleaned = session_id.strip()",
        "    if not cleaned:",
        "        return 'anon'",
        "    return f'refreshed:{cleaned}'",
        "DEFAULT_TIMEOUT_SEC = 30",
        "MAX_RETRY_LIMIT = 3",
    ]
    return "\n".join(lines) + "\n"


def test_compare_ast_trees_passes_compliant_mutation() -> None:
    """REQ-ISO-DUALTREE-01: Verify compliant AST mutation preserving symbols, REQ tags, syntax, and >= 95% line retention passes."""
    oracle = DualTreeVerificationOracle()
    baseline_src = _build_baseline_source()
    mutated_src = baseline_src + "AUDIT_ENABLED = True\n"

    baseline_files = {"src/auth.py": baseline_src}
    mutated_files = {"src/auth.py": mutated_src}

    res = oracle.compare_ast_trees(baseline_files, mutated_files)
    assert res["parity_passed"] is True
    assert res["missing_symbols"] == []
    assert res["missing_req_tags"] == []
    assert res["syntax_errors"] == []
    assert res["retention_ratio"] >= 0.95


def test_compare_ast_trees_detects_missing_symbols_and_req_tags() -> None:
    """REQ-ISO-DUALTREE-01: Verify compare_ast_trees flags missing top-level function validate_token and missing tag REQ-AUTH-01."""
    oracle = DualTreeVerificationOracle()
    baseline_files = {"src/auth.py": _build_baseline_source()}
    mutated_files = {
        "src/auth.py": (
            '"""Authentication service module (REQ-AUTH-02)."""\n'
            "from __future__ import annotations\n"
            "class TokenValidator:\n"
            "    def __init__(self, secret: str) -> None:\n"
            "        self.secret = secret\n"
            "    def check_prefix(self, token: str) -> bool:\n"
            "        return token.startswith('tok_')\n"
            "def refresh_session(session_id: str) -> str:\n"
            '    """REQ-AUTH-02: Refresh active session identifier."""\n'
            "    cleaned = session_id.strip()\n"
            "    if not cleaned:\n"
            "        return 'anon'\n"
            "    return f'refreshed:{cleaned}'\n"
            "DEFAULT_TIMEOUT_SEC = 30\n"
            "MAX_RETRY_LIMIT = 3\n"
            "EXTRA_PAD_1 = 1\n"
            "EXTRA_PAD_2 = 2\n"
            "EXTRA_PAD_3 = 3\n"
            "EXTRA_PAD_4 = 4\n"
            "EXTRA_PAD_5 = 5\n"
            "EXTRA_PAD_6 = 6\n"
            "EXTRA_PAD_7 = 7\n"
        )
    }

    res = oracle.compare_ast_trees(baseline_files, mutated_files)
    assert res["parity_passed"] is False
    assert "validate_token" in res["missing_symbols"]
    assert "REQ-AUTH-01" in res["missing_req_tags"]


def test_compare_ast_trees_detects_syntax_error_and_line_drop() -> None:
    """REQ-ISO-DUALTREE-01: Verify compare_ast_trees rejects SyntaxError mutations and < 95% line retention on >= 20-line files."""
    oracle = DualTreeVerificationOracle()
    baseline_files = {"src/auth.py": _build_baseline_source()}

    syntax_broken_files = {"src/auth.py": _build_baseline_source() + "def broken_syntax(:\n"}
    res_syntax = oracle.compare_ast_trees(baseline_files, syntax_broken_files)
    assert res_syntax["parity_passed"] is False
    assert len(res_syntax["syntax_errors"]) >= 1

    truncated_files = {
        "src/auth.py": (
            '"""REQ-AUTH-01 REQ-AUTH-02"""\n'
            "class TokenValidator:\n"
            "    pass\n"
            "def validate_token(token: str, secret: str) -> bool:\n"
            "    return True\n"
            "def refresh_session(session_id: str) -> str:\n"
            "    return session_id\n"
        )
    }
    res_drop = oracle.compare_ast_trees(baseline_files, truncated_files)
    assert res_drop["parity_passed"] is False
    assert res_drop["retention_ratio"] < 0.95


def test_evaluate_speculative_patch_approves_healthy_dual_tree() -> None:
    """REQ-ISO-DUALTREE-01: Verify evaluate_speculative_patch returns APPROVE_MERGE and 64-char SHA-256 receipt when healthy."""
    oracle = DualTreeVerificationOracle()
    baseline_files = {"src/auth.py": _build_baseline_source()}
    candidate_patch_files = {"src/auth.py": _build_baseline_source() + "PATCH_APPLIED = True\n"}

    res = oracle.evaluate_speculative_patch(
        baseline_files,
        candidate_patch_files,
        test_evaluator=lambda files: True,
    )
    assert res["verdict"] == "APPROVE_MERGE"
    assert res["baseline_healthy"] is True
    assert res["candidate_healthy"] is True
    assert isinstance(res["oracle_receipt_sha256"], str)
    assert len(res["oracle_receipt_sha256"]) == 64


def test_evaluate_speculative_patch_rejects_broken_candidate_tree() -> None:
    """REQ-ISO-DUALTREE-01: Verify evaluate_speculative_patch returns REJECT_ROLLBACK when AST parity fails or test_evaluator returns False."""
    oracle = DualTreeVerificationOracle()
    baseline_files = {"src/auth.py": _build_baseline_source()}
    broken_ast_files = {"src/auth.py": "def only_one_func() -> None:\n    pass\n"}

    res_ast_fail = oracle.evaluate_speculative_patch(
        baseline_files,
        broken_ast_files,
        test_evaluator=lambda files: True,
    )
    assert res_ast_fail["verdict"] == "REJECT_ROLLBACK"
    assert res_ast_fail["candidate_healthy"] is False

    compliant_files = {"src/auth.py": _build_baseline_source() + "FAIL_RUNTIME = True\n"}
    res_eval_fail = oracle.evaluate_speculative_patch(
        baseline_files,
        compliant_files,
        test_evaluator=lambda files: "FAIL_RUNTIME" not in files["src/auth.py"],
    )
    assert res_eval_fail["verdict"] == "REJECT_ROLLBACK"
    assert res_eval_fail["candidate_healthy"] is False
