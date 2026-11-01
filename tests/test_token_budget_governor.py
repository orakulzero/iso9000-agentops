"""Locked Agile V (P30) Verification Suite for Real-Time Token Budget Governor.

Requirement Traceability:
- REQ-ISO-BUDGET-01: Real-Time Token Budget Governor (`token_budget_governor.py`)

Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from iso9000_agentops.token_budget_governor import (  # noqa: E402
    TokenBudgetGovernor,
    ToolBudgetDecision,
)


def test_within_budget_payload_passes_untouched() -> None:
    """REQ-ISO-BUDGET-01: Verify payload within per-call and burst token budget passes untouched."""
    gov = TokenBudgetGovernor(
        max_tokens_per_call=500,
        max_tokens_per_burst=1500,
        burst_window_sec=60.0,
    )
    payload = "A" * 100
    decision = gov.enforce_tool_output_budget("read_file", payload)
    assert isinstance(decision, ToolBudgetDecision)
    assert decision.truncated is False
    assert decision.burst_throttled is False
    assert decision.output_text == payload
    assert decision.tokens_saved == 0


def test_oversized_single_tool_output_truncated_preserving_head_and_tail() -> None:
    """REQ-ISO-BUDGET-01: Verify oversized payload is truncated while preserving head, tail, and marker."""
    gov = TokenBudgetGovernor(
        max_tokens_per_call=200,
        max_tokens_per_burst=2000,
        burst_window_sec=60.0,
    )
    payload = "HEAD_ANCHOR_" + ("X" * 9970) + "_TAIL_ANCHOR"
    assert len(payload) >= 9990
    decision = gov.enforce_tool_output_budget("read_file", payload)
    assert decision.truncated is True
    assert decision.output_text.startswith("HEAD_ANCHOR_")
    assert decision.output_text.endswith("_TAIL_ANCHOR")
    assert "[TOKEN_BUDGET_GOVERNOR: TRUNCATED" in decision.output_text
    assert decision.tokens_saved > 0
    assert decision.final_tokens <= 250


def test_burst_window_throttles_cumulative_tool_invocations() -> None:
    """REQ-ISO-BUDGET-01: Verify cumulative tool invocations exceeding max_tokens_per_burst trigger burst throttling."""
    gov = TokenBudgetGovernor(
        max_tokens_per_call=400,
        max_tokens_per_burst=600,
        burst_window_sec=60.0,
    )
    chunk = "B" * 1400  # ~350 tokens
    d1 = gov.enforce_tool_output_budget("search_code", chunk)
    assert d1.burst_throttled is False

    # Second call pushes cumulative tokens above 600 burst limit
    d2 = gov.enforce_tool_output_budget("search_code", chunk)
    assert d2.burst_throttled is True
    assert d2.truncated is True


def test_python_source_budget_preserves_ast_signatures_when_truncated() -> None:
    """REQ-ISO-BUDGET-01: Verify truncated Python source preserves AST function and class signatures."""
    gov = TokenBudgetGovernor(
        max_tokens_per_call=180,
        max_tokens_per_burst=2000,
        burst_window_sec=60.0,
    )
    body_lines = "\n".join(f"    step_{i} = {i} * 2" for i in range(250))
    py_payload = (
        "def alpha(x: int) -> int:\n"
        f"{body_lines}\n"
        "    return x\n\n"
        "class Beta:\n"
        "    def execute(self) -> str:\n"
        "        return 'done'\n"
    )
    decision = gov.enforce_tool_output_budget("read_file", py_payload)
    assert decision.truncated is True
    assert "[TOKEN_BUDGET_GOVERNOR: TRUNCATED" in decision.output_text
    assert "alpha" in decision.output_text
    assert "Beta" in decision.output_text


def test_telemetry_snapshot_tracks_saved_tokens() -> None:
    """REQ-ISO-BUDGET-01: Verify get_budget_telemetry returns call counts, saved tokens, and burst tokens."""
    gov = TokenBudgetGovernor(
        max_tokens_per_call=150,
        max_tokens_per_burst=1000,
        burst_window_sec=60.0,
    )
    gov.enforce_tool_output_budget("read_file", "short text")
    gov.enforce_tool_output_budget("read_file", "Z" * 5000)

    telemetry = gov.get_budget_telemetry()
    assert telemetry["total_calls"] == 2
    assert telemetry["truncated_calls"] == 1
    assert telemetry["tokens_saved"] > 0
    assert telemetry["active_burst_tokens"] > 0


def test_req_iso_budget_01_traceability_and_english_hygiene() -> None:
    """REQ-ISO-BUDGET-01: Verify token_budget_governor.py contains REQ-ISO-BUDGET-01 and 0 Cyrillic chars."""
    target_file = REPO_ROOT / "iso9000_agentops" / "token_budget_governor.py"
    assert target_file.is_file(), f"Missing target module: {target_file}"
    content = target_file.read_text(encoding="utf-8")
    assert "REQ-ISO-BUDGET-01" in content
    for ch in content:
        code = ord(ch)
        assert not (0x0400 <= code <= 0x04FF), f"Cyrillic character found: {ch!r}"
