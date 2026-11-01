"""Real-Time Token Budget Governor (REQ-ISO-BUDGET-01).

Enforces per-call and sliding-window burst token budgets on tool outputs,
preserving head/tail anchors and Python AST symbol signatures when truncating.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import time
from typing import Any


@dataclass(frozen=True)
class ToolBudgetDecision:
    """Represents the outcome of enforcing a token budget on a tool payload (REQ-ISO-BUDGET-01)."""

    tool_name: str
    output_text: str
    original_tokens: int
    final_tokens: int
    tokens_saved: int
    truncated: bool
    burst_throttled: bool


class TokenBudgetGovernor:
    """Governs per-call and burst token consumption across tool invocations (REQ-ISO-BUDGET-01)."""

    def __init__(
        self,
        max_tokens_per_call: int = 500,
        max_tokens_per_burst: int = 2000,
        burst_window_sec: float = 60.0,
    ) -> None:
        """Initialize token budget thresholds and telemetry counters (REQ-ISO-BUDGET-01)."""
        self.max_tokens_per_call = max(16, int(max_tokens_per_call))
        self.max_tokens_per_burst = max(self.max_tokens_per_call, int(max_tokens_per_burst))
        self.burst_window_sec = max(1.0, float(burst_window_sec))
        self._burst_events: list[tuple[float, int]] = []
        self._total_calls = 0
        self._truncated_calls = 0
        self._burst_throttled_calls = 0
        self._total_tokens_saved = 0

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token count using deterministic 4-char heuristic (REQ-ISO-BUDGET-01)."""
        if not text:
            return 0
        return max(1, (len(text) + 3) // 4)

    @staticmethod
    def _extract_ast_signature_hint(payload: str) -> str:
        """Extract top-level Python AST symbol names if payload is valid Python (REQ-ISO-BUDGET-01)."""
        try:
            tree = ast.parse(payload)
        except SyntaxError:
            return ""
        names: list[str] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(node.name)
        if not names:
            return ""
        joined = ", ".join(names[:12])
        return f" | AST symbols: {joined}"

    def _prune_burst_window(self, now: float) -> int:
        """Remove expired burst window events and return active burst tokens (REQ-ISO-BUDGET-01)."""
        cutoff = now - self.burst_window_sec
        self._burst_events = [(ts, tok) for ts, tok in self._burst_events if ts >= cutoff]
        return sum(tok for _, tok in self._burst_events)

    def enforce_tool_output_budget(
        self,
        tool_name: str,
        payload: str,
    ) -> ToolBudgetDecision:
        """Enforce per-call and burst token limits on a tool output string (REQ-ISO-BUDGET-01)."""
        now = time.monotonic()
        active_burst = self._prune_burst_window(now)
        original_tokens = self._estimate_tokens(payload)

        burst_throttled = (active_burst + original_tokens) > self.max_tokens_per_burst
        if burst_throttled:
            remaining_burst = max(32, self.max_tokens_per_burst - active_burst)
            effective_limit = min(self.max_tokens_per_call, remaining_burst, max(32, original_tokens // 2))
        else:
            effective_limit = self.max_tokens_per_call

        self._total_calls += 1

        if original_tokens <= effective_limit and not burst_throttled:
            self._burst_events.append((now, original_tokens))
            return ToolBudgetDecision(
                tool_name=tool_name,
                output_text=payload,
                original_tokens=original_tokens,
                final_tokens=original_tokens,
                tokens_saved=0,
                truncated=False,
                burst_throttled=False,
            )

        ast_hint = self._extract_ast_signature_hint(payload)
        omitted_est = max(1, original_tokens - effective_limit)
        marker = f"\n...[TOKEN_BUDGET_GOVERNOR: TRUNCATED ~{omitted_est} tokens{ast_hint}]...\n"

        target_chars = max(len(marker) + 32, effective_limit * 4)
        avail_chars = max(32, target_chars - len(marker))
        head_chars = avail_chars // 2
        tail_chars = avail_chars - head_chars

        output_text = payload[:head_chars] + marker + payload[-tail_chars:]
        final_tokens = self._estimate_tokens(output_text)
        tokens_saved = max(1, original_tokens - final_tokens)

        self._truncated_calls += 1
        if burst_throttled:
            self._burst_throttled_calls += 1
        self._total_tokens_saved += tokens_saved
        self._burst_events.append((now, final_tokens))

        return ToolBudgetDecision(
            tool_name=tool_name,
            output_text=output_text,
            original_tokens=original_tokens,
            final_tokens=final_tokens,
            tokens_saved=tokens_saved,
            truncated=True,
            burst_throttled=burst_throttled,
        )

    def get_budget_telemetry(self) -> dict[str, Any]:
        """Return cumulative token governor telemetry snapshot (REQ-ISO-BUDGET-01)."""
        active_burst = self._prune_burst_window(time.monotonic())
        return {
            "total_calls": self._total_calls,
            "truncated_calls": self._truncated_calls,
            "burst_throttled_calls": self._burst_throttled_calls,
            "tokens_saved": self._total_tokens_saved,
            "active_burst_tokens": active_burst,
            "max_tokens_per_call": self.max_tokens_per_call,
            "max_tokens_per_burst": self.max_tokens_per_burst,
        }
