"""BabelArena Non-ASCII & Cyrillic Schema/AST Gate for ISO 9001:2015 AgentOps (REQ-ISO-BABEL-01).

Audits Python AST identifiers and recursive MCP JSON tool schemas for non-ASCII
identifier drift, Cyrillic characters (U+0400..U+04FF), and BPE token inflation.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re
from typing import Any, Mapping

CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
FALLBACK_IDENT_RE = re.compile(r"\b[^\W\d]\w*\b", re.UNICODE)


@dataclass(frozen=True)
class BabelAuditResult:
    """Immutable audit verdict from BabelArenaGate (REQ-ISO-BABEL-01)."""

    passed: bool
    non_ascii_identifiers: list[str]
    non_ascii_schema_keys: list[str]
    cyrillic_violations: int
    estimated_token_inflation_ratio: float


class BabelArenaGate:
    """Enforces 100% ASCII identifiers, schema keys, and zero Cyrillic drift (REQ-ISO-BABEL-01)."""

    def _estimate_inflation(self, text: str) -> float:
        """Compute estimated BPE token inflation ratio from non-ASCII byte expansion (REQ-ISO-BABEL-01)."""
        if not text:
            return 1.0
        non_ascii_chars = sum(1 for ch in text if ord(ch) > 127)
        if non_ascii_chars == 0:
            return 1.0
        cyrillic_chars = len(CYRILLIC_RE.findall(text))
        weighted_extra = (non_ascii_chars * 1.5) + (cyrillic_chars * 1.0)
        return round(1.0 + (weighted_extra / float(len(text))), 4)

    def audit_python_source(self, source_code: str) -> BabelAuditResult:
        """Audit Python source via AST for non-ASCII identifiers and Cyrillic characters (REQ-ISO-BABEL-01)."""
        text = source_code or ""
        non_ascii_Idents: list[str] = []
        seen: set[str] = set()

        def _record_ident(candidate: str | None) -> None:
            if candidate and not candidate.isascii() and candidate not in seen:
                seen.add(candidate)
                non_ascii_Idents.append(candidate)

        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    _record_ident(node.name)
                elif isinstance(node, ast.arg):
                    _record_ident(node.arg)
                elif isinstance(node, ast.Name):
                    _record_ident(node.id)
                elif isinstance(node, ast.Attribute):
                    _record_ident(node.attr)
                elif isinstance(node, ast.keyword):
                    _record_ident(node.arg)
                elif isinstance(node, ast.alias):
                    _record_ident(node.name)
                    _record_ident(node.asname)
        except SyntaxError:
            for match in FALLBACK_IDENT_RE.findall(text):
                _record_ident(match)

        cyrillic_count = len(CYRILLIC_RE.findall(text))
        inflation = self._estimate_inflation(text)
        passed = len(non_ascii_Idents) == 0 and cyrillic_count == 0

        return BabelAuditResult(
            passed=passed,
            non_ascii_identifiers=non_ascii_Idents,
            non_ascii_schema_keys=[],
            cyrillic_violations=cyrillic_count,
            estimated_token_inflation_ratio=inflation,
        )

    def audit_tool_schema(self, schema: Mapping[str, Any]) -> BabelAuditResult:
        """Recursively audit an MCP tool JSON schema for non-ASCII keys and Cyrillic strings (REQ-ISO-BABEL-01)."""
        non_ascii_keys: list[str] = []
        seen_keys: set[str] = set()
        text_fragments: list[str] = []

        def _walk(obj: Any) -> None:
            if isinstance(obj, Mapping):
                for raw_key, val in obj.items():
                    key_str = str(raw_key)
                    text_fragments.append(key_str)
                    if not key_str.isascii() and key_str not in seen_keys:
                        seen_keys.add(key_str)
                        non_ascii_keys.append(key_str)
                    _walk(val)
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    _walk(item)
            elif isinstance(obj, str):
                text_fragments.append(obj)

        _walk(schema)
        combined = " ".join(text_fragments)
        cyrillic_count = len(CYRILLIC_RE.findall(combined))
        inflation = self._estimate_inflation(combined)
        passed = len(non_ascii_keys) == 0 and cyrillic_count == 0

        return BabelAuditResult(
            passed=passed,
            non_ascii_identifiers=[],
            non_ascii_schema_keys=non_ascii_keys,
            cyrillic_violations=cyrillic_count,
            estimated_token_inflation_ratio=inflation,
        )
