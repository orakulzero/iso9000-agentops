"""AST-Based Specification-to-Code Drift Detector for ISO 9001:2015 AgentOps (REQ-ISO-DRIFT-01).

Audits technical specifications and implementation plans against repository AST
symbols, file paths, and callable parameter signatures to prevent documentation drift.

@requirement("REQ-ISO-DRIFT-01")
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re

INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
FILE_PATH_RE = re.compile(
    r"^(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:py|md|json|toml|ya?ml|sh|ps1)$"
    r"|^[A-Za-z0-9_.-]+\.(?:py|json|toml|ya?ml)$"
)
CALL_SIG_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\((.*)\)$")
BARE_SYMBOL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)$")
IGNORED_WORDS = {"True", "False", "None", "pytest", "git", "main", "python", "pip"}


@dataclass(frozen=True)
class SpecDriftReport:
    """Immutable report of specification-to-code synchronization audit.

    @requirement("REQ-ISO-DRIFT-01")
    """

    in_sync: bool
    missing_files: list[str]
    missing_symbols: list[str]
    signature_mismatches: list[str]
    checked_files_count: int
    checked_symbols_count: int


class SpecCodeDriftDetector:
    """Verifies that files, symbols, and signatures referenced in a spec exist in code.

    @requirement("REQ-ISO-DRIFT-01")
    """

    def _collect_repo_ast_index(
        self, repo_root: Path, candidate_files: list[Path]
    ) -> tuple[set[str], dict[str, list[tuple[str, ...]]]]:
        """Index class/function symbols and callable parameter tuples from Python files.

        @requirement("REQ-ISO-DRIFT-01")
        """
        symbols: set[str] = set()
        signatures: dict[str, list[tuple[str, ...]]] = {}
        py_files = list(candidate_files) or (
            [p for p in sorted(repo_root.rglob("*.py")) if ".git" not in p.parts and "__pycache__" not in p.parts]
            if repo_root.is_dir()
            else []
        )

        def _record_callable(name: str, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            symbols.add(name)
            raw_args = [a.arg for a in node.args.posonlyargs + node.args.args]
            stripped_args = raw_args[1:] if raw_args and raw_args[0] in ("self", "cls") else raw_args
            sig_list = signatures.setdefault(name, [])
            for candidate in (tuple(stripped_args), tuple(raw_args)):
                if candidate not in sig_list:
                    sig_list.append(candidate)

        for py_file in py_files:
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, SyntaxError):
                continue
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    symbols.add(node.name)
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            _record_callable(item.name, item)
                            _record_callable(f"{node.name}.{item.name}", item)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _record_callable(node.name, node)

        return symbols, signatures

    def _parse_spec_params(self, raw_params: str) -> tuple[str, ...]:
        """Normalize parameter list string from a specification call signature.

        @requirement("REQ-ISO-DRIFT-01")
        """
        if not raw_params.strip():
            return ()
        cleaned: list[str] = []
        for token in raw_params.split(","):
            part = token.strip()
            if not part or part in ("*", "/"):
                continue
            part = part.split("=", 1)[0].split(":", 1)[0].strip().lstrip("*")
            if part and part not in ("self", "cls"):
                cleaned.append(part)
        return tuple(cleaned)

    def audit_spec_against_repo(self, spec_markdown: str, repo_root: Path | str) -> SpecDriftReport:
        """Audit inline file paths, symbols, and callable signatures against repo_root.

        @requirement("REQ-ISO-DRIFT-01")
        """
        root = Path(repo_root).resolve()
        spans = [m.strip() for m in INLINE_CODE_RE.findall(spec_markdown or "") if m.strip()]

        ref_files: list[str] = []
        existing_py_files: list[Path] = []
        missing_files: list[str] = []
        call_checks: list[tuple[str, tuple[str, ...]]] = []
        bare_checks: list[str] = []

        for span in spans:
            if FILE_PATH_RE.match(span):
                if span not in ref_files:
                    ref_files.append(span)
                    target = root / span
                    if target.is_file():
                        if target.suffix == ".py":
                            existing_py_files.append(target)
                    else:
                        missing_files.append(span)
                continue
            call_match = CALL_SIG_RE.match(span)
            if call_match:
                call_checks.append((call_match.group(1), self._parse_spec_params(call_match.group(2))))
                continue
            sym_match = BARE_SYMBOL_RE.match(span)
            if sym_match and sym_match.group(1) not in IGNORED_WORDS and sym_match.group(1) not in bare_checks:
                bare_checks.append(sym_match.group(1))

        symbols, signatures = self._collect_repo_ast_index(root, existing_py_files)
        missing_symbols = [sym for sym in bare_checks if sym not in symbols]
        signature_mismatches: list[str] = []

        for fn_name, expected_params in call_checks:
            if fn_name not in symbols:
                if fn_name not in missing_symbols:
                    missing_symbols.append(fn_name)
                continue
            valid_sigs = signatures.get(fn_name, [])
            if expected_params not in valid_sigs:
                actual_str = ", ".join(valid_sigs[0]) if valid_sigs else ""
                signature_mismatches.append(f"{fn_name}: spec({', '.join(expected_params)}) != code({actual_str})")

        in_sync = not missing_files and not missing_symbols and not signature_mismatches
        return SpecDriftReport(
            in_sync=in_sync,
            missing_files=missing_files,
            missing_symbols=missing_symbols,
            signature_mismatches=signature_mismatches,
            checked_files_count=len(ref_files),
            checked_symbols_count=len(bare_checks) + len(call_checks),
        )
