"""Bidirectional Agile V Requirements Traceability Matrix (RTM) Engine (REQ-ISO-201).

Implements ISO 9001:2015 Clause 8.3 & Agile V (arXiv:2602.20684) bidirectional
requirements traceability across requirement specifications, AST production code
symbols, verification tests, and W3C PROV-DM evidence units.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REQ_ID_RE = re.compile(r"\bREQ-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")


def _iter_python_files(root: Path | str) -> list[Path]:
    """Return sorted list of Python files under root (REQ-ISO-201)."""
    target = Path(root).resolve()
    if target.is_file():
        return [target] if target.suffix == ".py" else []
    if not target.is_dir():
        return []
    files: list[Path] = []
    excluded = {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        ".supergraph",
        ".agents-learning",
        ".monitor",
        "node_modules",
    }
    for p in sorted(target.rglob("*.py")):
        if any(part in excluded for part in p.relative_to(target).parts):
            continue
        files.append(p)
    return files


def _extract_reqs_from_lines(
    lines: list[str],
    start_line: int,
    end_line: int,
    excluded_spans: list[tuple[int, int]] | None = None,
) -> list[str]:
    """Extract sorted deduplicated REQ IDs from 1-based line range [start_line, end_line] (REQ-ISO-201)."""
    spans = excluded_spans or []
    found: set[str] = set()
    lo = max(1, start_line)
    hi = min(len(lines), end_line)
    for lineno in range(lo, hi + 1):
        if any(ex_start <= lineno <= ex_end for ex_start, ex_end in spans):
            continue
        line_text = lines[lineno - 1]
        for match in REQ_ID_RE.findall(line_text):
            found.add(match)
    return sorted(found)


def _node_start_line(node: ast.AST) -> int:
    """Return 1-based starting line of an AST node including decorators (REQ-ISO-201)."""
    base = getattr(node, "lineno", 1)
    decorators = getattr(node, "decorator_list", None) or []
    dec_lines = [getattr(d, "lineno", base) for d in decorators]
    return min([base, *dec_lines])


def _node_end_line(node: ast.AST, default_end: int) -> int:
    """Return 1-based ending line of an AST node (REQ-ISO-201)."""
    return int(getattr(node, "end_lineno", None) or getattr(node, "lineno", default_end))


def extract_code_req_links(source_root: Path | str) -> list[dict[str, Any]]:
    """Scan Python source files via AST to extract module, class, function, and method REQ links (REQ-ISO-201)."""
    root_path = Path(source_root).resolve()
    base_dir = root_path.parent if root_path.is_file() else root_path
    results: list[dict[str, Any]] = []

    for py_file in _iter_python_files(root_path):
        try:
            source_text = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source_text, filename=str(py_file))
        except SyntaxError:
            continue

        lines = source_text.splitlines()
        rel_file = py_file.relative_to(base_dir).as_posix()

        # Collect top-level child spans so module-level scan excludes classes/functions
        top_child_spans: list[tuple[int, int]] = [
            (_node_start_line(top_node), _node_end_line(top_node, len(lines)))
            for top_node in tree.body
            if isinstance(top_node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        mod_reqs = _extract_reqs_from_lines(lines, 1, len(lines), top_child_spans)
        mod_doc = ast.get_docstring(tree) or ""
        for m in REQ_ID_RE.findall(mod_doc):
            if m not in mod_reqs:
                mod_reqs.append(m)
        mod_reqs = sorted(set(mod_reqs))
        if mod_reqs:
            results.append(
                {
                    "file": rel_file,
                    "symbol": py_file.stem,
                    "kind": "module",
                    "line": 1,
                    "req_ids": mod_reqs,
                }
            )

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                cls_start = _node_start_line(node)
                cls_end = _node_end_line(node, len(lines))
                method_spans: list[tuple[int, int]] = [
                    (_node_start_line(item), _node_end_line(item, cls_end))
                    for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                ]

                cls_reqs = _extract_reqs_from_lines(lines, cls_start, cls_end, method_spans)
                cls_doc = ast.get_docstring(node) or ""
                cls_reqs = sorted(set(cls_reqs) | set(REQ_ID_RE.findall(cls_doc)))
                results.append(
                    {
                        "file": rel_file,
                        "symbol": node.name,
                        "kind": "class",
                        "line": int(node.lineno),
                        "req_ids": cls_reqs,
                    }
                )

                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_start = _node_start_line(item)
                        m_end = _node_end_line(item, cls_end)
                        m_reqs = _extract_reqs_from_lines(lines, m_start, m_end)
                        m_doc = ast.get_docstring(item) or ""
                        m_reqs = sorted(set(m_reqs) | set(REQ_ID_RE.findall(m_doc)))
                        results.append(
                            {
                                "file": rel_file,
                                "symbol": f"{node.name}.{item.name}",
                                "kind": "method",
                                "line": int(item.lineno),
                                "req_ids": m_reqs,
                            }
                        )

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_start = _node_start_line(node)
                fn_end = _node_end_line(node, len(lines))
                fn_reqs = _extract_reqs_from_lines(lines, fn_start, fn_end)
                fn_doc = ast.get_docstring(node) or ""
                fn_reqs = sorted(set(fn_reqs) | set(REQ_ID_RE.findall(fn_doc)))
                results.append(
                    {
                        "file": rel_file,
                        "symbol": node.name,
                        "kind": "function",
                        "line": int(node.lineno),
                        "req_ids": fn_reqs,
                    }
                )

    return results


def extract_test_req_links(tests_root: Path | str) -> list[dict[str, Any]]:
    """Scan pytest files via AST to extract test functions/methods and linked REQ IDs (REQ-ISO-201)."""
    root_path = Path(tests_root).resolve()
    base_dir = root_path.parent if root_path.is_file() else root_path
    results: list[dict[str, Any]] = []

    for py_file in _iter_python_files(root_path):
        try:
            source_text = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source_text, filename=str(py_file))
        except SyntaxError:
            continue

        lines = source_text.splitlines()
        rel_file = py_file.relative_to(base_dir).as_posix()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                t_start = _node_start_line(node)
                t_end = _node_end_line(node, len(lines))
                t_reqs = _extract_reqs_from_lines(lines, t_start, t_end)
                t_doc = ast.get_docstring(node) or ""
                t_reqs = sorted(set(t_reqs) | set(REQ_ID_RE.findall(t_doc)))
                results.append(
                    {
                        "file": rel_file,
                        "test_name": node.name,
                        "line": int(node.lineno),
                        "req_ids": t_reqs,
                    }
                )
            elif isinstance(node, ast.ClassDef):
                cls_doc = ast.get_docstring(node) or ""
                cls_doc_reqs = set(REQ_ID_RE.findall(cls_doc))
                for item in node.body:
                    if isinstance(
                        item, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ) and item.name.startswith("test_"):
                        m_start = _node_start_line(item)
                        m_end = _node_end_line(item, len(lines))
                        m_reqs = _extract_reqs_from_lines(lines, m_start, m_end)
                        m_doc = ast.get_docstring(item) or ""
                        combined_reqs = sorted(
                            set(m_reqs) | set(REQ_ID_RE.findall(m_doc)) | cls_doc_reqs
                        )
                        results.append(
                            {
                                "file": rel_file,
                                "test_name": f"{node.name}.{item.name}",
                                "line": int(item.lineno),
                                "req_ids": combined_reqs,
                            }
                        )

    return results


def _normalize_requirements(requirements: Sequence[str | dict[str, Any]]) -> list[str]:
    """Normalize heterogeneous requirement specifications into a deduplicated list of REQ IDs (REQ-ISO-201)."""
    normalized: list[str] = []
    seen: set[str] = set()
    for item in requirements:
        candidates: list[str] = []
        if isinstance(item, dict):
            raw_id = str(item.get("id") or item.get("req_id") or "").strip()
            raw_text = str(item.get("text") or item.get("description") or "").strip()
            matches = REQ_ID_RE.findall(f"{raw_id} {raw_text}")
            if matches:
                candidates.extend(matches)
            elif raw_id:
                candidates.append(raw_id)
        elif isinstance(item, str):
            matches = REQ_ID_RE.findall(item)
            if matches:
                candidates.extend(matches)
            elif item.strip():
                candidates.append(item.strip())

        for req_id in candidates:
            if req_id not in seen:
                seen.add(req_id)
                normalized.append(req_id)
    return normalized


def build_requirements_traceability_matrix(
    requirements: Sequence[str | dict[str, Any]],
    source_root: Path | str,
    tests_root: Path | str,
    evidence_units: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a bidirectional Agile V Requirements Traceability Matrix (RTM) (REQ-ISO-201)."""
    req_list = _normalize_requirements(requirements)
    code_links = extract_code_req_links(source_root)
    test_links = extract_test_req_links(tests_root)
    ev_list = list(evidence_units or [])

    forward_trace: dict[str, dict[str, Any]] = {}
    for req_id in req_list:
        matched_code = sorted(
            {
                link["symbol"]
                for link in code_links
                if req_id in link.get("req_ids", [])
            }
        )
        matched_tests = sorted(
            {
                link["test_name"]
                for link in test_links
                if req_id in link.get("req_ids", [])
            }
        )
        matched_evidence: list[str] = []
        for ev in ev_list:
            if not isinstance(ev, dict):
                continue
            ev_reqs = ev.get("requirement_ids") or ev.get("req_ids") or []
            if req_id in ev_reqs:
                ev_hash = str(ev.get("stdout_sha256") or ev.get("evidence_id") or "")
                if ev_hash and ev_hash not in matched_evidence:
                    matched_evidence.append(ev_hash)

        forward_trace[req_id] = {
            "req_id": req_id,
            "code_symbols": matched_code,
            "test_names": matched_tests,
            "evidence_hashes": matched_evidence,
            "implemented": len(matched_code) > 0,
            "verified": len(matched_tests) > 0,
        }

    code_to_reqs: dict[str, list[str]] = {}
    for link in code_links:
        if link["req_ids"]:
            sym = str(link["symbol"])
            existing = set(code_to_reqs.get(sym, []))
            code_to_reqs[sym] = sorted(existing | set(link["req_ids"]))

    test_to_reqs: dict[str, list[str]] = {}
    for link in test_links:
        if link["req_ids"]:
            tname = str(link["test_name"])
            existing = set(test_to_reqs.get(tname, []))
            test_to_reqs[tname] = sorted(existing | set(link["req_ids"]))
            short_name = tname.split(".")[-1]
            if short_name not in test_to_reqs:
                test_to_reqs[short_name] = test_to_reqs[tname]

    orphan_requirements = [
        req_id for req_id in req_list if not forward_trace[req_id]["verified"]
    ]
    unimplemented_requirements = [
        req_id for req_id in req_list if not forward_trace[req_id]["implemented"]
    ]

    untraced_tests = sorted(
        {
            link["test_name"].split(".")[-1]
            for link in test_links
            if not link.get("req_ids")
        }
    )

    gold_plated_symbols = sorted(
        {
            link["symbol"]
            for link in code_links
            if link.get("kind") in ("class", "function", "method")
            and not link.get("req_ids")
            and not any(part.startswith("_") for part in str(link["symbol"]).split("."))
        }
    )

    if not req_list:
        coverage_ratio = 1.0
    else:
        fully_traced_count = sum(
            1
            for req_id in req_list
            if forward_trace[req_id]["implemented"] and forward_trace[req_id]["verified"]
        )
        coverage_ratio = fully_traced_count / float(len(req_list))

    compliant = len(orphan_requirements) == 0 and len(unimplemented_requirements) == 0

    return {
        "requirements": req_list,
        "forward_trace": forward_trace,
        "backward_trace": {
            "code_to_reqs": code_to_reqs,
            "test_to_reqs": test_to_reqs,
        },
        "orphan_requirements": orphan_requirements,
        "unimplemented_requirements": unimplemented_requirements,
        "untraced_tests": untraced_tests,
        "gold_plated_symbols": gold_plated_symbols,
        "coverage_ratio": coverage_ratio,
        "compliant": compliant,
    }


def render_rtm_markdown(rtm_report: dict[str, Any]) -> str:
    """Render a human-readable Markdown Requirements Traceability Matrix report (REQ-ISO-201)."""
    reqs: list[str] = list(rtm_report.get("requirements") or [])
    fwd: dict[str, dict[str, Any]] = rtm_report.get("forward_trace") or {}
    coverage = float(rtm_report.get("coverage_ratio", 0.0))
    compliant = bool(rtm_report.get("compliant", False))
    orphans = rtm_report.get("orphan_requirements") or []
    unimpl = rtm_report.get("unimplemented_requirements") or []
    gold = rtm_report.get("gold_plated_symbols") or []
    untraced = rtm_report.get("untraced_tests") or []

    lines: list[str] = [
        "# Agile V & ISO 9001:2015 Requirements Traceability Matrix (RTM)",
        "",
        f"- **Compliant**: `{compliant}`",
        f"- **Coverage Ratio**: `{coverage:.2%}`",
        f"- **Orphan Requirements**: `{', '.join(orphans) if orphans else 'None'}`",
        f"- **Unimplemented Requirements**: `{', '.join(unimpl) if unimpl else 'None'}`",
        f"- **Gold-Plated Symbols**: `{', '.join(gold) if gold else 'None'}`",
        f"- **Untraced Tests**: `{', '.join(untraced) if untraced else 'None'}`",
        "",
        "| REQ-ID | Code Symbols | Tests | Evidence | Status |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for req_id in reqs:
        node = fwd.get(req_id) or {}
        code_str = "<br>".join([f"`{c}`" for c in node.get("code_symbols", [])]) or "_None_"
        test_str = "<br>".join([f"`{t}`" for t in node.get("test_names", [])]) or "_None_"
        ev_str = "<br>".join([f"`{e[:8]}`" for e in node.get("evidence_hashes", [])]) or "_None_"
        
        status = "✅" if node.get("implemented") and node.get("verified") else "❌"
        if not node.get("implemented"):
            status += " (No Code)"
        elif not node.get("verified"):
            status += " (No Test)"
            
        lines.append(f"| **{req_id}** | {code_str} | {test_str} | {ev_str} | {status} |")

    return "\n".join(lines) + "\n"
