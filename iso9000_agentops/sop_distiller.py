"""DeepTutor SOP Curriculum DAG Distiller for ISO 9001:2015 AgentOps (REQ-ISO-DEEPTUTOR-01).

Distills Markdown Standard Operating Procedures (SOPs) into topologically validated,
frozen Directed Acyclic Graph (DAG) curriculum nodes with requirement traceability.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Sequence

REQ_ID_PATTERN = re.compile(r"\b(REQ-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b")
HEADING_STEP_RE = re.compile(r"^\s*#{2,6}\s+(.+?)\s*$")
LIST_STEP_RE = re.compile(r"^\s*\d+[.)]\s+(.+?)\s*$")
EXPLICIT_NODE_ID_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*)\s*:\s*(.+)$")
DEPENDS_ON_RE = re.compile(r"^\s*depends-on\s*:\s*(.+?)\s*$", re.IGNORECASE)
ASSERTION_RE = re.compile(r"^\s*(?:verify|assertion)\s*:\s*(.+?)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class SOPNode:
    """Immutable Standard Operating Procedure DAG node (REQ-ISO-DEEPTUTOR-01)."""

    node_id: str
    title: str
    prerequisite_ids: tuple[str, ...]
    verification_assertion: str
    req_id: str


class DeepTutorSOPDistiller:
    """Distills Markdown SOP specifications into verified curriculum DAGs (REQ-ISO-DEEPTUTOR-01)."""

    def distill_markdown_to_sop_dag(
        self,
        markdown_spec: str,
        default_req_prefix: str = "REQ-SOP",
    ) -> list[SOPNode]:
        """Parse Markdown into a validated, cycle-free list of SOPNode instances (REQ-ISO-DEEPTUTOR-01)."""
        if not isinstance(markdown_spec, str) or not markdown_spec.strip():
            raise ValueError("Markdown SOP specification must be a non-empty string.")

        raw_steps: list[tuple[str, list[str]]] = []
        current_header: str | None = None
        current_body: list[str] = []

        for raw_line in markdown_spec.splitlines():
            m = HEADING_STEP_RE.match(raw_line) or LIST_STEP_RE.match(raw_line)
            if m is not None:
                if current_header is not None:
                    raw_steps.append((current_header, current_body))
                current_header = m.group(1).strip()
                current_body = []
            elif current_header is not None:
                current_body.append(raw_line)

        if current_header is not None:
            raw_steps.append((current_header, current_body))
        if not raw_steps:
            raise ValueError("No extractable SOP steps found in Markdown specification.")

        prefix = default_req_prefix.strip().rstrip("-") or "REQ-SOP"
        nodes: list[SOPNode] = []

        for idx, (header_text, body_lines) in enumerate(raw_steps, start=1):
            id_match = EXPLICIT_NODE_ID_RE.match(header_text)
            node_id = id_match.group(1).strip() if id_match else f"step-{idx}"
            title_raw = id_match.group(2).strip() if id_match else header_text.strip()

            combined_text = f"{header_text}\n" + "\n".join(body_lines)
            req_match = REQ_ID_PATTERN.search(combined_text)
            req_id = req_match.group(1) if req_match else f"{prefix}-{idx:02d}"

            clean_title = re.sub(r"\s*\(\s*REQ-[A-Z0-9-]+\s*\)\s*", " ", title_raw).strip() or title_raw
            explicit_deps: list[str] | None = None
            assertion_text: str | None = None
            prose_lines: list[str] = []

            for line in body_lines:
                dep_match = DEPENDS_ON_RE.match(line)
                if dep_match is not None:
                    raw_dep = dep_match.group(1).strip()
                    explicit_deps = (
                        []
                        if raw_dep.lower() in ("none", "null", "-", "")
                        else [t.strip() for t in re.split(r"[,\s]+", raw_dep) if t.strip()]
                    )
                    continue
                assert_match = ASSERTION_RE.match(line)
                if assert_match is not None:
                    assertion_text = assert_match.group(1).strip()
                    continue
                stripped = line.strip()
                if stripped.startswith("assert "):
                    assertion_text = stripped
                elif stripped:
                    prose_lines.append(stripped)

            prereqs = (
                tuple(explicit_deps)
                if explicit_deps is not None
                else (() if idx == 1 else (nodes[-1].node_id,))
            )
            if not assertion_text:
                summary = prose_lines[0] if prose_lines else clean_title
                assertion_text = f"assert verify_sop_step({node_id!r}, {req_id!r})  # {summary}"

            nodes.append(SOPNode(node_id, clean_title, prereqs, assertion_text, req_id))

        self._validate_dag(nodes)
        return nodes

    def _validate_dag(self, nodes: Sequence[SOPNode]) -> None:
        """Verify prerequisite existence and absence of cycles in the SOP DAG (REQ-ISO-DEEPTUTOR-01)."""
        node_map: dict[str, SOPNode] = {}
        for node in nodes:
            if node.node_id in node_map:
                raise ValueError(f"Duplicate SOP node_id detected: {node.node_id}")
            node_map[node.node_id] = node

        for node in nodes:
            for prereq_id in node.prerequisite_ids:
                if prereq_id not in node_map:
                    raise ValueError(f"Unknown prerequisite {prereq_id!r} in {node.node_id!r}.")

        state: dict[str, int] = {node.node_id: 0 for node in nodes}

        def _dfs(nid: str) -> None:
            state[nid] = 1
            for prereq in node_map[nid].prerequisite_ids:
                if state[prereq] == 1:
                    raise ValueError(f"Cycle detected in SOP DAG involving {nid!r} -> {prereq!r}.")
                if state[prereq] == 0:
                    _dfs(prereq)
            state[nid] = 2

        for node in nodes:
            if state[node.node_id] == 0:
                _dfs(node.node_id)

    def evaluate_mastery_progress(
        self,
        nodes: Sequence[SOPNode],
        passed_node_ids: Iterable[str],
    ) -> dict[str, Any]:
        """Compute mastery percentage, unlocked next nodes, and blocked nodes (REQ-ISO-DEEPTUTOR-01)."""
        passed_set = set(passed_node_ids)
        total_nodes = len(nodes)
        mastered_nodes = [n.node_id for n in nodes if n.node_id in passed_set]
        mastered_count = len(mastered_nodes)
        mastery_pct = round((mastered_count / float(total_nodes)) * 100.0, 4) if total_nodes > 0 else 0.0

        unlocked_next_nodes = [
            n.node_id
            for n in nodes
            if n.node_id not in passed_set and all(p in passed_set for p in n.prerequisite_ids)
        ]
        blocked_nodes = [
            n.node_id
            for n in nodes
            if n.node_id not in passed_set and not all(p in passed_set for p in n.prerequisite_ids)
        ]

        return {
            "total_nodes": total_nodes,
            "mastered_count": mastered_count,
            "mastery_pct": mastery_pct,
            "mastered_nodes": mastered_nodes,
            "unlocked_next_nodes": unlocked_next_nodes,
            "blocked_nodes": blocked_nodes,
        }
