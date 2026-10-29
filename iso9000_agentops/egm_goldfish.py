"""Google Elephant-Goldfish Model (EGM) Zero-Context Review Engine (REQ-ISO-EGM-01).

Separates stateful Elephant specification planning from stateless, zero-context
Goldfish adversarial reviewers across four structured rubric stages.

@requirement("REQ-ISO-EGM-01")
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

EGM_RUBRIC_STAGES: tuple[str, ...] = (
    "zoom_out",
    "comprehension",
    "design_critic",
    "implementation_readiness",
)

STAGE_RUBRIC_CHECKLISTS: dict[str, tuple[str, ...]] = {
    "zoom_out": (
        "Does the architecture solve the root problem with minimal complexity (YAGNI)?",
        "Can existing repository modules be reused instead of introducing new abstractions?",
        "Are component boundaries and data flows proportional to system scale?",
    ),
    "comprehension": (
        "Can a cold reader with zero prior chat context understand every term and acronym?",
        "Are all module responsibilities, inputs, and outputs unambiguously specified?",
        "Are edge cases and failure states explicitly documented without implicit assumptions?",
    ),
    "design_critic": (
        "What single points of failure, race conditions, or security boundaries remain unmitigated?",
        "Do data structures and interfaces enforce invariants at construction time?",
        "Are error handling paths deterministic and free of silent fallbacks?",
    ),
    "implementation_readiness": (
        "Are exact file paths, class names, and function signatures specified without ambiguity?",
        "Can an isolated build agent implement the spec without making ad-hoc design guesses?",
        "Are verification tests and acceptance criteria concrete and executable?",
    ),
}

SEVERITY_RANK: dict[str, int] = {"critical": 0, "major": 1, "minor": 2, "info": 3}
TOP_HEADING_RE = re.compile(r"^\s*#\s+(.+?)\s*$")
DETAILED_HEADING_RE = re.compile(
    r"^\s*#{1,3}\s+.*\b(detailed|implementation|module\s+signatures|step-by-step|verification\s+plan)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class GoldfishReviewPacket:
    """Immutable zero-context review packet for a single Goldfish rubric stage.

    @requirement("REQ-ISO-EGM-01")
    """

    stage: str
    spec_markdown: str
    feature_range_lines: tuple[int, int]
    detailed_range_lines: tuple[int, int]
    referenced_files: dict[str, str]
    rubric_checklist: tuple[str, ...]
    chat_history_stripped: bool = True


class GoldfishZeroContextBuilder:
    """Builds zero-context Goldfish review packets and synthesizes shootdown findings.

    @requirement("REQ-ISO-EGM-01")
    """

    def discover_semantic_boundaries(self, spec_markdown: str) -> dict[str, tuple[int, int]]:
        """Locate 1-based line ranges for feature overview and detailed design sections.

        @requirement("REQ-ISO-EGM-01")
        """
        if not isinstance(spec_markdown, str) or not spec_markdown.strip():
            raise ValueError("Specification markdown must be a non-empty string.")

        lines = spec_markdown.splitlines()
        total_lines = len(lines)
        if total_lines < 2:
            return {"feature_range": (1, 1), "detailed_range": (1, 1)}

        detailed_start: int | None = None
        first_h1_seen = False
        for idx, raw_line in enumerate(lines, start=1):
            if TOP_HEADING_RE.match(raw_line):
                if not first_h1_seen:
                    first_h1_seen = True
                    continue
                detailed_start = idx
                break
            if idx > 1 and DETAILED_HEADING_RE.match(raw_line):
                detailed_start = idx
                break

        if detailed_start is None or detailed_start <= 1:
            detailed_start = max(2, (total_lines // 2) + 1)

        feature_end = detailed_start - 1
        while feature_end > 1 and not lines[feature_end - 1].strip():
            feature_end -= 1

        return {"feature_range": (1, feature_end), "detailed_range": (detailed_start, total_lines)}

    def build_review_packets(
        self,
        spec_markdown: str,
        referenced_files: Mapping[str, str] | None = None,
        conversation_history: Sequence[Mapping[str, Any]] | None = None,
    ) -> list[GoldfishReviewPacket]:
        """Construct four isolated Goldfish review packets with chat history stripped.

        @requirement("REQ-ISO-EGM-01")
        """
        if not isinstance(spec_markdown, str) or not spec_markdown.strip():
            raise ValueError("Specification markdown must be a non-empty string.")

        _ = conversation_history
        boundaries = self.discover_semantic_boundaries(spec_markdown)
        files_copy = dict(referenced_files or {})
        return [
            GoldfishReviewPacket(
                stage=stage,
                spec_markdown=spec_markdown,
                feature_range_lines=boundaries["feature_range"],
                detailed_range_lines=boundaries["detailed_range"],
                referenced_files=dict(files_copy),
                rubric_checklist=STAGE_RUBRIC_CHECKLISTS[stage],
                chat_history_stripped=True,
            )
            for stage in EGM_RUBRIC_STAGES
        ]

    def synthesize_goldfish_findings(self, raw_findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Deduplicate Goldfish findings, sort by severity, and evaluate shootdown gate.

        @requirement("REQ-ISO-EGM-01")
        """
        deduped: list[dict[str, str]] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for item in raw_findings:
            stage = str(item.get("stage", "")).strip().lower()
            target = str(item.get("target", "")).strip()
            issue = str(item.get("issue", "")).strip()
            severity = str(item.get("severity", "minor")).strip().lower()
            if severity not in SEVERITY_RANK:
                severity = "minor"

            norm_key = (
                " ".join(stage.split()),
                " ".join(target.lower().split()),
                " ".join(issue.lower().split()),
            )
            if norm_key not in seen_keys:
                seen_keys.add(norm_key)
                deduped.append({"stage": stage, "target": target, "issue": issue, "severity": severity})

        deduped.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
        blocking_count = sum(1 for f in deduped if f["severity"] in ("critical", "major"))
        return {
            "findings": deduped,
            "total_unique_findings": len(deduped),
            "blocking_count": blocking_count,
            "approved_for_implementation": blocking_count == 0,
        }
