"""Automated Forensic Git Bisect & Planarian Rollback Engine (REQ-GIT-BISECT-01).

Isolates the first regression-introducing commit across a commit range in
O(log2 N) evaluations and synthesizes a deterministic Planarian rollback plan
mapping affected files and AST symbols.

Requirement Traceability:
- REQ-GIT-BISECT-01: Automated Forensic Git Bisect & Planarian Rollback Engine
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
import subprocess
from typing import Any


def _normalize_commit(entry: Any) -> dict[str, Any]:
    """Normalize a commit string or mapping into a structured commit dictionary (REQ-GIT-BISECT-01)."""
    if isinstance(entry, Mapping):
        return {
            "sha": str(entry.get("sha", "")),
            "message": str(entry.get("message", "")),
            "files": [str(f) for f in entry.get("files", [])],
            "symbols": [str(s) for s in entry.get("symbols", [])],
        }
    return {
        "sha": str(entry),
        "message": "",
        "files": [],
        "symbols": [],
    }


class ForensicGitBisect:
    """Binary-search commit bisector and Planarian rollback synthesizer (REQ-GIT-BISECT-01)."""

    def _default_check_runner(
        self,
        commit: dict[str, Any],
        check_cmd: str | Sequence[str] | None,
        repo_path: str | Path,
        timeout_sec: float,
    ) -> bool:
        """Evaluate a commit using an external check command with explicit timeout (REQ-GIT-BISECT-01)."""
        if not check_cmd:
            return True
        proc = subprocess.run(
            check_cmd,
            shell=isinstance(check_cmd, str),
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1.0, float(timeout_sec)),
            check=False,
        )
        return proc.returncode == 0

    def run_forensic_bisect(
        self,
        commits: Sequence[Any],
        predicate_fn: Callable[[dict[str, Any]], bool] | None = None,
        check_cmd: str | Sequence[str] | None = None,
        repo_path: str | Path = ".",
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        """Locate the first bad commit in O(log2 N) steps and build a rollback plan (REQ-GIT-BISECT-01)."""
        normalized = [_normalize_commit(c) for c in commits]
        if not normalized:
            return {
                "requirement_id": "REQ-GIT-BISECT-01",
                "status": "EMPTY_RANGE",
                "first_bad_commit": None,
                "steps_evaluated": 0,
                "affected_files": [],
                "affected_symbols": [],
                "rollback_plan": None,
            }

        steps_evaluated = 0
        memo: dict[int, bool] = {}

        def evaluate_idx(idx: int) -> bool:
            nonlocal steps_evaluated
            if idx in memo:
                return memo[idx]
            steps_evaluated += 1
            commit_obj = normalized[idx]
            if predicate_fn is not None:
                passed = bool(predicate_fn(commit_obj))
            else:
                passed = self._default_check_runner(
                    commit_obj,
                    check_cmd=check_cmd,
                    repo_path=repo_path,
                    timeout_sec=timeout_sec,
                )
            memo[idx] = passed
            return passed

        last_idx = len(normalized) - 1
        if evaluate_idx(last_idx):
            return {
                "requirement_id": "REQ-GIT-BISECT-01",
                "status": "ALL_GOOD",
                "first_bad_commit": None,
                "steps_evaluated": steps_evaluated,
                "affected_files": [],
                "affected_symbols": [],
                "rollback_plan": None,
            }

        low = 0
        high = last_idx
        while low < high:
            mid = (low + high) // 2
            if evaluate_idx(mid):
                low = mid + 1
            else:
                high = mid

        culprit = normalized[low]
        target_sha = culprit["sha"]
        prev_good_sha = normalized[low - 1]["sha"] if low > 0 else None
        affected_files = list(culprit["files"])
        affected_symbols = list(culprit["symbols"])

        rollback_plan = {
            "target_sha": target_sha,
            "previous_good_sha": prev_good_sha,
            "strategy": "git_revert_ast_surgical",
            "command": f"git revert --no-edit {target_sha}",
            "affected_files": affected_files,
            "affected_symbols": affected_symbols,
        }

        return {
            "requirement_id": "REQ-GIT-BISECT-01",
            "status": "CULPRIT_FOUND",
            "first_bad_commit": target_sha,
            "steps_evaluated": steps_evaluated,
            "affected_files": affected_files,
            "affected_symbols": affected_symbols,
            "rollback_plan": rollback_plan,
        }


def run_forensic_bisect(
    commits: Sequence[Any],
    predicate_fn: Callable[[dict[str, Any]], bool] | None = None,
    check_cmd: str | Sequence[str] | None = None,
    repo_path: str | Path = ".",
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Convenience wrapper executing ForensicGitBisect.run_forensic_bisect (REQ-GIT-BISECT-01)."""
    return ForensicGitBisect().run_forensic_bisect(
        commits=commits,
        predicate_fn=predicate_fn,
        check_cmd=check_cmd,
        repo_path=repo_path,
        timeout_sec=timeout_sec,
    )
