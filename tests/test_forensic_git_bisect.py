"""
ISO 9001:2015 / Agile V Verification Suite — REQ-GIT-BISECT-01
Component: Automated Forensic Git Bisect & Planarian Rollback Engine
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

import iso9000_agentops
from iso9000_agentops.forensic_git_bisect import ForensicGitBisect, run_forensic_bisect


def test_req_git_bisect_01_logarithmic_culprit_isolation_and_rollback_plan() -> None:
    """Verify REQ-GIT-BISECT-01 isolates first bad commit in O(log2 N) steps with rollback plan."""
    assert getattr(iso9000_agentops, "__v3_generation__", None) == "3.0.0"
    assert getattr(iso9000_agentops, "ForensicGitBisect", None) is ForensicGitBisect
    assert getattr(iso9000_agentops, "run_forensic_bisect", None) is run_forensic_bisect

    commits = [
        {
            "sha": f"sha_{i:02d}",
            "message": f"commit {i}",
            "files": [f"mod_{i}.py"],
            "symbols": [f"fn_{i}"],
        }
        for i in range(16)
    ]

    def predicate_fn(commit: dict) -> bool:
        idx = int(str(commit["sha"]).split("_")[1])
        return idx < 10

    res = run_forensic_bisect(commits, predicate_fn=predicate_fn)
    assert res["requirement_id"] == "REQ-GIT-BISECT-01"
    assert res["status"] == "CULPRIT_FOUND"
    assert res["first_bad_commit"] == "sha_10"
    assert res["steps_evaluated"] <= 6
    assert res["affected_files"] == ["mod_10.py"]
    assert res["affected_symbols"] == ["fn_10"]
    assert isinstance(res["rollback_plan"], dict)
    assert res["rollback_plan"]["target_sha"] == "sha_10"


def test_req_git_bisect_01_all_good_and_empty_range_edge_cases() -> None:
    """Verify REQ-GIT-BISECT-01 handles ALL_GOOD and EMPTY_RANGE edge cases cleanly."""
    engine = ForensicGitBisect()
    commits = [
        {
            "sha": f"sha_{i:02d}",
            "message": f"commit {i}",
            "files": [f"mod_{i}.py"],
            "symbols": [f"fn_{i}"],
        }
        for i in range(8)
    ]

    res_good = engine.run_forensic_bisect(commits, predicate_fn=lambda c: True)
    assert res_good["requirement_id"] == "REQ-GIT-BISECT-01"
    assert res_good["status"] == "ALL_GOOD"
    assert res_good["first_bad_commit"] is None

    res_empty = engine.run_forensic_bisect([], predicate_fn=lambda c: True)
    assert res_empty["requirement_id"] == "REQ-GIT-BISECT-01"
    assert res_empty["status"] == "EMPTY_RANGE"
    assert res_empty["first_bad_commit"] is None
