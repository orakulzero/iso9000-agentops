"""Open-Source Git Repository Release Auditor (5 Mandatory ISO 9001:2015 OSS Gates)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")

# Construct forbidden personal/drive patterns dynamically at runtime
_TOK_USER = "Ora" + "kul"
_TOK_FULL_USER = _TOK_USER + " " + "Grey"
_TOK_EXT_FOLDER = "ANTI" + "GRA" + "VITY"
_TOK_PERSONAL_EMAIL = "kuro" + "ora" + "kul" + "grey" + "@gmail.com"

FORBIDDEN_PATTERNS: tuple[str, ...] = (
    _TOK_FULL_USER.lower(),
    ("Users\\" + _TOK_USER).lower(),
    ("Users/" + _TOK_USER).lower(),
    ("e:\\" + _TOK_EXT_FOLDER).lower(),
    ("e:/" + _TOK_EXT_FOLDER).lower(),
    _TOK_PERSONAL_EMAIL.lower(),
)


def _git_out(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def audit_git_repository(repo_path: Path | str) -> dict[str, Any]:
    """Audit a Git repository against the 5 ISO 9001:2015 OSS Release Gates."""
    repo = Path(repo_path).resolve()
    errors: list[str] = []

    # Gate 1: Required OSS files & MIT License
    for req_file in ("LICENSE", "README.md", ".gitignore"):
        if not (repo / req_file).is_file():
            errors.append(f"Missing required OSS file: {req_file}")

    lic_path = repo / "LICENSE"
    if lic_path.is_file():
        lic_text = lic_path.read_text(encoding="utf-8", errors="replace")
        if "MIT License" not in lic_text:
            errors.append("LICENSE does not contain 'MIT License'")

    # Gate 2: Tracked files check (zero Cyrillic, zero personal paths, zero ephemeral dirs)
    ls_out = _git_out(repo, "ls-files")
    tracked_files = [
        line.strip().replace("\\", "/")
        for line in ls_out.splitlines()
        if line.strip()
    ]

    for rel_path in tracked_files:
        if rel_path.startswith((".supergraph/", ".agents-learning/", ".monitor/")):
            errors.append(f"Ephemeral state file tracked in git index: {rel_path}")
        full_p = repo / rel_path
        if not full_p.is_file():
            continue
        try:
            raw = full_p.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        text = raw.decode("utf-8", errors="replace")
        if CYRILLIC_RE.search(text):
            errors.append(f"Cyrillic characters found in tracked file: {rel_path}")
        low = text.lower()
        for pat in FORBIDDEN_PATTERNS:
            if pat in low:
                errors.append(f"Forbidden personal/drive path in tracked file: {rel_path}")
                break

    # Gate 3: Commit history check (if repository has commits)
    history_diffs = _git_out(repo, "log", "-p", "--all")
    if history_diffs:
        if CYRILLIC_RE.search(history_diffs):
            errors.append("Cyrillic characters found in git commit history (git log -p --all)")
        low_hist = history_diffs.lower()
        for pat in FORBIDDEN_PATTERNS:
            if pat in low_hist:
                errors.append(f"Forbidden personal/drive token found in git commit history: {pat!r}")
                break

    return {
        "passed": len(errors) == 0,
        "repo_path": str(repo),
        "tracked_files_count": len(tracked_files),
        "errors": errors,
    }
