"""Tests for diff_tour.py with focus on verify_git_reference edge cases."""

from __future__ import annotations

from pathlib import Path

from iso9000_agentops.diff_tour import verify_git_reference, clear_git_blob_cache

def test_verify_git_reference_invalid_git_ref(tmp_path: Path):
    """Test that verify_git_reference handles an invalid or non-existent git reference gracefully."""
    clear_git_blob_cache()
    
    # Passing an invalid branch/commit name (e.g., "invalid-branch-name-1234")
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="nonexistent-commit-hash",
        file_path="src/main.py",
        line_start=1,
        line_end=5,
        use_cache=False,
    )
    
    assert result["valid"] is False
    assert result["error"] in ["FILE_OR_REF_NOT_FOUND", "GIT_COMMAND_FAILED"]
    # The message should contain details about the error
    assert "message" in result
    assert "nonexistent-commit-hash" in result["message"] or "failed to execute" in result["message"].lower() or "not found" in result["message"].lower()

def test_verify_git_reference_valid_git_ref_missing_file(tmp_path: Path):
    """Test verify_git_reference when the reference is valid (HEAD) but the file doesn't exist."""
    clear_git_blob_cache()

    # Need a real git repo to test git showHEAD:file
    # But since tmp_path is not a git repo, `git show HEAD:missing_file` will fail
    # Let's test that failure behavior too.
    
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="HEAD",
        file_path="nonexistent_file.py",
        line_start=1,
        line_end=5,
        use_cache=False,
    )
    
    assert result["valid"] is False
    assert result["error"] in ["FILE_OR_REF_NOT_FOUND", "GIT_COMMAND_FAILED"]

def test_verify_git_reference_line_out_of_bounds(tmp_path: Path, monkeypatch):
    """Test verify_git_reference when line bounds are invalid but file/ref is valid."""
    clear_git_blob_cache()
    
    # We can mock subprocess.run to simulate a valid file with 10 lines
    import subprocess
    class MockResult:
        returncode = 0
        stdout = "\n".join(str(i) for i in range(10))
        stderr = ""
        
    def mock_run(*args, **kwargs):
        return MockResult()
        
    monkeypatch.setattr(subprocess, "run", mock_run)

    # Test out of bounds (line_end > total_lines)
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="HEAD",
        file_path="src/main.py",
        line_start=1,
        line_end=15,
        use_cache=False,
    )
    
    assert result["valid"] is False
    assert result["error"] == "LINE_BOUNDS_OUT_OF_RANGE"
    assert result["total_lines"] == 10
    
    # Test line_start < 1
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="HEAD",
        file_path="src/main.py",
        line_start=0,
        line_end=5,
        use_cache=False,
    )
    
    assert result["valid"] is False
    assert result["error"] == "LINE_BOUNDS_OUT_OF_RANGE"
    
    # Test line_end < line_start
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="HEAD",
        file_path="src/main.py",
        line_start=5,
        line_end=2,
        use_cache=False,
    )
    
    assert result["valid"] is False
    assert result["error"] == "LINE_BOUNDS_OUT_OF_RANGE"

def test_verify_git_reference_success(tmp_path: Path, monkeypatch):
    """Test verify_git_reference success case."""
    clear_git_blob_cache()
    
    import subprocess
    class MockResult:
        returncode = 0
        stdout = "line1\nline2\nline3\nline4\nline5\n"
        stderr = ""
        
    def mock_run(*args, **kwargs):
        return MockResult()
        
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    result = verify_git_reference(
        repo_root=str(tmp_path),
        git_ref="HEAD",
        file_path="src/main.py",
        line_start=2,
        line_end=4,
        use_cache=True,
    )
    
    assert result["valid"] is True
    assert result["error"] is None
    assert result["total_lines"] == 5
    assert result["line_count"] == 3
