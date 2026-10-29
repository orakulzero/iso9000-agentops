"""Tests for iso9000_agentops.installer."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from iso9000_agentops.installer import install_hooks


def test_install_hooks_empty_target(tmp_path: Path) -> None:
    """Test the edge case where the target argument is an empty string."""
    with pytest.raises(ValueError, match="Unsupported hook installation target: ''"):
        install_hooks("", tmp_path)


def test_install_hooks_whitespace_target(tmp_path: Path) -> None:
    """Test the edge case where the target argument is just whitespace."""
    with pytest.raises(ValueError, match="Unsupported hook installation target: '   '"):
        install_hooks("   ", tmp_path)


def test_install_hooks_invalid_target(tmp_path: Path) -> None:
    """Test invalid target."""
    with pytest.raises(ValueError, match="Unsupported hook installation target: 'invalid'"):
        install_hooks("invalid", tmp_path)


def test_install_hooks_antigravity(tmp_path: Path) -> None:
    """Test installing hooks for antigravity."""
    dest = tmp_path / "dest"
    res = install_hooks("antigravity", dest)
    
    assert res["status"] == "ok"
    assert res["target"] == "antigravity"
    assert res["dest_dir"] == str(dest)
    assert len(res["installed_files"]) > 0
    
    # Check that directories and files are actually created
    assert (dest / "supergraph" / "hooks" / "hooks.json").exists()
    assert (dest / "supergraph" / "scripts" / "dag_pre_guard.py").exists()
    assert (dest / "antigravity-monitor" / "hooks" / "hooks.json").exists()
    
    # Verify contents of one hooks.json
    hooks_cfg = json.loads((dest / "supergraph" / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert hooks_cfg["plugin"] == "supergraph"


def test_install_hooks_claude_code(tmp_path: Path) -> None:
    """Test installing hooks for claude-code."""
    dest = tmp_path / "claude"
    res = install_hooks("claude-code", dest)
    
    assert res["status"] == "ok"
    assert res["target"] == "claude-code"
    assert res["dest_dir"] == str(dest)
    assert len(res["installed_files"]) > 0
    
    assert (dest / "hooks" / "pre_tool_guard.py").exists()
    assert (dest / "hooks" / "stop_gate.py").exists()
    assert (dest / "settings.json").exists()
    
    settings = json.loads((dest / "settings.json").read_text(encoding="utf-8"))
    assert "hooks" in settings


def test_install_hooks_target_normalization(tmp_path: Path) -> None:
    """Test that target argument normalization works."""
    dest1 = tmp_path / "1"
    res1 = install_hooks("  AntiGravity\n", dest1)
    assert res1["target"] == "antigravity"
    
    dest2 = tmp_path / "2"
    res2 = install_hooks("\tClaude-Code ", dest2)
    assert res2["target"] == "claude-code"
