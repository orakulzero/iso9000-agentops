import pytest
from pathlib import Path
from iso9000_agentops.cli import _extract_workspace_arg, _resolve_source_and_tests_dirs

def test_extract_workspace_arg_trailing_flag_no_value():
    """
    Test asserting that `_extract_workspace_arg(["--workspace"])`
    leaves the workspace as `Path.cwd()` and returns the token unchanged
    in the cleaned argv list.
    """
    argv = ["--workspace"]
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path.cwd()
    assert cleaned == ["--workspace"]

def test_extract_workspace_arg_with_value():
    argv = ["--workspace", "/tmp/ws"]
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path("/tmp/ws").resolve()
    assert cleaned == []

def test_extract_workspace_arg_with_equals():
    argv = ["--workspace=/tmp/ws"]
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path("/tmp/ws").resolve()
    assert cleaned == []

def test_extract_workspace_arg_with_other_args():
    argv = ["--foo", "bar", "--workspace", "/tmp/ws", "--baz"]
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path("/tmp/ws").resolve()
    assert cleaned == ["--foo", "bar", "--baz"]

def test_extract_workspace_arg_with_equals_and_other_args():
    argv = ["--foo", "--workspace=/tmp/ws", "--baz"]
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path("/tmp/ws").resolve()
    assert cleaned == ["--foo", "--baz"]

def test_extract_workspace_arg_empty():
    argv = []
    ws, cleaned = _extract_workspace_arg(argv)
    
    assert ws == Path.cwd()
    assert cleaned == []

def test_resolve_source_and_tests_dirs_explicit_args(tmp_path):
    ws = tmp_path
    src_arg = str(tmp_path / "explicit_src")
    tests_arg = str(tmp_path / "explicit_tests")
    
    src, tests = _resolve_source_and_tests_dirs(ws, src_arg, tests_arg)
    
    assert src == Path(src_arg).resolve()
    assert tests == Path(tests_arg).resolve()

def test_resolve_source_and_tests_dirs_implicit_src(tmp_path):
    ws = tmp_path
    (ws / "src").mkdir()
    
    src, tests = _resolve_source_and_tests_dirs(ws)
    
    assert src == (ws / "src")
    assert tests == ws

def test_resolve_source_and_tests_dirs_implicit_iso9000_agentops(tmp_path):
    ws = tmp_path
    (ws / "iso9000_agentops").mkdir()
    
    src, tests = _resolve_source_and_tests_dirs(ws)
    
    assert src == (ws / "iso9000_agentops")
    assert tests == ws

def test_resolve_source_and_tests_dirs_implicit_app(tmp_path):
    ws = tmp_path
    (ws / "app").mkdir()
    
    src, tests = _resolve_source_and_tests_dirs(ws)
    
    assert src == (ws / "app")
    assert tests == ws

def test_resolve_source_and_tests_dirs_fallback(tmp_path):
    ws = tmp_path
    
    src, tests = _resolve_source_and_tests_dirs(ws)
    
    assert src == ws
    assert tests == ws

def test_resolve_source_and_tests_dirs_implicit_tests(tmp_path):
    ws = tmp_path
    (ws / "tests").mkdir()
    
    src, tests = _resolve_source_and_tests_dirs(ws)
    
    assert src == ws
    assert tests == (ws / "tests")
