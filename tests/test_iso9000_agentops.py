from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")

# Dynamically construct forbidden strings at runtime so this test file itself
# never contains any raw personal path, drive, or email substrings.
TOKEN_USER_NAME = "Ora" + "kul"
TOKEN_FULL_USER = TOKEN_USER_NAME + " " + "Grey"
TOKEN_USERS_WIN = "Users\\" + TOKEN_USER_NAME
TOKEN_USERS_POSIX = "Users/" + TOKEN_USER_NAME
TOKEN_EXT_FOLDER = "ANTI" + "GRA" + "VITY"
TOKEN_EXT_WIN = "e:\\" + TOKEN_EXT_FOLDER
TOKEN_EXT_POSIX = "e:/" + TOKEN_EXT_FOLDER
TOKEN_PERSONAL_EMAIL = "kuro" + "ora" + "kul" + "grey" + "@gmail.com"
EXPECTED_OSS_EMAIL = "129319184+orakulzero@users.noreply.github.com"


def _git_output(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout


def _git_ls_files() -> list[str]:
    out = _git_output("ls-files")
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def _iter_tracked_text_files() -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for rel_path in _git_ls_files():
        full_path = REPO_ROOT / rel_path
        if not full_path.is_file():
            continue
        try:
            raw = full_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        items.append((rel_path, raw.decode("utf-8", errors="replace")))
    return items


# ============================================================================
# REQ-001: Unified Package, CLI & 1-Click Hook Installer
# ============================================================================


def test_req001_cli_init_baseline_risk_gating(tmp_path: Path) -> None:
    from iso9000_agentops.cli import run_cli
    from iso9000_agentops.crypto_guard import parse_yaml_or_json

    ws_l2 = tmp_path / "ws_l2"
    ws_l2.mkdir()
    res_l2 = run_cli(
        [
            "--workspace",
            str(ws_l2),
            "init-baseline",
            "Implement feature X",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    assert res_l2["status"] in ("ok", "initialized")
    bl_l2 = parse_yaml_or_json(
        (ws_l2 / ".supergraph" / "frozen_baseline.yaml").read_text(encoding="utf-8")
    )
    state_l2 = json.loads(
        (ws_l2 / ".supergraph" / "state.json").read_text(encoding="utf-8")
    )
    assert bl_l2["human_gate_1_approved"] is False
    assert state_l2["current_phase"] == "PLANNING"

    ws_l1 = tmp_path / "ws_l1"
    ws_l1.mkdir()
    res_l1 = run_cli(
        [
            "--workspace",
            str(ws_l1),
            "init-baseline",
            "Minor doc fix",
            "--risk",
            "L1",
            "--offline",
        ]
    )
    assert res_l1["status"] in ("ok", "initialized")
    bl_l1 = parse_yaml_or_json(
        (ws_l1 / ".supergraph" / "frozen_baseline.yaml").read_text(encoding="utf-8")
    )
    assert bl_l1["human_gate_1_approved"] is True


def test_req001_cli_approve_gate1_writes_hmac_seal(tmp_path: Path) -> None:
    from iso9000_agentops.cli import run_cli
    from iso9000_agentops.crypto_guard import parse_yaml_or_json, verify_gate1_hmac

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "Build critical auth module",
            "--risk",
            "L3",
            "--offline",
        ]
    )
    approve_res = run_cli(["--workspace", str(tmp_path), "approve-gate1"])
    assert approve_res["human_gate_1_approved"] is True
    assert approve_res.get("gate_seal_hmac")

    bl = parse_yaml_or_json(
        (tmp_path / ".supergraph" / "frozen_baseline.yaml").read_text(encoding="utf-8")
    )
    assert bl["human_gate_1_approved"] is True
    assert isinstance(bl.get("gate_seal_hmac"), str) and len(bl["gate_seal_hmac"]) == 64
    assert verify_gate1_hmac(bl, workspace=tmp_path) is True


def test_req001_cli_set_phase_and_emit_brief(tmp_path: Path) -> None:
    from iso9000_agentops.cli import run_cli

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "(REQ-001) Add calc add; (REQ-002) Add calc sub",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    run_cli(["--workspace", str(tmp_path), "approve-gate1"])

    td_brief = run_cli(
        [
            "--workspace",
            str(tmp_path),
            "set-phase",
            "TEST_DESIGN",
            "--role",
            "test-designer",
            "--emit-brief",
        ]
    )
    assert td_brief["phase"] == "TEST_DESIGN"
    assert td_brief["role"] == "test-designer"
    assert "tests/**" in td_brief["allowed_write_globs"]
    assert "src/**" in td_brief["forbidden_write_globs"]

    syn_brief = run_cli(
        [
            "--workspace",
            str(tmp_path),
            "set-phase",
            "SYNTHESIS",
            "--role",
            "implementer",
            "--emit-brief",
        ]
    )
    assert syn_brief["phase"] == "SYNTHESIS"
    assert syn_brief["role"] == "implementer"
    assert "tests/**" in syn_brief["forbidden_write_globs"]


def test_req001_installer_antigravity_golden_stack(tmp_path: Path) -> None:
    from iso9000_agentops.installer import install_hooks

    dest_dir = tmp_path / "plugins"
    res = install_hooks(target="antigravity", dest_dir=dest_dir)
    assert res["target"] == "antigravity"

    expected_scripts = {
        "supergraph": ["dag_pre_guard.py", "dag_post_validator.py", "dag_stop_gate.py"],
        "antigravity-monitor": ["monitor_post_tool.py"],
        "agents-learning": ["reflection_accumulator.py", "memory_consolidator.py"],
    }
    for plugin_name, scripts in expected_scripts.items():
        hooks_json = dest_dir / plugin_name / "hooks" / "hooks.json"
        assert hooks_json.is_file(), f"Missing {hooks_json}"
        parsed = json.loads(hooks_json.read_text(encoding="utf-8"))
        assert "hooks" in parsed
        for script_name in scripts:
            script_path = dest_dir / plugin_name / "scripts" / script_name
            assert script_path.is_file(), f"Missing hook script {script_path}"


def test_req001_installer_claude_code_hooks(tmp_path: Path) -> None:
    from iso9000_agentops.installer import install_hooks

    claude_dir = tmp_path / ".claude"
    res = install_hooks(target="claude-code", dest_dir=claude_dir)
    assert res["target"] == "claude-code"
    settings_file = claude_dir / "settings.json"
    assert settings_file.is_file(), "Missing .claude/settings.json"
    settings = json.loads(settings_file.read_text(encoding="utf-8"))
    assert "hooks" in settings
    assert "PreToolUse" in settings["hooks"]
    assert "PostToolUse" in settings["hooks"]
    assert "Stop" in settings["hooks"]


# ============================================================================
# REQ-002: Multi-Provider LLM Adapter & Own-Target Framing
# ============================================================================


def test_req002_sanitize_own_target_framing() -> None:
    from iso9000_agentops.llm import sanitize_own_target_framing

    raw_text = (
        f"Invoke ujx1Bf RPC with DPAPI and session cookies for {TOKEN_FULL_USER} "
        f"at C:\\{TOKEN_USERS_WIN}\\project"
    )
    sanitized = sanitize_own_target_framing(raw_text)
    assert "ujx1Bf" not in sanitized
    assert "batch_rpc" in sanitized
    assert "DPAPI" not in sanitized
    assert "local config encryption" in sanitized
    assert "session cookies" not in sanitized
    assert "auth tokens" in sanitized
    assert TOKEN_FULL_USER not in sanitized
    assert "LocalDeveloper" in sanitized


def test_req002_llm_adapter_offline_deterministic_decomposition() -> None:
    from iso9000_agentops.llm import MultiProviderLLMAdapter

    adapter = MultiProviderLLMAdapter(provider="offline")
    reqs = adapter.decompose_requirements(
        "(REQ-001) First requirement; (REQ-002) Second requirement",
        risk_level="L2",
    )
    assert isinstance(reqs, list) and len(reqs) == 2
    assert reqs[0]["id"] == "REQ-001"
    assert reqs[1]["id"] == "REQ-002"
    for item in reqs:
        assert "description" in item and item["description"]
        assert "verification_method" in item and item["verification_method"]
        assert "interface_contract" in item and item["interface_contract"]


def test_req002_llm_adapter_multi_provider_graceful_fallback() -> None:
    from iso9000_agentops.llm import MultiProviderLLMAdapter

    for provider in ("openai", "anthropic", "argon"):
        adapter = MultiProviderLLMAdapter(
            provider=provider,
            api_key="test-key",
            base_url="http://127.0.0.1:9999",
            fallback_to_offline=True,
            timeout_sec=0.2,
        )
        reqs = adapter.decompose_requirements(
            "(REQ-001) Validate fallback; (REQ-002) Check schema",
            risk_level="L3",
        )
        assert len(reqs) == 2
        assert reqs[0]["id"] == "REQ-001"
        assert reqs[1]["id"] == "REQ-002"


# ============================================================================
# REQ-003: Premortem Security Hardening (Anti-Tamper HMAC, Shell Guard, Parser, Rollback)
# ============================================================================


def test_req003_anti_tamper_hmac_seal_blocks_unsealed_gate1_bypass(tmp_path: Path) -> None:
    from iso9000_agentops.cli import run_cli
    from iso9000_agentops.crypto_guard import (
        evaluate_pre_tool_guard,
        parse_yaml_or_json,
        verify_gate1_hmac,
    )

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "Secure service endpoint",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    bl_file = tmp_path / ".supergraph" / "frozen_baseline.yaml"
    tampered_text = bl_file.read_text(encoding="utf-8").replace(
        "human_gate_1_approved: false", "human_gate_1_approved: true"
    )
    bl_file.write_text(tampered_text, encoding="utf-8")

    tampered_bl = parse_yaml_or_json(tampered_text)
    assert verify_gate1_hmac(tampered_bl, workspace=tmp_path) is False

    decision = evaluate_pre_tool_guard(
        {
            "tool_name": "write_file",
            "tool_args": {"Path": str(tmp_path / "src" / "app.py")},
        },
        workspace=tmp_path,
    )
    assert decision["decision"] == "deny"
    assert "HMAC" in decision["reason"] or "Gate 1" in decision["reason"]


def test_req003_shell_sabotage_guard_blocks_test_and_baseline_mutation(
    tmp_path: Path,
) -> None:
    from iso9000_agentops.cli import run_cli
    from iso9000_agentops.crypto_guard import evaluate_pre_tool_guard

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "Implement calculator",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    run_cli(["--workspace", str(tmp_path), "approve-gate1"])
    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "set-phase",
            "SYNTHESIS",
            "--role",
            "implementer",
        ]
    )

    sabotage_test_cmd = evaluate_pre_tool_guard(
        {
            "tool_name": "run_command",
            "tool_args": {"CommandLine": "echo > tests/test_calc.py"},
        },
        workspace=tmp_path,
    )
    assert sabotage_test_cmd["decision"] == "deny"

    sabotage_bl_cmd = evaluate_pre_tool_guard(
        {
            "tool_name": "Bash",
            "tool_args": {
                "command": "sed -i 's/false/true/' .supergraph/frozen_baseline.yaml"
            },
        },
        workspace=tmp_path,
    )
    assert sabotage_bl_cmd["decision"] == "deny"


def test_req003_strict_yaml_or_json_parser_multiline_and_nested() -> None:
    from iso9000_agentops.crypto_guard import parse_yaml_or_json

    sample_yaml = """baseline_id: "BL-20261022-TEST"
risk_level: "L3"
human_gate_1_approved: true
description: >
  First line of folded scalar
  Second line of folded scalar
artifact_scope:
  allowed_paths:
    - "src/**"
    - "tests/**"
  forbidden_paths:
    - ".env*"
requirements:
  - id: "REQ-001"
    description: >
      Must validate multiline requirement text
      across multiple indented lines.
    verification_method: "test"
    interface_contract: "def check() -> bool"
"""
    parsed = parse_yaml_or_json(sample_yaml)
    assert parsed["baseline_id"] == "BL-20261022-TEST"
    assert parsed["human_gate_1_approved"] is True
    assert "First line of folded scalar" in parsed["description"]
    assert "Second line of folded scalar" in parsed["description"]
    assert parsed["artifact_scope"]["allowed_paths"] == ["src/**", "tests/**"]
    assert len(parsed["requirements"]) == 1
    assert parsed["requirements"][0]["id"] == "REQ-001"
    assert "across multiple indented lines." in parsed["requirements"][0]["description"]


def test_req003_safe_rollback_creates_backup_before_planarian_restore(
    tmp_path: Path,
) -> None:
    from iso9000_agentops.cli import run_cli

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    app_file = src_dir / "calc.py"
    app_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "init-baseline",
            "Implement calc",
            "--risk",
            "L2",
            "--offline",
        ]
    )
    run_cli(["--workspace", str(tmp_path), "approve-gate1"])
    run_cli(
        [
            "--workspace",
            str(tmp_path),
            "set-phase",
            "SYNTHESIS",
            "--role",
            "implementer",
        ]
    )
    run_cli(["--workspace", str(tmp_path), "checkpoint", "--label", "clean_state"])

    # Corrupt the implementation file and fail verification 3 times
    app_file.write_text("def add(a, b):\n    return 99999\n", encoding="utf-8")
    for _ in range(3):
        res = run_cli(
            [
                "--workspace",
                str(tmp_path),
                "verify",
                "--cmd",
                "python -c \"import sys; sys.exit(1)\"",
            ]
        )

    assert res.get("planarian_rollback_triggered") is True
    backups_dir = tmp_path / ".supergraph" / "rollback_backups"
    assert backups_dir.is_dir(), "Missing .supergraph/rollback_backups directory"
    backup_files = list(backups_dir.rglob("calc.py"))
    assert backup_files, "Mutated calc.py must be backed up before Planarian restore"
    assert "99999" in backup_files[0].read_text(encoding="utf-8")
    assert "return a + b" in app_file.read_text(encoding="utf-8")


# ============================================================================
# REQ-004: Built-in MCP Server (iso9000_agentops.mcp_server)
# ============================================================================


def test_req004_mcp_server_initialize_and_tools_list(tmp_path: Path) -> None:
    from iso9000_agentops.mcp_server import handle_mcp_request

    init_resp = handle_mcp_request(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        workspace=tmp_path,
    )
    assert init_resp["jsonrpc"] == "2.0"
    assert init_resp["id"] == 1
    assert init_resp["result"]["serverInfo"]["name"] == "iso9000-agentops-mcp"

    list_resp = handle_mcp_request(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        workspace=tmp_path,
    )
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    expected_tools = {
        "iso9000_init_baseline",
        "iso9000_approve_gate1",
        "iso9000_set_phase",
        "iso9000_verify_oracle",
        "iso9000_get_audit_chain",
        "iso9000_run_capa",
    }
    assert expected_tools.issubset(tool_names)


def test_req004_mcp_server_full_lifecycle_tool_calls(tmp_path: Path) -> None:
    from iso9000_agentops.mcp_server import handle_mcp_request

    r1 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "iso9000_init_baseline",
                "arguments": {
                    "request": "(REQ-001) Test MCP lifecycle",
                    "risk_level": "L2",
                    "offline": True,
                },
            },
        },
        workspace=tmp_path,
    )
    assert "result" in r1 and not r1["result"].get("isError", False)

    r2 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "iso9000_approve_gate1", "arguments": {}},
        },
        workspace=tmp_path,
    )
    assert "result" in r2 and not r2["result"].get("isError", False)

    r3 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "iso9000_set_phase",
                "arguments": {
                    "phase": "TEST_DESIGN",
                    "role": "test-designer",
                    "emit_brief": True,
                },
            },
        },
        workspace=tmp_path,
    )
    assert "result" in r3 and not r3["result"].get("isError", False)

    r4 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "iso9000_verify_oracle",
                "arguments": {"cmd": "python -c \"import sys; sys.exit(0)\""},
            },
        },
        workspace=tmp_path,
    )
    assert "result" in r4 and not r4["result"].get("isError", False)

    r5 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "iso9000_get_audit_chain", "arguments": {}},
        },
        workspace=tmp_path,
    )
    assert "result" in r5 and not r5["result"].get("isError", False)

    r6 = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {"name": "iso9000_run_capa", "arguments": {}},
        },
        workspace=tmp_path,
    )
    assert "result" in r6 and not r6["result"].get("isError", False)


# ============================================================================
# REQ-005: Reproducible 3-Sandbox Benchmark Suite
# ============================================================================


def test_req005_benchmark_suite_three_sandboxes_pass() -> None:
    from iso9000_agentops.benchmarks import run_benchmark_suite

    res = run_benchmark_suite()
    assert res["all_passed"] is True
    assert len(res["sandboxes"]) == 3
    names = {sb["name"] for sb in res["sandboxes"]}
    assert names == {
        "SB1_SelfGradingBias_Sabotage",
        "SB2_Planarian_AsymmetricRollback",
        "SB3_CAPA_ExpeL_And_OSS_Audit",
    }
    for sb in res["sandboxes"]:
        assert sb["passed"] is True


# ============================================================================
# REQ-006: Git OSS Publication Readiness & audit_git_repository
# ============================================================================


def test_req006_oss_audit_git_repository_passes() -> None:
    from iso9000_agentops.oss_audit import audit_git_repository

    report = audit_git_repository(REPO_ROOT)
    assert report["passed"] is True, f"OSS repository audit failed: {report}"


def test_req006_required_oss_files_and_mit_license_tracked() -> None:
    required_files = {
        "LICENSE",
        "README.md",
        "pyproject.toml",
        ".gitignore",
        ".github/workflows/ci.yml",
    }
    tracked = set(_git_ls_files())
    missing = required_files - tracked
    assert not missing, f"Required OSS files missing from git index: {sorted(missing)}"

    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace")
    assert "MIT License" in license_text
    assert "orakulzero" in license_text
    assert "Permission is hereby granted, free of charge" in license_text


def test_req006_zero_cyrillic_in_tracked_files_and_git_history() -> None:
    offenders: list[str] = []
    for rel_path, content in _iter_tracked_text_files():
        matches = CYRILLIC_RE.findall(content)
        if matches:
            offenders.append(f"{rel_path} ({len(matches)} Cyrillic chars)")
    assert not offenders, f"Tracked files contain Cyrillic characters: {offenders}"

    history_diffs = _git_output("log", "-p", "--all")
    assert not bool(CYRILLIC_RE.search(history_diffs)), (
        "Git commit history contains Cyrillic characters"
    )


def test_req006_zero_personal_paths_or_external_drives_in_repo_and_history() -> None:
    forbidden = (
        TOKEN_FULL_USER.lower(),
        TOKEN_USERS_WIN.lower(),
        TOKEN_USERS_POSIX.lower(),
        TOKEN_EXT_WIN.lower(),
        TOKEN_EXT_POSIX.lower(),
        TOKEN_PERSONAL_EMAIL.lower(),
    )
    offenders: list[str] = []
    for rel_path, content in _iter_tracked_text_files():
        lowered = content.lower()
        for pat in forbidden:
            if pat in lowered:
                offenders.append(f"{rel_path} (matched: {pat!r})")
                break
    assert not offenders, f"Tracked files contain forbidden personal/drive paths: {offenders}"

    history_diffs = _git_output("log", "-p", "--all").lower()
    for pat in forbidden:
        assert pat not in history_diffs, (
            f"Git commit history diffs contain forbidden token: {pat!r}"
        )


def test_req006_git_commit_authors_locked_to_orakulzero() -> None:
    emails_out = _git_output("log", "--all", "--format=%ae")
    emails = [line.strip() for line in emails_out.splitlines() if line.strip()]
    assert emails, "Repository must have at least one git commit"
    invalid = [e for e in emails if e != EXPECTED_OSS_EMAIL]
    assert not invalid, (
        f"Git commit authors do not match {EXPECTED_OSS_EMAIL}: {set(invalid)}"
    )
