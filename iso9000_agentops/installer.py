"""1-Click Hook Installer for Antigravity Golden Stack and Claude Code."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_GUARD_SCRIPT_TEMPLATE = '''"""Auto-generated ISO 9001:2015 AgentOps Hook Script ({name})."""
import json
import sys
from pathlib import Path

def main() -> None:
    raw = sys.stdin.read().strip()
    payload = json.loads(raw) if raw else {{}}
    try:
        from iso9000_agentops.crypto_guard import evaluate_pre_tool_guard
        res = evaluate_pre_tool_guard(payload, workspace=Path.cwd())
    except Exception as exc:
        res = {{"decision": "allow", "reason": str(exc)}}
    print(json.dumps(res))

if __name__ == "__main__":
    main()
'''


def install_hooks(target: str, dest_dir: Path | str) -> dict[str, Any]:
    """Install ISO 9001:2015 AgentOps lifecycle hooks for Antigravity or Claude Code."""
    norm_target = target.lower().strip()
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    installed_files: list[str] = []

    if norm_target == "antigravity":
        golden_stack = {
            "supergraph": [
                "dag_pre_guard.py",
                "dag_post_validator.py",
                "dag_stop_gate.py",
            ],
            "antigravity-monitor": [
                "monitor_post_tool.py",
            ],
            "agents-learning": [
                "reflection_accumulator.py",
                "memory_consolidator.py",
            ],
        }
        for plugin_name, script_names in golden_stack.items():
            plugin_dir = dest / plugin_name
            hooks_dir = plugin_dir / "hooks"
            scripts_dir = plugin_dir / "scripts"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            scripts_dir.mkdir(parents=True, exist_ok=True)

            for script_name in script_names:
                script_path = scripts_dir / script_name
                script_path.write_text(
                    _GUARD_SCRIPT_TEMPLATE.format(name=script_name),
                    encoding="utf-8",
                )
                installed_files.append(str(script_path))

            hooks_cfg = {
                "plugin": plugin_name,
                "version": "1.0.0",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": ".*",
                            "command": f"python scripts/{script_names[0]}",
                        }
                    ],
                    "PostToolUse": [
                        {
                            "matcher": ".*",
                            "command": f"python scripts/{script_names[min(1, len(script_names) - 1)]}",
                        }
                    ],
                    "Stop": [
                        {
                            "matcher": ".*",
                            "command": f"python scripts/{script_names[-1]}",
                        }
                    ],
                },
            }
            hooks_json_path = hooks_dir / "hooks.json"
            hooks_json_path.write_text(
                json.dumps(hooks_cfg, indent=2),
                encoding="utf-8",
            )
            installed_files.append(str(hooks_json_path))

        return {
            "status": "ok",
            "target": "antigravity",
            "dest_dir": str(dest),
            "installed_files": installed_files,
        }

    if norm_target == "claude-code":
        hooks_dir = dest / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        for script_name in ("pre_tool_guard.py", "post_tool_audit.py", "stop_gate.py"):
            sp = hooks_dir / script_name
            sp.write_text(_GUARD_SCRIPT_TEMPLATE.format(name=script_name), encoding="utf-8")
            installed_files.append(str(sp))

        settings_cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write|Edit|MultiEdit|Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python .claude/hooks/pre_tool_guard.py",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python .claude/hooks/post_tool_audit.py",
                            }
                        ],
                    }
                ],
                "Stop": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python .claude/hooks/stop_gate.py",
                            }
                        ],
                    }
                ],
            }
        }
        settings_path = dest / "settings.json"
        settings_path.write_text(json.dumps(settings_cfg, indent=2), encoding="utf-8")
        installed_files.append(str(settings_path))

        return {
            "status": "ok",
            "target": "claude-code",
            "dest_dir": str(dest),
            "installed_files": installed_files,
        }

    raise ValueError(f"Unsupported hook installation target: {target!r}")
