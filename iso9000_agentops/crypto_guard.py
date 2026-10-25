"""Cryptographic Gate Seals, Recursive YAML/JSON Contract Parser, and Pre-Tool Guard."""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any


def _parse_scalar(val: str) -> Any:
    s = val.strip()
    if not s:
        return ""
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        inner = s[1:-1]
        return inner.replace('\\"', '"').replace("\\n", "\n")
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none", "~"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    if s.startswith("[") and s.endswith("]"):
        try:
            return json.loads(s)
        except Exception:
            inner = s[1:-1].strip()
            if not inner:
                return []
            return [_parse_scalar(part) for part in inner.split(",")]
    return s


def parse_yaml_or_json(text: str) -> dict[str, Any]:
    """Parse JSON or structured YAML (including folded/literal multiline scalars and nested lists/dicts)."""
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        return json.loads(stripped)

    raw_lines = text.splitlines()
    lines: list[tuple[int, str]] = []
    for raw in raw_lines:
        clean_r = raw.rstrip("\r\n")
        if not clean_r.strip() or clean_r.lstrip().startswith("#"):
            continue
        indent = len(clean_r) - len(clean_r.lstrip(" "))
        lines.append((indent, clean_r.strip()))

    def parse_block_scalar(start_idx: int, min_indent: int, style: str) -> tuple[str, int]:
        collected: list[str] = []
        idx = start_idx
        while idx < len(lines):
            ind, content = lines[idx]
            if ind < min_indent:
                break
            collected.append(content)
            idx += 1
        joiner = " " if style == ">" else "\n"
        return joiner.join(collected).strip(), idx

    def parse_mapping(start_idx: int, base_indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        idx = start_idx
        while idx < len(lines):
            ind, content = lines[idx]
            if ind < base_indent:
                break
            if content.startswith("- "):
                break
            if ":" not in content:
                idx += 1
                continue
            key, rest = content.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            idx += 1

            if rest in (">", "|", ">-", "|-"):
                style = ">" if rest.startswith(">") else "|"
                if idx < len(lines) and lines[idx][0] > ind:
                    scalar_val, idx = parse_block_scalar(idx, lines[idx][0], style)
                    result[key] = scalar_val
                else:
                    result[key] = ""
            elif rest == "":
                if idx < len(lines) and lines[idx][0] > ind:
                    next_ind, next_content = lines[idx]
                    if next_content.startswith("- "):
                        seq_val, idx = parse_sequence(idx, next_ind)
                        result[key] = seq_val
                    else:
                        map_val, idx = parse_mapping(idx, next_ind)
                        result[key] = map_val
                else:
                    result[key] = None
            else:
                result[key] = _parse_scalar(rest)
        return result, idx

    def parse_sequence(start_idx: int, base_indent: int) -> tuple[list[Any], int]:
        items: list[Any] = []
        idx = start_idx
        while idx < len(lines):
            ind, content = lines[idx]
            if ind < base_indent:
                break
            if not content.startswith("- "):
                break
            after_dash = content[2:].strip()
            idx += 1

            if ":" in after_dash and not (after_dash.startswith('"') or after_dash.startswith("'")):
                k, v = after_dash.split(":", 1)
                k = k.strip()
                v = v.strip()
                item_dict: dict[str, Any] = {}
                if v in (">", "|", ">-", "|-"):
                    style = ">" if v.startswith(">") else "|"
                    if idx < len(lines) and lines[idx][0] > ind:
                        s_val, idx = parse_block_scalar(idx, lines[idx][0], style)
                        item_dict[k] = s_val
                    else:
                        item_dict[k] = ""
                else:
                    item_dict[k] = _parse_scalar(v)

                if idx < len(lines) and lines[idx][0] > ind and not lines[idx][1].startswith("- "):
                    sub_map, idx = parse_mapping(idx, lines[idx][0])
                    item_dict.update(sub_map)
                items.append(item_dict)
            else:
                items.append(_parse_scalar(after_dash))
        return items, idx

    parsed, _ = parse_mapping(0, 0)
    return parsed


def _format_scalar(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return "null"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{s}"'


def dump_yaml_contract(data: dict[str, Any]) -> str:
    """Serialize a baseline dictionary into deterministic, human-readable YAML."""
    out: list[str] = []

    def write_dict(d: dict[str, Any], indent: int = 0) -> None:
        prefix = " " * indent
        for k, v in d.items():
            if isinstance(v, dict):
                out.append(f"{prefix}{k}:")
                write_dict(v, indent + 2)
            elif isinstance(v, list):
                out.append(f"{prefix}{k}:")
                if not v:
                    out[-1] = f"{prefix}{k}: []"
                for item in v:
                    if isinstance(item, dict):
                        first = True
                        for ik, iv in item.items():
                            if first:
                                out.append(f"{prefix}  - {ik}: {_format_scalar(iv)}")
                                first = False
                            else:
                                out.append(f"{prefix}    {ik}: {_format_scalar(iv)}")
                    else:
                        out.append(f"{prefix}  - {_format_scalar(item)}")
            else:
                out.append(f"{prefix}{k}: {_format_scalar(v)}")

    write_dict(data, 0)
    return "\n".join(out) + "\n"


def ensure_gate_secret(workspace: Path | str | None = None) -> str:
    """Read or generate the workspace HMAC secret key for Gate 1 approval seals."""
    env_secret = os.environ.get("ISO9000_GATE_SECRET")
    if env_secret:
        return env_secret
    ws = Path(workspace) if workspace is not None else Path.cwd()
    sg_dir = ws / ".supergraph"
    sg_dir.mkdir(parents=True, exist_ok=True)
    secret_file = sg_dir / ".gate_secret"
    if secret_file.is_file():
        return secret_file.read_text(encoding="utf-8").strip()
    new_secret = secrets.token_hex(32)
    secret_file.write_text(new_secret, encoding="utf-8")
    return new_secret


def _read_existing_gate_secret(workspace: Path | str | None = None) -> str | None:
    env_secret = os.environ.get("ISO9000_GATE_SECRET")
    if env_secret:
        return env_secret
    ws = Path(workspace) if workspace is not None else Path.cwd()
    secret_file = ws / ".supergraph" / ".gate_secret"
    if secret_file.is_file():
        val = secret_file.read_text(encoding="utf-8").strip()
        return val if val else None
    return None


def compute_gate1_hmac(
    baseline_dict: dict[str, Any], workspace: Path | str | None = None
) -> str:
    """Compute a 64-character hex HMAC-SHA256 seal over the baseline governance fields."""
    secret = _read_existing_gate_secret(workspace)
    if not secret:
        secret = ensure_gate_secret(workspace)
    baseline_id = str(baseline_dict.get("baseline_id", ""))
    risk_level = str(baseline_dict.get("risk_level", "L2")).upper()
    approved = "true" if baseline_dict.get("human_gate_1_approved") is True else "false"
    reqs_canonical = json.dumps(baseline_dict.get("requirements", []), sort_keys=True)
    payload = f"{baseline_id}|{risk_level}|{approved}|{reqs_canonical}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_gate1_hmac(
    baseline_dict: dict[str, Any], workspace: Path | str | None = None
) -> bool:
    """Verify Human Gate 1 approval and cryptographic HMAC seal for L2-L4 tasks."""
    risk_level = str(baseline_dict.get("risk_level", "L2")).upper()
    approved = baseline_dict.get("human_gate_1_approved") is True
    if risk_level in ("L0", "L1"):
        return approved
    if not approved:
        return False
    seal = baseline_dict.get("gate_seal_hmac")
    if not isinstance(seal, str) or len(seal) != 64:
        return False
    secret = _read_existing_gate_secret(workspace)
    if not secret:
        return False
    expected = compute_gate1_hmac(baseline_dict, workspace=workspace)
    return hmac.compare_digest(seal, expected)


def evaluate_pre_tool_guard(
    payload: dict[str, Any], workspace: Path | str | None = None
) -> dict[str, Any]:
    """Evaluate PreToolUse guardrails against frozen baseline HMAC seal, phase role isolation, and shell sabotage."""
    ws = Path(workspace).resolve() if workspace is not None else Path.cwd().resolve()
    sg_dir = ws / ".supergraph"
    bl_file = sg_dir / "frozen_baseline.yaml"
    state_file = sg_dir / "state.json"

    baseline: dict[str, Any] = {}
    if bl_file.is_file():
        baseline = parse_yaml_or_json(bl_file.read_text(encoding="utf-8", errors="replace"))

    state: dict[str, Any] = {}
    if state_file.is_file():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            state = {}

    risk_level = str(baseline.get("risk_level") or state.get("risk_level") or "L2").upper()
    if bl_file.is_file() and risk_level in ("L2", "L3", "L4"):
        if not verify_gate1_hmac(baseline, workspace=ws):
            return {
                "decision": "deny",
                "reason": "Human Gate 1 approval or valid HMAC seal missing for L2-L4 task.",
            }

    phase = str(state.get("current_phase") or state.get("phase") or "PLANNING").upper()
    strict_isolation = bool(state.get("strict_role_isolation", True))

    tool_name = str(
        payload.get("tool_name")
        or payload.get("tool")
        or payload.get("name")
        or ""
    )
    tool_args = (
        payload.get("tool_args")
        or payload.get("tool_input")
        or payload.get("arguments")
        or {}
    )
    if not isinstance(tool_args, dict):
        tool_args = {}

    shell_tools = {"run_command", "Bash", "bash", "execute_command", "cmd", "powershell"}
    write_tools = {
        "write_file",
        "edit_file",
        "Write",
        "Edit",
        "MultiEdit",
        "replace_file_content",
        "multi_replace_file_content",
    }

    if tool_name in shell_tools:
        cmd_str = str(
            tool_args.get("CommandLine")
            or tool_args.get("command")
            or tool_args.get("cmd")
            or ""
        )
        norm_cmd = cmd_str.replace("\\", "/")
        protected_Patterns = (
            "frozen_baseline.yaml",
            "audit_chain.json",
            ".gate_secret",
        )
        for prot in protected_Patterns:
            if prot in norm_cmd:
                return {
                    "decision": "deny",
                    "reason": f"Shell sabotage guard: command references protected artifact '{prot}'.",
                }

        mutation_indicators = (
            ">",
            ">>",
            "sed ",
            "rm ",
            "del ",
            "mv ",
            "cp ",
            "tee ",
            "Set-Content",
            "Out-File",
            "Remove-Item",
            "write_text",
        )
        if strict_isolation and phase == "SYNTHESIS":
            if ("tests/" in norm_cmd or "test_" in norm_cmd) and any(
                m in norm_cmd for m in mutation_indicators
            ):
                return {
                    "decision": "deny",
                    "reason": "Self-Grading Bias Prevention: shell command cannot mutate tests/ during SYNTHESIS phase.",
                }
        if strict_isolation and phase == "TEST_DESIGN":
            if ("src/" in norm_cmd or "app/" in norm_cmd) and any(
                m in norm_cmd for m in mutation_indicators
            ):
                return {
                    "decision": "deny",
                    "reason": "Role isolation: shell command cannot mutate src/ or app/ during TEST_DESIGN phase.",
                }

    if tool_name in write_tools:
        raw_target = str(
            tool_args.get("Path")
            or tool_args.get("file_path")
            or tool_args.get("TargetFile")
            or tool_args.get("path")
            or ""
        )
        if raw_target:
            target_path = Path(raw_target)
            if target_path.is_absolute():
                try:
                    rel_path = target_path.resolve().relative_to(ws).as_posix()
                except ValueError:
                    rel_path = target_path.as_posix()
            else:
                rel_path = target_path.as_posix().lstrip("./")

            if any(
                p in rel_path
                for p in ("frozen_baseline.yaml", "audit_chain.json", ".gate_secret")
            ):
                return {
                    "decision": "deny",
                    "reason": f"Direct mutation of protected governance file '{rel_path}' is forbidden.",
                }

            scope = baseline.get("artifact_scope") or {}
            if isinstance(scope, dict):
                forb_list = scope.get("forbidden_paths") or []
                for pat in forb_list:
                    if fnmatch.fnmatch(rel_path, str(pat)) or fnmatch.fnmatch(
                        Path(rel_path).name, str(pat)
                    ):
                        return {
                            "decision": "deny",
                            "reason": f"Path '{rel_path}' matches forbidden_paths pattern '{pat}'.",
                        }

            if strict_isolation and phase == "SYNTHESIS":
                if (
                    rel_path == "tests"
                    or rel_path.startswith("tests/")
                    or "/tests/" in f"/{rel_path}"
                ):
                    return {
                        "decision": "deny",
                        "reason": "Self-Grading Bias Prevention: Build-Agent cannot modify tests/ during SYNTHESIS phase.",
                    }
            if strict_isolation and phase == "TEST_DESIGN":
                if not (
                    rel_path == "tests"
                    or rel_path.startswith("tests/")
                    or "/tests/" in f"/{rel_path}"
                ):
                    return {
                        "decision": "deny",
                        "reason": "Role isolation: Test-Designer may only write inside tests/ during TEST_DESIGN phase.",
                    }

    return {
        "decision": "allow",
        "reason": "Permitted by ISO 9001:2015 PreToolUse guard.",
    }


def build_prov_hash_chain(
    activities: list[dict[str, Any]], initial_prev_hash: str = ""
) -> list[dict[str, Any]]:
    """Build a tamper-evident W3C PROV-DM SHA-256 hash chain over activity records."""
    chain: list[dict[str, Any]] = []
    current_prev = initial_prev_hash
    for i, act in enumerate(activities):
        prev_hash = current_prev if i == 0 else chain[i - 1]["entry_hash"]
        filtered = {k: v for k, v in act.items() if k not in ("prev_hash", "entry_hash")}
        canonical_json = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
        payload = f"{canonical_json}{prev_hash}".encode("utf-8")
        entry_hash = hashlib.sha256(payload).hexdigest()

        entry = dict(filtered)
        entry["prev_hash"] = prev_hash
        entry["entry_hash"] = entry_hash
        chain.append(entry)
        current_prev = entry_hash
    return chain


def verify_prov_hash_chain(
    chain: list[dict[str, Any]], initial_prev_hash: str = ""
) -> dict[str, Any]:
    """Verify cryptographic integrity of a W3C PROV-DM activity hash chain."""
    if not chain:
        return {
            "valid": True,
            "chain_length": 0,
            "tampered_indices": [],
            "head_hash": "",
        }

    tampered_indices: list[int] = []
    for i, entry in enumerate(chain):
        if not isinstance(entry, dict):
            tampered_indices.append(i)
            continue

        expected_prev = initial_prev_hash if i == 0 else chain[i - 1].get("entry_hash", "")
        actual_prev = entry.get("prev_hash")
        actual_entry_hash = entry.get("entry_hash")

        if (
            not isinstance(actual_entry_hash, str)
            or len(actual_entry_hash) != 64
            or not all(c in "0123456789abcdefABCDEF" for c in actual_entry_hash)
        ):
            tampered_indices.append(i)
            continue

        if actual_prev != expected_prev:
            tampered_indices.append(i)
            continue

        filtered = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash")}
        canonical_json = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
        payload = f"{canonical_json}{actual_prev}".encode("utf-8")
        recomputed = hashlib.sha256(payload).hexdigest()

        if recomputed.lower() != actual_entry_hash.lower():
            tampered_indices.append(i)

    head_hash = str(chain[-1].get("entry_hash", "")) if chain else ""
    return {
        "valid": len(tampered_indices) == 0,
        "chain_length": len(chain),
        "tampered_indices": tampered_indices,
        "head_hash": head_hash,
    }

