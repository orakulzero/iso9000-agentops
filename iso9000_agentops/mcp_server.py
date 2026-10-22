"""JSON-RPC 2.0 Model Context Protocol (MCP) Server for ISO 9001:2015 AgentOps."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from iso9000_agentops.cli import run_cli

MCP_TOOLS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "iso9000_init_baseline",
        "description": "Initialize an ISO 9001:2015 / Agile V frozen baseline and risk matrix.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request": {"type": "string"},
                "risk_level": {"type": "string", "default": "L2"},
                "offline": {"type": "boolean", "default": True},
            },
            "required": ["request"],
        },
    },
    {
        "name": "iso9000_approve_gate1",
        "description": "Approve Human Gate 1 and write a cryptographic HMAC-SHA256 seal.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "iso9000_set_phase",
        "description": "Transition Agile V state machine phase and emit role-isolated subagent brief.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "phase": {"type": "string"},
                "role": {"type": "string", "default": "implementer"},
                "emit_brief": {"type": "boolean", "default": True},
            },
            "required": ["phase"],
        },
    },
    {
        "name": "iso9000_verify_oracle",
        "description": "Run independent verification oracle, record W3C PROV-DM EvidenceUnit, or trigger Planarian rollback.",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "iso9000_get_audit_chain",
        "description": "Retrieve the current W3C PROV-DM SHA-256 audit chain and state summary.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "iso9000_run_capa",
        "description": "Execute Echelon 6 CAPA / ExpeL rule consolidation and Trace2Skill extraction.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trace2skill": {"type": "boolean", "default": False},
                "skill_name": {"type": "string", "default": "iso9000-learned-skill"},
            },
        },
    },
]


def handle_mcp_request(
    request: dict[str, Any], workspace: Path | str | None = None
) -> dict[str, Any]:
    """Process a single JSON-RPC 2.0 MCP request and return the JSON-RPC 2.0 response."""
    ws = Path(workspace).resolve() if workspace is not None else Path.cwd().resolve()
    req_id = request.get("id")
    method = str(request.get("method") or "")
    params = request.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "iso9000-agentops-mcp",
                    "version": "1.0.0",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": MCP_TOOLS_SCHEMA},
        }

    if method == "tools/call":
        tool_name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        try:
            if tool_name == "iso9000_init_baseline":
                cli_args = [
                    "--workspace",
                    str(ws),
                    "init-baseline",
                    str(args.get("request", "Default MCP task")),
                    "--risk",
                    str(args.get("risk_level", "L2")),
                ]
                if args.get("offline", True):
                    cli_args.append("--offline")
                out = run_cli(cli_args)
            elif tool_name == "iso9000_approve_gate1":
                out = run_cli(["--workspace", str(ws), "approve-gate1"])
            elif tool_name == "iso9000_set_phase":
                cli_args = [
                    "--workspace",
                    str(ws),
                    "set-phase",
                    str(args.get("phase", "PLANNING")),
                    "--role",
                    str(args.get("role", "implementer")),
                ]
                if args.get("emit_brief", True):
                    cli_args.append("--emit-brief")
                out = run_cli(cli_args)
            elif tool_name == "iso9000_verify_oracle":
                out = run_cli(
                    [
                        "--workspace",
                        str(ws),
                        "verify",
                        "--cmd",
                        str(args.get("cmd", "python -c \"import sys; sys.exit(0)\"")),
                    ]
                )
            elif tool_name == "iso9000_get_audit_chain":
                chain_file = ws / ".supergraph" / "audit_chain.json"
                if chain_file.is_file():
                    out = json.loads(chain_file.read_text(encoding="utf-8"))
                else:
                    out = {
                        "status": "empty",
                        "audit_chain_sha256": None,
                        "evidence_units": [],
                    }
            elif tool_name == "iso9000_run_capa":
                cli_args = ["--workspace", str(ws), "capa", "--offline"]
                if args.get("trace2skill"):
                    cli_args.extend(
                        [
                            "--trace2skill",
                            "--skill-name",
                            str(args.get("skill_name", "iso9000-learned-skill")),
                        ]
                    )
                out = run_cli(cli_args)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"Unknown tool: {tool_name}"}
                        ],
                        "isError": True,
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(out)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> None:
    """Run stdio JSON-RPC 2.0 MCP loop."""
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            req = json.loads(stripped)
            resp = handle_mcp_request(req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": str(exc)},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
