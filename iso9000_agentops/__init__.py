"""ISO 9001:2015 / Agile V / AgentOps Quality Pipeline Orchestrator."""

from __future__ import annotations

__version__ = "1.0.0"

from iso9000_agentops.cli import run_cli
from iso9000_agentops.crypto_guard import (
    compute_gate1_hmac,
    dump_yaml_contract,
    evaluate_pre_tool_guard,
    parse_yaml_or_json,
    verify_gate1_hmac,
)
from iso9000_agentops.installer import install_hooks
from iso9000_agentops.llm import MultiProviderLLMAdapter, sanitize_own_target_framing
from iso9000_agentops.mcp_server import handle_mcp_request
from iso9000_agentops.oss_audit import audit_git_repository

__all__ = [
    "__version__",
    "MultiProviderLLMAdapter",
    "audit_git_repository",
    "compute_gate1_hmac",
    "dump_yaml_contract",
    "evaluate_pre_tool_guard",
    "handle_mcp_request",
    "install_hooks",
    "parse_yaml_or_json",
    "run_cli",
    "sanitize_own_target_framing",
    "verify_gate1_hmac",
]
