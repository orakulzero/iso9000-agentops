"""ISO 9001:2015 / Agile V / AgentOps Quality Pipeline Orchestrator."""

from __future__ import annotations

__version__ = "1.2.0"

from iso9000_agentops.cli import run_cli
from iso9000_agentops.crypto_guard import (
    build_prov_hash_chain,
    compute_gate1_hmac,
    dump_yaml_contract,
    evaluate_pre_tool_guard,
    parse_yaml_or_json,
    verify_gate1_hmac,
    verify_prov_hash_chain,
)
from iso9000_agentops.diff_tour import (
    REVIEW_DIMENSIONS,
    SeniorReviewDimension,
    VALID_EPISTEMIC_BASES,
    build_diff_tour,
    clear_git_blob_cache,
    compute_diff_tour_risk_score,
    drop_revealing_asks,
    render_diff_tour_markdown,
    validate_diff_tour,
    verify_git_reference,
)
from iso9000_agentops.installer import install_hooks
from iso9000_agentops.llm import MultiProviderLLMAdapter, sanitize_own_target_framing
from iso9000_agentops.mcp_server import handle_mcp_request
from iso9000_agentops.oss_audit import audit_git_repository

__all__ = [
    "__version__",
    "MultiProviderLLMAdapter",
    "REVIEW_DIMENSIONS",
    "SeniorReviewDimension",
    "VALID_EPISTEMIC_BASES",
    "audit_git_repository",
    "build_diff_tour",
    "build_prov_hash_chain",
    "clear_git_blob_cache",
    "compute_diff_tour_risk_score",
    "compute_gate1_hmac",
    "drop_revealing_asks",
    "dump_yaml_contract",
    "evaluate_pre_tool_guard",
    "handle_mcp_request",
    "install_hooks",
    "parse_yaml_or_json",
    "render_diff_tour_markdown",
    "run_cli",
    "sanitize_own_target_framing",
    "validate_diff_tour",
    "verify_gate1_hmac",
    "verify_git_reference",
    "verify_prov_hash_chain",
]
