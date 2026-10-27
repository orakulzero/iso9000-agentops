"""ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V Quality Pipeline Orchestrator (REQ-ISO-204)."""

from __future__ import annotations

__version__ = "2.0.0"

from iso9000_agentops.aims_42001 import (
    assess_failure_modes,
    compute_fmea_rpn,
    generate_iso42001_soa,
)
from iso9000_agentops.certificate import (
    export_sarif_report,
    issue_quality_certificate,
    render_compliance_badge_svg,
    verify_quality_certificate,
)
from iso9000_agentops.cli import run_cli
from iso9000_agentops.crypto_guard import (
    build_merkle_audit_tree,
    build_prov_hash_chain,
    compute_gate1_hmac,
    dump_yaml_contract,
    evaluate_pre_tool_guard,
    generate_merkle_inclusion_proof,
    parse_yaml_or_json,
    verify_gate1_hmac,
    verify_merkle_inclusion_proof,
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
from iso9000_agentops.traceability import (
    build_requirements_traceability_matrix,
    extract_code_req_links,
    extract_test_req_links,
    render_rtm_markdown,
)

__all__ = [
    "__version__",
    "MultiProviderLLMAdapter",
    "REVIEW_DIMENSIONS",
    "SeniorReviewDimension",
    "VALID_EPISTEMIC_BASES",
    "assess_failure_modes",
    "audit_git_repository",
    "build_diff_tour",
    "build_merkle_audit_tree",
    "build_prov_hash_chain",
    "build_requirements_traceability_matrix",
    "clear_git_blob_cache",
    "compute_diff_tour_risk_score",
    "compute_fmea_rpn",
    "compute_gate1_hmac",
    "drop_revealing_asks",
    "dump_yaml_contract",
    "evaluate_pre_tool_guard",
    "export_sarif_report",
    "extract_code_req_links",
    "extract_test_req_links",
    "generate_iso42001_soa",
    "generate_merkle_inclusion_proof",
    "handle_mcp_request",
    "install_hooks",
    "issue_quality_certificate",
    "parse_yaml_or_json",
    "render_compliance_badge_svg",
    "render_diff_tour_markdown",
    "render_rtm_markdown",
    "run_cli",
    "sanitize_own_target_framing",
    "validate_diff_tour",
    "verify_gate1_hmac",
    "verify_git_reference",
    "verify_merkle_inclusion_proof",
    "verify_prov_hash_chain",
    "verify_quality_certificate",
]
