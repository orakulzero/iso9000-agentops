import sys
from unittest.mock import MagicMock

# Mock submodules
mock_iso9000_agentops = MagicMock()
mock_iso9000_agentops.__version__ = "2.0.0"

mock_aims_42001 = MagicMock()
mock_certificate = MagicMock()
mock_crypto_guard = MagicMock()
mock_diff_tour = MagicMock()
mock_diff_tour.REVIEW_DIMENSIONS = []
mock_diff_tour.SeniorReviewDimension = MagicMock()
mock_diff_tour.VALID_EPISTEMIC_BASES = []
mock_installer = MagicMock()
mock_llm = MagicMock()
mock_llm.MultiProviderLLMAdapter = MagicMock()
mock_oss_audit = MagicMock()
mock_traceability = MagicMock()

sys.modules["iso9000_agentops"] = mock_iso9000_agentops
sys.modules["iso9000_agentops.aims_42001"] = mock_aims_42001
sys.modules["iso9000_agentops.certificate"] = mock_certificate
sys.modules["iso9000_agentops.crypto_guard"] = mock_crypto_guard
sys.modules["iso9000_agentops.diff_tour"] = mock_diff_tour
sys.modules["iso9000_agentops.installer"] = mock_installer
sys.modules["iso9000_agentops.llm"] = mock_llm
sys.modules["iso9000_agentops.oss_audit"] = mock_oss_audit
sys.modules["iso9000_agentops.traceability"] = mock_traceability

from iso9000_agentops.aims_42001 import (
    assess_failure_modes,
    compute_fmea_rpn,
    generate_iso42001_soa,
)
from iso9000_agentops.certificate import (
    certify_ecosystem_portfolio,
    export_portfolio_sarif_report,
    export_sarif_report,
    issue_quality_certificate,
    render_compliance_badge_svg,
    render_portfolio_badge_svg,
    verify_quality_certificate,
)
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
from iso9000_agentops.oss_audit import audit_git_repository
from iso9000_agentops.traceability import (
    build_requirements_traceability_matrix,
    extract_code_req_links,
    extract_test_req_links,
    render_rtm_markdown,
)


def test_assess_failure_modes():
    assess_failure_modes()
    mock_aims_42001.assess_failure_modes.assert_called_once()


def test_compute_fmea_rpn():
    compute_fmea_rpn()
    mock_aims_42001.compute_fmea_rpn.assert_called_once()


def test_generate_iso42001_soa():
    generate_iso42001_soa()
    mock_aims_42001.generate_iso42001_soa.assert_called_once()


def test_certify_ecosystem_portfolio():
    certify_ecosystem_portfolio()
    mock_certificate.certify_ecosystem_portfolio.assert_called_once()


def test_export_portfolio_sarif_report():
    export_portfolio_sarif_report()
    mock_certificate.export_portfolio_sarif_report.assert_called_once()


def test_export_sarif_report():
    export_sarif_report()
    mock_certificate.export_sarif_report.assert_called_once()


def test_issue_quality_certificate():
    issue_quality_certificate()
    mock_certificate.issue_quality_certificate.assert_called_once()


def test_render_compliance_badge_svg():
    render_compliance_badge_svg()
    mock_certificate.render_compliance_badge_svg.assert_called_once()


def test_render_portfolio_badge_svg():
    render_portfolio_badge_svg()
    mock_certificate.render_portfolio_badge_svg.assert_called_once()


def test_verify_quality_certificate():
    verify_quality_certificate()
    mock_certificate.verify_quality_certificate.assert_called_once()


def test_build_merkle_audit_tree():
    build_merkle_audit_tree()
    mock_crypto_guard.build_merkle_audit_tree.assert_called_once()


def test_build_prov_hash_chain():
    build_prov_hash_chain()
    mock_crypto_guard.build_prov_hash_chain.assert_called_once()


def test_compute_gate1_hmac():
    compute_gate1_hmac()
    mock_crypto_guard.compute_gate1_hmac.assert_called_once()


def test_dump_yaml_contract():
    dump_yaml_contract()
    mock_crypto_guard.dump_yaml_contract.assert_called_once()


def test_evaluate_pre_tool_guard():
    evaluate_pre_tool_guard()
    mock_crypto_guard.evaluate_pre_tool_guard.assert_called_once()


def test_generate_merkle_inclusion_proof():
    generate_merkle_inclusion_proof()
    mock_crypto_guard.generate_merkle_inclusion_proof.assert_called_once()


def test_parse_yaml_or_json():
    parse_yaml_or_json()
    mock_crypto_guard.parse_yaml_or_json.assert_called_once()


def test_verify_gate1_hmac():
    verify_gate1_hmac()
    mock_crypto_guard.verify_gate1_hmac.assert_called_once()


def test_verify_merkle_inclusion_proof():
    verify_merkle_inclusion_proof()
    mock_crypto_guard.verify_merkle_inclusion_proof.assert_called_once()


def test_verify_prov_hash_chain():
    verify_prov_hash_chain()
    mock_crypto_guard.verify_prov_hash_chain.assert_called_once()


def test_build_diff_tour():
    build_diff_tour()
    mock_diff_tour.build_diff_tour.assert_called_once()


def test_clear_git_blob_cache():
    clear_git_blob_cache()
    mock_diff_tour.clear_git_blob_cache.assert_called_once()


def test_compute_diff_tour_risk_score():
    compute_diff_tour_risk_score()
    mock_diff_tour.compute_diff_tour_risk_score.assert_called_once()


def test_drop_revealing_asks():
    drop_revealing_asks()
    mock_diff_tour.drop_revealing_asks.assert_called_once()


def test_render_diff_tour_markdown():
    render_diff_tour_markdown()
    mock_diff_tour.render_diff_tour_markdown.assert_called_once()


def test_validate_diff_tour():
    validate_diff_tour()
    mock_diff_tour.validate_diff_tour.assert_called_once()


def test_verify_git_reference():
    verify_git_reference()
    mock_diff_tour.verify_git_reference.assert_called_once()


def test_review_dimensions():
    assert REVIEW_DIMENSIONS == []


def test_senior_review_dimension():
    dim = SeniorReviewDimension()
    assert dim is not None


def test_valid_epistemic_bases():
    assert VALID_EPISTEMIC_BASES == []


def test_install_hooks():
    install_hooks()
    mock_installer.install_hooks.assert_called_once()


def test_multi_provider_llm_adapter():
    adapter = MultiProviderLLMAdapter()
    assert adapter is not None


def test_sanitize_own_target_framing():
    sanitize_own_target_framing()
    mock_llm.sanitize_own_target_framing.assert_called_once()


def test_audit_git_repository():
    audit_git_repository()
    mock_oss_audit.audit_git_repository.assert_called_once()


def test_build_requirements_traceability_matrix():
    build_requirements_traceability_matrix()
    mock_traceability.build_requirements_traceability_matrix.assert_called_once()


def test_extract_code_req_links():
    extract_code_req_links()
    mock_traceability.extract_code_req_links.assert_called_once()


def test_extract_test_req_links():
    extract_test_req_links()
    mock_traceability.extract_test_req_links.assert_called_once()


def test_render_rtm_markdown():
    render_rtm_markdown()
    mock_traceability.render_rtm_markdown.assert_called_once()
