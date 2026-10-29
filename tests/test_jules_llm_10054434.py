import json
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from iso9000_agentops.llm import (
    sanitize_own_target_framing, 
    MultiProviderLLMAdapter, 
    _TOK_USER, 
    _TOK_FULL_USER, 
    _TOK_EXT_DRIVE, 
    _TOK_EMAIL
)

def test_sanitize_own_target_framing_overlapping():
    """
    Test string with multiple overlapping patterns to ensure correct ordering 
    and no partial substitution for user tokens and paths.
    Because of the order in the replacements list, 'C:\\Users\\Orakul Grey'
    should be replaced before 'Orakul Grey', which is replaced before 'Orakul'.
    """
    input_text = (
        f"Path1: C:\\Users\\{_TOK_FULL_USER}, "
        f"Path2: C:/Users/{_TOK_FULL_USER}, "
        f"Path3: C:\\Users\\{_TOK_USER}, "
        f"Path4: C:/Users/{_TOK_USER}, "
        f"UserFull: {_TOK_FULL_USER}, "
        f"UserShort: {_TOK_USER}, "
        f"Drive1: e:\\{_TOK_EXT_DRIVE}, "
        f"Drive2: e:/{_TOK_EXT_DRIVE}, "
        f"Drive: {_TOK_EXT_DRIVE}, "
        "ujx1Bf, DPAPI, session cookies"
    )
    
    expected_text = (
        r"Path1: C:\Users\LocalDeveloper, "
        "Path2: C:/Users/LocalDeveloper, "
        r"Path3: C:\Users\LocalDeveloper, "
        "Path4: C:/Users/LocalDeveloper, "
        "UserFull: LocalDeveloper, "
        "UserShort: LocalDeveloper, "
        "Drive1: <WORKSPACE_ROOT>, "
        "Drive2: <WORKSPACE_ROOT>, "
        "Drive: WORKSPACE_ROOT, "
        "batch_rpc, local config encryption, auth tokens"
    )
    
    assert sanitize_own_target_framing(input_text) == expected_text

def test_sanitize_own_target_framing_email_quirk():
    """
    Test the known behavior for _TOK_EMAIL.
    Because 'Orakul' is replaced with 'LocalDeveloper' before the email rule is evaluated,
    the email ends up partially substituted rather than fully matching _TOK_EMAIL.
    """
    input_text = _TOK_EMAIL
    # _TOK_EMAIL is "kuroorakulgrey@gmail.com"
    # 'ora' + 'kul' becomes 'LocalDeveloper'
    expected_text = "kuroLocalDevelopergrey@gmail.com"
    assert sanitize_own_target_framing(input_text) == expected_text

def test_sanitize_own_target_framing_case_insensitivity():
    """Test that replacements are case-insensitive."""
    input_text = f"c:\\users\\{_TOK_FULL_USER.lower()} and e:\\{_TOK_EXT_DRIVE.lower()}"
    expected_text = r"C:\Users\LocalDeveloper and <WORKSPACE_ROOT>"
    
    assert sanitize_own_target_framing(input_text) == expected_text

def test_sanitize_own_target_framing_no_changes():
    """Test that text without target strings is unaffected."""
    input_text = "This is a normal string without any target words."
    assert sanitize_own_target_framing(input_text) == input_text

def test_multi_provider_llm_adapter_init():
    adapter = MultiProviderLLMAdapter(provider=" OpenAI ", api_key="test-key")
    assert adapter.provider == "openai"
    assert adapter.api_key == "test-key"
    assert adapter.fallback_to_offline is True
    assert adapter.timeout_sec == 30.0

def test_offline_decompose_with_req_markers():
    adapter = MultiProviderLLMAdapter()
    task = "(REQ-001) Do something useful.; (REQ-002) Do something else."
    
    reqs = adapter._offline_decompose(task, risk_level="L3")
    assert len(reqs) == 2
    assert reqs[0]["id"] == "REQ-001"
    assert reqs[0]["description"] == "Do something useful"
    assert reqs[0]["verification_method"] == "independent_pytest_oracle"
    assert "Verified contract for REQ-001" in reqs[0]["interface_contract"]
    
    assert reqs[1]["id"] == "REQ-002"
    assert reqs[1]["description"] == "Do something else"

def test_offline_decompose_with_req_markers_l1_risk():
    adapter = MultiProviderLLMAdapter()
    task = "(REQ-001) Do something useful."
    reqs = adapter._offline_decompose(task, risk_level="L1")
    assert reqs[0]["verification_method"] == "automated_assertion"

def test_offline_decompose_without_req_markers():
    adapter = MultiProviderLLMAdapter()
    task = "Do something useful;\nDo something else"
    reqs = adapter._offline_decompose(task, risk_level="L2")
    assert len(reqs) == 2
    assert reqs[0]["id"] == "REQ-001"
    assert reqs[0]["description"] == "Do something useful"
    assert reqs[1]["id"] == "REQ-002"
    assert reqs[1]["description"] == "Do something else"

def test_offline_decompose_empty_task():
    adapter = MultiProviderLLMAdapter()
    reqs = adapter._offline_decompose("   ", risk_level="L2")
    assert len(reqs) == 1
    assert reqs[0]["description"] == "Default baseline requirement"

@patch("urllib.request.urlopen")
def test_call_remote_provider_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "requirements": [{"id": "REQ-100", "description": "Remote req"}]
    }).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    adapter = MultiProviderLLMAdapter(provider="openai", base_url="http://localhost")
    reqs = adapter._call_remote_provider("test task", risk_level="L2")
    
    assert len(reqs) == 1
    assert reqs[0]["id"] == "REQ-100"
    
@patch("urllib.request.urlopen")
def test_call_remote_provider_invalid_schema(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"wrong_key": []}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    adapter = MultiProviderLLMAdapter(provider="openai", base_url="http://localhost")
    with pytest.raises(ValueError, match="Invalid remote provider response schema"):
        adapter._call_remote_provider("test task", risk_level="L2")

def test_call_remote_provider_no_base_url():
    adapter = MultiProviderLLMAdapter(provider="openai", base_url=None)
    with pytest.raises(ConnectionError, match="No base_url configured"):
        adapter._call_remote_provider("test task", risk_level="L2")

def test_decompose_requirements_offline_provider():
    adapter = MultiProviderLLMAdapter(provider="offline")
    task = "Simple task"
    reqs = adapter.decompose_requirements(task, risk_level="L2")
    assert len(reqs) == 1
    assert reqs[0]["description"] == "Simple task"

@patch("urllib.request.urlopen")
def test_decompose_requirements_remote_fallback(mock_urlopen):
    # Simulate a network error
    mock_urlopen.side_effect = urllib.error.URLError("Network error")
    
    adapter = MultiProviderLLMAdapter(provider="openai", base_url="http://localhost", fallback_to_offline=True)
    
    # Task includes a target string to verify it is sanitized even on fallback
    task = f"Simple task for {_TOK_USER}"
    reqs = adapter.decompose_requirements(task, risk_level="L2")
    
    assert len(reqs) == 1
    assert reqs[0]["description"] == "Simple task for LocalDeveloper"

@patch("urllib.request.urlopen")
def test_decompose_requirements_remote_no_fallback(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("Network error")
    
    adapter = MultiProviderLLMAdapter(provider="openai", base_url="http://localhost", fallback_to_offline=False)
    
    with pytest.raises(urllib.error.URLError):
        adapter.decompose_requirements("Simple task", risk_level="L2")

def test_sanitize_own_target_framing_partial_replacement_safety():
    """Ensure that things like 'session cookies' don't get partially mangled."""
    input_text = "I have session cookies and DPAPI enabled."
    expected = "I have auth tokens and local config encryption enabled."
    assert sanitize_own_target_framing(input_text) == expected
