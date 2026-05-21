import pytest
from unittest.mock import patch, MagicMock
from policy_scanner.fetcher import PolicyFetcher
from policy_scanner.analyzer import PolicyAnalyzer
from policy_scanner.exceptions import PolicyFetchError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from policy_scanner.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

@pytest.fixture
def mock_fetcher():
    return PolicyFetcher()

@pytest.fixture
def mock_analyzer():
    return PolicyAnalyzer()

@patch('requests.head')
def test_find_policy_url_success(mock_head, mock_fetcher):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_head.return_value = mock_response
    
    url = mock_fetcher.find_policy_url("https://example.com")
    assert url == "https://example.com/privacy"

@patch('requests.head')
@patch('requests.get')
def test_find_policy_url_fallback(mock_get, mock_head, mock_fetcher):
    # Head fails
    mock_head_resp = MagicMock()
    mock_head_resp.status_code = 404
    mock_head.return_value = mock_head_resp
    
    # Get succeeds with HTML
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.text = '<html><body><a href="/legal-policy">Privacy Policy</a></body></html>'
    mock_get.return_value = mock_get_resp
    
    url = mock_fetcher.find_policy_url("https://example.com")
    assert url == "https://example.com/legal-policy"

def test_analyze_gdpr(mock_analyzer):
    text = "We require your explicit consent before data collection. You have the right to access your data."
    result = mock_analyzer.analyze(text, ["GDPR"])
    
    assert "findings" in result
    assert "scores" in result
    assert "GDPR" in result["scores"]
    
    findings = result["findings"]
    consent_finding = next(f for f in findings if f["clause"] == "Article 7 – Consent")
    assert consent_finding["status"] == "present"

@patch('policy_scanner.fetcher.PolicyFetcher.find_policy_url')
@patch('policy_scanner.fetcher.PolicyFetcher.fetch_policy_text')
def test_api_scan(mock_fetch, mock_find):
    mock_find.return_value = "https://example.com/privacy"
    mock_fetch.return_value = "We do not sell your info."
    
    response = client.post("/policy/scan", json={"base_url": "https://example.com", "frameworks": ["CCPA"]})
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "scores" in data
    assert data["policy_url"] == "https://example.com/privacy"
