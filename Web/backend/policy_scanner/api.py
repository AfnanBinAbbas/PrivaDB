import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import ipaddress
from urllib.parse import urlparse

from .fetcher import PolicyFetcher
from .analyzer import PolicyAnalyzer
from .exceptions import PolicyFetchError, AnalysisError

logger = logging.getLogger(__name__)

router = APIRouter()
fetcher = PolicyFetcher()
analyzer = PolicyAnalyzer()

class PolicyScanRequest(BaseModel):
    base_url: str
    frameworks: List[str] = Field(default_factory=lambda: ["GDPR", "CCPA", "ePrivacy"])

class Finding(BaseModel):
    framework: str
    clause: str
    status: str
    evidence: str
    reason: str
    remediation: str
    severity: str

class PolicyScanResponse(BaseModel):
    findings: List[Finding]
    scores: Dict[str, int]
    error: Optional[str] = None
    fallback: Optional[str] = None
    policy_url: Optional[str] = None

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        # Very basic check, in production use proper DNS resolution and IP checks
        if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0'):
            return False
        return True
    except Exception:
        return False

@router.post("/policy/scan", response_model=PolicyScanResponse)
async def scan_policy(request: PolicyScanRequest):
    base_url = request.base_url
    if not is_safe_url(base_url):
        raise HTTPException(status_code=400, detail="Invalid or unsafe URL provided.")
        
    try:
        policy_url = fetcher.find_policy_url(base_url)
        if not policy_url:
            return PolicyScanResponse(
                findings=[],
                scores={},
                error="Policy page unreachable or not found.",
                fallback="You can manually enter the policy URL if known."
            )
            
        text = fetcher.fetch_policy_text(policy_url)
        if not text:
            return PolicyScanResponse(
                findings=[],
                scores={},
                error="Failed to extract text from the policy page."
            )
            
        analysis_result = analyzer.analyze(text, request.frameworks)
        
        return PolicyScanResponse(
            findings=analysis_result["findings"],
            scores=analysis_result["scores"],
            policy_url=policy_url
        )
        
    except PolicyFetchError as e:
        logger.error(f"PolicyFetchError: {e}")
        return PolicyScanResponse(
            findings=[],
            scores={},
            error="Policy page unreachable",
            fallback="You can manually enter policy URL"
        )
    except Exception as e:
        logger.error(f"Unexpected error during policy scan: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
