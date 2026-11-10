import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import ipaddress
from urllib.parse import urlparse

from .fetcher import PolicyFetcher
from .analyzer import PolicyAnalyzer
from .disclosure import extract_disclosures, save_snapshot
from .gap import full_gap
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
    # Phase 9: structured disclosures (storage/vendors/purposes)
    disclosures: Optional[Dict[str, Any]] = None
    snapshot_path: Optional[str] = None


class GapRequest(BaseModel):
    base_url: str
    engine: Optional[str] = None   # "chrome" | "foxhound" | None=both


class GapResponse(BaseModel):
    domain: Optional[str] = None
    policy_url: Optional[str] = None
    snapshot_path: Optional[str] = None
    disclosures: Optional[Dict[str, Any]] = None
    behavior: Optional[Dict[str, Any]] = None
    gap: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

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
        disclosures = extract_disclosures(text)
        snapshot_path = save_snapshot(urlparse(base_url).netloc or base_url,
                                      policy_url, text, disclosures)

        return PolicyScanResponse(
            findings=analysis_result["findings"],
            scores=analysis_result["scores"],
            policy_url=policy_url,
            disclosures=disclosures,
            snapshot_path=snapshot_path,
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


@router.post("/policy/gap", response_model=GapResponse)
async def policy_gap(request: GapRequest):
    """Phase 9: policy disclosures vs observed identifier flows."""
    base_url = request.base_url
    if not is_safe_url(base_url):
        raise HTTPException(status_code=400,
                            detail="Invalid or unsafe URL provided.")
    try:
        policy_url = fetcher.find_policy_url(base_url)
        if not policy_url:
            return GapResponse(error="Policy page unreachable or not found.")
        text = fetcher.fetch_policy_text(policy_url)
        if not text:
            return GapResponse(error="Failed to extract policy text.")
        domain = urlparse(base_url).netloc or base_url
        report = full_gap(domain, text, policy_url,
                          engine=request.engine)
        return GapResponse(domain=domain, **report)
    except PolicyFetchError as e:
        logger.error(f"PolicyFetchError in gap: {e}")
        return GapResponse(error="Policy page unreachable")
    except Exception as e:
        logger.error(f"Unexpected error in gap analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
