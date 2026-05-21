# GRC Policy Scanner

A modular backend component for PrivaDB to scan and analyze website privacy policies and terms of service for compliance with GRC frameworks (GDPR, CCPA, ePrivacy).

## Installation

1. Install dependencies:
```bash
pip install -r requirements_policy_scanner.txt
```

2. Integrate the API router into your main FastAPI app:
```python
from policy_scanner.api import router as policy_router
app.include_router(policy_router, prefix="/api/v1")
```

## Configuration
Edit `config.yaml` to modify:
- `timeout_seconds`: Network request timeout.
- `user_agents`: List of User-Agents to rotate.
- `paths_to_check`: Common paths to check for policies.
- `frameworks`: Define rules, clauses, keywords, severity, and remediation steps.

## API Endpoints

### POST `/api/v1/policy/scan`
Request:
```json
{
  "base_url": "https://example.com",
  "frameworks": ["GDPR", "CCPA", "ePrivacy"]
}
```

Response:
```json
{
  "findings": [
    {
      "framework": "GDPR",
      "clause": "Article 7 – Consent",
      "status": "missing",
      "evidence": "",
      "reason": "Requires explicit user consent before data collection.",
      "remediation": "Add clear consent mechanisms and explanations.",
      "severity": "high"
    }
  ],
  "scores": {
    "GDPR": 85
  },
  "policy_url": "https://example.com/privacy"
}
```
