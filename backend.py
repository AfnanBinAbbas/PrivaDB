from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
import os
import time
from datetime import datetime
from extractor import extract_complete_data
from analyzer import PersistenceAnalyzer

app = FastAPI(title="Data Whisperer API", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://localhost:8080", "http://10.1.152.95:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str
    scenario: Optional[str] = "fresh_browser"
    use_incognito: Optional[bool] = True
    
    class Config:
        from_attributes = True

class AnalyzeRequest(BaseModel):
    scenario1_file: str
    scenario2_file: str
    scenario3_file: str

class ScanResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@app.get("/")
async def root():
    return {"message": "Data Whisperer API", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/scan", response_model=ScanResponse)
@app.options("/api/scan")  # Add this decorator for OPTIONS
async def scan_domain(request: ScanRequest = None):
    """
    Scan a domain and extract IndexedDB data and network requests.
    """
    try:
        # Handle OPTIONS request
        from fastapi import Request
        import inspect
        
        # Get the actual request object
        if request is None:
            return ScanResponse(success=False, error="No data provided")
        
        # Use default if domain not provided
        domain = request.domain or "https://www.youtube.com"
        
        # Rest of your existing code...
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        
        print(f"Starting scan for domain: {domain}")
        filename, result = await extract_complete_data(
            url=domain,
            scenario_name=request.scenario or "scan",
            use_incognito=request.use_incognito
        )
        
        frontend_result = transform_to_frontend_format(result, domain)
        
        return ScanResponse(
            success=True,
            data=frontend_result
        )
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return ScanResponse(success=False, error=str(e))

@app.post("/api/analyze", response_model=ScanResponse)
async def analyze_data(request: AnalyzeRequest):
    """
    Analyze extracted data from multiple scenarios to detect tracking patterns.
    """
    try:
        # Check if files exist
        files = [request.scenario1_file, request.scenario2_file, request.scenario3_file]
        for file in files:
            if not os.path.exists(file):
                raise HTTPException(status_code=404, detail=f"File not found: {file}")
        
        # Run analysis
        analyzer = PersistenceAnalyzer(
            request.scenario1_file,
            request.scenario2_file,
            request.scenario3_file
        )
        
        report = analyzer.generate_complete_report()
        
        return ScanResponse(
            success=True,
            data=report
        )
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan-and-analyze", response_model=ScanResponse)
async def scan_and_analyze(request: ScanRequest):
    """
    Complete workflow: Scan domain in 3 scenarios and analyze results.
    This mimics the run_three_scenarios() function.
    """
    try:
        domain = request.domain
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        
        results = {}
        
        # Scenario 1: Fresh browser
        print("Starting scenario 1: Fresh browser")
        file1, data1 = await extract_complete_data(domain, "fresh_browser", use_incognito=True)
        results['fresh_browser'] = data1
        
        # Wait 60 seconds
        print("Waiting 60 seconds for scenario 2...")
        await asyncio.sleep(60)
        
        # Scenario 2: Return visit
        print("Starting scenario 2: Return visit")
        file2, data2 = await extract_complete_data(domain, "return_visit", use_incognito=False)
        results['return_visit'] = data2
        
        # Wait 30 seconds
        print("Waiting 30 seconds for scenario 3...")
        await asyncio.sleep(30)
        
        # Scenario 3: Fresh browser again
        print("Starting scenario 3: Fresh browser again")
        file3, data3 = await extract_complete_data(domain, "cleared_browser", use_incognito=True)
        results['cleared_browser'] = data3
        
        # Analyze all three scenarios
        analyzer = PersistenceAnalyzer(file1, file2, file3)
        report = analyzer.generate_complete_report()
        
        # Combine scan results with analysis
        combined_result = {
            'scan_results': results,
            'analysis': report,
            'domain': domain
        }
        
        return ScanResponse(
            success=True,
            data=combined_result
        )
    except Exception as e:
        print(f"Error during scan and analyze: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

def transform_to_frontend_format(result: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """
    Transform the Python extractor result to match the frontend's expected format.
    """
    indexeddb_data = result.get('indexeddb_data', {})
    network_requests = result.get('network_requests', {})
    
    # Format timestamp properly
    timestamp = result.get('extraction_timestamp', time.time())
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp).isoformat()
    
    # Transform databases
    databases = []
    for db_name, db_data in indexeddb_data.get('databases', {}).items():
        stores = []
        for store_name, store_data in db_data.get('stores', {}).items():
            records = store_data.get('records', [])
            # Extract suspected user data from records
            suspected_user_data = []
            for record in records[:100]:  # Limit to first 100 records
                if isinstance(record, dict):
                    for key, value in record.items():
                        if isinstance(value, str) and len(value) > 10:
                            suspected_user_data.append({
                                'key': key,
                                'value': value[:100],  # Truncate long values
                                'valueLength': len(value),
                                'detectedPatterns': detect_patterns(value)
                            })
            
            stores.append({
                'name': store_name,
                'recordCount': store_data.get('record_count', 0),
                'suspectedUserData': suspected_user_data[:50]  # Limit to 50
            })
        
        databases.append({
            'name': db_name,
            'stores': stores
        })
    
    # Transform network requests to endpoints
    endpoints = []
    requests_list = network_requests.get('requests', [])
    for req in requests_list[:100]:  # Limit to first 100
        url = req.get('url', '')
        method = req.get('method', 'GET')
        
        # Extract parameters from URL
        parameters = []
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            parameters = [f"{k}={v[0]}" for k, v in params.items()][:10]
        except:
            pass
        
        endpoints.append({
            'url': url,
            'method': method,
            'parameters': parameters
        })
    
    return {
        'domain': domain,
        'timestamp': timestamp,
        'databases': databases,
        'endpoints': endpoints
    }

def detect_patterns(value: str) -> List[str]:
    """Detect potential tracking patterns in a value."""
    patterns = []
    value_lower = value.lower()
    
    if any(keyword in value_lower for keyword in ['user', 'uid', 'client_id']):
        patterns.append('user_identifier')
    if any(keyword in value_lower for keyword in ['session', 'token', 'auth']):
        patterns.append('session_token')
    if any(keyword in value_lower for keyword in ['device', 'browser', 'fingerprint']):
        patterns.append('device_fingerprint')
    if any(keyword in value_lower for keyword in ['track', 'analytics', 'gtm']):
        patterns.append('tracking')
    if len(value) > 32 and value.isalnum():
        patterns.append('long_identifier')
    
    return patterns


# ============================================
# TEST ENDPOINTS (Add these lines)
# ============================================

@app.get("/api/test-cors")
async def test_cors():
    import time
    return {"cors": "working", "timestamp": time.time()}

@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}

@app.post("/api/test-scan")
async def test_scan():
    """Simple test endpoint without complex validation"""
    return {
        "success": True,
        "message": "Backend is working",
        "data": {"test": "data"}
    }
# ============================================
# MAIN EXECUTION (This already exists)
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
