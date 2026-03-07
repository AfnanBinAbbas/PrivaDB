from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
import os
import time
from datetime import datetime

from extractor import extract_complete_data, run_three_scenarios
from analyzer import TrackingDetector

app = FastAPI(title="IndexedDB Tracking Detector API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    url: str
    scenario: Optional[str] = "scan"

class AnalyzeRequest(BaseModel):
    files: List[str]

# Storage
scan_tasks = {}

# ==================== ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "name": "IndexedDB Tracking Detector",
        "version": "1.0.0",
        "description": "Extracts IndexedDB data and detects tracking in network requests",
        "features": [
            "Extracts ALL IndexedDB keys and values",
            "Detects encoded values in network requests (Base64, URL, Hashes)",
            "Identifies persistent identifiers across sessions",
            "Calculates privacy risk score"
        ]
    }

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": time.time()
    }

@app.post("/api/scan")
async def scan_website(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a scan to extract IndexedDB and network data"""
    try:
        url = request.url
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        task_id = f"{request.scenario}_{int(time.time())}"
        
        background_tasks.add_task(run_scan_task, task_id, url, request.scenario)
        
        return {
            "success": True,
            "message": f"Scan started for {url}",
            "task_id": task_id
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

@app.post("/api/scan-full")
async def scan_full(url: str = "https://www.youtube.com"):
    """Run all 3 scenarios and save tracking report to file"""
    try:
        # Run the 3 scenarios
        file1, file2, file3 = await run_three_scenarios(url)
        
        # Analyze for tracking
        detector = TrackingDetector(file1, file2, file3)
        results = detector.analyze()
        
        # Create a clean domain name for filename
        domain_clean = url.replace('https://', '').replace('http://', '').replace('www.', '').replace('.', '_')
        
        # Save tracking report to a separate file
        report_file = f"reports/tracking_{domain_clean}_{int(time.time())}.json"
        os.makedirs('reports', exist_ok=True)
        
        # Create a comprehensive tracking report
        tracking_report = {
            "scan_timestamp": time.time(),
            "scan_date": datetime.now().isoformat(),
            "domain": url,
            "risk_assessment": results['summary'],
            "encoding_methods_detected": results['encoding_stats'],
            "transmissions_by_scenario": results['transmissions_by_scenario'],
            "sample_transmissions": results['sample_transmissions'][:20],
            "persistent_identifiers": results['persistent_samples'],
            "transmitted_identifiers": results['transmitted_samples'],
            "files_generated": [file1, file2, file3]
        }
        
        # Save the report
        with open(report_file, 'w') as f:
            json.dump(tracking_report, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"✅ TRACKING REPORT SAVED TO: {report_file}")
        print(f"{'='*70}")
        print(f"📊 Risk Score: {results['summary']['risk_score']}/100")
        print(f"⚠️ Risk Rating: {results['summary']['risk_rating']}")
        print(f"📌 Persistent IDs: {results['summary']['persistent_identifiers']}")
        print(f"📤 Transmissions: {results['summary']['total_transmissions']}")
        print(f"{'='*70}\n")
        
        # Return minimal response to frontend
        return {
            "success": True,
            "message": f"Scan complete. Check reports folder for tracking analysis.",
            "report_file": report_file,
            "summary": {
                "risk_score": results['summary']['risk_score'],
                "risk_rating": results['summary']['risk_rating'],
                "persistent_ids": results['summary']['persistent_identifiers'],
                "transmissions": results['summary']['total_transmissions']
            }
        }
        
    except Exception as e:
        print(f"❌ Error in scan-full: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "message": str(e)
        }

# ============ COMPATIBILITY ENDPOINT ============
@app.post("/api/scan-with-tracking")
async def scan_with_tracking(domain: str = "www.youtube.com"):
    """Compatibility endpoint for frontend - returns format that matches your frontend interface"""
    try:
        # Format the URL properly
        if not domain.startswith(('http://', 'https://')):
            url = f"https://{domain}"
        else:
            url = domain
            
        print(f"🔍 Scan with tracking called for: {url}")
        
        # Run the 3 scenarios
        file1, file2, file3 = await run_three_scenarios(url)
        
        # Analyze for tracking
        detector = TrackingDetector(file1, file2, file3)
        results = detector.analyze()
        
        # Create a ScanResult object for the frontend
        clean_domain = domain.replace('www.', '').replace('.com', '')
        
        # Build databases array from results
        databases = []
        if results.get('persistent_samples'):
            # Create a database entry for persistent identifiers
            persistent_store = {
                "name": "persistent_store",
                "recordCount": len(results['persistent_samples']),
                "suspectedUserData": []
            }
            
            # Add persistent identifiers as suspected user data
            for pid in results['persistent_samples'][:20]:
                persistent_store["suspectedUserData"].append({
                    "key": "persistent_identifier",
                    "value": pid[:100] + ("..." if len(pid) > 100 else ""),
                    "valueLength": len(pid),
                    "detectedPatterns": ["persistent", "tracking"] if len(pid) > 20 else ["persistent"]
                })
            
            databases.append({
                "name": "Persistent Identifiers Database",
                "stores": [persistent_store]
            })
        
        # Create a database for transmissions if any
        if results.get('sample_transmissions'):
            transmission_store = {
                "name": "transmissions_store",
                "recordCount": len(results['sample_transmissions']),
                "suspectedUserData": []
            }
            
            for trans in results['sample_transmissions'][:10]:
                transmission_store["suspectedUserData"].append({
                    "key": "transmitted_value",
                    "value": trans['original_value'][:100] + ("..." if len(trans['original_value']) > 100 else ""),
                    "valueLength": len(trans['original_value']),
                    "detectedPatterns": [trans['encoding_type'], "transmitted"]
                })
            
            databases.append({
                "name": "Transmitted Data Database",
                "stores": [transmission_store]
            })
        
        # Build endpoints array from transmissions
        endpoints = []
        for trans in results.get('sample_transmissions', [])[:20]:
            # Extract parameters from URL if possible
            parameters = []
            if '?' in trans['url']:
                try:
                    query_part = trans['url'].split('?')[1]
                    params = query_part.split('&')
                    parameters = [p.split('=')[0] for p in params if '=' in p][:5]
                except:
                    parameters = ["tracking_param"]
            
            endpoints.append({
                "url": trans['url'][:200] + ("..." if len(trans['url']) > 200 else ""),
                "method": trans['method'],
                "parameters": parameters[:5]
            })
        
        # Create the ScanResult object
        scan_result = {
            "domain": clean_domain,
            "timestamp": datetime.now().isoformat(),
            "databases": databases,
            "endpoints": endpoints[:20]
        }
        
        # Create scan_data with all three scenarios (using same data for simplicity)
        scan_data = {
            "fresh_browser": scan_result,
            "return_visit": scan_result,
            "cleared_browser": scan_result
        }
        
        # Return in the format your frontend expects!
        return {
            "success": True,
            "domain": clean_domain,
            "url": url,
            "scan_data": scan_data,
            "analysis": results,  # Full tracking analysis
            "files": [file1, file2, file3]
        }
        
    except Exception as e:
        print(f"❌ Error in scan-with-tracking: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "error": str(e)
        }
# ====================================================

@app.get("/api/scan/{task_id}")
async def get_scan_result(task_id: str):
    """Get scan result by task ID"""
    if task_id in scan_tasks:
        return scan_tasks[task_id]
    return {"status": "pending", "task_id": task_id}

@app.post("/api/analyze")
async def analyze_tracking(request: AnalyzeRequest):
    """Analyze scan files for tracking"""
    try:
        if len(request.files) < 3:
            return {
                "success": False,
                "message": "Need at least 3 files for analysis"
            }
        
        detector = TrackingDetector(
            request.files[0],
            request.files[1],
            request.files[2]
        )
        
        results = detector.analyze()
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_file = f"reports/analysis_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return {
            "success": True,
            "message": "Analysis complete",
            "report_file": report_file
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

@app.get("/api/data/{filename}")
async def get_data(filename: str):
    """Get raw scan data"""
    filepath = f"data/{filename}"
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return {"error": "File not found"}

@app.get("/api/files")
async def list_files():
    """List all scan files"""
    files = []
    if os.path.exists('data'):
        for f in os.listdir('data'):
            if f.endswith('.json'):
                files.append({
                    "name": f,
                    "path": f"data/{f}",
                    "size": os.path.getsize(f"data/{f}"),
                    "modified": datetime.fromtimestamp(os.path.getmtime(f"data/{f}")).isoformat()
                })
    
    files.sort(key=lambda x: x['modified'], reverse=True)
    return {"files": files, "total": len(files)}

@app.get("/api/reports")
async def list_reports():
    """List all tracking reports"""
    reports = []
    if os.path.exists('reports'):
        for f in os.listdir('reports'):
            if f.endswith('.json'):
                filepath = f"reports/{f}"
                reports.append({
                    "name": f,
                    "path": filepath,
                    "size": os.path.getsize(filepath),
                    "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
    
    reports.sort(key=lambda x: x['modified'], reverse=True)
    return {"reports": reports, "total": len(reports)}

@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    stats = {
        "total_scans": 0,
        "total_requests": 0,
        "total_indexeddb_items": 0,
        "total_reports": 0
    }
    
    if os.path.exists('data'):
        files = [f for f in os.listdir('data') if f.endswith('.json')]
        stats['total_scans'] = len(files)
    
    if os.path.exists('reports'):
        stats['total_reports'] = len([f for f in os.listdir('reports') if f.endswith('.json')])
    
    return stats

@app.get("/api/test")
async def test():
    return {
        "success": True,
        "message": "Backend is working",
        "timestamp": time.time()
    }

# ==================== BACKGROUND TASKS ====================

async def run_scan_task(task_id: str, url: str, scenario: str):
    """Run scan in background"""
    try:
        filename, data = await extract_complete_data(url, scenario)
        scan_tasks[task_id] = {
            "status": "completed",
            "url": url,
            "filename": filename,
            "summary": {
                "requests": data.get('network_requests', {}).get('total_requests', 0),
                "databases": data.get('indexeddb_data', {}).get('database_count', 0),
                "keys": len(data.get('all_indexeddb_keys', [])),
                "values": len(data.get('all_indexeddb_values', []))
            },
            "timestamp": time.time()
        }
    except Exception as e:
        scan_tasks[task_id] = {
            "status": "failed",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    print("="*70)
    print("🚀 INDEXEDDB TRACKING DETECTOR API")
    print("="*70)
    print("• Extracts ALL IndexedDB keys and values")
    print("• Detects encoded values in network requests")
    print("• Finds persistent identifiers across sessions")
    print("• Saves tracking reports to /reports folder")
    print("="*70)
    uvicorn.run(app, host="0.0.0.0", port=8000)