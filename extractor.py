import asyncio
import json
import time
import os
from urllib.parse import urlparse
from playwright.async_api import async_playwright

class DataExtractor:
    def __init__(self):
        self.network_requests = []
        
    async def extract_indexeddb_data(self, page):
        """Extract complete IndexedDB data including content"""
        script = """
        async () => {
            const result = {
                timestamp: new Date().toISOString(),
                databases: {},
                database_count: 0,
                total_records: 0
            };
            
            try {
                if (!window.indexedDB) {
                    result.error = "IndexedDB not supported";
                    return result;
                }
                
                // Get list of databases
                if (window.indexedDB.databases) {
                    const dbs = await window.indexedDB.databases();
                    result.database_count = dbs.length;
                    
                    // Extract data from each database
                    for (const dbInfo of dbs) {
                        if (!dbInfo.name) continue;
                        
                        const dbData = {
                            name: dbInfo.name,
                            version: dbInfo.version,
                            stores: {},
                            record_count: 0
                        };
                        
                        try {
                            // Open database
                            const request = indexedDB.open(dbInfo.name, dbInfo.version);
                            
                            await new Promise((resolve, reject) => {
                                request.onsuccess = async (event) => {
                                    const db = event.target.result;
                                    const storeNames = Array.from(db.objectStoreNames);
                                    
                                    for (const storeName of storeNames) {
                                        try {
                                            const transaction = db.transaction(storeName, "readonly");
                                            const store = transaction.objectStore(storeName);
                                            const getAllRequest = store.getAll();
                                            
                                            const records = await new Promise((res, rej) => {
                                                getAllRequest.onsuccess = () => res(getAllRequest.result);
                                                getAllRequest.onerror = () => res([]);
                                            });
                                            
                                            dbData.stores[storeName] = {
                                                records: records,
                                                record_count: records.length
                                            };
                                            dbData.record_count += records.length;
                                            result.total_records += records.length;
                                        } catch (storeErr) {
                                            dbData.stores[storeName] = {
                                                error: storeErr.toString(),
                                                records: []
                                            };
                                        }
                                    }
                                    db.close();
                                    resolve();
                                };
                                request.onerror = () => {
                                    dbData.error = "Failed to open database";
                                    resolve();
                                };
                            });
                            
                        } catch (dbErr) {
                            dbData.error = dbErr.toString();
                        }
                        
                        result.databases[dbInfo.name] = dbData;
                    }
                } else {
                    result.error = "indexedDB.databases() not available";
                }
                
            } catch (err) {
                result.error = err.toString();
            }
            
            return result;
        }
        """
        
        return await page.evaluate(script)
    
    async def setup_network_listener(self, page):
        """Setup listener to capture network requests with post data"""
        self.network_requests = []
        
        async def on_request(request):
            try:
                request_data = {
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'post_data': request.post_data,
                    'resource_type': request.resource_type,
                    'timestamp': time.time(),
                    'domain': urlparse(request.url).netloc
                }
                
                # Try to get response
                try:
                    response = await request.response()
                    if response:
                        request_data['response'] = {
                            'status': response.status,
                            'headers': dict(response.headers),
                            'url': response.url
                        }
                except:
                    pass
                
                self.network_requests.append(request_data)
            except:
                pass
        
        page.on("request", on_request)
        return page

async def extract_complete_data(url, scenario_name, use_incognito=True):
    """Extract IndexedDB data and network requests only"""
    extractor = DataExtractor()
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        
        if use_incognito:
            context = await browser.new_context()
        else:
            context = await browser.new_context(storage_state=None)
        
        page = await context.new_page()
        page = await extractor.setup_network_listener(page)

        print(f"\n{'='*50}")
        print(f"🌐 SCENARIO: {scenario_name.upper()}")
        print(f"🔗 URL: {url}")
        print('='*50)
        
        # Visit the website
        print(f"   Loading page and capturing network requests...")
        try:
            await page.goto(url, wait_until='networkidle', timeout=60000)
        except:
            await page.goto(url, wait_until='domcontentloaded', timeout=60000)
        
        # Wait for additional requests
        await asyncio.sleep(10)
        
        # Extract IndexedDB data
        print(f"   Extracting IndexedDB data...")
        indexeddb_data = await extractor.extract_indexeddb_data(page)
        
        # Compile results
        result = {
            'scenario': scenario_name,
            'url': url,
            'extraction_timestamp': time.time(),
            'network_requests': {
                'total_requests': len(extractor.network_requests),
                'requests': extractor.network_requests
            },
            'indexeddb_data': indexeddb_data
        }
        
        # Create filename
        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"data/{scenario_name}_{domain}_complete.json"
        
        if not os.path.exists('data'):
            os.makedirs('data')
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        # Print summary
        print(f"✅ Extraction complete for {scenario_name}")
        print(f"   Network requests: {len(extractor.network_requests)}")
        print(f"   IndexedDB databases: {indexeddb_data.get('database_count', 0)}")
        print(f"   Total records: {indexeddb_data.get('total_records', 0)}")
        print(f"💾 Saved to: {filename}")
        
        await context.close()
        await browser.close()
        
        return filename, result

async def run_three_scenarios():
    """Run all 3 scenarios"""
    url = "https://www.youtube.com"
    
    print("="*60)
    print("📊 INDEXEDDB + NETWORK REQUEST EXTRACTOR")
    print("="*60)
    print("Extracting: IndexedDB data + Network requests")
    print("Running 3 scenarios:")
    print("1. Fresh browser (first visit)")
    print("2. Return visit (after 1 min)")
    print("3. Fresh browser again")
    print("="*60)
    
    if not os.path.exists('data'):
        os.makedirs('data')
    
    results = {}
    
    # Scenario 1: Fresh browser
    print(f"\n▶️ STARTING SCENARIO 1/3: Fresh Browser")
    file1, data1 = await extract_complete_data(url, "fresh_browser", use_incognito=True)
    results['fresh_browser'] = data1
    
    # Wait 60 seconds for scenario 2
    print(f"\n⏳ Waiting 60 seconds for scenario 2...")
    for i in range(6):
        if (i+1) * 10 <= 60:
            print(f"   {(i+1)*10} seconds passed...")
        await asyncio.sleep(10)
    
    # Scenario 2: Return visit
    print(f"\n▶️ STARTING SCENARIO 2/3: Return Visit")
    file2, data2 = await extract_complete_data(url, "return_visit", use_incognito=False)
    results['return_visit'] = data2
    
    # Wait 30 seconds for scenario 3
    print(f"\n⏳ Waiting 30 seconds for scenario 3...")
    await asyncio.sleep(30)
    
    # Scenario 3: Fresh browser again
    print(f"\n▶️ STARTING SCENARIO 3/3: Fresh Browser Again")
    file3, data3 = await extract_complete_data(url, "cleared_browser", use_incognito=True)
    results['cleared_browser'] = data3
    
    # Generate summary
    print(f"\n{'='*60}")
    print("📈 EXTRACTION SUMMARY")
    print('='*60)
    
    summary = {
        'website': url,
        'scenarios_completed': 3,
        'files': [file1, file2, file3],
        'summary_by_scenario': {}
    }
    
    for scenario, data in results.items():
        db_count = data.get('indexeddb_data', {}).get('database_count', 0)
        db_names = list(data.get('indexeddb_data', {}).get('databases', {}).keys())
        network_reqs = data.get('network_requests', {}).get('total_requests', 0)
        records = data.get('indexeddb_data', {}).get('total_records', 0)
        
        summary['summary_by_scenario'][scenario] = {
            'databases': db_count,
            'network_requests': network_reqs,
            'indexeddb_records': records,
            'has_error': 'error' in data.get('indexeddb_data', {})
        }
        
        status = "✅" if 'error' not in data.get('indexeddb_data', {}) else "❌"
        print(f"{status} {scenario}:")
        print(f"   Databases: {db_count} | Records: {records}")
        print(f"   Network requests: {network_reqs}")
    
    summary_file = "data/extraction_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Summary saved to: {summary_file}")
    print(f"\n{'='*60}")
    print("🎯 READY FOR ANALYSIS")
    print(f"Files to analyze: {file1}, {file2}, {file3}")
    print('='*60)
    
    return results

def main():
    try:
        import playwright
    except ImportError:
        print("Installing playwright...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
        subprocess.check_call(["playwright", "install", "chromium"])
    
    asyncio.run(run_three_scenarios())

if __name__ == "__main__":
    main()