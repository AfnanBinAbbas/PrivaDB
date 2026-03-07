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
        """Extract complete IndexedDB data including ALL keys and values"""
        script = """
        async () => {
            const result = {
                timestamp: new Date().toISOString(),
                databases: {},
                database_count: 0,
                total_records: 0,
                all_keys: [],      // Store ALL keys for tracking
                all_values: []     // Store ALL values for tracking
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
                                            
                                            // Get ALL records with their keys
                                            const records = [];
                                            const cursorRequest = store.openCursor();
                                            
                                            await new Promise((res) => {
                                                cursorRequest.onsuccess = (e) => {
                                                    const cursor = e.target.result;
                                                    if (cursor) {
                                                        // Store key and value together
                                                        records.push({
                                                            key: cursor.key,
                                                            value: cursor.value
                                                        });
                                                        
                                                        // Add key to all_keys if it's a string
                                                        if (typeof cursor.key === 'string') {
                                                            result.all_keys.push(cursor.key);
                                                        } else if (cursor.key !== null) {
                                                            result.all_keys.push(JSON.stringify(cursor.key));
                                                        }
                                                        
                                                        // Extract ALL values (including nested)
                                                        const extractValues = (obj) => {
                                                            if (typeof obj === 'string') {
                                                                result.all_values.push(obj);
                                                            } else if (typeof obj === 'number' || typeof obj === 'boolean') {
                                                                result.all_values.push(String(obj));
                                                            } else if (Array.isArray(obj)) {
                                                                obj.forEach(extractValues);
                                                            } else if (obj && typeof obj === 'object') {
                                                                Object.values(obj).forEach(extractValues);
                                                            }
                                                        };
                                                        
                                                        extractValues(cursor.value);
                                                        cursor.continue();
                                                    } else {
                                                        res();
                                                    }
                                                };
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
            
            // Remove duplicates
            result.all_keys = [...new Set(result.all_keys)];
            result.all_values = [...new Set(result.all_values)];
            
            return result;
        }
        """
        
        return await page.evaluate(script)
    
    async def setup_network_listener(self, page):
        """Setup listener to capture ALL network requests"""
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

async def extract_complete_data(url, scenario_name, use_incognito=True, headless=True):
    """Extract IndexedDB data and network requests"""
    extractor = DataExtractor()
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        
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

        # Set longer timeout for the entire operation
        page.set_default_timeout(120000)  # 120 seconds

        try:
            # Try with networkidle first (wait for all network requests)
            await page.goto(url, wait_until='networkidle', timeout=90000)
        except Exception as e:
            print(f"   ⚠️ Network timeout ({str(e)[:50]}), trying basic page load...")
            try:
                # Fallback to domcontentloaded (faster, less strict)
                await page.goto(url, wait_until='domcontentloaded', timeout=90000)
            except Exception as e2:
                print(f"   ⚠️ Still timing out, trying one more time...")
                # Last resort - just navigate and hope for the best
                await page.goto(url, timeout=120000)
        
        print(f"   ✅ Page loaded")
        
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
            'indexeddb_data': indexeddb_data,
            'all_indexeddb_keys': indexeddb_data.get('all_keys', []),
            'all_indexeddb_values': indexeddb_data.get('all_values', [])
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
        print(f"   Total keys extracted: {len(indexeddb_data.get('all_keys', []))}")
        print(f"   Total values extracted: {len(indexeddb_data.get('all_values', []))}")
        print(f"💾 Saved to: {filename}")
        
        await context.close()
        await browser.close()
        
        return filename, result

async def run_three_scenarios(url="https://www.youtube.com"):
    """Run all 3 scenarios"""
    
    print("="*60)
    print("📊 INDEXEDDB + NETWORK REQUEST EXTRACTOR")
    print("="*60)
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
    
    print(f"\n✅ All scenarios complete!")
    print(f"📁 Files: {file1}, {file2}, {file3}")
    
    return file1, file2, file3

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