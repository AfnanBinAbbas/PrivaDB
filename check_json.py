# save as check_json.py
import json

files = [
    "data/fresh_browser.json",
    "data/same_session_return.json", 
    "data/cleared_browser.json"
]

for file in files:
    try:
        with open(file, 'r') as f:
            data = json.load(f)
        print(f"\n✅ {file}:")
        print(f"   Scenario: {data.get('scenario', 'No scenario key')}")
        print(f"   Keys: {list(data.keys())}")
        
        # Check IndexedDB data
        if 'indexeddb_data' in data:
            print(f"   IndexedDB databases: {data['indexeddb_data'].get('database_count', 0)}")
            print(f"   IndexedDB keys: {list(data['indexeddb_data'].keys())}")
        
        # Check network requests
        if 'network_requests' in data:
            print(f"   Network requests: {data['network_requests'].get('total_requests', 0)}")
    except Exception as e:
        print(f"\n❌ {file}: {e}")