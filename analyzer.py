import json
import base64
import hashlib
import urllib.parse
import os
import time
import re
from collections import defaultdict

class TrackingDetector:
    def __init__(self, file1, file2, file3):
        self.data1 = self.load_json(file1)
        self.data2 = self.load_json(file2)
        self.data3 = self.load_json(file3)
        self.encoder = ValueEncoder()
        
        # Common UI text to filter out
        self.ui_text_blacklist = [
            'shorts', 'gaming', 'music', 'news', 'account', 'search', 
            'history', 'subscriptions', 'library', 'home', 'trending',
            'kevlar', 'signal', 'content', 'params', 'service', 'header',
            'maxageseconds', 'simpletext', 'accessibilitydata', 'client.version',
            'false', 'true', 'button', 'menu', 'icon', 'tooltip', 'label',
            'سائن', 'کریں', 'کی', 'بورڈ', 'تلاش', 'ہوم', 'آپ', 'مدد',
            'premium', 'kids', 'music', 'round', 'fill', 'outline',
            'experimental', 'svg', 'png', 'jpg', 'css', 'js', 'json',
            'get', 'post', 'fetch', 'xhr', 'script', 'stylesheet',
            'fonts', 'gstatic', 'googleapis', 'youtube.com', 'ytimg',
            'roboto', 'sans', 'woff2', 'ttf', 'eot', 'cookie', 'cookies',
            'localhost', '127.0.0.1', 'cdn', 'api', 'v1', 'v2', 'v3'
        ]
        
        # Patterns that indicate real tracking
        self.tracking_patterns = [
            r'visitor', r'device', r'session', r'token', r'id[^a-z]',
            r'uuid', r'fingerprint', r'client_id', r'user_id',
            r'ga[_\d]', r'gid', r'experiment', r'flag', r'auth',
            r'credential', r'jwt', r'bearer', r'api[_-]?key',
            r'[0-9a-f]{32,}',  # MD5-like
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64-like
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # UUID
        ]
        
    def load_json(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return {}
    
    def is_tracking_identifier(self, value):
        """Determine if a value is REAL tracking data, not UI text"""
        value_str = str(value)
        
        # Skip None, empty, or very short values
        if not value_str or len(value_str) < 8:
            return False
        
        value_lower = value_str.lower()
        
        # ===== FILTER OUT UI TEXT =====
        
        # Skip if contains common UI words
        for ui_word in self.ui_text_blacklist:
            if ui_word in value_lower and len(value_str) < 30:
                return False
        
        # Skip URLs and paths (unless they contain tracking parameters)
        if value_lower.startswith(('http://', 'https://', '/', './', '../')):
            # But keep if it has tracking parameters
            if '?' in value_str and any(p in value_str for p in ['id=', 'token=', 'uid=', 'sid=', 'visitor=']):
                return True
            return False
        
        # Skip if it's a single word without numbers (UI text)
        words = value_str.split()
        if len(words) == 1 and not any(c.isdigit() for c in value_str):
            if len(value_str) < 30:  # Short words like "Shorts", "gaming"
                return False
        
        # ===== DETECT REAL TRACKING =====
        
        # Check tracking patterns
        for pattern in self.tracking_patterns:
            if re.search(pattern, value_lower):
                return True
        
        # High-entropy detection (random-looking strings)
        if len(value_str) > 20:
            # Count character types
            letters = sum(c.isalpha() for c in value_str)
            digits = sum(c.isdigit() for c in value_str)
            special = len(value_str) - letters - digits
            
            # Random strings have mix of types
            if digits > 5 and special > 2:
                return True
            
            # Base64-like (only A-Za-z0-9+/=)
            if re.match(r'^[A-Za-z0-9+/=]+$', value_str) and len(value_str) > 30:
                return True
            
            # Hex-like
            if re.match(r'^[0-9a-fA-F]+$', value_str) and len(value_str) > 16:
                return True
            
            # High entropy (Shannon entropy > 3.5)
            if self.calculate_entropy(value_str) > 3.5:
                return True
        
        # Check for timestamps
        if value_str.isdigit() and len(value_str) in [10, 13]:
            # Check if it's a reasonable timestamp
            timestamp = int(value_str)
            if 1000000000 < timestamp < 2000000000:  # Between 2001 and 2033
                return True
        
        return False
    
    def calculate_entropy(self, s):
        """Calculate Shannon entropy of string"""
        if not s:
            return 0
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = s.count(char)
            if freq > 0:
                freq = float(freq) / len(s)
                entropy -= freq * (freq and freq ** 0.5)
        return entropy
    
    # ============ DYNAMIC ANALYSIS (Your existing code) ============
    
    def get_all_indexeddb_items(self, data):
        """Extract ALL keys and values from IndexedDB (Dynamic)"""
        items = []
        
        if not data:
            return items
        
        # Get from all_keys and all_values
        all_keys = data.get('all_indexeddb_keys', [])
        all_values = data.get('all_indexeddb_values', [])
        
        for key in all_keys:
            if isinstance(key, str) and self.is_tracking_identifier(key):
                items.append({
                    'value': key,
                    'type': 'key',
                    'source': 'all_keys',
                    'is_tracking': True
                })
        
        for value in all_values:
            if isinstance(value, str) and self.is_tracking_identifier(value):
                items.append({
                    'value': value,
                    'type': 'value',
                    'source': 'all_values',
                    'is_tracking': True
                })
        
        # Also get from database structure
        indexeddb_data = data.get('indexeddb_data', {})
        databases = indexeddb_data.get('databases', {})
        
        for db_name, db_data in databases.items():
            stores = db_data.get('stores', {})
            for store_name, store_data in stores.items():
                records = store_data.get('records', [])
                
                for record in records:
                    if isinstance(record, dict):
                        # Add key if it's tracking
                        if 'key' in record and isinstance(record['key'], str):
                            if self.is_tracking_identifier(record['key']):
                                items.append({
                                    'value': record['key'],
                                    'type': 'record_key',
                                    'db': db_name,
                                    'store': store_name,
                                    'is_tracking': True
                                })
                        
                        # Add value if it's tracking
                        if 'value' in record:
                            self._extract_tracking_from_object(record['value'], db_name, store_name, items)
        
        return items
    
    def _extract_tracking_from_object(self, obj, db_name, store_name, items):
        """Recursively extract tracking strings from objects"""
        if obj is None:
            return
        
        if isinstance(obj, str):
            if self.is_tracking_identifier(obj):
                items.append({
                    'value': obj,
                    'type': 'nested_value',
                    'db': db_name,
                    'store': store_name,
                    'is_tracking': True
                })
        elif isinstance(obj, (int, float, bool)):
            str_val = str(obj)
            if self.is_tracking_identifier(str_val):
                items.append({
                    'value': str_val,
                    'type': 'primitive',
                    'db': db_name,
                    'store': store_name,
                    'is_tracking': True
                })
        elif isinstance(obj, list):
            for item in obj:
                self._extract_tracking_from_object(item, db_name, store_name, items)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(key, str) and self.is_tracking_identifier(key):
                    items.append({
                        'value': key,
                        'type': 'object_key',
                        'db': db_name,
                        'store': store_name,
                        'is_tracking': True
                    })
                self._extract_tracking_from_object(val, db_name, store_name, items)
    
    def find_in_network_requests(self, items, requests):
        """Find IndexedDB items in network requests (Dynamic)"""
        transmissions = []
        
        # Only process items that are already identified as tracking
        tracking_items = [item for item in items if item.get('is_tracking', False)]
        
        print(f"   Checking {len(tracking_items)} tracking items against {len(requests)} requests")
        
        for item in tracking_items:
            original = item['value']
            
            # Generate ALL possible encodings
            encodings = self.encoder.generate_all_encodings(original)
            
            for request in requests:
                # Build search text from request
                url = request.get('url', '')
                post_data = request.get('post_data', '')
                headers = json.dumps(request.get('headers', {}))
                
                search_text = f"{url} {post_data} {headers}"
                
                for encoded_value, encoding_type in encodings.items():
                    if not encoded_value:
                        continue
                    
                    if encoded_value in search_text:
                        transmissions.append({
                            'original_value': original[:100],
                            'encoded_value': encoded_value[:100],
                            'encoding_type': encoding_type,
                            'url': url[:200],
                            'method': request.get('method', 'GET'),
                            'item_type': item.get('type', 'unknown'),
                            'location': f"{item.get('db', 'unknown')}.{item.get('store', 'unknown')}",
                            'confidence': self.calculate_confidence(original, encoding_type)
                        })
                        break  # Found, move to next request
                
                if transmissions and transmissions[-1].get('original_value') == original[:100]:
                    break  # Found in this request, move to next item
        
        return transmissions
    
    def calculate_confidence(self, value, encoding_type):
        """Calculate confidence score for a transmission"""
        base = 0.95 if encoding_type == 'original' else 0.85
        
        # Boost for high-entropy
        if len(value) > 30 and self.calculate_entropy(value) > 3.5:
            base += 0.1
        
        # Boost for tracking-related key names
        tracking_keys = ['visitor', 'device', 'session', 'token', 'id']
        if any(key in value.lower() for key in tracking_keys):
            base += 0.1
        
        # Boost for typical identifier formats
        if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', value):  # Base64
            base += 0.1
        if re.match(r'^[0-9a-f]{32,}$', value):  # MD5/hex
            base += 0.1
        
        return min(0.99, base)
    
    def find_persistent_identifiers(self):
        """Find identifiers that persist across all 3 scenarios"""
        items1 = self.get_all_indexeddb_items(self.data1)
        items2 = self.get_all_indexeddb_items(self.data2)
        items3 = self.get_all_indexeddb_items(self.data3)
        
        print(f"   Found {len(items1)} tracking items")
        print(f"   Found {len(items2)} tracking items")
        print(f"   Found {len(items3)} tracking items")
        
        # Create sets of tracking values
        values1 = {item['value'] for item in items1 if item.get('is_tracking', False)}
        values2 = {item['value'] for item in items2 if item.get('is_tracking', False)}
        values3 = {item['value'] for item in items3 if item.get('is_tracking', False)}
        
        # Find intersection (present in ALL scenarios)
        persistent = values1 & values2 & values3
        
        print(f"   Persistent tracking IDs: {len(persistent)}")
        
        return list(persistent), items1, items2, items3
    
    # ============ NEW: STATIC OPERATIONS ANALYSIS ============
    
    def analyze_indexeddb_operations(self):
        """Analyze IndexedDB operations from the extracted data"""
        
        operations = {
            'database_opens': [],
            'store_creations': [],
            'put_operations': [],
            'get_operations': [],
            'delete_operations': [],
            'transactions': []
        }
        
        # Look for operation patterns in the data
        for scenario_idx, data in enumerate([self.data1, self.data2, self.data3]):
            if not data:
                continue
            
            # Check all_indexeddb_keys for operation-related names
            all_keys = data.get('all_indexeddb_keys', [])
            
            # Database names themselves indicate operations
            indexeddb_data = data.get('indexeddb_data', {})
            databases = indexeddb_data.get('databases', {})
            
            for db_name, db_data in databases.items():
                # This database exists, so there was an indexedDB.open operation
                operations['database_opens'].append({
                    'database': db_name,
                    'version': db_data.get('version', 'unknown'),
                    'scenario': scenario_idx
                })
                
                stores = db_data.get('stores', {})
                for store_name, store_data in stores.items():
                    # This store exists, so there was a createObjectStore operation
                    operations['store_creations'].append({
                        'database': db_name,
                        'store': store_name,
                        'scenario': scenario_idx
                    })
                    
                    # Records exist, so there were put/add operations
                    record_count = store_data.get('record_count', 0)
                    if record_count > 0:
                        operations['put_operations'].append({
                            'database': db_name,
                            'store': store_name,
                            'record_count': record_count,
                            'scenario': scenario_idx
                        })
            
            # Check for special operation indicators in keys
            operation_keywords = {
                'transaction': 'transactions',
                'cursor': 'cursor_operations',
                'delete': 'delete_operations',
                'clear': 'delete_operations',
                'getAll': 'get_operations'
            }
            
            for key in all_keys:
                if isinstance(key, str):
                    key_lower = key.lower()
                    for keyword, op_type in operation_keywords.items():
                        if keyword in key_lower:
                            operations[op_type].append({
                                'indicator': key,
                                'scenario': scenario_idx
                            })
        
        # Calculate statistics
        op_stats = {}
        for op_type, op_list in operations.items():
            op_stats[op_type] = len(op_list)
        
        return operations, op_stats
    
    def get_operation_risk_score(self, op_stats):
        """Calculate risk score based on operations"""
        score = 0
        factors = []
        
        # Multiple databases suggest complex storage
        if op_stats.get('database_opens', 0) > 3:
            score += 10
            factors.append(f"Multiple databases ({op_stats['database_opens']})")
        
        # Multiple stores suggest organized tracking
        if op_stats.get('store_creations', 0) > 5:
            score += 15
            factors.append(f"Multiple object stores ({op_stats['store_creations']})")
        
        # Write operations indicate data persistence
        if op_stats.get('put_operations', 0) > 10:
            score += 20
            factors.append(f"High number of write operations ({op_stats['put_operations']})")
        elif op_stats.get('put_operations', 0) > 0:
            score += 10
            factors.append(f"Write operations detected ({op_stats['put_operations']})")
        
        return score, factors
    
    # ============ MAIN ANALYSIS ============
    
    def analyze(self):
        """Complete tracking analysis - Dynamic + Static"""
        
        print("\n🔍 ANALYZING FOR REAL TRACKING DATA")
        print("="*70)
        
        # ===== DYNAMIC ANALYSIS (Your existing code) =====
        print("\n📊 DYNAMIC ANALYSIS (Runtime Data):")
        # Find persistent identifiers
        persistent_values, items1, items2, items3 = self.find_persistent_identifiers()
        
        # Get network requests
        req1 = self.data1.get('network_requests', {}).get('requests', []) if self.data1 else []
        req2 = self.data2.get('network_requests', {}).get('requests', []) if self.data2 else []
        req3 = self.data3.get('network_requests', {}).get('requests', []) if self.data3 else []
        
        # Find transmissions in each scenario
        trans1 = self.find_in_network_requests(items1, req1)
        trans2 = self.find_in_network_requests(items2, req2)
        trans3 = self.find_in_network_requests(items3, req3)
        
        # Find which persistent values are transmitted
        transmitted_persistent = set()
        all_transmissions = trans1 + trans2 + trans3
        
        for trans in all_transmissions:
            if trans['original_value'] in persistent_values:
                transmitted_persistent.add(trans['original_value'])
        
        # Group by encoding type
        encoding_stats = defaultdict(int)
        for trans in all_transmissions:
            encoding_stats[trans['encoding_type']] += 1
        
        # ===== STATIC OPERATIONS ANALYSIS (NEW) =====
        print("\n🔧 STATIC ANALYSIS (Code Operations):")
        operations, op_stats = self.analyze_indexeddb_operations()
        
        print(f"   Database opens: {op_stats.get('database_opens', 0)}")
        print(f"   Store creations: {op_stats.get('store_creations', 0)}")
        print(f"   Write operations: {op_stats.get('put_operations', 0)}")
        
        # Calculate risk scores
        dynamic_risk_score = 0
        risk_factors = []
        
        # Dynamic risk factors (based on actual data)
        if len(persistent_values) > 10:
            dynamic_risk_score += 20
            risk_factors.append(f"High number of persistent tracking identifiers ({len(persistent_values)})")
        elif len(persistent_values) > 5:
            dynamic_risk_score += 10
            risk_factors.append(f"Moderate persistent tracking identifiers ({len(persistent_values)})")
        
        if len(transmitted_persistent) > 5:
            dynamic_risk_score += 30
            risk_factors.append(f"High transmission rate ({len(transmitted_persistent)} tracking identifiers sent)")
        elif len(transmitted_persistent) > 0:
            dynamic_risk_score += 15
            risk_factors.append(f"Tracking identifiers being transmitted to servers")
        
        if encoding_stats.get('base64', 0) > 0 or encoding_stats.get('md5', 0) > 0:
            dynamic_risk_score += 25
            risk_factors.append(f"Encoded transmission detected (Base64/Hashes) - indicates intentional tracking")
        
        # Static risk factors (based on operations)
        static_risk_score, static_factors = self.get_operation_risk_score(op_stats)
        risk_factors.extend(static_factors)
        
        # Combined risk score
        total_risk_score = min(100, dynamic_risk_score + static_risk_score)
        
        # Determine rating
        if total_risk_score >= 60:
            rating = "HIGH_RISK"
        elif total_risk_score >= 30:
            rating = "MEDIUM_RISK"
        else:
            rating = "LOW_RISK"
        
        # ===== RESULTS =====
        return {
            'summary': {
                'total_indexeddb_items': len(items1),
                'persistent_identifiers': len(persistent_values),
                'total_transmissions': len(all_transmissions),
                'persistent_transmitted': len(transmitted_persistent),
                'transmission_rate': f"{(len(transmitted_persistent)/max(1,len(persistent_values))*100):.1f}%",
                'risk_score': total_risk_score,
                'risk_rating': rating,
                'risk_factors': risk_factors
            },
            'encoding_stats': dict(encoding_stats),
            'transmissions_by_scenario': {
                'fresh_browser': len(trans1),
                'return_visit': len(trans2),
                'cleared_browser': len(trans3)
            },
            'sample_transmissions': all_transmissions[:30],
            'persistent_samples': list(persistent_values)[:20],
            'transmitted_samples': list(transmitted_persistent)[:10],
            # NEW: Operations analysis results
            'operations_analysis': {
                'summary': op_stats,
                'details': operations
            }
        }


class ValueEncoder:
    """Generate ALL possible encoded versions of a value"""
    
    def generate_all_encodings(self, value):
        """Generate every possible encoding of a value"""
        encodings = {}
        value_str = str(value)
        
        # Original
        encodings[value_str] = 'original'
        
        try:
            # URL Encoding
            encodings[urllib.parse.quote(value_str)] = 'url_encoded'
            encodings[urllib.parse.quote_plus(value_str)] = 'url_plus_encoded'
        except:
            pass
        
        try:
            # Base64
            b64 = base64.b64encode(value_str.encode()).decode()
            encodings[b64] = 'base64'
            encodings[b64.rstrip('=')] = 'base64_no_padding'
        except:
            pass
        
        try:
            # Hex
            encodings[value_str.encode().hex()] = 'hex'
        except:
            pass
        
        try:
            # Common hashes
            encodings[hashlib.md5(value_str.encode()).hexdigest()] = 'md5'
            encodings[hashlib.sha1(value_str.encode()).hexdigest()] = 'sha1'
            encodings[hashlib.sha256(value_str.encode()).hexdigest()] = 'sha256'
        except:
            pass
        
        try:
            # JSON
            encodings[json.dumps(value_str)] = 'json_string'
            encodings[json.dumps({'id': value_str})] = 'json_wrapped'
        except:
            pass
        
        # Common transformations
        encodings[value_str.lower()] = 'lowercase'
        encodings[value_str.upper()] = 'uppercase'
        
        # Truncated versions (common in URLs)
        if len(value_str) > 16:
            encodings[value_str[:16]] = 'prefix_16'
            encodings[value_str[-16:]] = 'suffix_16'
        
        if len(value_str) > 32:
            encodings[value_str[:32]] = 'prefix_32'
            encodings[value_str[-32:]] = 'suffix_32'
        
        return encodings


def main():
    print("="*70)
    print("🔍 INDEXEDDB TRACKING DETECTOR - HYBRID MODE")
    print("="*70)
    print("• Dynamic Analysis: Runtime data + network transmissions")
    print("• Static Analysis: IndexedDB operations detection")
    print("="*70)
    
    # Find files
    files = []
    if os.path.exists('data'):
        for f in os.listdir('data'):
            if '_complete.json' in f:
                files.append(f"data/{f}")
    
    files.sort(key=os.path.getmtime, reverse=True)
    
    if len(files) < 3:
        print("❌ Need at least 3 scan files")
        print("   Run extractor.py first")
        return
    
    files_to_use = files[:3]
    print(f"📂 Analyzing: {[os.path.basename(f) for f in files_to_use]}")
    
    # Run analysis
    detector = TrackingDetector(files_to_use[0], files_to_use[1], files_to_use[2])
    results = detector.analyze()
    
    # Print results
    print("\n" + "="*70)
    print("📊 TRACKING DETECTION RESULTS")
    print("="*70)
    print(f"📌 IndexedDB items: {results['summary']['total_indexeddb_items']}")
    print(f"📌 Persistent identifiers: {results['summary']['persistent_identifiers']}")
    print(f"📌 Total transmissions: {results['summary']['total_transmissions']}")
    print(f"📌 Persistent transmitted: {results['summary']['persistent_transmitted']}")
    print(f"📌 Transmission rate: {results['summary']['transmission_rate']}")
    print(f"📊 Risk Score: {results['summary']['risk_score']}/100")
    print(f"⚠️ Risk Rating: {results['summary']['risk_rating']}")
    
    print("\n⚠️ Risk Factors:")
    for factor in results['summary']['risk_factors']:
        print(f"   • {factor}")
    
    # NEW: Print operations analysis
    print("\n🔧 INDEXEDDB OPERATIONS DETECTED:")
    op_summary = results['operations_analysis']['summary']
    print(f"   • Database opens: {op_summary.get('database_opens', 0)}")
    print(f"   • Store creations: {op_summary.get('store_creations', 0)}")
    print(f"   • Write operations (put/add): {op_summary.get('put_operations', 0)}")
    print(f"   • Transaction operations: {op_summary.get('transactions', 0)}")
    
    print("\n🔧 Encoding Methods Detected:")
    for enc, count in results['encoding_stats'].items():
        print(f"   • {enc}: {count} times")
    
    if results['sample_transmissions']:
        print("\n🔍 REAL TRACKING TRANSMISSIONS:")
        for i, trans in enumerate(results['sample_transmissions'][:10]):
            print(f"\n   {i+1}. Original: {trans['original_value'][:50]}...")
            print(f"     Encoded as: {trans['encoding_type']} (confidence: {trans['confidence']:.2f})")
            print(f"     URL: {trans['url'][:80]}...")
    
    # Save report
    os.makedirs('reports', exist_ok=True)
    report_file = f"reports/tracking_hybrid_{int(time.time())}.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Hybrid report saved to: {report_file}")


if __name__ == "__main__":
    main()