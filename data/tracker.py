import json
import re
from urllib.parse import urlparse, parse_qs

class EnhancedTrackingDetector:
    def __init__(self, standard_data_file, persistence_file=None):
        self.standard_data_file = standard_data_file
        self.persistence_file = persistence_file
        self.loaded_data = None
        self.persistence_data = None
        self.tracking_matches = []
        self.persistent_tracking_matches = []
        
    def load_all_data(self):
        """Load both standard data and persistence results"""
        # Load standard data
        try:
            with open(self.standard_data_file, 'r', encoding='utf-8') as f:
                self.loaded_data = json.load(f)
            print(f"✅ Loaded standard data: {self.loaded_data['website']}")
            print(f"   Requests: {len(self.loaded_data['network_requests'])}")
            print(f"   IndexedDB records: {self.loaded_data['summary']['indexed_db_stats']['total_records']}")
        except Exception as e:
            print(f"❌ Error loading standard data: {e}")
            return False
        
        # Load persistence data if provided
        if self.persistence_file:
            try:
                with open(self.persistence_file, 'r', encoding='utf-8') as f:
                    self.persistence_data = json.load(f)
                print(f"✅ Loaded persistence data")
                print(f"   Verified persistent IDs: {len(self.persistence_data.get('persistent_identifiers', []))}")
            except Exception as e:
                print(f"⚠️  Could not load persistence data: {e}")
                self.persistence_data = None
        
        return True
    
    def get_verified_persistent_ids(self):
        """Extract verified persistent IDs from persistence analysis"""
        if not self.persistence_data:
            return set()
        
        persistent_ids = set()
        for pid in self.persistence_data.get('persistent_identifiers', []):
            # Add both values for comparison
            persistent_ids.add(pid.get('first_visit_value', ''))
            persistent_ids.add(pid.get('fresh_browser_value', ''))
        
        # Remove empty strings
        persistent_ids = {pid for pid in persistent_ids if pid}
        print(f"🔍 Extracted {len(persistent_ids)} verified persistent IDs")
        return persistent_ids
    
    def extract_all_indexeddb_values(self):
        """Extract ALL values from IndexedDB (your original method)"""
        values = set()
        
        if not self.loaded_data or 'indexed_db_data' not in self.loaded_data:
            return values
            
        indexed_db = self.loaded_data['indexed_db_data']
        
        # Extract from all databases and stores
        if 'databases' in indexed_db:
            for db_name, db_content in indexed_db['databases'].items():
                if isinstance(db_content, dict):
                    for store_name, records in db_content.items():
                        if isinstance(records, list):
                            for record in records:
                                self._extract_values_from_record(record, values)
        
        print(f"🔍 Found {len(values)} total values in IndexedDB")
        return values
    
    def _extract_values_from_record(self, record, values_set):
        """Recursively extract values from IndexedDB records"""
        if isinstance(record, dict):
            if '_serialized' in record:
                serialized = record['_serialized']
                self._find_potential_ids_in_string(serialized, values_set)
            
            if '_original' in record:
                self._extract_values_from_object(record['_original'], values_set)
            else:
                self._extract_values_from_object(record, values_set)
        else:
            self._extract_values_from_object(record, values_set)
    
    def _extract_values_from_object(self, obj, values_set, current_key=""):
        """Extract values from any object"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{current_key}.{key}" if current_key else key
                self._extract_values_from_object(value, values_set, full_key)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_values_from_object(item, values_set, current_key)
        elif isinstance(obj, (str, int, float)):
            if self._is_potential_tracking_id(obj, current_key):
                values_set.add(str(obj))
    
    def _find_potential_ids_in_string(self, text, values_set):
        """Find potential tracking IDs in serialized strings"""
        if not isinstance(text, str):
            return
            
        patterns = [
            r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}',
            r'[a-fA-F0-9]{32}',
            r'[a-fA-F0-9]{16,}',
            r'[a-zA-Z0-9_\-=+/]{20,}',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if self._is_potential_tracking_id(match):
                    values_set.add(match)
    
    def _is_potential_tracking_id(self, value, key_name=""):
        """Determine if a value looks like a tracking ID"""
        if not isinstance(value, (str, int, float)):
            return False
        
        str_value = str(value)
        
        if not str_value or len(str_value) < 8:
            return False
        
        tracking_keys = ['id', 'uid', 'user_id', 'userId', 'client_id', 'device_id', 
                        'session_id', 'tracking_id', 'ga_id', 'gid', 'cid', 
                        'visitor_id', 'uuid', 'deviceId', 'visitorData',
                        'key', 'token', 'session', 'tracking', 'identifier']
        
        if key_name and any(tracking_key in key_name.lower() for tracking_key in tracking_keys):
            return True
        
        if len(str_value) >= 8:
            if (re.match(r'^[a-zA-Z0-9_\-=+/]{8,}$', str_value) and
                not re.match(r'^\d{1,10}$', str_value) and
                not re.match(r'^20\d{2}-\d{2}-\d{2}', str_value) and
                not any(word in str_value.lower() for word in [
                    'null', 'undefined', 'true', 'false', 'http', 'https', 
                    'www.', '.com', '.org', 'localhost'
                ])):
                return True
        
        return False
    
    def analyze_network_requests(self, indexed_values):
        """Analyze all network requests for tracking patterns"""
        if not self.loaded_data or 'network_requests' not in self.loaded_data:
            return []
        
        matches = []
        requests = self.loaded_data['network_requests']
        
        print(f"🔎 Scanning {len(requests)} requests...")
        
        for i, request in enumerate(requests):
            if request.get('url'):
                url_matches = self._check_url_for_matches(request['url'], indexed_values)
                for match in url_matches:
                    match['request_method'] = request.get('method', 'GET')
                    match['resource_type'] = request.get('resource_type', 'unknown')
                    matches.append(match)
            
            if request.get('post_data'):
                post_matches = self._check_post_data(request['post_data'], indexed_values)
                for match in post_matches:
                    match['request_method'] = request.get('method', 'POST')
                    match['resource_type'] = request.get('resource_type', 'unknown')
                    match['request_url'] = request.get('url', 'POST_DATA')
                    matches.append(match)
            
            if (i + 1) % 20 == 0:
                print(f"   Scanned {i + 1}/{len(requests)} requests...")
        
        return matches
    
    def _check_url_for_matches(self, url, indexed_values):
        """Check URL for matching values"""
        matches = []
        try:
            for value in indexed_values:
                if value and len(value) >= 8 and value in url:
                    matches.append({
                        'match_type': 'url_content',
                        'parameter_name': 'full_url',
                        'matched_value': value,
                        'request_url': url,
                        'confidence': 'medium'
                    })
            
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                for value in values:
                    if value in indexed_values:
                        matches.append({
                            'match_type': 'url_parameter',
                            'parameter_name': param,
                            'matched_value': value,
                            'request_url': url,
                            'confidence': 'high'
                        })
            
            path_segments = [seg for seg in parsed.path.split('/') if seg]
            for segment in path_segments:
                if segment in indexed_values:
                    matches.append({
                        'match_type': 'url_path',
                        'parameter_name': 'path_segment',
                        'matched_value': segment,
                        'request_url': url,
                        'confidence': 'medium'
                    })
                    
        except Exception as e:
            print(f"Error checking URL {url}: {e}")
        
        return matches
    
    def _check_post_data(self, post_data, indexed_values):
        """Check POST data for matches"""
        matches = []
        try:
            if post_data.strip().startswith('{'):
                data = json.loads(post_data)
                flattened = self._flatten_json(data)
                for key, value in flattened.items():
                    if str(value) in indexed_values:
                        matches.append({
                            'match_type': 'post_data_json',
                            'parameter_name': key,
                            'matched_value': value,
                            'request_url': 'POST_DATA',
                            'confidence': 'high'
                        })
            
            elif '=' in post_data:
                params = parse_qs(post_data)
                for param, values in params.items():
                    for value in values:
                        if value in indexed_values:
                            matches.append({
                                'match_type': 'post_data_form',
                                'parameter_name': param,
                                'matched_value': value,
                                'request_url': 'POST_DATA',
                                'confidence': 'high'
                            })
                            
        except Exception as e:
            for value in indexed_values:
                if len(value) > 10 and value in post_data:
                    matches.append({
                        'match_type': 'post_data_raw',
                        'parameter_name': 'raw_data',
                        'matched_value': value,
                        'request_url': 'POST_DATA',
                        'confidence': 'low'
                    })
        
        return matches
    
    def _flatten_json(self, data, parent_key='', sep='.'):
        """Flatten nested JSON objects"""
        items = []
        if isinstance(data, dict):
            for k, v in data.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(self._flatten_json(v, new_key, sep=sep).items())
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        items.extend(self._flatten_json({str(i): item}, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
        return dict(items)
    
    def detect_comprehensive_tracking(self):
        """Run comprehensive tracking detection"""
        if not self.load_all_data():
            return {}
        
        print("\n" + "="*60)
        print("🔍 COMPREHENSIVE TRACKING ANALYSIS")
        print("="*60)
        
        results = {
            'verified_persistent_tracking': [],
            'potential_tracking': [],
            'summary': {}
        }
        
        # 1. Check VERIFIED persistent IDs (from persistence analysis)
        if self.persistence_data:
            print("\n📋 ANALYZING VERIFIED PERSISTENT IDs")
            print("-" * 40)
            persistent_ids = self.get_verified_persistent_ids()
            if persistent_ids:
                persistent_matches = self.analyze_network_requests(persistent_ids)
                results['verified_persistent_tracking'] = persistent_matches
                print(f"✅ Found {len(persistent_matches)} matches for verified persistent IDs")
            else:
                print("⚠️  No verified persistent IDs found")
        else:
            print("⚠️  No persistence data provided - skipping verified ID analysis")
        
        # 2. Check ALL potential tracking IDs (original method)
        print("\n📋 ANALYZING ALL POTENTIAL TRACKING VALUES")
        print("-" * 40)
        all_values = self.extract_all_indexeddb_values()
        all_matches = self.analyze_network_requests(all_values)
        results['potential_tracking'] = all_matches
        print(f"✅ Found {len(all_matches)} total potential tracking matches")
        
        # 3. Summary
        results['summary'] = {
            'website': self.loaded_data['website'],
            'verified_persistent_ids': len(persistent_ids) if self.persistence_data else 0,
            'verified_persistent_matches': len(results['verified_persistent_tracking']),
            'total_potential_values': len(all_values),
            'potential_tracking_matches': len(all_matches),
            'total_requests_analyzed': len(self.loaded_data['network_requests'])
        }
        
        self.tracking_matches = all_matches
        self.persistent_tracking_matches = results['verified_persistent_tracking']
        
        return results
    
    def generate_comprehensive_report(self, output_file=None):
        """Generate comprehensive tracking report"""
        results = self.detect_comprehensive_tracking()
        
        if output_file is None:
            domain = urlparse(self.loaded_data['website']).netloc.replace('.', '_')
            output_file = f"enhanced_tracking_report_{domain}.json"
        
        report = {
            'website': self.loaded_data['website'],
            'analysis_timestamp': self._get_timestamp(),
            'summary': results['summary'],
            'verified_persistent_tracking': results['verified_persistent_tracking'],
            'potential_tracking': results['potential_tracking'][:100],  # Limit to first 100
            'persistence_data_used': bool(self.persistence_data)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Enhanced tracking report saved to: {output_file}")
        
        # Print summary
        print("\n" + "="*60)
        print("📊 TRACKING ANALYSIS RESULTS")
        print("="*60)
        print(f"Website: {results['summary']['website']}")
        print(f"Total requests analyzed: {results['summary']['total_requests_analyzed']}")
        
        if self.persistence_data:
            print(f"\n🔐 VERIFIED PERSISTENT TRACKING:")
            print(f"   Verified persistent IDs: {results['summary']['verified_persistent_ids']}")
            print(f"   Verified tracking matches: {results['summary']['verified_persistent_matches']}")
            
            if results['verified_persistent_tracking']:
                print("\n   🚨 VERIFIED TRACKING FOUND:")
                for match in results['verified_persistent_tracking']:
                    print(f"     • {match['matched_value'][:30]}... in {match['request_url'][:50]}...")
            else:
                print("   ✅ No verified tracking found (good for privacy!)")
        
        print(f"\n🔍 POTENTIAL TRACKING:")
        print(f"   Total IndexedDB values: {results['summary']['total_potential_values']}")
        print(f"   Potential tracking matches: {results['summary']['potential_tracking_matches']}")
        
        if results['potential_tracking']:
            print(f"\n   ⚠️  Top potential tracking matches:")
            for i, match in enumerate(results['potential_tracking'][:5]):
                print(f"     {i+1}. {match['matched_value'][:30]}...")
                print(f"        → {match['request_url'][:60]}...")
                print(f"        Type: {match['match_type']} | Confidence: {match['confidence']}")
        
        return output_file
    
    def _get_timestamp(self):
        """Get current timestamp"""
        import time
        return time.time()
    
    def _deduplicate_matches(self, matches):
        """Remove duplicate matches"""
        seen = set()
        unique_matches = []
        for match in matches:
            identifier = (match['matched_value'], match['request_url'], match['match_type'])
            if identifier not in seen:
                seen.add(identifier)
                unique_matches.append(match)
        return unique_matches

def main():
    """Main function for enhanced tracking detection"""
    print("="*60)
    print("🔍 ENHANCED TRACKING DETECTOR")
    print("="*60)
    
    # Use both files if available
    standard_file = "complete_data_www_youtube_com.json"
    persistence_file = "persistence_report_www_youtube_com.json"
    
    print(f"Standard data: {standard_file}")
    print(f"Persistence data: {persistence_file}")
    print()
    
    detector = EnhancedTrackingDetector(standard_file, persistence_file)
    
    # Generate comprehensive report
    report_file = detector.generate_comprehensive_report()
    
    print("\n" + "="*60)
    print("✅ ANALYSIS COMPLETE")
    print("="*60)
    
    # Quick answer for your FYP
    results = detector.detect_comprehensive_tracking()
    
    print("\n🎯 FYP CONCLUSION:")
    if results['summary']['verified_persistent_matches'] > 0:
        print("🚨 TRACKING CONFIRMED: YouTube sends persistent client identifiers to servers")
    else:
        print("✅ NO TRACKING DETECTED: YouTube keeps persistent identifiers client-side")
    
    print(f"\nEvidence: {results['summary']['verified_persistent_ids']} verified persistent IDs")
    print(f"Tracking matches found: {results['summary']['verified_persistent_matches']}")

if __name__ == "__main__":
    main()