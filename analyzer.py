import json
from collections import defaultdict
import os
import re

class PersistenceAnalyzer:
    def __init__(self, scenario1_file, scenario2_file, scenario3_file):
        print(f"📂 Loading files from data folder...")
        self.scenario1 = self.load_json(scenario1_file)
        self.scenario2 = self.load_json(scenario2_file)
        self.scenario3 = self.load_json(scenario3_file)
        
        if not self.scenario1 or not self.scenario2 or not self.scenario3:
            print("❌ ERROR: Failed to load one or more JSON files!")
            return
        
        self.results = {
            'persistent_identifiers': [],
            'session_only_identifiers': [],
            'volatile_identifiers': [],
            'summary': defaultdict(int)
        }
    
    def load_json(self, filename):
        """Load JSON with multiple encoding attempts"""
        encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    return json.load(f)
            except:
                continue
        
        try:
            with open(filename, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
                return json.loads(content)
        except:
            return {}
    
    def extract_all_values(self, data, source_name):
        """Extract all potential identifier values from a scenario"""
        values = set()
        
        if not data:
            return values
        
        # Extract from ALL data (not just >8 letters)
        values.update(self._deep_extract_all_strings(data, source_name))
        
        return values
    
    def _deep_extract_all_strings(self, data, path=""):
        """Extract ALL strings from nested structure"""
        values = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Add key if it's a string
                if isinstance(key, str) and len(key) > 3:  # Changed from 8 to 3
                    values.add(key)
                
                # Add value if it's a string
                if isinstance(value, str) and len(value) > 3:  # Changed from 8 to 3
                    values.add(value)
                elif isinstance(value, (dict, list)):
                    values.update(self._deep_extract_all_strings(value, f"{path}.{key}"))
        
        elif isinstance(data, list):
            for item in data:
                values.update(self._deep_extract_all_strings(item, path))
        
        elif isinstance(data, str) and len(data) > 3:  # Changed from 8 to 3
            values.add(data)
        
        return values
    
    def analyze_persistence_patterns(self):
        """Main analysis for the 3 scenarios"""
        print("🔍 Analyzing persistence across 3 scenarios...")
        
        # Extract ALL strings (>3 characters) from each scenario
        s1_values = self.extract_all_values(self.scenario1, "scenario1")
        s2_values = self.extract_all_values(self.scenario2, "scenario2") 
        s3_values = self.extract_all_values(self.scenario3, "scenario3")
        
        print(f"\n📊 Found strings (>3 chars):")
        print(f"  Fresh browser: {len(s1_values)}")
        print(f"  Return visit:  {len(s2_values)}")
        print(f"  Cleared:       {len(s3_values)}")
        
        # Find PERSISTENT IDs (present in ALL 3 scenarios)
        persistent_ids = s1_values.intersection(s2_values).intersection(s3_values)
        
        # Store results
        for pid in persistent_ids:
            self.results['persistent_identifiers'].append({
                'value': pid[:100] + ('...' if len(pid) > 100 else ''),
                'full_length': len(pid),
                'type': 'persistent'
            })
        
        # Summary
        self.results['summary'] = {
            'total_persistent_ids': len(persistent_ids),
            'scenario1_total': len(s1_values),
            'scenario2_total': len(s2_values),
            'scenario3_total': len(s3_values)
        }
        
        return self.results
    
    def check_network_transmission(self):
        """Check which identifiers are sent in network requests"""
        print("\n" + "="*60)
        print("🌐 CHECKING NETWORK TRANSMISSION OF IDENTIFIERS")
        print("="*60)
        
        # Get all persistent identifiers
        persistent_ids = [item['value'] for item in self.results['persistent_identifiers']]
        
        results = {
            'transmitted_identifiers': [],
            'by_scenario': {},
            'summary': {}
        }
        
        # Check each scenario
        scenarios = [
            ('fresh_browser', self.scenario1),
            ('return_visit', self.scenario2),
            ('cleared_browser', self.scenario3)
        ]
        
        all_transmitted = set()
        
        for scenario_name, scenario_data in scenarios:
            transmitted_in_scenario = set()
            
            if 'network_requests' in scenario_data:
                requests = scenario_data['network_requests'].get('requests', [])
                
                print(f"\n🔍 Checking {scenario_name}: {len(requests)} requests")
                
                for request_idx, request in enumerate(requests):
                    # Build search text from all parts of request
                    search_text = ""
                    
                    # URL
                    url = request.get('url', '')
                    search_text += f" {url}"
                    
                    # Method
                    search_text += f" {request.get('method', '')}"
                    
                    # POST data
                    post_data = request.get('post_data', '')
                    if post_data:
                        search_text += f" {post_data}"
                    
                    # Headers
                    headers = request.get('headers', {})
                    for header_value in headers.values():
                        search_text += f" {header_value}"
                    
                    # Check each identifier
                    for pid in persistent_ids:
                        if pid in search_text and pid not in transmitted_in_scenario:
                            transmitted_in_scenario.add(pid)
                            all_transmitted.add(pid)
                            
                            # Store details
                            results['transmitted_identifiers'].append({
                                'identifier': pid,
                                'scenario': scenario_name,
                                'found_in': self._find_where_in_request(pid, request),
                                'url': url[:200] + ('...' if len(url) > 200 else ''),
                                'request_index': request_idx
                            })
            
            results['by_scenario'][scenario_name] = {
                'count': len(transmitted_in_scenario),
                'identifiers': list(transmitted_in_scenario)
            }
        
        # Summary
        results['summary'] = {
            'total_transmitted': len(all_transmitted),
            'total_persistent': len(persistent_ids),
            'transmission_rate': f"{(len(all_transmitted) / len(persistent_ids) * 100):.1f}%"
        }
        
        # Display results
        print(f"\n📤 NETWORK TRANSMISSION RESULTS:")
        print(f"   Total persistent identifiers: {len(persistent_ids)}")
        print(f"   Transmitted to network: {len(all_transmitted)}")
        print(f"   Transmission rate: {results['summary']['transmission_rate']}")
        
        print(f"\n📊 By scenario:")
        for scenario, data in results['by_scenario'].items():
            print(f"   • {scenario}: {data['count']} identifiers transmitted")
        
        # Show examples
        if results['transmitted_identifiers']:
            print(f"\n🔍 EXAMPLES OF TRANSMITTED IDENTIFIERS:")
            for i, trans in enumerate(results['transmitted_identifiers'][:10]):
                print(f"   {i+1}. {trans['identifier'][:50]}...")
                print(f"      Found in: {trans['found_in']}")
                print(f"      URL: {trans['url'][:80]}...")
        
        return results
    
    def _find_where_in_request(self, identifier, request):
        """Find where in the request the identifier was found"""
        locations = []
        
        # Check URL
        if 'url' in request and identifier in request['url']:
            locations.append('url')
        
        # Check POST data
        if 'post_data' in request and request['post_data'] and identifier in str(request['post_data']):
            locations.append('post_data')
        
        # Check headers
        if 'headers' in request:
            for header_name, header_value in request['headers'].items():
                if identifier in str(header_value):
                    locations.append(f'header:{header_name}')
        
        return ', '.join(locations) if locations else 'unknown'
    
    def detect_tracking_patterns(self):
        """Detect known tracking patterns"""
        tracking_keywords = {
            'youtube': ['youtube', 'yt', 'visitor', 'bootstrap'],
            'google': ['google', 'ga', 'analytics', 'gtm', 'goog'],
            'user': ['user', 'uid', 'client', 'session', 'token'],
            'device': ['browser', 'device', 'screen', 'keyboard'],
            'advertising': ['ad', 'track', 'pixel', 'beacon']
        }
        
        tracking_results = []
        
        for item in self.results['persistent_identifiers']:
            identifier = item['value'].lower()
            
            for category, keywords in tracking_keywords.items():
                for keyword in keywords:
                    if keyword in identifier:
                        tracking_results.append({
                            'identifier': item['value'],
                            'category': category,
                            'matched_keyword': keyword,
                            'length': item['full_length']
                        })
                        break
        
        return tracking_results
    
    def generate_complete_report(self):
        """Generate comprehensive analysis report"""
        os.makedirs('reports', exist_ok=True)
        
        print("\n" + "="*60)
        print("📊 GENERATING COMPLETE ANALYSIS REPORT")
        print("="*60)
        
        # 1. Analyze persistence
        print("\n1️⃣ ANALYZING PERSISTENCE...")
        persistence_results = self.analyze_persistence_patterns()
        
        # 2. Check network transmission
        print("\n2️⃣ CHECKING NETWORK TRANSMISSION...")
        network_results = self.check_network_transmission()
        
        # 3. Detect tracking
        print("\n3️⃣ DETECTING TRACKING PATTERNS...")
        tracking_results = self.detect_tracking_patterns()
        
        # Combine all results
        full_report = {
            'persistence_analysis': persistence_results,
            'network_transmission': network_results,
            'tracking_detection': {
                'total_tracking_patterns': len(tracking_results),
                'patterns_found': tracking_results[:50]  # Limit to 50
            },
            'summary': {
                'total_persistent_identifiers': persistence_results['summary']['total_persistent_ids'],
                'transmitted_to_network': network_results['summary']['total_transmitted'],
                'tracking_patterns_detected': len(tracking_results)
            }
        }
        
        # Save report
        report_file = "reports/complete_analysis.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2, ensure_ascii=False)
        
        # Print final summary
        print("\n" + "="*60)
        print("🎯 COMPLETE ANALYSIS RESULTS")
        print("="*60)
        print(f"📊 Persistence Analysis:")
        print(f"   • Persistent identifiers: {full_report['summary']['total_persistent_identifiers']}")
        print(f"   • Transmitted to network: {full_report['summary']['transmitted_to_network']}")
        print(f"   • Tracking patterns: {full_report['summary']['tracking_patterns_detected']}")
        
        print(f"\n⚠️  KEY FINDINGS:")
        if network_results['summary']['total_transmitted'] > 0:
            print(f"   • {network_results['summary']['transmission_rate']} of identifiers sent to YouTube servers")
        
        if tracking_results:
            print(f"   • Found tracking in: {len(set(t['category'] for t in tracking_results))} categories")
        
        print(f"\n💾 Full report saved to: {report_file}")
        
        return full_report

def main():
    """Main analysis function"""
    print("="*60)
    print("🔍 ENHANCED TRACKING ANALYZER")
    print("="*60)
    
    # Files to analyze
    files = [
        "data/fresh_browser.json",
        "data/same_session_return.json", 
        "data/cleared_browser.json"
    ]
    
    # Check files exist
    for file in files:
        if not os.path.exists(file):
            print(f"❌ Missing: {file}")
            return
    
    # Run analysis
    analyzer = PersistenceAnalyzer(*files)
    analyzer.generate_complete_report()

if __name__ == "__main__":
    main()