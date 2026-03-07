import re
import json
import os
from urllib.parse import urljoin, urlparse
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from collections import defaultdict

class StaticIndexedDBAnalyzer:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.js_files = []  # Store downloaded JS content
        self.html_files = []  # Store HTML content
        self.visited_urls = set()
        
        # IndexedDB operations to detect
        self.operations = {
            'database_opens': [],      # indexedDB.open()
            'store_creations': [],      # createObjectStore()
            'put_operations': [],       # .put()
            'add_operations': [],       # .add()
            'get_operations': [],       # .get()
            'getAll_operations': [],    # .getAll()
            'delete_operations': [],    # .delete()
            'clear_operations': [],     # .clear()
            'transactions': []          # transaction()
        }
        
        # Patterns for detection
        self.patterns = {
            'database_opens': r'indexedDB\.open\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(\d+)',
            'store_creations': r'createObjectStore\s*\(\s*[\'"]([^\'"]+)[\'"]',
            'put_operations': r'\.put\s*\(\s*([^,)]+)',
            'add_operations': r'\.add\s*\(\s*([^,)]+)',
            'get_operations': r'\.get\s*\(\s*([^)]+)',
            'getAll_operations': r'\.getAll\s*\(',
            'delete_operations': r'\.delete\s*\(\s*([^)]+)',
            'clear_operations': r'\.clear\s*\(',
            'transactions': r'transaction\s*\(\s*[\'"]([^\'"]+)[\'"]'
        }
        
        # Tracking-related keywords
        self.tracking_keywords = [
            'track', 'analytics', 'visitor', 'session', 'fingerprint',
            'userid', 'clientid', 'uuid', 'ga_', 'gid', 'token',
            'persistent', 'identifier', 'unique'
        ]
    
    async def crawl_and_analyze(self, max_pages=5):
        """Crawl website and analyze all JS files"""
        print(f"\n🔍 Starting static analysis of {self.url}")
        
        async with aiohttp.ClientSession() as session:
            await self._crawl_page(session, self.url, max_pages)
        
        print(f"\n✅ Analysis complete!")
        print(f"   Pages crawled: {len(self.visited_urls)}")
        print(f"   JS files found: {len(self.js_files)}")
        
        return self.generate_report()
    
    async def _crawl_page(self, session, url, max_pages):
        """Recursively crawl pages"""
        if len(self.visited_urls) >= max_pages or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        print(f"   Crawling: {url}")
        
        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                
                html = await response.text()
                self.html_files.append({'url': url, 'content': html})
                
                # Parse HTML for scripts
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find external JS files
                for script in soup.find_all('script'):
                    if script.get('src'):
                        js_url = urljoin(url, script['src'])
                        if self.domain in js_url:
                            await self._download_js(session, js_url)
                    else:
                        # Inline script
                        if script.string:
                            self._analyze_javascript(script.string, f"{url}:inline")
                
                # Find links to other pages on same domain
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if self.domain in full_url and full_url not in self.visited_urls:
                        await self._crawl_page(session, full_url, max_pages)
                        
        except Exception as e:
            print(f"   Error crawling {url}: {e}")
    
    async def _download_js(self, session, js_url):
        """Download and analyze JavaScript file"""
        try:
            async with session.get(js_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    self.js_files.append({'url': js_url, 'content': content})
                    self._analyze_javascript(content, js_url)
        except Exception as e:
            print(f"   Error downloading {js_url}: {e}")
    
    def _analyze_javascript(self, content, source):
        """Static analysis of JavaScript for IndexedDB operations"""
        
        # Check each operation pattern
        for op_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, content):
                line_num = content.count('\n', 0, match.start()) + 1
                
                operation = {
                    'source': source,
                    'line': line_num,
                    'match': match.group(0)[:100],
                    'context': self._get_context(content, match.start(), 50)
                }
                
                # Add extracted values
                if match.groups():
                    operation['value'] = match.group(1)
                
                self.operations[op_type].append(operation)
                
                # Check if this might be tracking-related
                if any(keyword in match.group(0).lower() for keyword in self.tracking_keywords):
                    operation['tracking_suspicious'] = True
        
        # Look for tracking-related variable names
        for keyword in self.tracking_keywords:
            pattern = rf'\b\w*{keyword}\w*\b'
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if len(match.group()) > 4:  # Avoid short matches
                    line_num = content.count('\n', 0, match.start()) + 1
                    self.operations.setdefault('tracking_identifiers', []).append({
                        'source': source,
                        'line': line_num,
                        'identifier': match.group(),
                        'context': self._get_context(content, match.start(), 30)
                    })
    
    def _get_context(self, content, position, context_chars):
        """Get surrounding context of a match"""
        start = max(0, position - context_chars)
        end = min(len(content), position + context_chars)
        return content[start:end].replace('\n', ' ').strip()
    
    def generate_report(self):
        """Generate static analysis report"""
        
        # Count operations by type
        operation_counts = {}
        for op_type, ops in self.operations.items():
            operation_counts[op_type] = len(ops)
        
        # Identify tracking risk based on operations
        risk_score = 0
        risk_factors = []
        
        if operation_counts.get('database_opens', 0) > 2:
            risk_score += 20
            risk_factors.append(f"Multiple database opens ({operation_counts['database_opens']})")
        
        if operation_counts.get('store_creations', 0) > 3:
            risk_score += 20
            risk_factors.append(f"Multiple store creations ({operation_counts['store_creations']})")
        
        if operation_counts.get('put_operations', 0) > 5:
            risk_score += 25
            risk_factors.append(f"High number of write operations ({operation_counts['put_operations']})")
        
        if operation_counts.get('tracking_identifiers', 0) > 0:
            risk_score += 30
            risk_factors.append(f"Tracking-related identifiers found in code")
        
        # Determine rating
        if risk_score >= 60:
            rating = "HIGH_RISK"
        elif risk_score >= 30:
            rating = "MEDIUM_RISK"
        else:
            rating = "LOW_RISK"
        
        return {
            'url': self.url,
            'domain': self.domain,
            'static_analysis': {
                'pages_analyzed': len(self.visited_urls),
                'js_files_analyzed': len(self.js_files),
                'operations_detected': operation_counts,
                'operation_details': self.operations
            },
            'risk_assessment': {
                'risk_score': risk_score,
                'risk_rating': rating,
                'risk_factors': risk_factors
            }
        }
    
    def save_report(self, filename=None):
        """Save static analysis report to file"""
        os.makedirs('reports', exist_ok=True)
        
        report = self.generate_report()
        
        if not filename:
            domain_clean = self.domain.replace('.', '_')
            filename = f"reports/static_analysis_{domain_clean}_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Static analysis report saved to: {filename}")
        return filename


async def main():
    url = input("Enter URL to analyze (e.g., https://example.com): ") or "https://www.youtube.com"
    
    analyzer = StaticIndexedDBAnalyzer(url)
    report = await analyzer.crawl_and_analyze()
    analyzer.save_report()
    
    # Print summary
    print("\n" + "="*60)
    print("📊 STATIC ANALYSIS SUMMARY")
    print("="*60)
    print(f"📌 Database opens: {report['static_analysis']['operations_detected'].get('database_opens', 0)}")
    print(f"📌 Store creations: {report['static_analysis']['operations_detected'].get('store_creations', 0)}")
    print(f"📌 Write operations: {report['static_analysis']['operations_detected'].get('put_operations', 0)}")
    print(f"📌 Tracking identifiers: {report['static_analysis']['operations_detected'].get('tracking_identifiers', 0)}")
    print(f"\n📊 Risk Score: {report['risk_assessment']['risk_score']}/100")
    print(f"⚠️ Risk Rating: {report['risk_assessment']['risk_rating']}")
    
    if report['risk_assessment']['risk_factors']:
        print("\n⚠️ Risk Factors:")
        for factor in report['risk_assessment']['risk_factors']:
            print(f"   • {factor}")

if __name__ == "__main__":
    import time
    asyncio.run(main())