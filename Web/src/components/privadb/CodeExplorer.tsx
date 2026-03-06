import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

const tabs = [
  {
    label: 'IndexedDB Extraction',
    file: 'crawler.py',
    code: `async def extract_indexeddb(self, page) -> list:
    """Extract all IndexedDB databases from page."""
    return await page.evaluate("""() => {
        return new Promise(async (resolve) => {
            const dbs = await indexedDB.databases();
            const results = [];
            
            for (const dbInfo of dbs) {
                const db = await new Promise((res, rej) => {
                    const req = indexedDB.open(dbInfo.name, dbInfo.version);
                    req.onsuccess = () => res(req.result);
                    req.onerror = () => rej(req.error);
                });
                
                const stores = [...db.objectStoreNames];
                const data = {};
                
                for (const storeName of stores) {
                    const tx = db.transaction(storeName, 'readonly');
                    const store = tx.objectStore(storeName);
                    data[storeName] = await new Promise((res) => {
                        const req = store.getAll();
                        req.onsuccess = () => res(req.result);
                    });
                }
                
                results.push({
                    name: dbInfo.name,
                    version: dbInfo.version,
                    stores: data
                });
                db.close();
            }
            resolve(results);
        });
    }""")`,
  },
  {
    label: 'Shannon Entropy',
    file: 'detector.py',
    code: `import math

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness,
    suggesting a tracking identifier.
    
    Args:
        data: Input string to analyze
        
    Returns:
        Entropy value in bits per character
    """
    if not data:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    length = len(data)
    
    # Calculate entropy
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    
    return round(entropy, 4)`,
  },
  {
    label: 'Flow Classification',
    file: 'detector.py',
    code: `def classify_flow(self, entry: TrackingEntry) -> FlowResult:
    """Classify the information flow of a tracking entry.
    
    Categories:
    - Confidentiality: Data leaving the origin
    - Integrity: Data staying within origin
    
    Sub-categories:
    - Internal: Within same origin
    - External/Same-site: Different origin, same site
    - External/Cross-site: Different origin, different site
    """
    source = entry.origin_domain
    dest = entry.target_domain
    
    if source == dest:
        return FlowResult(
            type="integrity",
            confinement="internal",
            confidence=self._calc_confidence(entry)
        )
    
    if self._same_site(source, dest):
        return FlowResult(
            type="confidentiality",
            confinement="external-same-site",
            confidence=self._calc_confidence(entry)
        )
    
    return FlowResult(
        type="confidentiality",
        confinement="external-cross-site",
        confidence=self._calc_confidence(entry)
    )`,
  },
  {
    label: 'CLI Commands',
    file: 'main.py',
    code: `# Basic usage — analyze a single site
$ python main.py https://example.com

# Analyze multiple sites
$ python main.py https://site1.com https://site2.com

# Custom output directory
$ python main.py --output ./my-results https://example.com

# Analyze from a file of URLs
$ python main.py --file urls.txt

# Verbose mode with debug logging
$ python main.py --verbose https://example.com

# Generate only specific report formats
$ python main.py --format json,csv https://example.com

# Set custom entropy threshold
$ python main.py --entropy 3.5 https://example.com`,
  },
];

export const CodeExplorer: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(tabs[activeTab].code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="code" className="py-24 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Code Explorer</h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Key code snippets from the PRIVADB codebase with syntax highlighting.
          </p>
        </div>

        <div className="glass rounded-2xl overflow-hidden">
          {/* Tab bar */}
          <div className="flex overflow-x-auto border-b border-border/50">
            {tabs.map((tab, i) => (
              <button
                key={i}
                onClick={() => setActiveTab(i)}
                className={`px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 ${
                  activeTab === i
                    ? 'text-primary border-primary'
                    : 'text-muted-foreground border-transparent hover:text-foreground hover:border-border'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Code block */}
          <div className="relative">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border/30">
              <span className="text-xs font-mono text-muted-foreground">{tabs[activeTab].file}</span>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono overflow-x-auto leading-relaxed max-h-96">
              <code className="text-foreground/80">{tabs[activeTab].code}</code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
};
