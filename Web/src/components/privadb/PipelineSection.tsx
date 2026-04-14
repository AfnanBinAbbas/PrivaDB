import React, { useState } from 'react';
import { Globe, Search, BarChart3 } from 'lucide-react';

const phases = [
  {
    icon: Globe,
    phase: 'Phase 1',
    title: 'Crawling',
    description: 'Playwright-based web crawler that visits sites and extracts IndexedDB data across multiple iterations.',
    params: [
      { key: 'HEADLESS', value: 'true' },
      { key: 'TIMEOUT', value: '30s' },
      { key: 'ITERATIONS', value: '3' },
    ],
    code: `async def extract_indexeddb(page):
    """Extract all IndexedDB databases and stores."""
    return await page.evaluate("""() => {
        return new Promise(async (resolve) => {
            const dbs = await indexedDB.databases();
            const results = [];
            for (const db of dbs) {
                const conn = await new Promise((res) => {
                    const req = indexedDB.open(db.name);
                    req.onsuccess = () => res(req.result);
                });
                // Extract stores and entries...
                results.push({ name: db.name, stores });
            }
            resolve(results);
        });
    }""")`,
    color: 'from-blue-500 to-cyan-500',
  },
  {
    icon: Search,
    phase: 'Phase 2',
    title: 'Detection',
    description: 'Entropy analysis engine that identifies tracking identifiers and classifies information flows.',
    params: [
      { key: 'MIN_ID_LENGTH', value: '8' },
      { key: 'ENTROPY_THRESHOLD', value: '3.0' },
      { key: 'TRACKER_DOMAINS', value: '578' },
    ],
    code: `def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = -sum(
        (count/length) * math.log2(count/length)
        for count in freq.values()
    )
    return entropy`,
    color: 'from-primary to-purple-500',
  },
  {
    icon: BarChart3,
    phase: 'Phase 3',
    title: 'Reporting',
    description: 'Generates comprehensive analysis reports with statistical summaries and visualization charts.',
    params: [
      { key: 'CHARTS', value: '6 types' },
      { key: 'FORMATS', value: 'CSV, JSON' },
      { key: 'OUTPUT', value: './results/' },
    ],
    code: `def generate_charts(stats: dict, output_dir: str):
    """Generate matplotlib visualization charts."""
    # Confidence distribution pie chart
    fig, ax = plt.subplots(figsize=(8, 6))
    labels = ['HIGH', 'MEDIUM', 'LOW']
    sizes = [stats['high'], stats['medium'], stats['low']]
    colors = ['#ef4444', '#f59e0b', '#22c55e']
    ax.pie(sizes, labels=labels, colors=colors,
           autopct='%1.1f%%', startangle=90)
    ax.set_title('Confidence Distribution')
    fig.savefig(f'{output_dir}/confidence.png')`,
    color: 'from-emerald-500 to-teal-500',
  },
];

export const PipelineSection: React.FC = () => {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <section id="pipeline" className="py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            3-Phase Analysis Pipeline
          </h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            PRIVADB processes websites through a systematic pipeline — crawl, detect, and report.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {phases.map((phase, i) => {
            const Icon = phase.icon;
            const isExpanded = expanded === i;
            return (
              <div
                key={i}
                className={`glass rounded-2xl p-6 transition-all duration-500 cursor-pointer group hover:glow-sm ${
                  isExpanded ? 'md:col-span-3 glow-md' : ''
                }`}
                onClick={() => setExpanded(isExpanded ? null : i)}
              >
                <div className={`flex ${isExpanded ? 'md:flex-row' : 'flex-col'} gap-6`}>
                  <div className={isExpanded ? 'md:w-1/3' : ''}>
                    {/* Icon */}
                    <div className={`w-12 h-12 rounded-xl ${phase.color} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                      <Icon size={24} className="text-white" />
                    </div>

                    <div className="text-xs font-medium text-primary uppercase tracking-wider mb-1">{phase.phase}</div>
                    <h3 className="text-xl font-semibold mb-3">{phase.title}</h3>
                    <p className="text-sm text-muted-foreground mb-4">{phase.description}</p>

                    {/* Params */}
                    <div className="flex flex-wrap gap-2">
                      {phase.params.map((p, j) => (
                        <span key={j} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-muted/50 text-xs font-mono">
                          <span className="text-muted-foreground">{p.key}=</span>
                          <span className="text-primary font-medium">{p.value}</span>
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Code snippet on expand */}
                  {isExpanded && (
                    <div className="md:w-2/3 mt-4 md:mt-0">
                      <pre className="bg-background/80 rounded-xl p-4 text-xs font-mono overflow-x-auto border border-border/50 leading-relaxed">
                        <code className="text-foreground/80">{phase.code}</code>
                      </pre>
                    </div>
                  )}
                </div>

                <div className="mt-4 text-xs text-muted-foreground">
                  {isExpanded ? 'Click to collapse' : 'Click to view code →'}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
