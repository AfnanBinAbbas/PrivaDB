import React, { useState } from 'react';
import { FileCode2, ArrowRight } from 'lucide-react';
import { motion } from 'framer-motion';

const files = [
  { name: 'main.py', role: 'CLI Orchestrator', desc: 'Entry point and pipeline coordination' },
  { name: 'crawler.py', role: 'Web Crawler', desc: 'Playwright-based site visitor and IndexedDB extractor' },
  { name: 'detector.py', role: 'Detection Engine', desc: 'Entropy analysis, flow classification, and tracking detection' },
  { name: 'reporter.py', role: 'Report Generator', desc: 'JSON/CSV output and matplotlib chart generation' },
];

const codeSnippets: Record<string, string> = {
  'main.py': `def main():
    parser = argparse.ArgumentParser(
        description='PRIVADB: IndexedDB Tracking Detector'
    )
    parser.add_argument('urls', nargs='+', help='URLs to analyze')
    parser.add_argument('--output', default='./results')
    args = parser.parse_args()

    # Phase 1: Crawl
    crawler = Crawler(config)
    raw_data = crawler.crawl(args.urls)

    # Phase 2: Detect
    detector = Detector(config)
    results = detector.analyze(raw_data)

    # Phase 3: Report
    reporter = Reporter(config)
    reporter.generate(results, args.output)`,
  'crawler.py': `class Crawler:
    async def crawl(self, urls: list[str]):
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.config.HEADLESS
            )
            for url in urls:
                for i in range(self.config.CRAWL_ITERATIONS):
                    page = await browser.new_page()
                    await page.goto(url, timeout=self.config.TIMEOUT)
                    await page.wait_for_timeout(self.config.IDLE_WAIT)
                    idb_data = await self.extract_indexeddb(page)
                    self.results.append(idb_data)
            await browser.close()`,
  'detector.py': `class Detector:
    def classify_flow(self, entry) -> str:
        """Classify information flow type."""
        if self._is_external(entry.domain):
            if self._is_cross_site(entry):
                return "cross-site-confidentiality"
            return "same-site-confidentiality"
        return "internal-integrity"

    def _is_tracking(self, value: str) -> bool:
        if len(value) < self.config.MIN_ID_LENGTH:
            return False
        entropy = self.shannon_entropy(value)
        return entropy >= self.config.ENTROPY_THRESHOLD`,
  'reporter.py': `class Reporter:
    def generate(self, results, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
        # Summary JSON
        summary = self._build_summary(results)
        with open(f'{output_dir}/summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # CSV export
        self._export_csv(results, output_dir)
        
        # Generate charts
        self._generate_charts(results.stats, output_dir)
        
        print(f"Report generated: {output_dir}")`,
};

export const ArchitectureSection: React.FC = () => {
  const [selected, setSelected] = useState('main.py');

  return (
    <section id="architecture" className="py-24 px-4 relative z-10">
      <motion.div
        className="max-w-6xl mx-auto"
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-100px" }}
        transition={{ duration: 0.6 }}
      >
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Architecture</h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Click each module to explore its role in the pipeline.
          </p>
        </div>

        {/* Flow diagram */}
        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-4 mb-12">
          {files.map((file, i) => (
            <React.Fragment key={file.name}>
              <button
                onClick={() => setSelected(file.name)}
                className={`flex items-center gap-2 px-4 py-3 rounded-xl transition-all text-sm font-medium ${selected === file.name
                    ? 'bg-primary text-primary-foreground glow-sm scale-105'
                    : 'glass hover:bg-muted/50'
                  }`}
              >
                <FileCode2 size={16} />
                {file.name}
              </button>
              {i < files.length - 1 && (
                <ArrowRight size={18} className="text-muted-foreground hidden sm:block" />
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Detail card */}
        <motion.div
          className="glass rounded-2xl p-6 md:p-8"
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <div className="flex flex-col md:flex-row gap-6">
            <div className="md:w-1/3">
              <div className="text-xs font-medium text-primary uppercase tracking-wider mb-1">
                {files.find(f => f.name === selected)?.role}
              </div>
              <h3 className="text-2xl font-bold font-mono mb-2">{selected}</h3>
              <p className="text-sm text-muted-foreground">
                {files.find(f => f.name === selected)?.desc}
              </p>
            </div>
            <div className="md:w-2/3">
              <pre className="bg-background/80 rounded-xl p-4 text-xs font-mono overflow-x-auto border border-border/50 leading-relaxed max-h-80">
                <code className="text-foreground/80">{codeSnippets[selected]}</code>
              </pre>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </section>
  );
};
