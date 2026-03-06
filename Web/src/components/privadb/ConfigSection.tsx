import React from 'react';

const configData = [
  { setting: 'HEADLESS', value: 'true', desc: 'Run browser without GUI' },
  { setting: 'PAGE_LOAD_TIMEOUT', value: '30,000ms', desc: 'Max wait for page load' },
  { setting: 'IDLE_WAIT', value: '8,000ms', desc: 'Wait after page load' },
  { setting: 'CRAWL_ITERATIONS', value: '3', desc: 'Visits per site' },
  { setting: 'MIN_ID_LENGTH', value: '8', desc: 'Minimum tracking ID length' },
  { setting: 'ENTROPY_THRESHOLD', value: '3.0', desc: 'Shannon entropy cutoff' },
  { setting: 'KNOWN_TRACKER_DOMAINS', value: '41', desc: 'Known tracker list' },
  { setting: 'BLACKLISTED_TRACKER_DOMAINS', value: '537', desc: 'Blacklisted domains' },
  { setting: 'TOTAL_TRACKER_DOMAINS', value: '578', desc: 'Combined tracker DB' },
];

export const ConfigSection: React.FC = () => (
  <section className="py-24 px-4">
    <div className="max-w-4xl mx-auto">
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Configuration</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Key parameters from <code className="font-mono text-primary">config.py</code> that control the analysis pipeline.
        </p>
      </div>

      <div className="glass rounded-2xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border/50">
              <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-4">Setting</th>
              <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-4">Value</th>
              <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-4 hidden md:table-cell">Description</th>
            </tr>
          </thead>
          <tbody>
            {configData.map((row, i) => (
              <tr key={i} className="border-b border-border/30 last:border-0 hover:bg-muted/30 transition-colors">
                <td className="px-6 py-3.5 text-sm font-mono font-medium">{row.setting}</td>
                <td className="px-6 py-3.5 text-sm font-mono text-primary font-medium">{row.value}</td>
                <td className="px-6 py-3.5 text-sm text-muted-foreground hidden md:table-cell">{row.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  </section>
);
