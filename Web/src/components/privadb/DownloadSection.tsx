import React from 'react';
import { FileJson, FileSpreadsheet, FileText } from 'lucide-react';

const downloads = [
  {
    icon: FileJson,
    name: 'summary.json',
    desc: 'Full analysis results with all tracking events and classifications',
    size: '~2.4 MB',
  },
  {
    icon: FileJson,
    name: 'statistics.json',
    desc: 'Aggregate metrics, confidence distributions, and flow statistics',
    size: '~48 KB',
  },
  {
    icon: FileSpreadsheet,
    name: 'tracking_events.csv',
    desc: 'All tracking events in tabular format for further analysis',
    size: '~1.8 MB',
  },
];

const csvPreview = `site_url,database,store,key,value_hash,entropy,confidence,flow_type,confinement
https://example.com,__idb_store,tracking,uid,a3f8c2...,4.21,HIGH,confidentiality,cross-site
https://news.site,analytics_db,sessions,sid,b7e1d9...,3.87,MEDIUM,confidentiality,same-site
https://shop.com,cart_store,preferences,pref_id,c4a2f1...,2.94,LOW,integrity,internal`;

export const DownloadSection: React.FC = () => (
  <section id="download" className="py-24 px-4">
    <div className="max-w-5xl mx-auto">
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Download Results</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Access the full analysis data in multiple formats.
        </p>
      </div>

      <div className="grid md:grid-cols-3 gap-6 mb-12">
        {downloads.map((dl, i) => {
          const Icon = dl.icon;
          return (
            <div key={i} className="glass rounded-2xl p-6 hover:glow-sm transition-all group cursor-pointer">
              <Icon size={32} className="text-primary mb-4 group-hover:scale-110 transition-transform" />
              <h3 className="font-mono font-medium mb-1">{dl.name}</h3>
              <p className="text-xs text-muted-foreground mb-3">{dl.desc}</p>
              <span className="text-xs font-mono text-muted-foreground">{dl.size}</span>
            </div>
          );
        })}
      </div>

      {/* CSV Preview */}
      <div className="glass rounded-2xl overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border/50">
          <FileText size={14} className="text-muted-foreground" />
          <span className="text-xs font-mono text-muted-foreground">CSV Format Preview</span>
        </div>
        <pre className="p-4 text-xs font-mono overflow-x-auto leading-relaxed">
          <code className="text-foreground/70">{csvPreview}</code>
        </pre>
      </div>
    </div>
  </section>
);
