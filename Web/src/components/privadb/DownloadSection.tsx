import React from 'react';
import { FileJson, FileSpreadsheet, FileText } from 'lucide-react';
import { motion } from 'framer-motion';

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
  <section id="download" className="py-24 px-4 relative z-10">
    <motion.div
      className="max-w-5xl mx-auto"
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-100px" }}
      transition={{ duration: 0.6 }}
    >
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Download Results</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Access the full analysis data in multiple formats.
        </p>
      </div>

      <motion.div
        className="grid md:grid-cols-3 gap-6 mb-12"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: "-50px" }}
        variants={{
          hidden: { opacity: 0 },
          visible: {
            opacity: 1,
            transition: { staggerChildren: 0.15 }
          }
        }}
      >
        {downloads.map((dl, i) => {
          const Icon = dl.icon;
          return (
            <motion.div
              key={i}
              className="glass rounded-2xl p-6 hover:glow-sm transition-all group cursor-pointer"
              variants={{ hidden: { opacity: 0, scale: 0.95 }, visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } } }}
            >
              <Icon size={32} className="text-primary mb-4 group-hover:scale-110 transition-transform" />
              <h3 className="font-mono font-medium mb-1">{dl.name}</h3>
              <p className="text-xs text-muted-foreground mb-3">{dl.desc}</p>
              <span className="text-xs font-mono text-muted-foreground">{dl.size}</span>
            </motion.div>
          );
        })}
      </motion.div>

      {/* CSV Preview */}
      <motion.div
        className="glass rounded-2xl overflow-hidden"
        initial={{ opacity: 0, scale: 0.98 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.5, delay: 0.4 }}
      >
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border/50">
          <FileText size={14} className="text-muted-foreground" />
          <span className="text-xs font-mono text-muted-foreground">CSV Format Preview</span>
        </div>
        <pre className="p-4 text-xs font-mono overflow-x-auto leading-relaxed">
          <code className="text-foreground/70">{csvPreview}</code>
        </pre>
      </motion.div>
    </motion.div>
  </section>
);
