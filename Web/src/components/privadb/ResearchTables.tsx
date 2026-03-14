import React from 'react';
import { motion } from 'framer-motion';

const confinementData = [
  { type: 'Internal', flows: '1,342', percentage: '62.7%' },
  { type: 'External', flows: '797', percentage: '37.3%' },
];

const externalData = [
  { type: 'Same-site', flows: '312', percentage: '39.1%' },
  { type: 'Cross-site', flows: '485', percentage: '60.9%' },
];

const TableCard: React.FC<{ title: string; subtitle: string; data: { type: string; flows: string; percentage: string }[] }> = ({ title, subtitle, data }) => (
  <motion.div
    className="glass rounded-2xl p-6 hover:glow-sm transition-all"
    variants={{
      hidden: { opacity: 0, scale: 0.95 },
      visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } }
    }}
  >
    <h3 className="text-lg font-semibold mb-1">{title}</h3>
    <p className="text-xs text-muted-foreground mb-4">{subtitle}</p>
    <table className="w-full">
      <thead>
        <tr className="border-b border-border/50">
          <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2">Type</th>
          <th className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider py-2">Flows</th>
          <th className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider py-2">Share</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} className="border-b border-border/30 last:border-0">
            <td className="py-3 text-sm font-medium">{row.type}</td>
            <td className="py-3 text-sm font-mono text-right">{row.flows}</td>
            <td className="py-3 text-sm font-mono text-primary text-right font-medium">{row.percentage}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </motion.div>
);

export const ResearchTables: React.FC = () => (
  <section className="py-24 px-4 relative z-10">
    <motion.div
      className="max-w-4xl mx-auto"
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-100px" }}
      transition={{ duration: 0.6 }}
    >
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Research Findings</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Summary of information flow analysis across all analyzed websites.
        </p>
      </div>

      <motion.div
        className="grid md:grid-cols-2 gap-6"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: "-50px" }}
        variants={{
          hidden: { opacity: 0 },
          visible: {
            opacity: 1,
            transition: { staggerChildren: 0.2 }
          }
        }}
      >
        <TableCard
          title="Table III: Confinement Analysis"
          subtitle="Information flow confinement classification"
          data={confinementData}
        />
        <TableCard
          title="Table IV: External Flow Breakdown"
          subtitle="External flow destination analysis"
          data={externalData}
        />
      </motion.div>
    </motion.div>
  </section>
);
