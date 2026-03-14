import React from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';

const confidenceData = [
  { name: 'HIGH', value: 156, color: 'hsl(0, 84%, 60%)' },
  { name: 'MEDIUM', value: 342, color: 'hsl(38, 92%, 50%)' },
  { name: 'LOW', value: 749, color: 'hsl(142, 71%, 45%)' },
];

const flowData = [
  { name: 'Confidentiality', value: 1247, fill: 'hsl(239, 84%, 67%)' },
  { name: 'Integrity', value: 892, fill: 'hsl(280, 80%, 65%)' },
];

const confinementData = [
  { name: 'Internal', value: 62.7, color: 'hsl(239, 84%, 67%)' },
  { name: 'External', value: 37.3, color: 'hsl(280, 80%, 65%)' },
];

const crossSiteData = [
  { name: 'Same-site', value: 39.1, color: 'hsl(142, 71%, 45%)' },
  { name: 'Cross-site', value: 60.9, color: 'hsl(0, 84%, 60%)' },
];

const MiniPie: React.FC<{ data: { name: string; value: number; color: string }[]; title: string }> = ({ data, title }) => (
  <div className="glass rounded-2xl p-6 hover:glow-sm transition-all">
    <h3 className="text-sm font-medium text-muted-foreground mb-4">{title}</h3>
    <div className="flex items-center gap-4">
      <ResponsiveContainer width={120} height={120}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={30} outerRadius={50} paddingAngle={3} dataKey="value">
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} stroke="transparent" />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-col gap-2">
        {data.map((entry, i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            <span className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
            <span className="text-muted-foreground">{entry.name}</span>
            <span className="font-mono font-medium">{typeof entry.value === 'number' && entry.value < 100 ? `${entry.value}%` : entry.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  </div>
);

export const MetricsSection: React.FC = () => (
  <section id="metrics" className="py-24 px-4 relative z-10">
    <motion.div
      className="max-w-6xl mx-auto"
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-100px" }}
      transition={{ duration: 0.6 }}
    >
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Live Metrics Dashboard</h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          Key findings from analyzing 677 websites for persistent tracking behavior.
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
            transition: { staggerChildren: 0.15 }
          }
        }}
      >
        <motion.div variants={{ hidden: { opacity: 0, scale: 0.95 }, visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } } }}>
          <MiniPie data={confidenceData} title="Confidence Distribution" />
        </motion.div>

        {/* Bar chart for flow classification */}
        <motion.div variants={{ hidden: { opacity: 0, scale: 0.95 }, visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } } }} className="glass rounded-2xl p-6 hover:glow-sm transition-all">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">Flow Classification</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={flowData} layout="vertical" barCategoryGap={12}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={100} tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '12px',
                  fontSize: '12px'
                }}
              />
              <Bar dataKey="value" radius={[0, 8, 8, 0]}>
                {flowData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div variants={{ hidden: { opacity: 0, scale: 0.95 }, visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } } }}>
          <MiniPie data={confinementData} title="Confinement Analysis" />
        </motion.div>

        <motion.div variants={{ hidden: { opacity: 0, scale: 0.95 }, visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } } }}>
          <MiniPie data={crossSiteData} title="Cross-site Analysis" />
        </motion.div>
      </motion.div>
    </motion.div>
  </section>
);
