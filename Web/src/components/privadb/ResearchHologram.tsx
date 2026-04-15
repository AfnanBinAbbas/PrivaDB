import React from 'react';
import { motion } from 'framer-motion';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadialBarChart, RadialBar, Legend
} from 'recharts';
import { BarChart3, Clock, Database, Zap, Globe, ShieldAlert } from 'lucide-react';

const researchData = [
  { name: 'Day 1', sites: 150, leaks: 12 },
  { name: 'Day 2', sites: 320, leaks: 28 },
  { name: 'Day 3', sites: 580, leaks: 45 },
  { name: 'Day 4', sites: 840, leaks: 92 },
  { name: 'Day 5', sites: 1200, leaks: 148 },
  { name: 'Day 6', sites: 1500, leaks: 210 },
  { name: 'Day 7', sites: 1845, leaks: 268 },
];

const radialData = [
  { name: 'IndexedDB Usage', value: 12, fill: '#0ea5e9' },
  { name: 'Third Party Spying', value: 10, fill: '#f43f5e' },
  { name: 'Secure Storage', value: 9, fill: '#10b981' },
];

export const ResearchHologram: React.FC = () => {
  return (
    <section id="research-hologram" className="py-24 px-4 relative">
      <div className="max-w-4xl mx-auto">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1.5 glass rounded-full text-xs font-bold mb-4 text-primary border border-primary/20">
            <span className="w-1.5 h-1.5 rounded-full bg-primary" />
            Global Intelligence Core
          </div>
          <h2 className="text-3xl md:text-5xl font-bold mb-4 tracking-tighter">Research Findings</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Real-time telemetry from our global crawl of 500+ top Tranco domains, analyzed via dual-engine taint tracking.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Main Hologram Card 1: Time & Growth */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="glass rounded-3xl p-6 border-cyan-500/20 relative overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent pointer-events-none" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-500">
                    <BarChart3 size={20} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold uppercase tracking-widest text-cyan-400">Scale Metrics</h3>
                    <p className="text-[15px] text-muted-foreground">Cumulative Site Analysis</p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-mono font-bold text-cyan-400">1,845</div>
                  <div className="text-[10px] text-green-400 font-bold">+24% Week</div>
                </div>
              </div>

              <div className="h-48 w-full mt-4">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={researchData}>
                    <defs>
                      <linearGradient id="colorSites" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area 
                      type="monotone" 
                      dataKey="sites" 
                      stroke="#0ea5e9" 
                      fillOpacity={1} 
                      fill="url(#colorSites)" 
                      strokeWidth={3}
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', border: '1px solid rgba(0,255,255,0.2)', borderRadius: '12px' }}
                      itemStyle={{ color: '#0ea5e9' }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            
          </motion.div>

          {/* Main Hologram Card 2: Exfiltration Radar */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="glass rounded-3xl p-6 border-pink-500/20 relative overflow-hidden group"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-pink-500/5 to-transparent pointer-events-none" />
            <div className="relative z-10 h-full flex flex-col">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-pink-500/10 text-pink-500">
                    <ShieldAlert size={20} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold uppercase tracking-widest text-pink-400">Leak Probability</h3>
                    <p className="text-[15px] text-muted-foreground">Comparative Ecosystem Analysis</p>
                  </div>
                </div>
              </div>

              <div className="flex-1 flex items-center justify-center">
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <RadialBarChart 
                      innerRadius="30%" 
                      outerRadius="100%" 
                      data={radialData} 
                      startAngle={180} 
                      endAngle={0}
                    >
                      <RadialBar
                        label={{ fill: '#fff', position: 'insideStart', fontSize: '15px' }}
                        background
                        dataKey="value"
                        cornerRadius={10}
                      />
                    </RadialBarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 mt-4">
                {radialData.map((d, i) => (
                  <div key={i} className="text-center">
                    <div className="text-sm font-bold" style={{ color: d.fill }}>{d.value}%</div>
                    <div className="text-[15px] text-muted-foreground uppercase">{d.name.split(' ')[0]}</div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>

        {/* Floating Stat Micro-Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
          {[
            { label: 'Avg Time / Site', value: '150s', icon: Clock, color: 'text-blue-400' },
            { label: 'Storage Usage', value: '2.2 GB', icon: Database, color: 'text-purple-400' },
            { label: 'Domains Scanned', value: '500', icon: Globe, color: 'text-cyan-400' },
            { label: 'Active Sinks', icon: Zap, value: '13', color: 'text-yellow-400' },
          ].map((stat, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              viewport={{ once: true }}
              className="glass p-4 rounded-2xl flex items-center gap-3 hover:scale-105 transition-transform"
            >
              <stat.icon className={`${stat.color} opacity-80`} size={18} />
              <div>
                <div className="text-xs text-muted-foreground font-medium">{stat.label}</div>
                <div className="text-base font-mono font-bold">{stat.value}</div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};
