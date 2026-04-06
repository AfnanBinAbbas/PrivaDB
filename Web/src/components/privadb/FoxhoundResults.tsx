import React, { useState, useEffect, useMemo } from 'react';
import {
  Globe, Search, Database, ArrowRight, Shield, AlertTriangle,
  ChevronDown, ChevronUp, Download, Loader2, Filter, BarChart3,
  Eye, Zap, Activity
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

/* ── Types ─────────────────────────────────────────────────────────── */
type FoxhoundEvent = {
  databaseName: string;
  key: string;
  value: string;
  source: string;
  sink: string;
  statusCode: number;
  domain: string;
  requestUrl: string;
};

type FoxhoundData = Record<string, FoxhoundEvent[]>;

/* ── Animated Counter ──────────────────────────────────────────────── */
const AnimatedCounter: React.FC<{ target: number; duration?: number; label: string; icon: React.ElementType; color: string }> = ({
  target, duration = 1200, label, icon: Icon, color,
}) => {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (target === 0) { setCount(0); return; }
    const step = Math.max(1, Math.floor(target / (duration / 16)));
    let current = 0;
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      setCount(current);
      if (current >= target) clearInterval(timer);
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: 'spring', stiffness: 200, damping: 20 }}
      className="glass rounded-xl p-4 flex flex-col items-center gap-2 relative overflow-hidden group"
    >
      <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 ${color} blur-3xl`} />
      <Icon size={20} className="text-primary relative z-10" />
      <span className="text-2xl font-bold font-mono relative z-10">{count.toLocaleString()}</span>
      <span className="text-xs text-muted-foreground relative z-10">{label}</span>
    </motion.div>
  );
};

/* ── Sink Badge ────────────────────────────────────────────────────── */
const SinkBadge: React.FC<{ sink: string }> = ({ sink }) => {
  const colorMap: Record<string, string> = {
    'document.cookie': 'bg-red-500/15 text-red-400 border-red-500/20',
    'fetch.body': 'bg-blue-500/15 text-blue-400 border-blue-500/20',
    'fetch.url': 'bg-cyan-500/15 text-cyan-400 border-cyan-500/20',
    'XMLHttpRequest.send': 'bg-amber-500/15 text-amber-400 border-amber-500/20',
    'XMLHttpRequest.open(url)': 'bg-orange-500/15 text-orange-400 border-orange-500/20',
    'navigator.sendBeacon(url)': 'bg-purple-500/15 text-purple-400 border-purple-500/20',
    'navigator.sendBeacon(body)': 'bg-violet-500/15 text-violet-400 border-violet-500/20',
    'script.src': 'bg-pink-500/15 text-pink-400 border-pink-500/20',
    'img.src': 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
    'iframe.src': 'bg-teal-500/15 text-teal-400 border-teal-500/20',
    'WebSocket': 'bg-indigo-500/15 text-indigo-400 border-indigo-500/20',
  };
  const cls = colorMap[sink] || 'bg-gray-500/15 text-gray-400 border-gray-500/20';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-medium border ${cls}`}>
      {sink}
    </span>
  );
};

/* ── Flow Arrow ────────────────────────────────────────────────────── */
const FlowArrow: React.FC<{ source: string; sink: string }> = ({ source, sink }) => (
  <div className="flex items-center gap-2 text-xs">
    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono text-[10px]">{source}</span>
    <motion.div animate={{ x: [0, 4, 0] }} transition={{ repeat: Infinity, duration: 1.5 }}>
      <ArrowRight size={12} className="text-muted-foreground" />
    </motion.div>
    <SinkBadge sink={sink} />
  </div>
);

/* ── Site Card ─────────────────────────────────────────────────────── */
const SiteCard: React.FC<{ domain: string; events: FoxhoundEvent[]; index: number }> = ({ domain, events, index }) => {
  const [expanded, setExpanded] = useState(false);
  const uniqueSinks = useMemo(() => [...new Set(events.map(e => e.sink))], [events]);
  const uniqueDbs = useMemo(() => [...new Set(events.map(e => e.databaseName))], [events]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.4 }}
      className="glass rounded-xl overflow-hidden"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-muted/30 transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <Globe size={14} className="text-primary" />
          </div>
          <div className="min-w-0">
            <span className="text-sm font-semibold block truncate">{domain}</span>
            <span className="text-[11px] text-muted-foreground">
              {events.length} exfiltration{events.length !== 1 ? 's' : ''} · {uniqueDbs.length} db{uniqueDbs.length !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0 ml-4">
          <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-red-500/15 text-red-400 text-xs font-mono">
            <AlertTriangle size={10} /> {events.length}
          </span>
          <motion.div animate={{ rotate: expanded ? 180 : 0 }} transition={{ duration: 0.2 }}>
            <ChevronDown size={16} className="text-muted-foreground" />
          </motion.div>
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 pt-2 border-t border-border/30 space-y-4">
              {/* Sink Distribution */}
              <div>
                <h4 className="text-xs font-medium text-muted-foreground mb-2">Sink Distribution</h4>
                <div className="flex flex-wrap gap-1.5">
                  {uniqueSinks.map(sink => {
                    const ct = events.filter(e => e.sink === sink).length;
                    return (
                      <div key={sink} className="flex items-center gap-1">
                        <SinkBadge sink={sink} />
                        <span className="text-[10px] text-muted-foreground">×{ct}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Events Table */}
              <div className="rounded-lg border border-border/30 overflow-hidden">
                <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/30 sticky top-0">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground">Database</th>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground">Key</th>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground">Flow</th>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground hidden lg:table-cell">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map((evt, i) => (
                        <motion.tr
                          key={i}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: i * 0.02 }}
                          className="border-t border-border/20 hover:bg-muted/20 transition-colors"
                        >
                          <td className="px-3 py-2 font-mono text-[11px]">
                            <div className="flex items-center gap-1.5">
                              <Database size={10} className="text-primary shrink-0" />
                              <span className="truncate max-w-[120px]">{evt.databaseName}</span>
                            </div>
                          </td>
                          <td className="px-3 py-2 font-mono text-[11px] max-w-[200px] truncate" title={evt.key}>
                            {evt.key.split('/').pop()}
                          </td>
                          <td className="px-3 py-2">
                            <FlowArrow source={evt.source} sink={evt.sink} />
                          </td>
                          <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground max-w-[150px] truncate hidden lg:table-cell" title={evt.value}>
                            {evt.value.length > 40 ? evt.value.slice(0, 40) + '…' : evt.value}
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

/* ── Main Component ────────────────────────────────────────────────── */
export const FoxhoundResults: React.FC = () => {
  const [data, setData] = useState<FoxhoundData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sinkFilter, setSinkFilter] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('http://localhost:8000/foxhound/results');
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
        setData(await res.json());
      } catch (e: any) {
        setError(e.message || 'Failed to load Foxhound results');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  /* Computed stats */
  const stats = useMemo(() => {
    if (!data) return { sites: 0, events: 0, sinks: 0, databases: 0 };
    const allEvents = Object.values(data).flat();
    return {
      sites: Object.keys(data).length,
      events: allEvents.length,
      sinks: new Set(allEvents.map(e => e.sink)).size,
      databases: new Set(allEvents.map(e => e.databaseName)).size,
    };
  }, [data]);

  const allSinks = useMemo(() => {
    if (!data) return [];
    return [...new Set(Object.values(data).flat().map(e => e.sink))].sort();
  }, [data]);

  /* Filtered data */
  const filteredEntries = useMemo(() => {
    if (!data) return [];
    return Object.entries(data)
      .filter(([domain]) => !searchQuery || domain.toLowerCase().includes(searchQuery.toLowerCase()))
      .map(([domain, events]) => {
        const filtered = sinkFilter ? events.filter(e => e.sink === sinkFilter) : events;
        return [domain, filtered] as [string, FoxhoundEvent[]];
      })
      .filter(([, events]) => events.length > 0)
      .sort(([, a], [, b]) => b.length - a.length);
  }, [data, searchQuery, sinkFilter]);

  const handleExport = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `foxhound-results-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── Loading ──────────────────────────────────────────────────────── */
  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex flex-col items-center justify-center gap-4 py-20"
      >
        <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
          <Loader2 size={32} className="text-primary" />
        </motion.div>
        <p className="text-sm text-muted-foreground">Loading Foxhound taint-tracking results…</p>
      </motion.div>
    );
  }

  /* ── Error ─────────────────────────────────────────────────────────── */
  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-xl p-8 text-center"
      >
        <AlertTriangle size={28} className="text-amber-400 mx-auto mb-3" />
        <p className="text-sm font-medium mb-1">Could not load Foxhound results</p>
        <p className="text-xs text-muted-foreground">{error}</p>
        <p className="text-xs text-muted-foreground mt-2">Make sure the backend is running on port 8000</p>
      </motion.div>
    );
  }

  if (!data || Object.keys(data).length === 0) {
    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass rounded-xl p-8 text-center">
        <Eye size={28} className="text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No Foxhound results available</p>
      </motion.div>
    );
  }

  /* ── Dashboard ─────────────────────────────────────────────────────── */
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="space-y-6"
    >
      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <AnimatedCounter target={stats.sites} label="Sites Analyzed" icon={Globe} color="bg-blue-500/10" />
        <AnimatedCounter target={stats.events} label="Exfiltration Events" icon={Zap} color="bg-red-500/10" />
        <AnimatedCounter target={stats.sinks} label="Unique Sinks" icon={Activity} color="bg-purple-500/10" />
        <AnimatedCounter target={stats.databases} label="Databases" icon={Database} color="bg-emerald-500/10" />
      </div>

      {/* Toolbar */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass rounded-xl p-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
      >
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by domain…"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-muted/50 border border-border/30 text-sm focus:outline-none focus:ring-1 focus:ring-primary/50"
          />
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg border transition-colors ${
              sinkFilter
                ? 'border-primary/50 bg-primary/10 text-primary'
                : 'border-border/30 glass hover:bg-muted/50'
            }`}
          >
            <Filter size={13} />
            {sinkFilter ? `Sink: ${sinkFilter}` : 'Filter by Sink'}
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg glass border border-border/30 hover:bg-muted/50 transition-colors"
          >
            <Download size={13} />
            Export
          </button>
        </div>
      </motion.div>

      {/* Sink Filter Chips */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="glass rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-medium text-muted-foreground">Filter by Sink Type</h4>
                {sinkFilter && (
                  <button
                    onClick={() => setSinkFilter(null)}
                    className="text-[10px] text-primary hover:underline"
                  >
                    Clear filter
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allSinks.map(sink => (
                  <button
                    key={sink}
                    onClick={() => setSinkFilter(sinkFilter === sink ? null : sink)}
                    className={`transition-all duration-200 ${sinkFilter === sink ? 'ring-1 ring-primary scale-105' : 'opacity-70 hover:opacity-100'}`}
                  >
                    <SinkBadge sink={sink} />
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results Count */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Showing <span className="font-medium text-foreground">{filteredEntries.length}</span> of{' '}
          <span className="font-medium text-foreground">{Object.keys(data).length}</span> sites
          {sinkFilter && <> with <SinkBadge sink={sinkFilter} /></>}
        </p>
      </div>

      {/* Site Cards */}
      <div className="space-y-3">
        {filteredEntries.map(([domain, events], index) => (
          <SiteCard key={domain} domain={domain} events={events} index={index} />
        ))}
      </div>

      {filteredEntries.length === 0 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass rounded-xl p-8 text-center">
          <Search size={24} className="text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No results match your filters</p>
        </motion.div>
      )}
    </motion.div>
  );
};
