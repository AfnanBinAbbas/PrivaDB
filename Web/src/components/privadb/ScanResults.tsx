import React, { useState, useEffect, useMemo } from 'react';
import {
  Database, Shield, AlertTriangle, CheckCircle, XCircle,
  Filter, Search, Download, Eye, EyeOff, BarChart3,
  Globe, Zap, ArrowRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import EntropyCalculator from './EntropyCalculator';

interface ScanResult {
  status_code: number;
  idb_value: string;
  tracker_category: string;
  is_exfiltrated: boolean;
  responsible_tracker: string;
  database: string;
  key: string;
  entropy: number;
}

interface ScanResultsData {
  chrome: Record<string, ScanResult[]>;
  foxhound: Record<string, ScanResult[]>;
  summary: {
    total_scans: number;
    completed_scans: number;
    chrome_scans: number;
    foxhound_scans: number;
  };
}

const ScanResults: React.FC = () => {
  const [data, setData] = useState<ScanResultsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedEngine, setSelectedEngine] = useState<'chrome' | 'foxhound' | 'all'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showExfiltratedOnly, setShowExfiltratedOnly] = useState(false);
  const [selectedValue, setSelectedValue] = useState<string>('');
  const [retrying, setRetrying] = useState(false);

  useEffect(() => {
    fetchResults();
    
    // Retry every 60 seconds if there's no data
    const interval = setInterval(() => {
      if (!data) {
        fetchResults();
      }
    }, 60000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchResults = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('http://localhost:8000/scan/results', {
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(30000) // 30 second timeout
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.detail || 
          errorData.error || 
          `Server error: ${response.status} ${response.statusText}`
        );
      }
      
      const result = await response.json();
      setData(result);
      setError(null);
    } catch (err) {
      let errorMessage = 'Unknown error occurred';
      
      if (err instanceof TypeError) {
        if (err.message.includes('Failed to fetch')) {
          errorMessage = 'Cannot connect to backend server. Is it running on port 8000?';
        } else if (err.message.includes('timeout')) {
          errorMessage = 'Request timed out. The server took too long to respond.';
        } else {
          errorMessage = `Network error: ${err.message}`;
        }
      } else if (err instanceof Error) {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
      console.error('Error fetching results:', err);
    } finally {
      setLoading(false);
      setRetrying(false);
    }
  };
  
  const handleRetry = async () => {
    setRetrying(true);
    await fetchResults();
  };

  const filteredResults = useMemo(() => {
    if (!data) return {};

    const results: Record<string, ScanResult[]> = {};

    const engines = selectedEngine === 'all' ? ['chrome', 'foxhound'] : [selectedEngine];

    for (const engine of engines) {
      const engineData = data[engine as keyof ScanResultsData] as Record<string, ScanResult[]>;
      if (!engineData) continue;

      for (const [domain, items] of Object.entries(engineData)) {
        const filtered = items.filter(item => {
          const matchesSearch = !searchTerm ||
            item.idb_value.toLowerCase().includes(searchTerm.toLowerCase()) ||
            item.key.toLowerCase().includes(searchTerm.toLowerCase()) ||
            item.database.toLowerCase().includes(searchTerm.toLowerCase()) ||
            item.responsible_tracker.toLowerCase().includes(searchTerm.toLowerCase());

          const matchesExfil = !showExfiltratedOnly || item.is_exfiltrated;

          return matchesSearch && matchesExfil;
        });

        if (filtered.length > 0) {
          results[`${engine}:${domain}`] = filtered;
        }
      }
    }

    return results;
  }, [data, selectedEngine, searchTerm, showExfiltratedOnly]);

  const stats = useMemo(() => {
    if (!data) return { total: 0, exfiltrated: 0, unique: 0 };

    let total = 0;
    let exfiltrated = 0;
    const uniqueValues = new Set<string>();

    for (const items of Object.values(filteredResults)) {
      for (const item of items) {
        total++;
        if (item.is_exfiltrated) exfiltrated++;
        uniqueValues.add(item.idb_value);
      }
    }

    return { total, exfiltrated, unique: uniqueValues.size };
  }, [filteredResults]);

  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex flex-col items-center justify-center p-12 bg-muted/30 rounded-xl border border-cyan-500/30 neon-glow-cyan"
      >
        <motion.div 
          animate={{ rotate: 360 }}
          transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
          className="rounded-full h-16 w-16 border-2 border-cyan-500/30 border-t-cyan-400 mb-4 shadow-[0_0_20px_rgba(0,255,255,0.5)]"
        />
        <p className="text-cyan-400 font-bold text-lg cyber-flicker">Scanning databases...</p>
        <p className="text-xs text-cyan-400/60 mt-2">Analyzing IndexedDB records</p>
      </motion.div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-red-500/10 border border-red-500/30 rounded-xl p-8 text-center neon-glow-pink"
      >
        <motion.div 
          className="flex justify-center mb-4"
          animate={{ scale: [1, 1.1, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          <AlertTriangle className="h-12 w-12 text-red-400 drop-shadow-lg" />
        </motion.div>
        <h3 className="text-lg font-bold text-red-400 mb-2">Unable to Load Results</h3>
        <p className="text-red-400/80 mb-6 max-w-md mx-auto">{error}</p>
        <div className="flex gap-3 justify-center">
          <motion.button
            onClick={handleRetry}
            disabled={retrying}
            className="px-6 py-2 bg-cyan-600 text-white rounded-lg hover:shadow-lg hover:shadow-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 neon-glow-cyan"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            {retrying ? (
              <>
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity }} className="rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                Retrying...
              </>
            ) : (
              <>
                <BarChart3 className="h-4 w-4" />
                Retry
              </>
            )}
          </motion.button>
          <motion.a
            href="http://localhost:8081"
            className="px-6 py-2 bg-muted text-foreground rounded-lg hover:bg-muted/80"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Go Home
          </motion.a>
        </div>
        <p className="text-xs text-red-400/60 mt-4">
          Make sure the backend server is running: <code className="bg-red-500/20 px-2 py-1 rounded font-mono">python3 backend/server.py</code>
        </p>
      </motion.div>
    );
  }

  if (!data || (Object.keys(data.chrome || {}).length === 0 && Object.keys(data.foxhound || {}).length === 0)) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="bg-purple-500/10 border border-dashed border-purple-500/30 rounded-xl p-12 text-center neon-glow-purple"
      >
        <motion.div animate={{ y: [0, -10, 0] }} transition={{ duration: 2, repeat: Infinity }}>
          <Database className="h-12 w-12 text-purple-400 mx-auto mb-4 drop-shadow-lg" />
        </motion.div>
        <h3 className="text-lg font-bold text-purple-400 mb-2">No Results Available</h3>
        <p className="text-purple-400/80 mb-6 max-w-md mx-auto">
          Run a scan to analyze IndexedDB exfiltration and generate results.
        </p>
        <div className="flex gap-3 justify-center">
          <motion.button
            onClick={handleRetry}
            className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:shadow-lg hover:shadow-purple-500/50 neon-glow-purple"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Check for Updates
          </motion.button>
        </div>
      </motion.div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-4xl font-extrabold tracking-tight mb-2">Scan Results</h2>
          <p className="text-xl text-muted-foreground">
            IndexedDB analysis and exfiltration detection
          </p>
        </div>
        <motion.button
          onClick={fetchResults}
          whileHover={{ scale: 1.05, backgroundColor: 'rgba(var(--primary-rgb), 0.9)' }}
          whileTap={{ scale: 0.95 }}
          className="px-8 py-3 bg-primary text-primary-foreground rounded-full font-bold shadow-lg shadow-primary/20 transition-all hover:neon-glow-cyan"
        >
          Refresh Data
        </motion.button>
      </div>

      {/* Summary Stats */}
      {data && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            whileHover={{ scale: 1.05 }}
            className="glass rounded-xl p-4 text-center border border-blue-500/30 hover:border-blue-500/80 neon-glow-blue hover:neon-pulse"
          >
            <motion.div animate={{ rotate: 360 }} transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}>
              <BarChart3 className="mx-auto h-8 w-8 text-blue-400 mb-2 drop-shadow-lg" />
            </motion.div>
            <div className="text-2xl font-bold text-blue-400">{data.summary.total_scans}</div>
            <div className="text-sm text-blue-400/60">Total Scans</div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.1 }}
            whileHover={{ scale: 1.05 }}
            className="glass rounded-xl p-4 text-center border border-green-500/30 hover:border-green-500/80 neon-glow-green hover:neon-pulse"
          >
            <motion.div animate={{ scale: [1, 1.2, 1] }} transition={{ duration: 2, repeat: Infinity }}>
              <CheckCircle className="mx-auto h-8 w-8 text-green-400 mb-2 drop-shadow-lg" />
            </motion.div>
            <div className="text-2xl font-bold text-green-400">{data.summary.completed_scans}</div>
            <div className="text-sm text-green-400/60">Completed</div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            whileHover={{ scale: 1.05 }}
            className="glass rounded-xl p-4 text-center border border-orange-500/30 hover:border-orange-500/80 neon-glow-orange hover:neon-pulse"
          >
            <motion.div animate={{ y: [0, -5, 0] }} transition={{ duration: 2, repeat: Infinity }}>
              <Shield className="mx-auto h-8 w-8 text-orange-400 mb-2 drop-shadow-lg" />
            </motion.div>
            <div className="text-2xl font-bold text-orange-400">{stats.exfiltrated}</div>
            <div className="text-sm text-orange-400/60">Exfiltrated</div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.3 }}
            whileHover={{ scale: 1.05 }}
            className="glass rounded-xl p-4 text-center border border-purple-500/30 hover:border-purple-500/80 neon-glow-purple hover:neon-pulse"
          >
            <motion.div animate={{ rotate: -360 }} transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}>
              <Database className="mx-auto h-8 w-8 text-purple-400 mb-2 drop-shadow-lg" />
            </motion.div>
            <div className="text-2xl font-bold text-purple-400">{stats.unique}</div>
            <div className="text-sm text-purple-400/60">Unique Values</div>
          </motion.div>
        </div>
      )}

      {/* Filters */}
      <div className="glass rounded-xl p-4">
        <div className="flex flex-wrap gap-4 items-center">
          <div className="flex items-center gap-2">
            <Filter size={16} />
            <span className="font-medium">Filters:</span>
          </div>

          <select
            value={selectedEngine}
            onChange={(e) => setSelectedEngine(e.target.value as any)}
            className="px-3 py-1 bg-background/50 border border-border rounded-lg"
          >
            <option value="all">All Engines</option>
            <option value="chrome">Chrome Only</option>
            <option value="foxhound">Foxhound Only</option>
          </select>

          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Search values, keys, databases..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="px-3 py-1 bg-background/50 border border-border rounded-lg min-w-64"
            />
            <Search size={16} className="text-muted-foreground" />
          </div>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={showExfiltratedOnly}
              onChange={(e) => setShowExfiltratedOnly(e.target.checked)}
              className="rounded"
            />
            <span className="text-sm">Exfiltrated only</span>
          </label>
        </div>
      </div>

      {/* Results Grid - Expanded to Full Width */}
      <div className="grid grid-cols-1 gap-6">
        {/* Results Table */}
        <div className="glass rounded-xl p-4">
          <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
              <Database className="text-cyan-400" size={24} />
              Detected Tracking Identifiers
            </h3>
            <div className="text-xs text-muted-foreground bg-muted/30 px-3 py-1 rounded-full border border-border">
              Showing {Object.keys(filteredResults).length} domains with activity
            </div>
          </div>
          
          <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
            {Object.entries(filteredResults).map(([domainKey, items]) => {
              const [engine, domain] = domainKey.split(':');
              return (
                <div key={domainKey} className="space-y-3 bg-background/20 rounded-xl p-4 border border-border/50">
                  <div className="flex items-center justify-between border-b border-border/30 pb-2">
                    <div className="flex items-center gap-2 text-sm font-bold text-cyan-400">
                      <Globe size={16} />
                      <span className="tracking-tight">{domain}</span>
                    </div>
                    <span className={`px-3 py-0.5 rounded-full text-[10px] font-bold tracking-widest uppercase ${
                      engine === 'chrome' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                    }`}>
                      {engine}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 gap-2">
                    {items.map((item, idx) => (
                      <ResultRow key={idx} item={item} idx={idx} />
                    ))}
                  </div>
                </div>
              );
            })}
            {Object.keys(filteredResults).length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                <Search size={48} className="opacity-20 mb-4" />
                <p className="text-lg font-medium">No results match your filters</p>
                <p className="text-sm opacity-60">Try adjusting your search term or engine selection</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Sub-component for individual result rows with expandability
const ResultRow: React.FC<{ item: ScanResult; idx: number }> = ({ item, idx }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(idx * 0.05, 0.5) }}
      className={`group border border-border/30 rounded-lg overflow-hidden transition-all duration-300 ${
        isExpanded ? 'bg-background/60 border-cyan-500/30 shadow-lg shadow-cyan-950/20' : 'bg-background/20 hover:bg-background/40'
      }`}
    >
      <div 
        className="flex items-center justify-between p-3 cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center gap-4 flex-1 min-w-0">
          <div className="flex-shrink-0">
            {item.is_exfiltrated ? (
              <div className="w-8 h-8 rounded-full bg-red-500/10 flex items-center justify-center border border-red-500/30">
                <AlertTriangle size={16} className="text-red-400" />
              </div>
            ) : (
              <div className="w-8 h-8 rounded-full bg-green-500/10 flex items-center justify-center border border-green-500/30">
                <CheckCircle size={16} className="text-green-400" />
              </div>
            )}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="font-mono text-xl font-bold text-foreground/90 truncate max-w-[400px]" title={item.idb_value}>
                {item.idb_value}
              </span>
              <span className={`flex-shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                item.tracker_category === 'first_party'
                  ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }`}>
                {item.tracker_category.replace('_', ' ')}
              </span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <Database size={12} /> {item.database}
              </span>
              <span className="opacity-30">|</span>
              <span className="truncate max-w-[200px]" title={item.key}>Key: {item.key}</span>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-3 ml-4">
          <div className="text-right hidden sm:block">
            <div className={`text-xs font-bold ${item.is_exfiltrated ? 'text-red-400' : 'text-green-400'}`}>
              {item.is_exfiltrated ? 'EXFILTRATED' : 'SAFE'}
            </div>
            <div className="text-[10px] opacity-40">Status: {item.status_code}</div>
          </div>
          <motion.div
            animate={{ rotate: isExpanded ? 180 : 0 }}
            className="text-muted-foreground"
          >
            <ArrowRight size={16} />
          </motion.div>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-border/30 bg-background/40"
          >
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Detection Logic</h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Flow Direction</span>
                    <span className="text-cyan-400 font-medium">Outflow (Storage → Network)</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Confinement</span>
                    <span className="text-cyan-400 font-medium font-mono text-xs">CROSS-ORIGIN</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Sink Class</span>
                    <span className="text-cyan-400 font-medium font-mono text-xs">{item.is_exfiltrated ? 'XHR_BODY / FETCH' : 'None'}</span>
                  </div>
                </div>
              </div>
              
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Tracking Meta</h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Responsible Tracker</span>
                    <span className={item.is_exfiltrated ? 'text-red-400 font-bold' : 'text-muted-foreground italic'}>
                      {item.responsible_tracker || 'None detected'}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Evidence Confidence</span>
                    <span className={`font-bold ${item.is_exfiltrated ? 'text-orange-400' : 'text-green-400'}`}>
                      {item.is_exfiltrated ? 'CRITICAL (HIGH)' : 'LOW / NORMAL'}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Exfiltration URL</span>
                    <span className="text-xs font-mono text-cyan-400 max-w-[200px] truncate text-right">
                      {item.is_exfiltrated ? 'captured_request.url' : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="md:col-span-2 pt-2 space-y-4">
                <h4 className="text-sm font-bold text-muted-foreground uppercase tracking-wider mb-2">Taint Tracking Path</h4>
                <TaintFlowGraph item={item} />
                
                <h4 className="text-sm font-bold text-muted-foreground uppercase tracking-wider mb-2">Raw Value (Scrollable)</h4>
                <div className="p-4 bg-black/40 rounded border border-border/30 font-mono text-base text-cyan-300 break-all max-h-48 overflow-y-auto">
                  {item.idb_value}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};
/* ── TaintFlowGraph Component ────────────────────────────────────── */
const TaintFlowGraph: React.FC<{ item: ScanResult }> = ({ item }) => {
  const is3rdParty = item.tracker_category === 'third_party';
  
  const nodes = [
    { 
      id: 'source', 
      label: 'IndexedDB Source', 
      sub: `${item.database} / ${item.key}`,
      icon: Database,
      color: 'text-cyan-400',
      description: 'Dynamic data extracted from persistent storage.'
    },
    { 
      id: 'hook', 
      label: 'Privacy Hook', 
      sub: 'Proxy: IDBRequest.get()',
      icon: Shield,
      color: 'text-blue-400',
      description: 'Taint engine intercepts retrieval and labels value.'
    },
    { 
      id: 'filter', 
      label: 'Security Shield', 
      sub: is3rdParty ? '3rd Party Detected' : '1st Party Verified',
      icon: Filter,
      color: is3rdParty ? 'text-red-400' : 'text-green-400',
      description: 'Party-segregation filter identifies exfiltration intent.'
    },
    { 
      id: 'sink', 
      label: 'Network Sink', 
      sub: item.is_exfiltrated ? (item.responsible_tracker || 'Exfiltration') : 'Access Denied',
      icon: Zap,
      color: item.is_exfiltrated ? 'text-red-500' : 'text-gray-500',
      description: item.is_exfiltrated ? 'Value leaked via XHR/Fetch body.' : 'Propagation blocked by browser policy.'
    }
  ];

  return (
    <div className="relative w-full py-8 px-4 bg-black/20 rounded-xl border border-border/20 overflow-x-auto min-w-[800px] mb-6">
      <div className="flex items-center justify-between gap-4 relative z-10">
        {nodes.map((node, i) => {
          const Icon = node.icon;
          return (
            <React.Fragment key={node.id}>
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.2 }}
                className="flex flex-col items-center gap-3 w-48 text-center group"
              >
                <div className={`p-4 rounded-2xl bg-muted/40 border border-border/50 ${node.color} shadow-lg relative group-hover:scale-110 transition-transform duration-300`}>
                  <div className={`absolute inset-0 rounded-2xl opacity-20 blur-xl ${node.color.replace('text-', 'bg-')}`} />
                  <Icon size={32} className="relative z-10" />
                </div>
                <div className="space-y-1">
                  <div className={`text-base font-bold ${node.color}`}>${node.label}</div>
                  <div className="text-[11px] font-mono text-muted-foreground truncate w-full px-2" title={node.sub}>
                    ${node.sub}
                  </div>
                </div>
                
                {/* Expandable node info */}
                <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute top-full mt-4 left-1/2 -translate-x-1/2 w-56 p-3 glass-strong rounded-lg z-50 text-xs pointer-events-none border border-border/30">
                  ${node.description}
                </div>
              </motion.div>

              {i < nodes.length - 1 && (
                <div className="flex-1 flex items-center justify-center -mx-4">
                  <div className="relative w-full h-1 bg-border/20 rounded-full overflow-hidden">
                    <motion.div 
                      className={`absolute inset-y-0 left-0 bg-gradient-to-r ${is3rdParty ? 'from-red-500 to-red-400' : 'from-blue-500 to-cyan-400'}`}
                      initial={{ width: '0%', left: '-100%' }}
                      animate={{ 
                        width: ['20%', '20%', '20%'],
                        left: ['-20%', '120%'],
                      }}
                      transition={{ 
                        duration: 2, 
                        repeat: Infinity, 
                        ease: 'linear',
                        delay: i * 0.5
                      }}
                    />
                  </div>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
      
      {/* Background connecting lines (SVG) */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-10">
        <defs>
          <linearGradient id="flow-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#0ea5e9" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        <path d="M 0 50% L 100% 50%" stroke="url(#flow-grad)" strokeWidth="2" strokeDasharray="10,10" />
      </svg>
    </div>
  );
};

export default ScanResults;
