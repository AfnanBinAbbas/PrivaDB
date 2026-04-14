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
    
    // Retry every 5 seconds if there's no data
    const interval = setInterval(() => {
      if (!data) {
        fetchResults();
      }
    }, 5000);
    
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
      for (const [domain, items] of Object.entries(data[engine] || {})) {
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
          <h2 className="text-2xl font-bold">Scan Results</h2>
          <p className="text-muted-foreground">
            IndexedDB analysis and exfiltration detection
          </p>
        </div>
        <button
          onClick={fetchResults}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
        >
          Refresh
        </button>
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

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Results Table */}
        <div className="glass rounded-xl p-4">
          <h3 className="text-lg font-semibold mb-4">Detected Values</h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {Object.entries(filteredResults).map(([domainKey, items]) => {
              const [engine, domain] = domainKey.split(':');
              return (
                <div key={domainKey} className="space-y-2">
                  <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                    <Globe size={14} />
                    <span>{domain}</span>
                    <span className="px-2 py-0.5 bg-primary/20 text-primary rounded text-xs">
                      {engine}
                    </span>
                  </div>
                  {items.map((item, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="flex items-center justify-between p-3 bg-background/30 rounded-lg hover:bg-background/50 cursor-pointer"
                      onClick={() => setSelectedValue(item.idb_value)}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          {item.is_exfiltrated ? (
                            <XCircle size={14} className="text-red-400" />
                          ) : (
                            <CheckCircle size={14} className="text-green-400" />
                          )}
                          <span className="font-mono text-sm truncate">{item.idb_value}</span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>DB: {item.database}</span>
                          <span>Key: {item.key}</span>
                          <span>Status: {item.status_code}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          item.tracker_category === 'first_party'
                            ? 'bg-green-500/20 text-green-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}>
                          {item.tracker_category}
                        </span>
                        {item.is_exfiltrated && (
                          <span className="text-xs text-muted-foreground">
                            → {item.responsible_tracker}
                          </span>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </div>
              );
            })}
            {Object.keys(filteredResults).length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                No results match the current filters
              </div>
            )}
          </div>
        </div>

        {/* Entropy Calculator */}
        <div>
          <EntropyCalculator
            value={selectedValue}
            onEntropyChange={(entropy) => {
              // Could update results with entropy if needed
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default ScanResults;