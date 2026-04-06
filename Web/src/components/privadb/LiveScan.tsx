import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  Play, Upload, Plus, X, Settings2, ChevronDown, ChevronUp,
  Globe, Search, BarChart3, Check, AlertCircle, FileText,
  Loader2, Copy, Download, Trash2, Shield
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import confetti from 'canvas-confetti';

const triggerSuccessAnimation = () => {
  const duration = 3 * 1000;
  const animationEnd = Date.now() + duration;
  const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 100, colors: ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b'] };

  const randomInRange = (min: number, max: number) => Math.random() * (max - min) + min;

  const interval: any = setInterval(function() {
    const timeLeft = animationEnd - Date.now();

    if (timeLeft <= 0) {
      return clearInterval(interval);
    }

    const particleCount = 50 * (timeLeft / duration);
    // Fire from left
    confetti({
      ...defaults, particleCount,
      origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 }
    });
    // Fire from right
    confetti({
      ...defaults, particleCount,
      origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 }
    });
  }, 250);
};

type ScanConfig = {
  headless: boolean;
  iterations: number;
  overwrite: boolean;
  crawlOnly: boolean;
  detectOnly: boolean;
  sitesLimit: number | null;
  outputFile: string | null;
};

type ScanPhase = {
  name: string;
  icon: React.ElementType;
  status: 'pending' | 'running' | 'done' | 'error';
  progress: number;
  message: string;
};

type ScanResult = {
  url: string;
  databases: number;
  trackingEvents: number;
  confidence: { high: number; medium: number; low: number };
  flowTypes: { confidentiality: number; integrity: number };
  trackerDomains: string[];
  entropy: { avg: number; max: number };
};

type BackendScanResults = {
  domain: string;
  url: string;
  indexeddb_summary: {
    database_count: number;
    total_records: number;
  };
  exfiltration_summary: {
    total: number;
    high_confidence: number;
    medium_confidence: number;
    low_confidence: number;
  };
  flow_classification: {
    outflow_flows: number;
    inflow_flows: number;
    internal_flows: number;
    external_flows: number;
  };
  exfiltration_events: {
    request_domain: string;
    identifier_entropy: number;
    confidence: string;
  }[];
  stage?: 'crawl_only' | 'full';
};

type BackendScanRecord = {
  scan_id: string;
  status: string;
  url: string;
  results?: BackendScanResults;
};

const defaultConfig: ScanConfig = {
  headless: true,
  iterations: 3,
  overwrite: false,
  crawlOnly: false,
  detectOnly: false,
  sitesLimit: null,
  outputFile: null,
};

const generateMockResult = (url: string): ScanResult => {
  const rand = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
  const high = rand(0, 8);
  const medium = rand(2, 15);
  const low = rand(5, 30);
  const conf = high + medium + low;
  const trackerPool = [
    'google-analytics.com', 'doubleclick.net', 'facebook.com', 'criteo.com',
    'hotjar.com', 'mixpanel.com', 'segment.io', 'amplitude.com',
    'onesignal.com', 'pubmatic.com', 'adsrvr.org', 'taboola.com',
    'outbrain.com', 'linkedin.com', 'tiktok.com', 'snapchat.com',
  ];
  const numTrackers = rand(1, 7);
  const shuffled = [...trackerPool].sort(() => Math.random() - 0.5);

  return {
    url,
    databases: rand(1, 8),
    trackingEvents: conf,
    confidence: { high, medium, low },
    flowTypes: {
      confidentiality: rand(Math.floor(conf * 0.4), Math.floor(conf * 0.8)),
      integrity: rand(Math.floor(conf * 0.2), Math.floor(conf * 0.6)),
    },
    trackerDomains: shuffled.slice(0, numTrackers),
    entropy: {
      avg: parseFloat((Math.random() * 2 + 2.5).toFixed(2)),
      max: parseFloat((Math.random() * 2 + 4).toFixed(2)),
    },
  };
};

const ConfidenceBadge: React.FC<{ level: string; count: number }> = ({ level, count }) => {
  const colors: Record<string, string> = {
    HIGH: 'bg-red-500/15 text-red-600 dark:text-red-400',
    MEDIUM: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
    LOW: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-mono font-medium ${colors[level]}`}>
      {level} {count}
    </span>
  );
};

const ResultCard: React.FC<{ result: ScanResult, index: number }> = ({ result, index }) => {
  const [expanded, setExpanded] = useState(index === 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ 
        delay: index * 0.1, 
        type: 'spring', 
        stiffness: 300, 
        damping: 20, 
        duration: 0.8 
      }}
      className="glass rounded-xl overflow-hidden border border-border/40 relative shadow-[0_0_15px_rgba(var(--primary-rgb),0.1)] hover:shadow-[0_0_25px_rgba(var(--primary-rgb),0.2)] transition-shadow"
    >
      {/* Exfiltration glow pulse */}
      {result.trackingEvents > 0 && (
        <motion.div 
          className="absolute inset-0 rounded-xl ring-2 ring-destructive/30 border-destructive/20"
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 1, 0.5] }}
          transition={{ duration: 1.5, repeat: Infinity, repeatType: "reverse" }}
        />
      )}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-muted/30 transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <Globe size={16} className="text-primary shrink-0" />
          <span className="text-sm font-medium truncate">{result.url}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0 ml-4">
          <ConfidenceBadge level="HIGH" count={result.confidence.high} />
          <span className="text-xs text-muted-foreground hidden sm:inline">
            {result.trackingEvents} events
          </span>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </button>

      {expanded && (
        <div className="px-5 pb-5 border-t border-border/30 pt-4 space-y-4">
          {/* Stats grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Databases', value: result.databases },
              { label: 'Tracking Events', value: result.trackingEvents },
              { label: 'Avg Entropy', value: result.entropy.avg },
              { label: 'Max Entropy', value: result.entropy.max },
            ].map((stat, i) => (
              <div key={i} className="bg-muted/30 rounded-lg px-3 py-2">
                <div className="text-xs text-muted-foreground">{stat.label}</div>
                <div className="text-lg font-mono font-semibold">{stat.value}</div>
              </div>
            ))}
          </div>

          {/* Confidence */}
          <div>
            <div className="text-xs text-muted-foreground mb-2">Confidence Distribution</div>
            <div className="flex gap-2">
              <ConfidenceBadge level="HIGH" count={result.confidence.high} />
              <ConfidenceBadge level="MEDIUM" count={result.confidence.medium} />
              <ConfidenceBadge level="LOW" count={result.confidence.low} />
            </div>
          </div>

          {/* Flow */}
          <div>
            <div className="text-xs text-muted-foreground mb-2">Flow Classification</div>
            <div className="flex gap-4 text-sm">
              <span className="font-mono">
                <span className="text-muted-foreground">Outflows:</span>{' '}
                <span className="text-primary font-medium">{result.flowTypes.confidentiality}</span>
              </span>
              <span className="font-mono">
                <span className="text-muted-foreground">Inflows:</span>{' '}
                <span className="font-medium">{result.flowTypes.integrity}</span>
              </span>
            </div>
          </div>

          {/* Trackers */}
          <div>
            <div className="text-xs text-muted-foreground mb-2">
              Detected Tracker Domains ({result.trackerDomains.length})
            </div>
            <div className="flex flex-wrap gap-1.5">
              {result.trackerDomains.map((domain, i) => (
                <span key={i} className="inline-flex items-center px-2 py-1 rounded-md bg-primary/10 text-xs font-mono text-amber-600">
                  {domain}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
};

export const LiveScan: React.FC = () => {
  const [engine, setEngine] = useState<'chrome' | 'foxhound'>('chrome');
  const [urls, setUrls] = useState<string[]>(['']);
  const [showConfig, setShowConfig] = useState(false);
  const [config, setConfig] = useState<ScanConfig>(defaultConfig);
  const [scanning, setScanning] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [phases, setPhases] = useState<ScanPhase[]>([]);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const stopSignalRef = useRef<boolean>(false);

  const fetchHistory = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8000/history');
      if (!response.ok) return;
      const data = await response.json();

      const mappedHistory = data
        .filter((s: BackendScanRecord) => s.status === 'completed' && s.results)
        .map((s: BackendScanRecord) => {
          const res = s.results!;
          return {
            url: s.url,
            databases: res.indexeddb_summary?.database_count || 0,
            trackingEvents: res.exfiltration_summary?.total || 0,
            confidence: {
              high: res.exfiltration_summary?.high_confidence || 0,
              medium: res.exfiltration_summary?.medium_confidence || 0,
              low: res.exfiltration_summary?.low_confidence || 0,
            },
            flowTypes: {
              confidentiality: res.flow_classification?.outflow_flows || 0,
              integrity: res.flow_classification?.inflow_flows || 0,
            },
            trackerDomains: res.exfiltration_events?.map((e: { request_domain: string }) => e.request_domain) || [],
            entropy: {
              avg: res.exfiltration_events?.length ? (res.exfiltration_events.reduce((v: number, e: { identifier_entropy: number }) => v + e.identifier_entropy, 0) / res.exfiltration_events.length) : 0,
              max: res.exfiltration_events?.length ? Math.max(...res.exfiltration_events.map((e: { identifier_entropy: number }) => e.identifier_entropy)) : 0,
            },
          };
        });
      setHistory(mappedHistory);
    } catch (e) {
      console.error('Failed to fetch history:', e);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validUrls = urls.filter(u => u.trim().length > 0);

  const addUrl = () => setUrls(prev => [...prev, '']);
  const removeUrl = (index: number) => setUrls(prev => prev.filter((_, i) => i !== index));
  const updateUrl = (index: number, value: string) => {
    // Strip http:// or https:// if present
    const cleanValue = value.replace(/^https?:\/\//i, '').replace(/\/$/, '');
    setUrls(prev => prev.map((u, i) => (i === index ? cleanValue : u)));
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const lines = text
        .split('\n')
        .map(l => l.trim().replace(/^https?:\/\//i, '').replace(/\/$/, ''))
        .filter(l => l.length > 0 && !l.startsWith('#'));
      if (lines.length > 0) {
        setUrls(lines);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

  const startScan = useCallback(async () => {
    if (validUrls.length === 0) return;
    setScanning(true);
    setScanComplete(false);
    setResults([]);
    stopSignalRef.current = false;

    const update = (idx: number, patch: Partial<ScanPhase>) => {
      setPhases(prev => prev.map((p, i) => (i === idx ? { ...p, ...patch } : p)));
    };

    try {
      for (let i = 0; i < validUrls.length; i++) {
        if (stopSignalRef.current) break;
        
        const currentUrl = validUrls[i];
        const progressPrefix = validUrls.length > 1 ? `[${i + 1}/${validUrls.length}]` : '';

        // Reset phases for the current site
        setPhases([
          { name: 'Starting', icon: Settings2, status: 'pending', progress: 0, message: 'Preparing environment...' },
          { name: 'Crawling', icon: Globe, status: 'pending', progress: 0, message: 'Browser initialization...' },
          { name: 'Analysis', icon: Search, status: 'pending', progress: 0, message: 'Static & Dynamic analysis...' },
          { name: 'Reporting', icon: BarChart3, status: 'pending', progress: 0, message: 'Finalizing data...' },
        ]);

        update(0, { status: 'running', message: `${progressPrefix}Connecting to backend...` });

        const response = await fetch('http://localhost:8000/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: currentUrl,
            headless: config.headless,
            crawl_only: false,
            detect_only: false,
            engine: engine
          }),
        }).catch(() => {
          throw new Error('Backend server is offline or unreachable. Please ensure it is running on port 8000.');
        });

        if (!response.ok) throw new Error('Failed to start scan API. Server returned ' + response.status);

        const { scan_id } = await response.json();
        setCurrentScanId(scan_id);
        setLastScanId(scan_id);
        update(0, { progress: 100, status: 'done', message: 'Scan Engine connected' });

        // Polling loop
        let completed = false;
        while (!completed) {
          if (stopSignalRef.current) {
            setPhases(prev => prev.map(p => p.status === 'running' || p.status === 'pending' ? { ...p, status: 'error', message: 'Scan stopped by user' } : p));
            break;
          }
          await sleep(2000);
          const statusRes = await fetch(`http://localhost:8000/scan/${scan_id}`);
          if (!statusRes.ok) throw new Error('Failed to fetch scan status');

          const data = await statusRes.json() as BackendScanRecord & { progress: number; error?: string };
          const { status, progress, results: scanResults } = data;

          // Check again after sleep
          if (stopSignalRef.current) break;

          // Explicitly set each phase status based on the backend state
          setPhases(prev => prev.map((p, phaseIdx) => {
            const isDone = (s: string, idx: number) => {
              if (s === 'completed') return true;
              if (s === 'reporting' && idx < 3) return true;
              if (s === 'detecting' && idx < 2) return true;
              if (s === 'crawling' && idx < 1) return true;
              if (s === 'starting' && idx < 0) return true;
              return false;
            };

            const isCurrent = (s: string, idx: number) => {
              if (s === 'starting' && idx === 0) return true;
              if (s === 'crawling' && idx === 1) return true;
              if (s === 'detecting' && idx === 2) return true;
              if (s === 'reporting' && idx === 3) return true;
              return false;
            };

            if (isDone(status, phaseIdx)) return { ...p, status: 'done' as const, progress: 100 };
            if (isCurrent(status, phaseIdx)) {
              let msg = p.message;
              if (status === 'starting') msg = `${progressPrefix}Initializing playlets...`;
              if (status === 'crawling') msg = `${progressPrefix}Crawling ${currentUrl}... (This takes ~30s)`;
              if (status === 'detecting') msg = `${progressPrefix}Analyzing IndexedDB entries...`;
              if (status === 'reporting') msg = `${progressPrefix}Generating report...`;
              
              // Set the active progress to an indeterminate middle value so it looks active
              // instead of stuck at 10% global progress for 30s.
              return { ...p, status: 'running' as const, progress: 65, message: msg };
            }
            return { ...p, status: 'pending' as const, progress: 0 };
          }));

          if (status === 'completed') {
            // Map backend results to frontend format
            const mappedResult: ScanResult = {
              url: data.url || currentUrl,
              databases: scanResults?.indexeddb_summary?.database_count || 0,
              trackingEvents: scanResults?.exfiltration_summary?.total || 0,
              confidence: {
                high: scanResults?.exfiltration_summary?.high_confidence || 0,
                medium: scanResults?.exfiltration_summary?.medium_confidence || 0,
                low: scanResults?.exfiltration_summary?.low_confidence || 0,
              },
              flowTypes: {
                confidentiality: scanResults?.flow_classification?.outflow_flows || 0,
                integrity: scanResults?.flow_classification?.inflow_flows || 0,
              },
              trackerDomains: scanResults?.exfiltration_events?.map((e: { request_domain: string }) => e.request_domain) || [],
              entropy: {
                avg: scanResults?.exfiltration_events?.length ? (scanResults.exfiltration_events.reduce((s: number, e: { identifier_entropy: number }) => s + e.identifier_entropy, 0) / scanResults.exfiltration_events.length) : 0,
                max: scanResults?.exfiltration_events?.length ? Math.max(...scanResults.exfiltration_events.map((e: { identifier_entropy: number }) => e.identifier_entropy)) : 0,
              },
            };

            setResults(prev => [...prev, mappedResult]);
            completed = true;
            triggerSuccessAnimation(); // Fire creative UI animation
            fetchHistory(); // Refresh history after scan
          } else if (status === 'stopped') {
            setPhases(prev => prev.map(p => p.status === 'running' ? { ...p, status: 'error', message: 'Scan stopped by user' } : p));
            completed = true;
          } else if (status === 'failed') {
            throw new Error(data.error || 'Scan failed');
          }
        }
        if (stopSignalRef.current) break;
      }

      if (!stopSignalRef.current) {
        setScanComplete(true);
      }
    } catch (error: unknown) {
      if (!stopSignalRef.current) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error('Scan error:', error);
        
        // Update only the currently running or first pending phase to show the error
        setPhases(prev => {
          let errorSet = false;
          return prev.map(p => {
            if (!errorSet && (p.status === 'running' || p.status === 'pending')) {
              errorSet = true;
              return { ...p, status: 'error', message: errorMessage };
            }
            return p;
          });
        });
      }
    } finally {
      setScanning(false);
      setStopping(false);
      setCurrentScanId(null);
    }
  }, [validUrls, fetchHistory, config.headless, engine]);

  const stopScan = async () => {
    if (!currentScanId) return;
    setStopping(true);
    stopSignalRef.current = true;
    try {
      await fetch(`http://localhost:8000/scan/${currentScanId}/stop`, { method: 'POST' });
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  const stopAllScans = async () => {
    setStopping(true);
    stopSignalRef.current = true;
    try {
      await fetch(`http://localhost:8000/scan/all/stop`, { method: 'POST' });
    } catch (error) {
      console.error('Error stopping all scans:', error);
    }
  };

  const totalEvents = results.reduce((s, r) => s + r.trackingEvents, 0);
  const totalHigh = results.reduce((s, r) => s + r.confidence.high, 0);
  const allTrackers = [...new Set(results.flatMap(r => r.trackerDomains))];

  const exportResults = () => {
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'privadb_scan_results.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const generateCliCommand = () => {
    const isSingle = urls.filter(u => u.trim()).length <= 1;
    const urlValue = urls.find(u => u.trim()) || 'https://example.com';

    // Orchestrator main.py for all runs
    const parts = ['python3 main.py'];

    // If no specific mode selected, use --all as the user requested
    if (!config.crawlOnly && !config.detectOnly) {
      parts.push('--all');
    } else {
      if (config.crawlOnly) parts.push('--crawl-only');
      if (config.detectOnly) parts.push('--detect-only');
    }

    if (isSingle) {
      parts.push(`--url ${urlValue}`);
    } else if (config.sitesLimit) {
      parts.push(`--sites ${config.sitesLimit}`);
    } else {
      parts.push('--input-file sites_list.json');
    }

    if (!config.headless) parts.push('--no-headless');
    if (config.iterations !== 3) parts.push(`--iterations ${config.iterations}`);
    if (config.overwrite) parts.push('--overwrite');
    if (config.outputFile) parts.push(`--output ${config.outputFile}`);

    return parts.join(' ');
  };

  const containerVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6, staggerChildren: 0.1 } }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } }
  };

  return (
    <section id="live-scan" className="py-24 px-4 relative z-10">
      <motion.div
        className="max-w-4xl mx-auto"
        variants={containerVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: "-100px" }}
      >
        <motion.div variants={itemVariants} className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 glass rounded-full text-xs text-primary font-medium mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            Interactive Demo
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Live Scan</h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Enter websites to analyze for persistent IndexedDB tracking. Upload a .txt file or add URLs manually.
          </p>

          {/* Engine Toggle */}
          <div className="mt-6 inline-flex items-center p-1 glass rounded-xl relative">
            <motion.div
              className="absolute inset-y-1 w-[calc(50%-4px)] rounded-lg bg-primary/20 border border-primary/30"
              animate={{ x: engine === 'chrome' ? 4 : 'calc(100% + 4px)' }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            />
            <button
              onClick={() => { setEngine('chrome'); }}
              className={`relative z-10 flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                engine === 'chrome' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Globe size={15} />
              Chrome (Live Scan)
            </button>
            <button
              onClick={() => { setEngine('foxhound'); }}
              className={`relative z-10 flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                engine === 'foxhound' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Shield size={15} />
              Foxhound (Taint Tracking)
            </button>
          </div>
        </motion.div>

        {/* Input area */}
        <motion.div variants={itemVariants} className="glass rounded-2xl p-6 mb-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h3 className="text-sm font-medium">Target URLs</h3>
            <div className="flex items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt"
                onChange={handleFileUpload}
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg glass hover:bg-muted/50 transition-colors"
                disabled={scanning}
              >
                <Upload size={14} />
                Upload .txt
              </button>
              <button
                onClick={addUrl}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg glass hover:bg-muted/50 transition-colors"
                disabled={scanning}
              >
                <Plus size={14} />
                Add URL
              </button>
            </div>
          </div>

          <div className="space-y-2">
            <AnimatePresence>
              {urls.map((url, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, height: 0, scale: 0.95 }}
                  animate={{ opacity: 1, height: 'auto', scale: 1 }}
                  exit={{ opacity: 0, height: 0, scale: 0.95 }}
                  className="flex items-center gap-2 overflow-hidden"
                >
                  <div className="relative flex-1 my-1">
                    <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="text"
                      value={url}
                      onChange={e => updateUrl(i, e.target.value)}
                      placeholder="https://example.com"
                      disabled={scanning}
                      className="w-full pl-9 pr-4 py-2.5 bg-background/80 border border-border/50 rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50 placeholder:text-muted-foreground/50"
                    />
                  </div>
                  {urls.length > 1 && (
                    <button
                      onClick={() => removeUrl(i)}
                      disabled={scanning}
                      className="p-2 text-muted-foreground hover:text-destructive transition-colors rounded-lg hover:bg-destructive/10"
                    >
                      <X size={16} />
                    </button>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          {/* File info hint */}
          <p className="text-xs text-muted-foreground mt-3 flex items-center gap-1.5">
            <FileText size={12} />
            Upload a .txt file with one URL per line, or add URLs manually above.
          </p>
        </motion.div>

        {/* Configuration panel */}
        <motion.div variants={itemVariants} className="glass rounded-2xl overflow-hidden mb-6">
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="w-full flex items-center justify-between px-6 py-4 hover:bg-muted/30 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Settings2 size={16} className="text-primary" />
              <span className="text-sm font-medium">Configuration Options</span>
              <span className="text-xs text-muted-foreground">(--help)</span>
            </div>
            {showConfig ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          <AnimatePresence>
            {showConfig && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="px-6 pb-6 border-t border-border/30 pt-4 overflow-hidden"
              >
                <div className="grid sm:grid-cols-2 gap-4">
                  {/* Pipeline Flow */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-medium text-primary uppercase tracking-wider">Pipeline Flow</h4>

                    <label className="flex items-center justify-between">
                      <div>
                        <span className="text-sm">--overwrite</span>
                        <p className="text-xs text-muted-foreground">No confirmation prompts</p>
                      </div>
                      <button
                        onClick={() => setConfig(c => ({ ...c, overwrite: !c.overwrite }))}
                        className={`w-10 h-5 rounded-full transition-colors relative ${config.overwrite ? 'bg-primary' : 'bg-muted'}`}
                      >
                        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${config.overwrite ? 'left-5' : 'left-0.5'}`} />
                      </button>
                    </label>
                  </div>

                  {/* Automation & Scaling */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-medium text-primary uppercase tracking-wider">Scaling</h4>

                    <label className="block">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">--sites</span>
                        <span className="text-xs font-mono text-primary">{config.sitesLimit || 'All'}</span>
                      </div>
                      <input
                        type="number"
                        placeholder="Limit sites (e.g. 10)"
                        value={config.sitesLimit || ''}
                        onChange={e => setConfig(c => ({ ...c, sitesLimit: e.target.value ? Number(e.target.value) : null }))}
                        className="w-full bg-background border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                      />
                    </label>

                    <label className="block">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">--output</span>
                        <span className="text-xs font-mono text-primary">{config.outputFile || 'None'}</span>
                      </div>
                      <input
                        type="text"
                        placeholder="Save log to file..."
                        value={config.outputFile || ''}
                        onChange={e => setConfig(c => ({ ...c, outputFile: e.target.value || null }))}
                        className="w-full bg-background border border-border/50 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                      />
                    </label>
                  </div>
                </div>

                <div className="mt-6 pt-6 border-t border-border/30 grid sm:grid-cols-2 gap-4">
                  {/* Iterations (Common to both scripts) */}
                  <label className="block">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm">--iterations</span>
                      <span className="text-xs font-mono text-primary">{config.iterations}</span>
                    </div>
                    <input
                      type="range"
                      min={1}
                      max={10}
                      value={config.iterations}
                      onChange={e => setConfig(c => ({ ...c, iterations: Number(e.target.value) }))}
                      className="w-full accent-primary"
                    />
                    <p className="text-xs text-muted-foreground">Crawl iterations per site</p>
                  </label>

                  {/* Headless Toggle */}
                  <label className="flex items-center justify-between pt-4">
                    <div>
                      <span className="text-sm">--no-headless</span>
                      <p className="text-xs text-muted-foreground">Visible browser window</p>
                    </div>
                    <button
                      onClick={() => setConfig(c => ({ ...c, headless: !c.headless }))}
                      className={`w-10 h-5 rounded-full transition-colors relative ${!config.headless ? 'bg-primary' : 'bg-muted'}`}
                    >
                      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${!config.headless ? 'left-5' : 'left-0.5'}`} />
                    </button>
                  </label>
                </div>

                {/* CLI preview */}
                <div className="mt-6 bg-background/80 rounded-xl p-3 border border-border/30">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-muted-foreground">Generated CLI Command</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(generateCliCommand())}
                      className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      <Copy size={12} /> Copy
                    </button>
                  </div>
                  <pre className="text-xs font-mono text-primary/80 whitespace-pre-wrap">{generateCliCommand()}</pre>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Run button and Active Scan Controls */}
        <motion.div variants={itemVariants}>
          {scanning ? (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1 py-3 bg-primary/10 text-primary border border-primary/20 rounded-xl font-medium text-sm flex items-center justify-center gap-3 backdrop-blur-sm">
                  <Loader2 size={16} className="animate-spin" />
                  <span className="font-mono">Processing: {validUrls.length} targets</span>
                </div>
                
                <div className="flex gap-2">
                  <motion.button
                    onClick={stopScan}
                    disabled={stopping}
                    className="flex-1 sm:flex-none px-6 py-3 bg-amber-500/10 text-amber-600 border border-amber-500/20 rounded-xl font-medium text-sm hover:bg-amber-500/20 transition-all flex items-center justify-center gap-2"
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <X size={16} />
                    Skip Current
                  </motion.button>
                  
                  <motion.button
                    onClick={stopAllScans}
                    disabled={stopping}
                    className="flex-1 sm:flex-none px-6 py-3 bg-red-500 text-white rounded-xl font-medium text-sm hover:bg-red-600 transition-all flex items-center justify-center gap-2 shadow-lg shadow-red-500/20"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    {stopping ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
                    Stop All Sessions
                  </motion.button>
                </div>
              </div>
              
              {/* Help text for stopping */}
              <p className="text-[10px] text-muted-foreground text-center italic">
                Stopping all sessions will terminate the current URL and prevent further URLs in the list from starting.
              </p>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row items-center gap-4">
              <motion.button
                onClick={() => startScan()}
                disabled={scanning || validUrls.length === 0}
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-10 py-3.5 rounded-xl bg-primary text-primary-foreground disabled:opacity-50 disabled:cursor-not-allowed transition-all font-bold shadow-xl shadow-primary/25 text-base"
                whileHover={{ scale: (scanning || validUrls.length === 0) ? 1 : 1.02 }}
                whileTap={{ scale: (scanning || validUrls.length === 0) ? 1 : 0.98 }}
              >
                <Play size={20} fill="currentColor" />
                <span>Start Discovery Scan ({validUrls.length})</span>
              </motion.button>
              
              {validUrls.length > 5 && (
                <span className="text-xs text-muted-foreground font-mono bg-muted/30 px-3 py-1 rounded-full border border-border/40">
                  Batch Mode Active
                </span>
              )}
            </div>
          )}
        </motion.div>

        {/* Progress phases */}
        <AnimatePresence>
          {phases.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="mt-8 glass rounded-2xl p-6 space-y-4"
            >
              <h3 className="text-sm font-medium mb-4">Pipeline Progress</h3>
              {phases.map((phase, i) => {
                const Icon = phase.icon;
                return (
                  <div key={i} className="flex items-start gap-3">
                    <div className={`mt-0.5 w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors ${phase.status === 'done' ? 'bg-emerald-500/15 text-emerald-500' :
                      phase.status === 'running' ? 'bg-primary/15 text-primary' :
                        phase.status === 'error' ? 'bg-destructive/15 text-destructive' :
                          'bg-muted text-muted-foreground'
                      }`}>
                      {phase.status === 'done' ? <Check size={16} /> :
                        phase.status === 'running' ? <Loader2 size={16} className="animate-spin" /> :
                          phase.status === 'error' ? <AlertCircle size={16} /> :
                            <Icon size={16} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{phase.name}</span>
                        {phase.status !== 'pending' && (
                          <span className="text-xs font-mono text-muted-foreground">{phase.progress}%</span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{phase.message}</p>
                      {phase.status === 'running' && (
                        <div className="mt-3 relative h-1.5 w-full bg-muted/30 rounded-full overflow-hidden ring-1 ring-border/20">
                          {/* Subdued underglow to make it pop inside Dark Mode bounds */}
                          <motion.div
                            className="absolute top-0 left-0 h-full bg-primary/40 blur-[3px] rounded-full"
                            initial={{ width: '0%' }}
                            animate={{ width: `${phase.progress}%` }}
                            transition={{ duration: 0.8, ease: "easeOut" }}
                          />
                          {/* Animated Shimmer Bar Component */}
                          <motion.div
                            className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary/30 via-primary to-primary/30 rounded-full shadow-[0_0_8px_rgba(var(--primary-rgb),0.5)]"
                            initial={{ width: "0%", backgroundPosition: "100% 0%" }}
                            animate={{ 
                              width: `${phase.progress}%`,
                              backgroundPosition: ["200% 0%", "-200% 0%"]
                            }}
                            transition={{
                              width: { duration: 0.8, ease: "easeOut" },
                              backgroundPosition: { duration: 1.5, repeat: Infinity, ease: "linear" }
                            }}
                            style={{ backgroundSize: "200% 100%" }}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        <AnimatePresence>
          {((scanComplete && results.length > 0) || (history.length > 0)) && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-8 space-y-6"
            >
              {/* Header with History Toggle */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <h3 className="text-lg font-semibold">{results.length > 0 ? 'Current Scan Results' : 'Scan History'}</h3>
                <button
                  onClick={() => setShowHistory(!showHistory)}
                  className="flex items-center gap-1.5 px-4 py-2 text-sm rounded-xl glass hover:bg-primary/10 transition-colors text-primary font-medium"
                >
                  {showHistory ? 'View Current' : 'View History'}
                  <FileText size={16} />
                </button>
              </div>

              {!showHistory && results.length > 0 && (
                <>
                  {/* Summary strip */}
                  <div className="glass rounded-2xl p-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                      <h3 className="text-sm font-medium">Scan Summary</h3>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={exportResults}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg glass hover:bg-muted/50 transition-colors"
                        >
                          <Download size={14} />
                          Export JSON
                        </button>
                        <button
                          onClick={() => { setResults([]); setPhases([]); setScanComplete(false); }}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg glass hover:bg-destructive/10 hover:text-destructive transition-colors"
                        >
                          <Trash2 size={14} />
                          Clear
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                      <div>
                        <div className="text-2xl font-bold tabular-nums">{results.length}</div>
                        <div className="text-xs text-muted-foreground">Sites Scanned</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold tabular-nums">{totalEvents}</div>
                        <div className="text-xs text-muted-foreground">Tracking Events</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold tabular-nums text-red-500">{totalHigh}</div>
                        <div className="text-xs text-muted-foreground">High Confidence</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold tabular-nums">{allTrackers.length}</div>
                        <div className="text-xs text-muted-foreground">Unique Trackers</div>
                      </div>
                    </div>
                  </div>

                  {/* Per-site results */}
                  <div className="space-y-3">
                    {results.map((result, i) => (
                      <ResultCard key={i} result={result} index={i} />
                    ))}
                  </div>
                </>
              )}

              {showHistory && (
                <div className="space-y-3">
                  {history.length > 0 ? (
                    history.map((result, i) => (
                      <ResultCard key={`hist-${i}`} result={result} index={i} />
                    ))
                  ) : (
                    <div className="text-center py-12 glass rounded-2xl">
                      <p className="text-muted-foreground">No scan history found.</p>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </section>
  );
};
