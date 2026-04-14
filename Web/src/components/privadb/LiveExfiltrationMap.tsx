import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Zap, Shield, AlertCircle, Activity, Database, ArrowRight, ExternalLink } from 'lucide-react';
import { getDomainCoords } from '../../utils/geoUtils';

/* ── Types ─────────────────────────────────────────────────────────── */
type DataFlow = {
  id: string;
  source: string;
  target: string;
  value: string;
  database: string;
  key: string;
  isExfiltrated: boolean;
  tracker: string;
  engine: string;
  timestamp: number;
};

type FlowNode = {
  id: string;
  label: string;
  x: number;
  y: number;
  type: 'database' | 'tracker' | 'sink';
  color: string;
};

// High-fidelity World Map Paths (Simplified yet accurate)
const WORLD_PATHS = [
  "M120,50 L145,55 L165,65 L180,85 L185,110 L175,135 L160,165 L140,195 L125,230 L105,270 L85,310 L70,345 L50,375 L30,350 L20,310 L15,260 L25,210 L45,160 L75,110 L100,70 Z",
  "M190,200 L210,195 L230,205 L245,220 L255,240 L260,265 L250,290 L235,315 L215,340 L195,365 L180,385 L165,365 L155,340 L150,315 L155,290 L165,265 L175,240 L185,220 Z",
  "M380,40 L400,35 L420,40 L440,35 L460,45 L475,65 L485,85 L490,110 L480,135 L465,160 L445,185 L425,210 L410,235 L390,260 L370,285 L355,310 L340,285 L330,260 L325,235 L330,210 L335,185 L340,160 L335,135 L345,110 L355,85 L365,65 Z",
  "M380,35 L405,30 L430,35 L455,25 L480,30 L505,25 L530,35 L555,45 L580,35 L605,45 L630,55 L655,65 L680,85 L700,110 L710,140 L705,170 L690,200 L670,230 L645,255 L615,275 L580,285 L545,295 L510,300 L475,295 L440,285 L415,270 L395,250 L380,225 L370,200 L365,170 L370,140 L375,110 L370,85 L375,60 Z",
  "M650,280 L675,275 L700,285 L720,305 L725,330 L715,355 L695,375 L670,385 L645,375 L625,355 L620,330 L630,305 Z",
  "M150,55 L165,50 L175,60 L165,70 L155,70 Z",
  "M710,125 L725,120 L735,130 L725,145 L715,145 Z",
  "M650,225 L675,220 L695,235 L685,250 L660,255 Z"
];

export const LiveExfiltrationMap: React.FC = () => {
  const [flows, setFlows] = useState<DataFlow[]>([]);
  const [nodes, setNodes] = useState<FlowNode[]>([]);
  const [selectedFlow, setSelectedFlow] = useState<DataFlow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    totalFlows: 0,
    exfiltratedFlows: 0,
    uniqueTrackers: 0,
    uniqueDatabases: 0
  });

  // Fetch scan results and build data flow architecture
  useEffect(() => {
    const fetchData = async () => {
      try {
        setError(null);
        const res = await fetch('http://localhost:8000/scan/results', {
          signal: AbortSignal.timeout(15000)
        });
        
        if (!res.ok) {
          const errorData = await res.json().catch(() => ({}));
          throw new Error(errorData.detail || `Failed to fetch results: ${res.statusText}`);
        }
        
        const data = await res.json();
        if (!data || (typeof data !== 'object')) {
          throw new Error('Invalid response format');
        }

        const allFlows: DataFlow[] = [];
        const nodeMap = new Map<string, FlowNode>();
        const trackers = new Set<string>();
        const databases = new Set<string>();

        // Process Chrome and Foxhound results
        for (const [engine, domains] of Object.entries(data)) {
          if (engine === 'summary') continue;

          for (const [domain, results] of Object.entries(domains as Record<string, any>)) {
            for (const result of results as any[]) {
              if (result.is_exfiltrated) {
                const flowId = `${engine}-${domain}-${result.key}-${Date.now()}`;

                const flow: DataFlow = {
                  id: flowId,
                  source: domain,
                  target: result.responsible_tracker,
                  value: result.idb_value,
                  database: result.database,
                  key: result.key,
                  isExfiltrated: result.is_exfiltrated,
                  tracker: result.responsible_tracker,
                  engine: engine,
                  timestamp: Date.now()
                };

                allFlows.push(flow);
                trackers.add(result.responsible_tracker);
                databases.add(result.database);

                // Create nodes
                const dbNodeId = `db-${result.database}`;
                if (!nodeMap.has(dbNodeId)) {
                  const coords = getDomainCoords(domain);
                  nodeMap.set(dbNodeId, {
                    id: dbNodeId,
                    label: result.database,
                    x: coords.x + Math.random() * 100 - 50,
                    y: coords.y + Math.random() * 100 - 50,
                    type: 'database',
                    color: '#3b82f6'
                  });
                }

                const trackerNodeId = `tracker-${result.responsible_tracker}`;
                if (!nodeMap.has(trackerNodeId)) {
                  const coords = getDomainCoords(result.responsible_tracker);
                  nodeMap.set(trackerNodeId, {
                    id: trackerNodeId,
                    label: result.responsible_tracker,
                    x: coords.x + Math.random() * 100 - 50,
                    y: coords.y + Math.random() * 100 - 50,
                    type: 'tracker',
                    color: '#ef4444'
                  });
                }
              }
            }
          }
        }

        setFlows(allFlows.slice(-20)); // Keep last 20 flows
        setNodes(Array.from(nodeMap.values()));

        setStats({
          totalFlows: allFlows.length,
          exfiltratedFlows: allFlows.filter(f => f.isExfiltrated).length,
          uniqueTrackers: trackers.size,
          uniqueDatabases: databases.size
        });
        
        setLoading(false);
      } catch (e) {
        const errorMsg = e instanceof Error ? e.message : 'Unknown error occurred';
        console.error('Failed to fetch flow data:', errorMsg);
        setError(errorMsg);
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const renderFlow = (flow: DataFlow, index: number) => {
    const sourceNode = nodes.find(n => n.label === flow.source);
    const targetNode = nodes.find(n => n.label === flow.target);

    if (!sourceNode || !targetNode) return null;

    const midX = (sourceNode.x + targetNode.x) / 2;
    const midY = (sourceNode.y + targetNode.y) / 2;
    const flowColor = flow.isExfiltrated ? "#00ffff" : "#00ff88";
    const glowColor = flow.isExfiltrated ? "rgba(0, 255, 255, 0.5)" : "rgba(0, 255, 136, 0.5)";

    return (
      <g key={flow.id}>
        {/* Glow background line */}
        <line
          x1={sourceNode.x}
          y1={sourceNode.y}
          x2={targetNode.x}
          y2={targetNode.y}
          stroke={glowColor}
          strokeWidth="8"
          opacity="0.3"
          style={{ filter: 'blur(4px)' }}
        />

        {/* Main flow line */}
        <motion.line
          x1={sourceNode.x}
          y1={sourceNode.y}
          x2={targetNode.x}
          y2={targetNode.y}
          stroke={flowColor}
          strokeWidth="2"
          style={{
            filter: `drop-shadow(0 0 4px ${flowColor})`,
            strokeDasharray: '10,10'
          }}
          animate={{
            strokeDashoffset: [0, -20]
          }}
          transition={{
            duration: 1,
            repeat: Infinity,
            ease: 'linear'
          }}
        />

        {/* Animated data particle */}
        <motion.circle
          r="4"
          fill={flowColor}
          cx={sourceNode.x}
          cy={sourceNode.y}
          style={{
            filter: `drop-shadow(0 0 6px ${flowColor})`,
            boxShadow: `0 0 10px ${flowColor}`
          }}
          animate={{
            cx: [sourceNode.x, targetNode.x],
            cy: [sourceNode.y, targetNode.y]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'linear',
            delay: index * 0.2
          }}
        />

        {/* Direction arrow with glow */}
        <motion.polygon
          points="0,-3 6,0 0,3"
          fill={flowColor}
          style={{
            filter: `drop-shadow(0 0 4px ${flowColor})`
          }}
          animate={{
            opacity: [0.6, 1, 0.6]
          }}
          transition={{
            duration: 0.8,
            repeat: Infinity
          }}
          transform={`translate(${midX}, ${midY}) rotate(${Math.atan2(targetNode.y - sourceNode.y, targetNode.x - sourceNode.x) * 180 / Math.PI})`}
        />
      </g>
    );
  };

  return (
    <div className="glass rounded-3xl p-4 sm:p-6 border border-cyan-500/10 relative overflow-hidden min-h-[400px] h-[50vh] md:h-[600px] bg-[#020d1a]">
      {/* Loading State */}
      {loading && !error && (
        <motion.div 
          className="absolute inset-0 flex items-center justify-center bg-cyan-500/10 backdrop-blur-sm z-10 neon-glow-cyan"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="text-center">
            <motion.div 
              animate={{ rotate: 360 }}
              transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
              className="rounded-full h-16 w-16 border-2 border-cyan-500/30 border-t-cyan-400 mx-auto mb-4 shadow-[0_0_30px_rgba(0,255,255,0.5)]"
            />
            <p className="text-cyan-400 font-bold cyber-flicker">Mapping data flows...</p>
            <p className="text-xs text-cyan-400/60 mt-2">Analyzing exfiltration patterns</p>
          </div>
        </motion.div>
      )}
      
      {/* Error State */}
      {error && (
        <motion.div 
          className="absolute inset-0 flex items-center justify-center bg-red-500/10 backdrop-blur-sm z-10 neon-glow-pink"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <motion.div 
            className="text-center bg-background/90 backdrop-blur-sm rounded-xl p-6 border border-red-500/30"
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 200 }}
          >
            <motion.div animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 2, repeat: Infinity }}>
              <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4 drop-shadow-lg" />
            </motion.div>
            <p className="text-red-400 font-bold">Failed to Load Flows</p>
            <p className="text-xs text-red-400/60 mt-2 max-w-xs">{error}</p>
            <motion.button
              className="mt-4 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded-lg text-sm neon-glow-pink"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              Try Again
            </motion.button>
          </motion.div>
        </motion.div>
      )}
      
      {/* Background World Map */}
      <svg className="absolute inset-0 w-full h-full opacity-20">
        <defs>
          {/* Removed SVG linearGradient for ocean background */}
        </defs>
        {WORLD_PATHS.map((path, i) => (
          <path key={i} d={path} fill="url(#ocean)" stroke="#334155" strokeWidth="0.5" />
        ))}
      </svg>

      {/* Header */}
      <div className="relative z-10 flex items-center justify-between mb-4">
        <div>
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="text-cyan-400" />
            Data Flow Architecture
          </h3>
          <p className="text-sm text-gray-400">Real-time exfiltration tracking</p>
        </div>
        <div className="flex gap-4">
          <div className="text-center">
            <div className="text-lg font-bold text-cyan-400">{stats.totalFlows}</div>
            <div className="text-xs text-gray-400">Total Flows</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-red-400">{stats.exfiltratedFlows}</div>
            <div className="text-xs text-gray-400">Exfiltrated</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-purple-400">{stats.uniqueTrackers}</div>
            <div className="text-xs text-gray-400">Trackers</div>
          </div>
        </div>
      </div>

      {/* Flow Visualization */}
      <svg className="absolute inset-0 w-full h-full" style={{ top: '80px' }}>
        {/* Render flows */}
        {flows.map((flow, index) => renderFlow(flow, index))}

        {/* Render nodes */}
        {nodes.map((node) => (
          <g key={node.id}>
            <circle
              cx={node.x}
              cy={node.y}
              r="8"
              fill={node.color}
            />
            <text
              x={node.x}
              y={node.y - 15}
              textAnchor="middle"
              className="text-xs fill-white font-medium"
            >
              {node.label.length > 15 ? node.label.substring(0, 15) + '...' : node.label}
            </text>
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-black/50 rounded-lg p-3">
        <div className="text-xs font-medium text-white mb-2">Legend</div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-400 rounded"></div>
            <span className="text-xs text-gray-300">Database</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-400 rounded"></div>
            <span className="text-xs text-gray-300">Tracker</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-0.5 bg-red-400"></div>
            <span className="text-xs text-gray-300">Exfiltration</span>
          </div>
        </div>
      </div>
    </div>
  );
};
