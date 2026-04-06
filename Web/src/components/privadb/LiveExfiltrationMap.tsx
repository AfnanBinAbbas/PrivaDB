import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Zap, Shield, AlertCircle, Activity } from 'lucide-react';
import { getDomainCoords } from '../../utils/geoUtils';

/* ── Types ─────────────────────────────────────────────────────────── */
type MapEvent = {
  id: string;
  x: number;
  y: number;
  domain: string;
  sink: string;
  timestamp: number;
};

type FoxhoundEvent = {
  domain: string;
  sink: string;
  value: string;
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
  const [events, setEvents] = useState<MapEvent[]>([]);
  const [stats, setStats] = useState({ 
    web_breaches: 0, 
    platform_breaches: 0,
    active_threats: 0 
  });
  const dataRef = useRef<FoxhoundEvent[]>([]);
  
  // Consolidated Simulation Loop
  useEffect(() => {
    const interval = setInterval(() => {
      // Pick source: Website (80%) vs Other Platform (20%)
      const isWebsite = Math.random() < 0.8 && dataRef.current.length > 0;
      
      let domain = "shady-site.io";
      let type = "Web Exfiltration";
      let coords = { x: 400, y: 200 };

      if (isWebsite) {
        const rawEvent = dataRef.current[Math.floor(Math.random() * dataRef.current.length)];
        domain = rawEvent.domain;
        type = rawEvent.sink.includes('.') ? rawEvent.sink.split('.').pop()! : rawEvent.sink;
        coords = getDomainCoords(domain);
      } else {
        domain = ["Cloud Storage", "Mobile App", "IoT Device", "Legacy DB"][Math.floor(Math.random() * 4)];
        type = "System Breach";
        coords = { x: 200 + Math.random() * 500, y: 100 + Math.random() * 200 };
      }
      
      const newEvent: MapEvent = {
        id: Math.random().toString(36).substr(2, 9),
        x: coords.x + (Math.random() * 30 - 15),
        y: coords.y + (Math.random() * 30 - 15),
        domain: domain,
        sink: type,
        timestamp: Date.now()
      };
      
      setEvents(prev => [...prev.slice(-12), newEvent]);
      setStats(prev => ({
        ...prev,
        web_breaches: prev.web_breaches + (isWebsite ? 1 : 0),
        platform_breaches: prev.platform_breaches + (isWebsite ? 0 : 1),
        active_threats: prev.active_threats + 1
      }));
    }, 2000);
    
    return () => clearInterval(interval);
  }, []);

  // Fetch initial data to simulate live stream
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('http://localhost:8000/foxhound/results');
        if (!res.ok) return;
        const rawData = await res.json();
        dataRef.current = Object.values(rawData).flat() as FoxhoundEvent[];
      } catch (e) {
        console.error("Failed to fetch map data", e);
      }
    })();
  }, []);

  return (
    <div className="glass rounded-3xl p-6 border border-cyan-500/10 relative overflow-hidden h-[500px] bg-[#020d1a]">
      <div className="absolute top-6 left-6 z-10 space-y-1">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h2 className="text-xl font-bold tracking-tight text-white/90">Global Breach Intelligence</h2>
        </div>
        <p className="text-[10px] text-cyan-400/60 uppercase tracking-[0.2em] font-bold flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)]" />
          Live Monitoring Active
        </p>
      </div>

      <div className="absolute top-6 right-6 z-10 flex gap-6">
        <div className="text-right">
          <p className="text-[9px] text-muted-foreground uppercase font-black tracking-tighter">Web Exfiltration</p>
          <p className="text-2xl font-mono font-bold text-cyan-400">{stats.web_breaches.toLocaleString()}</p>
        </div>
        <div className="text-right border-l border-white/5 pl-6">
          <p className="text-[9px] text-muted-foreground uppercase font-black tracking-tighter text-magenta-400">Other Platforms</p>
          <p className="text-2xl font-mono font-bold text-teal-300">{stats.platform_breaches.toLocaleString()}</p>
        </div>
      </div>

      {/* World Map Container */}
      <div className="absolute inset-0 flex items-center justify-center select-none pointer-events-none">
        <svg viewBox="0 0 800 400" className="w-full h-full max-w-4xl opacity-80">
          <defs>
            <pattern id="dotPattern" x="0" y="0" width="4.5" height="4.5" patternUnits="userSpaceOnUse">
              <circle cx="1.5" cy="1.5" r="1.1" fill="currentColor" className="text-cyan-500/30" />
            </pattern>
            <clipPath id="worldMask">
              {WORLD_PATHS.map((path, i) => (
                <path key={i} d={path} />
              ))}
            </clipPath>
          </defs>
          
          {/* Dotted Background Limited by the World Mask */}
          <rect 
            x="0" y="0" width="800" height="400" 
            fill="url(#dotPattern)" 
            clipPath="url(#worldMask)"
          />

          {/* Outlines for depth */}
          {WORLD_PATHS.map((path, i) => (
            <path 
              key={`outline-${i}`}
              d={path} 
              fill="none"
              className="stroke-cyan-500/10 stroke-[0.5]"
            />
          ))}
          
          {/* Grid lines (very subtle) */}
          <g opacity="0.02">
             {[...Array(20)].map((_, i) => (<line key={i} x1={i*40} y1="0" x2={i*40} y2="400" stroke="#fff" />))}
             {[...Array(10)].map((_, i) => (<line key={i} x1="0" y1={i*40} x2="800" y2={i*40} stroke="#fff" />))}
          </g>
        </svg>
      </div>

      {/* Event Visualization Layer */}
      <svg viewBox="0 0 800 400" className="absolute inset-0 w-full h-full max-w-4xl m-auto z-0 pointer-events-none">
        <AnimatePresence>
          {events.map(event => (
            <React.Fragment key={event.id}>
              {/* Ripple effect */}
              <motion.circle
                cx={event.x}
                cy={event.y}
                initial={{ r: 0, opacity: 0.8 }}
                animate={{ r: 35, opacity: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 1.5, ease: "easeOut" }}
                className={event.sink.includes('Web') ? "fill-cyan-500/30 stroke-cyan-400/50" : "fill-teal-400/30 stroke-teal-300/50"}
              />
              
              {/* Point */}
              <motion.circle
                cx={event.x}
                cy={event.y}
                initial={{ r: 0, scale: 0 }}
                animate={{ r: 2.5, scale: 1 }}
                className={event.sink.includes('Web') ? "fill-cyan-400 shadow-[0_0_10px_#22d3ee]" : "fill-teal-300 shadow-[0_0_10px_#5eead4]"}
              />
              
              {/* Target Label */}
              <motion.g
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
              >
                <text
                  x={event.x + 8}
                  y={event.y - 4}
                  className="fill-white/80 text-[7px] font-mono font-bold uppercase tracking-wider"
                >
                  {event.domain}
                </text>
                <text
                  x={event.x + 8}
                  y={event.y + 6}
                  className="fill-cyan-400/60 text-[5px] font-mono uppercase"
                >
                  {event.sink}
                </text>
              </motion.g>
            </React.Fragment>
          ))}
        </AnimatePresence>
      </svg>

      {/* Comparison Legend */}
      <div className="absolute bottom-6 right-6 z-10 flex gap-4 items-center scale-75 origin-bottom-right opacity-60">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyan-400" />
          <span className="text-[10px] text-white/60 font-mono uppercase">Web Protocol</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-teal-300" />
          <span className="text-[10px] text-white/60 font-mono uppercase">Internal Platforms</span>
        </div>
      </div>

      {/* Bottom Log */}
      <div className="absolute bottom-6 left-6 z-10 w-fit max-w-[300px]">
        <div className="bg-black/40 backdrop-blur-md rounded-lg p-3 border border-white/5 font-mono text-[10px] space-y-1 shadow-2xl">
          <p className="text-white/40 mb-2 border-b border-white/5 pb-1 flex justify-between">
            <span>EVENT_LOG</span>
            <span className="text-[8px]">{new Date().toLocaleTimeString()}</span>
          </p>
          <AnimatePresence mode="popLayout">
            {events.slice(-3).reverse().map((e, idx) => (
              <motion.div 
                key={e.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex items-center gap-2 overflow-hidden"
              >
                <span className="text-red-500 shrink-0">[{idx === 0 ? "NEW" : "LOG"}]</span>
                <span className="truncate text-white/80">{e.domain} → {e.sink}</span>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>

      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-primary/5 blur-[120px] pointer-events-none" />
    </div>
  );
};
