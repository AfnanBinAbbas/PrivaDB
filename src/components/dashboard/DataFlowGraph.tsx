import { useEffect, useRef, useState } from 'react';
import { Database, FolderOpen, Globe, Server, Zap } from 'lucide-react';
import { cn } from '@/lib/utils';
import { DataFlowNode, DataFlowEdge } from '@/types/detector';

interface DataFlowGraphProps {
  nodes: DataFlowNode[];
  edges: DataFlowEdge[];
}

const nodeConfig = {
  database: { icon: Database, color: 'text-primary', bg: 'bg-primary/20', border: 'border-primary/50' },
  store: { icon: FolderOpen, color: 'text-warning', bg: 'bg-warning/20', border: 'border-warning/50' },
  endpoint: { icon: Server, color: 'text-success', bg: 'bg-success/20', border: 'border-success/50' },
  external: { icon: Globe, color: 'text-destructive', bg: 'bg-destructive/20', border: 'border-destructive/50' },
};

export function DataFlowGraph({ nodes, edges }: DataFlowGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });

  useEffect(() => {
    const updateDimensions = () => {
      if (svgRef.current?.parentElement) {
        const { width, height } = svgRef.current.parentElement.getBoundingClientRect();
        setDimensions({ width: Math.max(width - 32, 600), height: Math.max(height - 80, 300) });
      }
    };
    
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  // Scale node positions to fit container
  const scaledNodes = nodes.map(node => ({
    ...node,
    x: (node.x / 700) * (dimensions.width - 100) + 50,
    y: (node.y / 400) * (dimensions.height - 60) + 30,
  }));

  const getNodeById = (id: string) => scaledNodes.find(n => n.id === id);

  const connectedToHovered = hoveredNode
    ? new Set(edges.filter(e => e.source === hoveredNode || e.target === hoveredNode).flatMap(e => [e.source, e.target]))
    : null;

  return (
    <div className="glass rounded-xl h-full flex flex-col">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div>
          <h3 className="font-semibold flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Data Flow Visualization
          </h3>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time data movement tracking
          </p>
        </div>
        <div className="flex gap-4">
          {Object.entries(nodeConfig).map(([type, config]) => {
            const Icon = config.icon;
            return (
              <div key={type} className="flex items-center gap-1.5 text-xs">
                <Icon className={cn('h-3 w-3', config.color)} />
                <span className="text-muted-foreground capitalize">{type}</span>
              </div>
            );
          })}
        </div>
      </div>
      
      <div className="flex-1 relative p-4 overflow-hidden">
        <svg
          ref={svgRef}
          width={dimensions.width}
          height={dimensions.height}
          className="absolute inset-0"
        >
          <defs>
            <marker
              id="arrowhead"
              markerWidth="10"
              markerHeight="7"
              refX="9"
              refY="3.5"
              orient="auto"
            >
              <polygon
                points="0 0, 10 3.5, 0 7"
                fill="hsl(var(--primary))"
                opacity="0.6"
              />
            </marker>
            <marker
              id="arrowhead-active"
              markerWidth="10"
              markerHeight="7"
              refX="9"
              refY="3.5"
              orient="auto"
            >
              <polygon
                points="0 0, 10 3.5, 0 7"
                fill="hsl(var(--primary))"
              />
            </marker>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>

          {/* Edges */}
          {edges.map((edge) => {
            const source = getNodeById(edge.source);
            const target = getNodeById(edge.target);
            if (!source || !target) return null;

            const isHighlighted = connectedToHovered?.has(edge.source) && connectedToHovered?.has(edge.target);
            const opacity = hoveredNode ? (isHighlighted ? 1 : 0.15) : 0.6;

            // Calculate control point for curved line
            const midX = (source.x + target.x) / 2;
            const midY = (source.y + target.y) / 2;
            const dx = target.x - source.x;
            const dy = target.y - source.y;
            const curvature = 0.2;
            const controlX = midX - dy * curvature;
            const controlY = midY + dx * curvature;

            return (
              <g key={edge.id}>
                <path
                  d={`M ${source.x} ${source.y} Q ${controlX} ${controlY} ${target.x} ${target.y}`}
                  fill="none"
                  stroke="hsl(var(--primary))"
                  strokeWidth={Math.min(Math.max(edge.frequency / 50, 1), 4)}
                  strokeOpacity={opacity}
                  markerEnd={isHighlighted ? "url(#arrowhead-active)" : "url(#arrowhead)"}
                  className="transition-all duration-300"
                  filter={isHighlighted ? "url(#glow)" : undefined}
                  strokeDasharray={isHighlighted ? "none" : "4 4"}
                >
                  {isHighlighted && (
                    <animate
                      attributeName="stroke-dashoffset"
                      values="100;0"
                      dur="2s"
                      repeatCount="indefinite"
                    />
                  )}
                </path>
              </g>
            );
          })}

          {/* Nodes */}
          {scaledNodes.map((node) => {
            const config = nodeConfig[node.type];
            const Icon = config.icon;
            const isHighlighted = hoveredNode === node.id || connectedToHovered?.has(node.id);
            const opacity = hoveredNode ? (isHighlighted ? 1 : 0.3) : 1;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer transition-all duration-300"
                style={{ opacity }}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                <circle
                  r={isHighlighted ? 28 : 24}
                  className={cn(
                    'fill-card stroke-2 transition-all duration-300',
                    isHighlighted ? 'stroke-primary' : 'stroke-border'
                  )}
                  filter={isHighlighted ? "url(#glow)" : undefined}
                />
                <foreignObject x="-12" y="-12" width="24" height="24">
                  <div className="flex items-center justify-center h-full">
                    <Icon className={cn('h-5 w-5', config.color)} />
                  </div>
                </foreignObject>
                <text
                  y={38}
                  textAnchor="middle"
                  className="fill-muted-foreground text-[10px] font-mono"
                >
                  {node.label.length > 15 ? node.label.substring(0, 15) + '...' : node.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
