import { Globe, ExternalLink, Activity, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Endpoint } from '@/types/detector';

interface EndpointListProps {
  endpoints: Endpoint[];
}

export function EndpointList({ endpoints }: EndpointListProps) {
  return (
    <div className="glass rounded-xl h-full flex flex-col">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div>
          <h3 className="font-semibold flex items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            Detected Endpoints
          </h3>
          <p className="text-xs text-muted-foreground mt-1">
            {endpoints.length} endpoints monitored
          </p>
        </div>
        <Badge variant="glow" className="font-mono">
          {endpoints.reduce((acc, e) => acc + e.dataFlowCount, 0)} flows
        </Badge>
      </div>
      
      <ScrollArea className="flex-1">
        <div className="p-3 space-y-2">
          {endpoints.map((endpoint, index) => (
            <EndpointCard key={endpoint.url} endpoint={endpoint} index={index} />
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function EndpointCard({ endpoint, index }: { endpoint: Endpoint; index: number }) {
  const urlParts = new URL(endpoint.url);
  const formattedTime = new Date(endpoint.lastChecked).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <div 
      className="p-3 rounded-lg bg-secondary/30 border border-border/50 hover:border-primary/30 transition-all duration-300 animate-fade-in"
      style={{ animationDelay: `${index * 50}ms` }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Badge 
              variant={endpoint.status === 200 ? 'glow-success' : 'glow-warning'} 
              className="text-[10px] font-mono px-1.5"
            >
              {endpoint.status}
            </Badge>
            <span className="text-xs text-muted-foreground font-mono">
              {urlParts.hostname}
            </span>
          </div>
          
          <p className="text-sm font-mono text-foreground mt-1 truncate">
            {urlParts.pathname}
          </p>
          
          <div className="flex items-center gap-3 mt-2">
            <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <Activity className="h-3 w-3 text-primary" />
              <span className="font-mono">{endpoint.dataFlowCount}</span>
              <span>flows</span>
            </div>
            <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <Clock className="h-3 w-3" />
              <span className="font-mono">{formattedTime}</span>
            </div>
          </div>
          
          <div className="flex flex-wrap gap-1 mt-2">
            {endpoint.parameters.slice(0, 4).map((param) => (
              <span 
                key={param}
                className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary rounded font-mono"
              >
                {param}
              </span>
            ))}
            {endpoint.parameters.length > 4 && (
              <span className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded font-mono">
                +{endpoint.parameters.length - 4}
              </span>
            )}
          </div>
        </div>
        
        <a 
          href={endpoint.url} 
          target="_blank" 
          rel="noopener noreferrer"
          className="p-2 rounded-lg hover:bg-primary/10 transition-colors"
        >
          <ExternalLink className="h-4 w-4 text-muted-foreground hover:text-primary" />
        </a>
      </div>
    </div>
  );
}
