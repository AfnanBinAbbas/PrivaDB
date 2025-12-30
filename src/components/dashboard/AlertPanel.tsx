import { AlertTriangle, AlertCircle, Info, CheckCircle, ExternalLink, Clock, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ExfiltrationEvent, SeverityLevel } from '@/types/detector';

interface AlertPanelProps {
  events: ExfiltrationEvent[];
}

const severityConfig: Record<SeverityLevel, {
  icon: typeof AlertTriangle;
  badgeVariant: 'glow-destructive' | 'glow-warning' | 'glow' | 'glow-success';
  borderClass: string;
  bgClass: string;
}> = {
  critical: {
    icon: AlertTriangle,
    badgeVariant: 'glow-destructive',
    borderClass: 'border-l-destructive',
    bgClass: 'bg-destructive/5',
  },
  warning: {
    icon: AlertCircle,
    badgeVariant: 'glow-warning',
    borderClass: 'border-l-warning',
    bgClass: 'bg-warning/5',
  },
  info: {
    icon: Info,
    badgeVariant: 'glow',
    borderClass: 'border-l-primary',
    bgClass: 'bg-primary/5',
  },
  success: {
    icon: CheckCircle,
    badgeVariant: 'glow-success',
    borderClass: 'border-l-success',
    bgClass: 'bg-success/5',
  },
};

export function AlertPanel({ events }: AlertPanelProps) {
  const criticalCount = events.filter(e => e.severity === 'critical').length;
  const warningCount = events.filter(e => e.severity === 'warning').length;

  return (
    <div className="glass rounded-xl h-full flex flex-col">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div>
          <h3 className="font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-destructive" />
            Exfiltration Alerts
          </h3>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time data leak detection
          </p>
        </div>
        <div className="flex gap-2">
          {criticalCount > 0 && (
            <Badge variant="glow-destructive" className="font-mono">
              {criticalCount} critical
            </Badge>
          )}
          {warningCount > 0 && (
            <Badge variant="glow-warning" className="font-mono">
              {warningCount} warning
            </Badge>
          )}
        </div>
      </div>
      
      <ScrollArea className="flex-1">
        <div className="p-3 space-y-3">
          {events.map((event, index) => (
            <AlertCard key={event.id} event={event} index={index} />
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function AlertCard({ event, index }: { event: ExfiltrationEvent; index: number }) {
  const config = severityConfig[event.severity];
  const Icon = config.icon;
  
  const formattedTime = new Date(event.timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div 
      className={cn(
        'rounded-lg border-l-4 p-4 transition-all duration-300 hover:scale-[1.01] animate-slide-in-right',
        config.borderClass,
        config.bgClass,
        'border border-border/50'
      )}
      style={{ animationDelay: `${index * 50}ms` }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className={cn(
            'p-2 rounded-lg',
            event.severity === 'critical' ? 'bg-destructive/20' : 
            event.severity === 'warning' ? 'bg-warning/20' : 'bg-primary/20'
          )}>
            <Icon className={cn(
              'h-4 w-4',
              event.severity === 'critical' ? 'text-destructive' : 
              event.severity === 'warning' ? 'text-warning' : 'text-primary'
            )} />
          </div>
          
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant={config.badgeVariant} className="text-[10px] uppercase">
                {event.severity}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                {event.method.toUpperCase()}
              </Badge>
              <span className="text-[10px] text-muted-foreground font-mono">
                {Math.round(event.confidence * 100)}% confidence
              </span>
            </div>
            
            <p className="text-sm font-medium">
              Data from <code className="text-primary bg-primary/10 px-1 rounded text-xs">{event.sourceStore}</code>
            </p>
            
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ExternalLink className="h-3 w-3" />
              <span className="font-mono truncate">{event.destinationDomain}</span>
            </div>
            
            <div className="mt-2 p-2 rounded bg-background/50 border border-border/50">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Data Preview</p>
              <p className="text-xs font-mono text-foreground mt-1 truncate">
                {event.dataPreview}
              </p>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-1 text-[10px] text-muted-foreground flex-shrink-0">
          <Clock className="h-3 w-3" />
          <span className="font-mono">{formattedTime}</span>
        </div>
      </div>
    </div>
  );
}
