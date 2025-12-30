import { AlertTriangle, AlertCircle, Info, CheckCircle, Clock, Search, Radar, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { TimelineEvent, SeverityLevel } from '@/types/detector';

interface TimelineProps {
  events: TimelineEvent[];
}

const severityIcons: Record<SeverityLevel, typeof AlertTriangle> = {
  critical: AlertTriangle,
  warning: AlertCircle,
  info: Info,
  success: CheckCircle,
};

const typeIcons = {
  discovery: Search,
  endpoint: Radar,
  exfiltration: Shield,
  scan: Clock,
};

const severityColors: Record<SeverityLevel, string> = {
  critical: 'text-destructive bg-destructive/20 border-destructive/50',
  warning: 'text-warning bg-warning/20 border-warning/50',
  info: 'text-primary bg-primary/20 border-primary/50',
  success: 'text-success bg-success/20 border-success/50',
};

export function Timeline({ events }: TimelineProps) {
  return (
    <div className="glass rounded-xl h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <h3 className="font-semibold flex items-center gap-2">
          <Clock className="h-4 w-4 text-primary" />
          Activity Timeline
        </h3>
        <p className="text-xs text-muted-foreground mt-1">
          Chronological event log
        </p>
      </div>
      
      <ScrollArea className="flex-1">
        <div className="p-4">
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-4 top-0 bottom-0 w-px bg-gradient-to-b from-primary/50 via-border to-transparent" />
            
            {/* Events */}
            <div className="space-y-4">
              {events.map((event, index) => {
                const SeverityIcon = severityIcons[event.severity];
                const TypeIcon = typeIcons[event.type];
                
                const formattedTime = new Date(event.timestamp).toLocaleTimeString('en-US', {
                  hour: '2-digit',
                  minute: '2-digit',
                });

                return (
                  <div 
                    key={event.id} 
                    className="relative pl-10 animate-fade-in"
                    style={{ animationDelay: `${index * 75}ms` }}
                  >
                    {/* Node */}
                    <div className={cn(
                      'absolute left-1.5 w-5 h-5 rounded-full border-2 flex items-center justify-center',
                      severityColors[event.severity]
                    )}>
                      <div className={cn(
                        'w-2 h-2 rounded-full',
                        event.severity === 'critical' ? 'bg-destructive animate-pulse' :
                        event.severity === 'warning' ? 'bg-warning' :
                        event.severity === 'success' ? 'bg-success' : 'bg-primary'
                      )} />
                    </div>
                    
                    {/* Content */}
                    <div className="bg-secondary/30 rounded-lg p-3 border border-border/50 hover:border-primary/30 transition-colors">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            'p-1.5 rounded',
                            severityColors[event.severity]
                          )}>
                            <TypeIcon className="h-3 w-3" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">{event.title}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{event.description}</p>
                          </div>
                        </div>
                        <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0">
                          {formattedTime}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
