import { Shield, Settings, Download, Play, Pause, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useState } from 'react';

export function Header() {
  const [isScanning, setIsScanning] = useState(true);

  return (
    <header className="glass border-b border-border sticky top-0 z-50">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="p-2 rounded-xl bg-primary/20 glow-primary">
                  <Shield className="h-6 w-6 text-primary" />
                </div>
                {isScanning && (
                  <span className="absolute -top-1 -right-1 w-3 h-3 bg-success rounded-full animate-pulse" />
                )}
              </div>
              <div>
                <h1 className="text-xl font-bold text-gradient">
                  IndexedDB Exfiltration Detector
                </h1>
                <p className="text-xs text-muted-foreground">
                  Real-time data leak monitoring & visualization
                </p>
              </div>
            </div>
            
            <Badge 
              variant={isScanning ? 'glow-success' : 'outline'} 
              className="font-mono"
            >
              {isScanning ? 'MONITORING' : 'PAUSED'}
            </Badge>
          </div>
          
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsScanning(!isScanning)}
              className="gap-2"
            >
              {isScanning ? (
                <>
                  <Pause className="h-4 w-4" />
                  Pause
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Resume
                </>
              )}
            </Button>
            
            <Button variant="outline" size="sm" className="gap-2">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
            
            <Button variant="outline" size="sm" className="gap-2">
              <Download className="h-4 w-4" />
              Export
            </Button>
            
            <Button variant="ghost" size="icon">
              <Settings className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
