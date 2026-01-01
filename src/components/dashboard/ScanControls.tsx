import { Play, Square, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

interface ScanControlsProps {
  onStartScan: () => void;
  onStopScan: () => void;
  isScanning: boolean;
  domainCount: number;
  currentScanIndex: number;
}

export function ScanControls({
  onStartScan,
  onStopScan,
  isScanning,
  domainCount,
  currentScanIndex,
}: ScanControlsProps) {
  const progress = domainCount > 0 ? (currentScanIndex / domainCount) * 100 : 0;

  return (
    <Card className="glass border-border/50">
      <CardContent className="p-4 space-y-3">
        <div className="flex gap-2">
          {!isScanning ? (
            <Button 
              onClick={onStartScan} 
              disabled={domainCount === 0}
              className="flex-1 gap-2"
            >
              <Play className="h-4 w-4" />
              Start Scan
            </Button>
          ) : (
            <Button 
              onClick={onStopScan} 
              variant="destructive"
              className="flex-1 gap-2"
            >
              <Square className="h-4 w-4" />
              Stop Scan
            </Button>
          )}
        </div>

        {isScanning && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1">
                <Loader2 className="h-3 w-3 animate-spin" />
                Scanning...
              </span>
              <span className="font-mono text-primary">
                {currentScanIndex} / {domainCount}
              </span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>
        )}

        {!isScanning && domainCount === 0 && (
          <p className="text-xs text-muted-foreground text-center">
            Add domains above to start scanning
          </p>
        )}
      </CardContent>
    </Card>
  );
}
