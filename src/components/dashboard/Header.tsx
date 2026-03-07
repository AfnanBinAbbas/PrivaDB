import { Shield, Settings, Download, Play, Pause, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useState } from 'react';
import { toast } from 'sonner';
import { scannerApi } from '@/lib/api/scanner';

export function Header() {
  const [isScanning, setIsScanning] = useState(true);

  const handleExportReport = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/generate-report?domain=youtube.com');
      const report = await response.json();

      if (report.error) {
        toast.error(report.error);
        return;
      }

      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `data_whisperer_report_${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      toast.success('Report exported successfully!');
    } catch (error) {
      toast.error('Failed to export report');
      console.error(error);
    }
  };

  const handleFullTrackingAnalysis = async () => {
    try {
      toast.info('Starting full tracking analysis (3 scenarios, ~2 minutes)...');
      const result = await scannerApi.scanWithTracking('youtube.com');

      if (result.success && result.tracking_analysis) {
        const analysis = result.tracking_analysis;
        const summary = analysis.summary || {};
        const tracking = analysis.tracking_detection || {};

        toast.success('Tracking analysis complete!', {
          description: `Found ${summary.total_persistent_identifiers || 0} persistent IDs, ${tracking.total_tracking_patterns || 0} tracking patterns`
        });

        console.log('📊 FULL TRACKING ANALYSIS:', result.tracking_analysis);
        console.log('🔍 TRACKING CATEGORIES:', tracking.patterns_found?.slice(0, 10));
      } else {
        toast.error(result.error || 'Analysis failed');
      }
    } catch (error) {
      toast.error('Failed to run tracking analysis');
      console.error(error);
    }
  };

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

            <Button
              variant="default"
              size="sm"
              className="gap-2 bg-primary"
              onClick={handleFullTrackingAnalysis}
            >
              <Shield className="h-4 w-4" />
              Full Tracking Analysis
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={handleExportReport}
            >
              <Download className="h-4 w-4" />
              Export Report
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