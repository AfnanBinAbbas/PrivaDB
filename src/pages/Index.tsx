import { useState, useCallback } from 'react';
import { Database, Activity, AlertTriangle, Radar, Shield, TrendingUp } from 'lucide-react';
import { Header } from '@/components/dashboard/Header';
import { StatCard } from '@/components/dashboard/StatCard';
import { DatabaseExplorer } from '@/components/dashboard/DatabaseExplorer';
import { AlertPanel } from '@/components/dashboard/AlertPanel';
import { DataFlowGraph } from '@/components/dashboard/DataFlowGraph';
import { Timeline } from '@/components/dashboard/Timeline';
import { EndpointList } from '@/components/dashboard/EndpointList';
import { DomainInput } from '@/components/dashboard/DomainInput';
import { ScanControls } from '@/components/dashboard/ScanControls';
import { scannerApi, ScanResult } from '@/lib/api/scanner';
import { toast } from 'sonner';
import { v4 as uuidv4 } from "uuid";
import type { 
  DomainScan, 
  Endpoint, 
  DataFlowNode, 
  DataFlowEdge, 
  TimelineEvent, 
  Stats,
  ExfiltrationEvent 
} from '@/types/detector';

const Index = () => {
  const [domains, setDomains] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanIndex, setCurrentScanIndex] = useState(0);
  
  // Dashboard data state
  const [scans, setScans] = useState<DomainScan[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [nodes, setNodes] = useState<DataFlowNode[]>([]);
  const [edges, setEdges] = useState<DataFlowEdge[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [exfiltrationEvents] = useState<ExfiltrationEvent[]>([]);
  
  const [stats, setStats] = useState<Stats>({
    totalDatabases: 0,
    totalRecords: 0,
    suspectedLeaks: 0,
    endpointsScanned: 0,
    exfiltrationEvents: 0,
    riskScore: 0,
  });

  const updateStats = useCallback((newScans: DomainScan[], newEndpoints: Endpoint[]) => {
    const totalDatabases = newScans.reduce((sum, s) => sum + s.databases.length, 0);
    const totalRecords = newScans.reduce(
      (sum, s) => sum + s.databases.reduce(
        (dbSum, db) => dbSum + db.stores.reduce((storeSum, store) => storeSum + store.recordCount, 0),
        0
      ),
      0
    );
    const suspectedLeaks = newScans.reduce(
      (sum, s) => sum + s.databases.reduce(
        (dbSum, db) => dbSum + db.stores.reduce((storeSum, store) => storeSum + store.suspectedUserData.length, 0),
        0
      ),
      0
    );

    setStats({
      totalDatabases,
      totalRecords,
      suspectedLeaks,
      endpointsScanned: newEndpoints.length,
      exfiltrationEvents: 0,
      riskScore: Math.min(100, Math.round((suspectedLeaks / Math.max(1, totalRecords)) * 100 * 10)),
    });
  }, []);

  const handleStartScan = useCallback(async () => {
    if (domains.length === 0) {
      toast.error('Add at least one domain to scan');
      return;
    }

    setIsScanning(true);
    setCurrentScanIndex(0);

    const allScans: DomainScan[] = [];
    const allEndpoints: Endpoint[] = [];
    const allNodes: DataFlowNode[] = [];
    const allEdges: DataFlowEdge[] = [];
    const allEvents: TimelineEvent[] = [];

    for (let i = 0; i < domains.length; i++) {
      const domain = domains[i];
      setCurrentScanIndex(i + 1);
      
      // Add scanning placeholder
      const scanningEntry: DomainScan = {
        domain,
        timestamp: new Date().toISOString(),
        status: 'scanning',
        databases: [],
      };
      setScans([...allScans, scanningEntry]);
      
      toast.info(`Scanning ${domain}...`);

      const response = await scannerApi.scanDomain(domain);
      
      if (response.success && response.data) {
        const result = response.data;
        const domainScan = scannerApi.convertToDomainScan(result);
        const domainEndpoints = scannerApi.convertToEndpoints(result);
        const domainNodes = scannerApi.convertToDataFlowNodes(result);
        const domainEdges = scannerApi.convertToDataFlowEdges(domainNodes);
        const timelineEvent = scannerApi.createTimelineEvent(result);

        allScans.push(domainScan);
        allEndpoints.push(...domainEndpoints);
        allNodes.push(...domainNodes);
        allEdges.push(...domainEdges);
        allEvents.push(timelineEvent);

        toast.success(`Completed scan of ${domain}`);
      } else {
        const errorScan: DomainScan = {
          domain,
          timestamp: new Date().toISOString(),
          status: 'error',
          databases: [],
        };
        allScans.push(errorScan);
        
        allEvents.push({
          id: uuidv4(),
          timestamp: new Date().toISOString(),
          type: 'scan',
          title: `Failed to scan ${domain}`,
          description: response.error || 'Unknown error',
          severity: 'critical',
        });
        
        toast.error(`Failed to scan ${domain}: ${response.error}`);
      }

      // Update state after each scan
      setScans([...allScans]);
      setEndpoints([...allEndpoints]);
      setNodes([...allNodes]);
      setEdges([...allEdges]);
      setTimelineEvents([...allEvents]);
      updateStats(allScans, allEndpoints);

      // Small delay between scans
      if (i < domains.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    setIsScanning(false);
    toast.success(`Scan complete! Analyzed ${domains.length} domains`);
  }, [domains, updateStats]);

  const handleStopScan = useCallback(() => {
    setIsScanning(false);
    toast.info('Scan stopped');
  }, []);

  return (
    <div className="min-h-screen bg-background grid-pattern">
      <Header />
      
      <main className="p-6 space-y-6">
        {/* Stats Row */}
        <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard
            title="Databases"
            value={stats.totalDatabases}
            icon={Database}
            variant="primary"
          />
          <StatCard
            title="Records Analyzed"
            value={stats.totalRecords.toLocaleString()}
            icon={Activity}
          />
          <StatCard
            title="Suspected Leaks"
            value={stats.suspectedLeaks}
            icon={AlertTriangle}
            variant="warning"
            trend={stats.suspectedLeaks > 0 ? { value: stats.suspectedLeaks, direction: 'up' } : undefined}
          />
          <StatCard
            title="Endpoints Scanned"
            value={stats.endpointsScanned}
            icon={Radar}
            variant="success"
          />
          <StatCard
            title="Exfiltration Events"
            value={stats.exfiltrationEvents}
            icon={Shield}
            variant="destructive"
          />
          <StatCard
            title="Risk Score"
            value={`${stats.riskScore}%`}
            subtitle={stats.riskScore > 50 ? "High Risk" : stats.riskScore > 20 ? "Medium Risk" : "Low Risk"}
            icon={TrendingUp}
            variant={stats.riskScore > 50 ? "warning" : stats.riskScore > 20 ? "primary" : "success"}
          />
        </section>

        {/* Main Grid */}
        <div className="grid grid-cols-12 gap-6">
          {/* Left Column - Domain Input & Database Explorer */}
          <section className="col-span-12 lg:col-span-3 space-y-4">
            <DomainInput onDomainsChange={setDomains} />
            <ScanControls 
              onStartScan={handleStartScan}
              onStopScan={handleStopScan}
              isScanning={isScanning}
              domainCount={domains.length}
              currentScanIndex={currentScanIndex}
            />
            <div className="h-[350px]">
              <DatabaseExplorer scans={scans} />
            </div>
          </section>

          {/* Center Column - Flow Graph & Alerts */}
          <section className="col-span-12 lg:col-span-6 space-y-6">
            <div className="h-[350px]">
              <DataFlowGraph nodes={nodes} edges={edges} />
            </div>
            <div className="h-[230px]">
              <AlertPanel events={exfiltrationEvents} />
            </div>
          </section>

          {/* Right Column - Timeline */}
          <section className="col-span-12 lg:col-span-3 h-[600px]">
            <Timeline events={timelineEvents} />
          </section>
        </div>

        {/* Bottom Row - Endpoints */}
        <section className="h-[300px]">
          <EndpointList endpoints={endpoints} />
        </section>
      </main>
    </div>
  );
};

export default Index;
