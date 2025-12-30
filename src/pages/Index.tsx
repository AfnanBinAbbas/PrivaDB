import { Database, Activity, AlertTriangle, Radar, Shield, TrendingUp } from 'lucide-react';
import { Header } from '@/components/dashboard/Header';
import { StatCard } from '@/components/dashboard/StatCard';
import { DatabaseExplorer } from '@/components/dashboard/DatabaseExplorer';
import { AlertPanel } from '@/components/dashboard/AlertPanel';
import { DataFlowGraph } from '@/components/dashboard/DataFlowGraph';
import { Timeline } from '@/components/dashboard/Timeline';
import { EndpointList } from '@/components/dashboard/EndpointList';
import { 
  mockStats, 
  mockDomainScans, 
  mockExfiltrationEvents, 
  mockEndpoints,
  mockDataFlowNodes,
  mockDataFlowEdges,
  mockTimelineEvents 
} from '@/data/mockData';

const Index = () => {
  return (
    <div className="min-h-screen bg-background grid-pattern">
      <Header />
      
      <main className="p-6 space-y-6">
        {/* Stats Row */}
        <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard
            title="Databases"
            value={mockStats.totalDatabases}
            icon={Database}
            variant="primary"
          />
          <StatCard
            title="Records Analyzed"
            value={mockStats.totalRecords.toLocaleString()}
            icon={Activity}
          />
          <StatCard
            title="Suspected Leaks"
            value={mockStats.suspectedLeaks}
            icon={AlertTriangle}
            variant="warning"
            trend={{ value: 12, direction: 'up' }}
          />
          <StatCard
            title="Endpoints Scanned"
            value={mockStats.endpointsScanned}
            icon={Radar}
            variant="success"
          />
          <StatCard
            title="Exfiltration Events"
            value={mockStats.exfiltrationEvents}
            icon={Shield}
            variant="destructive"
            trend={{ value: 3, direction: 'up' }}
          />
          <StatCard
            title="Risk Score"
            value={`${mockStats.riskScore}%`}
            subtitle="High Risk"
            icon={TrendingUp}
            variant="warning"
          />
        </section>

        {/* Main Grid */}
        <div className="grid grid-cols-12 gap-6">
          {/* Left Column - Database Explorer */}
          <section className="col-span-12 lg:col-span-3 h-[600px]">
            <DatabaseExplorer scans={mockDomainScans} />
          </section>

          {/* Center Column - Flow Graph & Alerts */}
          <section className="col-span-12 lg:col-span-6 space-y-6">
            <div className="h-[350px]">
              <DataFlowGraph nodes={mockDataFlowNodes} edges={mockDataFlowEdges} />
            </div>
            <div className="h-[230px]">
              <AlertPanel events={mockExfiltrationEvents} />
            </div>
          </section>

          {/* Right Column - Timeline */}
          <section className="col-span-12 lg:col-span-3 h-[600px]">
            <Timeline events={mockTimelineEvents} />
          </section>
        </div>

        {/* Bottom Row - Endpoints */}
        <section className="h-[300px]">
          <EndpointList endpoints={mockEndpoints} />
        </section>
      </main>
    </div>
  );
};

export default Index;
