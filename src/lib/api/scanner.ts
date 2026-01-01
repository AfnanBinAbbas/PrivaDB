import { supabase } from '@/integrations/supabase/client';
import type { DomainScan, Endpoint, DataFlowNode, DataFlowEdge, TimelineEvent, SeverityLevel } from '@/types/detector';

export interface ScanResult {
  domain: string;
  timestamp: string;
  databases: {
    name: string;
    stores: {
      name: string;
      recordCount: number;
      suspectedUserData: {
        key: string;
        value: string;
        valueLength: number;
        detectedPatterns: string[];
      }[];
    }[];
  }[];
  endpoints: {
    url: string;
    method: string;
    parameters: string[];
  }[];
}

export interface ScanResponse {
  success: boolean;
  data?: ScanResult;
  error?: string;
}

export const scannerApi = {
  async scanDomain(domain: string): Promise<ScanResponse> {
    const { data, error } = await supabase.functions.invoke('scan-domain', {
      body: { domain },
    });

    if (error) {
      console.error('Scan error:', error);
      return { success: false, error: error.message };
    }

    return data;
  },

  // Convert scan result to dashboard-compatible format
  convertToDomainScan(result: ScanResult): DomainScan {
    return {
      domain: result.domain,
      timestamp: result.timestamp,
      status: 'completed',
      databases: result.databases.map((db) => ({
        name: db.name,
        version: 1,
        stores: db.stores.map((store) => ({
          name: store.name,
          recordCount: store.recordCount,
          suspectedUserData: store.suspectedUserData,
        })),
      })),
    };
  },

  convertToEndpoints(result: ScanResult): Endpoint[] {
    return result.endpoints.map((ep) => ({
      url: ep.url,
      status: 200,
      parameters: ep.parameters,
      lastChecked: result.timestamp,
      dataFlowCount: 0,
    }));
  },

  convertToDataFlowNodes(result: ScanResult): DataFlowNode[] {
    const nodes: DataFlowNode[] = [];
    
    // Add database nodes
    result.databases.forEach((db, i) => {
      nodes.push({
        id: `db-${i}`,
        type: 'database',
        label: db.name,
        x: 100,
        y: 100 + i * 80,
      });
      
      // Add store nodes
      db.stores.forEach((store, j) => {
        nodes.push({
          id: `store-${i}-${j}`,
          type: 'store',
          label: store.name,
          x: 250,
          y: 100 + i * 80 + j * 40,
        });
      });
    });

    // Add endpoint nodes
    result.endpoints.slice(0, 5).forEach((ep, i) => {
      let urlPath = ep.url;
      try {
        urlPath = new URL(ep.url, 'https://example.com').pathname;
      } catch {
        // Keep original if URL parsing fails
      }
      nodes.push({
        id: `endpoint-${i}`,
        type: 'endpoint',
        label: urlPath.slice(0, 20) + (urlPath.length > 20 ? '...' : ''),
        x: 400,
        y: 100 + i * 60,
      });
    });

    return nodes;
  },

  convertToDataFlowEdges(nodes: DataFlowNode[]): DataFlowEdge[] {
    const edges: DataFlowEdge[] = [];
    const dbNodes = nodes.filter(n => n.type === 'database');
    const storeNodes = nodes.filter(n => n.type === 'store');
    const endpointNodes = nodes.filter(n => n.type === 'endpoint');

    // Connect databases to stores
    dbNodes.forEach((db, i) => {
      storeNodes.filter(s => s.id.startsWith(`store-${i}`)).forEach(store => {
        edges.push({
          id: `edge-${db.id}-${store.id}`,
          source: db.id,
          target: store.id,
          frequency: Math.floor(Math.random() * 100) + 10,
          lastSeen: new Date().toISOString(),
        });
      });
    });

    // Connect stores to endpoints
    storeNodes.forEach(store => {
      endpointNodes.slice(0, 2).forEach(ep => {
        edges.push({
          id: `edge-${store.id}-${ep.id}`,
          source: store.id,
          target: ep.id,
          frequency: Math.floor(Math.random() * 50) + 5,
          lastSeen: new Date().toISOString(),
        });
      });
    });

    return edges;
  },

  createTimelineEvent(result: ScanResult): TimelineEvent {
    const totalRecords = result.databases.reduce(
      (sum, db) => sum + db.stores.reduce((s, store) => s + store.recordCount, 0),
      0
    );

    const severity: SeverityLevel = totalRecords > 10 ? 'warning' : 'info';

    return {
      id: crypto.randomUUID(),
      timestamp: result.timestamp,
      type: 'scan',
      title: `Scanned ${result.domain}`,
      description: `Found ${result.databases.length} databases with ${totalRecords} suspected records`,
      severity,
    };
  },
};
