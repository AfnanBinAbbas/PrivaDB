import { v4 as uuidv4 } from "uuid";
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

export interface TrackingAnalysisResponse {
  success: boolean;
  domain?: string;
  url?: string;
  scan_data?: {
    fresh_browser: ScanResult;
    return_visit: ScanResult;
    cleared_browser: ScanResult;
  };
  analysis?: any;
  files?: any;
  error?: string;
}

// Backend API URL
const BACKEND_API_URL = 'http://localhost:8000';

export const scannerApi = {
  // Single domain scan (quick)
  async scanDomain(domain: string): Promise<ScanResponse> {
    try {
      const response = await fetch(`${BACKEND_API_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Backend scan error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Backend connection failed'
      };
    }
  },

  // Full tracking analysis (3 scenarios + analyzer)
  async scanWithTracking(domain: string): Promise<TrackingAnalysisResponse> {
    try {
      const response = await fetch(`${BACKEND_API_URL}/api/scan-with-tracking?domain=${domain}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Backend scan-with-tracking error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Backend connection failed'
      };
    }
  },

  async scanAndAnalyze(domain: string): Promise<ScanResponse> {
    try {
      const response = await fetch(`${BACKEND_API_URL}/api/scan-and-analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Backend scan-and-analyze error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  async analyzeData(scenario1File: string, scenario2File: string, scenario3File: string): Promise<ScanResponse> {
    try {
      const response = await fetch(`${BACKEND_API_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scenario1_file: scenario1File,
          scenario2_file: scenario2File,
          scenario3_file: scenario3File,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Backend analyze error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  // Helper function to map backend response to ScanResult
  mapToScanResult(response: TrackingAnalysisResponse, scenario: 'fresh_browser' | 'return_visit' | 'cleared_browser'): ScanResult {
    const scenarioData = response.scan_data?.[scenario];

    return {
      domain: response.url?.replace('https://', '').replace('http://', '').replace('www.', '') || 'unknown',
      timestamp: new Date().toISOString(),
      databases: scenarioData?.databases || [],
      endpoints: scenarioData?.endpoints || []
    };
  },

  // Helper function to extract tracking analysis summary
  getTrackingSummary(response: TrackingAnalysisResponse) {
    return response.analysis?.summary || null;
  },

  // Helper function to get sample transmissions
  getSampleTransmissions(response: TrackingAnalysisResponse) {
    return response.analysis?.sample_transmissions || [];
  },

  // Helper function to get risk assessment
  getRiskAssessment(response: TrackingAnalysisResponse) {
    const summary = response.analysis?.summary;
    if (!summary) return null;

    return {
      score: summary.risk_score,
      rating: summary.risk_rating,
      factors: summary.risk_factors || []
    };
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

    result.databases.forEach((db, i) => {
      nodes.push({
        id: `db-${i}`,
        type: 'database',
        label: db.name,
        x: 100,
        y: 100 + i * 80,
      });

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
      id: uuidv4(),
      timestamp: result.timestamp,
      type: 'scan',
      title: `Scanned ${result.domain}`,
      description: `Found ${result.databases.length} databases with ${totalRecords} suspected records`,
      severity,
    };
  },
};