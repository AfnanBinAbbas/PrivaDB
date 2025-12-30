export type SeverityLevel = 'critical' | 'warning' | 'info' | 'success';

export interface DatabaseRecord {
  key: string;
  value: string;
  valueLength: number;
  detectedPatterns: string[];
}

export interface ObjectStore {
  name: string;
  recordCount: number;
  suspectedUserData: DatabaseRecord[];
}

export interface Database {
  name: string;
  version: number;
  stores: ObjectStore[];
}

export interface DomainScan {
  domain: string;
  timestamp: string;
  databases: Database[];
  status: 'scanning' | 'completed' | 'error';
}

export interface ExfiltrationEvent {
  id: string;
  timestamp: string;
  sourceStore: string;
  sourceKey: string;
  destinationDomain: string;
  endpoint: string;
  dataPreview: string;
  severity: SeverityLevel;
  confidence: number;
  method: 'fetch' | 'xhr' | 'beacon' | 'websocket' | 'form';
}

export interface Endpoint {
  url: string;
  status: number;
  parameters: string[];
  lastChecked: string;
  dataFlowCount: number;
}

export interface DataFlowNode {
  id: string;
  type: 'database' | 'store' | 'endpoint' | 'external';
  label: string;
  x: number;
  y: number;
}

export interface DataFlowEdge {
  id: string;
  source: string;
  target: string;
  frequency: number;
  lastSeen: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'discovery' | 'endpoint' | 'exfiltration' | 'scan';
  title: string;
  description: string;
  severity: SeverityLevel;
}

export interface Stats {
  totalDatabases: number;
  totalRecords: number;
  suspectedLeaks: number;
  endpointsScanned: number;
  exfiltrationEvents: number;
  riskScore: number;
}
