import { 
  DomainScan, 
  ExfiltrationEvent, 
  Endpoint, 
  DataFlowNode, 
  DataFlowEdge, 
  TimelineEvent, 
  Stats 
} from '@/types/detector';

export const mockStats: Stats = {
  totalDatabases: 12,
  totalRecords: 1847,
  suspectedLeaks: 23,
  endpointsScanned: 156,
  exfiltrationEvents: 7,
  riskScore: 72,
};

export const mockDomainScans: DomainScan[] = [
  {
    domain: 'analytics-tracker.io',
    timestamp: '2024-01-15T14:32:00Z',
    status: 'completed',
    databases: [
      {
        name: 'userDB',
        version: 3,
        stores: [
          {
            name: 'profiles',
            recordCount: 42,
            suspectedUserData: [
              {
                key: 'user_12345',
                value: 'JohnDoe_EncryptedData123',
                valueLength: 24,
                detectedPatterns: ['mixed_alphanumeric', 'underscore_separated'],
              },
              {
                key: 'session_token',
                value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                valueLength: 156,
                detectedPatterns: ['jwt_token', 'base64_encoded'],
              },
            ],
          },
          {
            name: 'preferences',
            recordCount: 18,
            suspectedUserData: [
              {
                key: 'email_hash',
                value: 'a1b2c3d4e5f6g7h8i9j0',
                valueLength: 20,
                detectedPatterns: ['hex_encoded'],
              },
            ],
          },
        ],
      },
      {
        name: 'trackingDB',
        version: 1,
        stores: [
          {
            name: 'events',
            recordCount: 234,
            suspectedUserData: [
              {
                key: 'fingerprint_v2',
                value: 'fp_8a7b6c5d4e3f2g1h0i9j',
                valueLength: 24,
                detectedPatterns: ['fingerprint_pattern'],
              },
            ],
          },
        ],
      },
    ],
  },
  {
    domain: 'shopping-platform.com',
    timestamp: '2024-01-15T14:28:00Z',
    status: 'completed',
    databases: [
      {
        name: 'cartDB',
        version: 2,
        stores: [
          {
            name: 'cart_items',
            recordCount: 5,
            suspectedUserData: [],
          },
          {
            name: 'user_data',
            recordCount: 1,
            suspectedUserData: [
              {
                key: 'customer_id',
                value: 'cust_9876543210abcdef',
                valueLength: 22,
                detectedPatterns: ['customer_identifier'],
              },
            ],
          },
        ],
      },
    ],
  },
  {
    domain: 'social-network.app',
    timestamp: '2024-01-15T14:35:00Z',
    status: 'scanning',
    databases: [],
  },
];

export const mockExfiltrationEvents: ExfiltrationEvent[] = [
  {
    id: 'exf_001',
    timestamp: '2024-01-15T14:45:23Z',
    sourceStore: 'userDB.profiles',
    sourceKey: 'session_token',
    destinationDomain: 'third-party-analytics.com',
    endpoint: '/api/v2/collect',
    dataPreview: 'eyJhbGciOiJIUzI1Ni...',
    severity: 'critical',
    confidence: 0.95,
    method: 'fetch',
  },
  {
    id: 'exf_002',
    timestamp: '2024-01-15T14:42:11Z',
    sourceStore: 'trackingDB.events',
    sourceKey: 'fingerprint_v2',
    destinationDomain: 'ad-network.io',
    endpoint: '/pixel/track',
    dataPreview: 'fp_8a7b6c5d4e3f2g1h0i9j',
    severity: 'critical',
    confidence: 0.88,
    method: 'beacon',
  },
  {
    id: 'exf_003',
    timestamp: '2024-01-15T14:38:45Z',
    sourceStore: 'userDB.preferences',
    sourceKey: 'email_hash',
    destinationDomain: 'marketing-platform.net',
    endpoint: '/api/identify',
    dataPreview: 'a1b2c3d4e5f6g7h8i9j0',
    severity: 'warning',
    confidence: 0.72,
    method: 'xhr',
  },
  {
    id: 'exf_004',
    timestamp: '2024-01-15T14:30:00Z',
    sourceStore: 'cartDB.user_data',
    sourceKey: 'customer_id',
    destinationDomain: 'analytics-tracker.io',
    endpoint: '/events',
    dataPreview: 'cust_9876543210abcdef',
    severity: 'warning',
    confidence: 0.65,
    method: 'fetch',
  },
];

export const mockEndpoints: Endpoint[] = [
  {
    url: 'https://analytics-tracker.io/api/v2/collect',
    status: 200,
    parameters: ['uid', 'sid', 'event', 'data'],
    lastChecked: '2024-01-15T14:45:00Z',
    dataFlowCount: 156,
  },
  {
    url: 'https://third-party-analytics.com/api/v2/collect',
    status: 200,
    parameters: ['token', 'payload', 'timestamp'],
    lastChecked: '2024-01-15T14:45:23Z',
    dataFlowCount: 89,
  },
  {
    url: 'https://ad-network.io/pixel/track',
    status: 200,
    parameters: ['fp', 'ref', 'utm_source'],
    lastChecked: '2024-01-15T14:42:11Z',
    dataFlowCount: 234,
  },
  {
    url: 'https://marketing-platform.net/api/identify',
    status: 200,
    parameters: ['email', 'hash', 'source'],
    lastChecked: '2024-01-15T14:38:45Z',
    dataFlowCount: 45,
  },
];

export const mockDataFlowNodes: DataFlowNode[] = [
  { id: 'db_1', type: 'database', label: 'userDB', x: 50, y: 150 },
  { id: 'store_1', type: 'store', label: 'profiles', x: 200, y: 100 },
  { id: 'store_2', type: 'store', label: 'preferences', x: 200, y: 200 },
  { id: 'db_2', type: 'database', label: 'trackingDB', x: 50, y: 300 },
  { id: 'store_3', type: 'store', label: 'events', x: 200, y: 300 },
  { id: 'ep_1', type: 'endpoint', label: '/api/v2/collect', x: 400, y: 150 },
  { id: 'ep_2', type: 'endpoint', label: '/pixel/track', x: 400, y: 300 },
  { id: 'ext_1', type: 'external', label: 'third-party-analytics.com', x: 600, y: 100 },
  { id: 'ext_2', type: 'external', label: 'ad-network.io', x: 600, y: 200 },
  { id: 'ext_3', type: 'external', label: 'marketing-platform.net', x: 600, y: 300 },
];

export const mockDataFlowEdges: DataFlowEdge[] = [
  { id: 'e1', source: 'db_1', target: 'store_1', frequency: 42, lastSeen: '2024-01-15T14:45:00Z' },
  { id: 'e2', source: 'db_1', target: 'store_2', frequency: 18, lastSeen: '2024-01-15T14:44:00Z' },
  { id: 'e3', source: 'db_2', target: 'store_3', frequency: 234, lastSeen: '2024-01-15T14:45:00Z' },
  { id: 'e4', source: 'store_1', target: 'ep_1', frequency: 156, lastSeen: '2024-01-15T14:45:23Z' },
  { id: 'e5', source: 'store_3', target: 'ep_2', frequency: 89, lastSeen: '2024-01-15T14:42:11Z' },
  { id: 'e6', source: 'ep_1', target: 'ext_1', frequency: 156, lastSeen: '2024-01-15T14:45:23Z' },
  { id: 'e7', source: 'ep_1', target: 'ext_2', frequency: 45, lastSeen: '2024-01-15T14:40:00Z' },
  { id: 'e8', source: 'ep_2', target: 'ext_2', frequency: 89, lastSeen: '2024-01-15T14:42:11Z' },
  { id: 'e9', source: 'store_2', target: 'ext_3', frequency: 23, lastSeen: '2024-01-15T14:38:45Z' },
];

export const mockTimelineEvents: TimelineEvent[] = [
  {
    id: 'tl_001',
    timestamp: '2024-01-15T14:45:23Z',
    type: 'exfiltration',
    title: 'Critical: Session Token Leaked',
    description: 'JWT token from userDB.profiles sent to third-party-analytics.com',
    severity: 'critical',
  },
  {
    id: 'tl_002',
    timestamp: '2024-01-15T14:42:11Z',
    type: 'exfiltration',
    title: 'Critical: Fingerprint Exfiltrated',
    description: 'Browser fingerprint sent to ad-network.io via beacon',
    severity: 'critical',
  },
  {
    id: 'tl_003',
    timestamp: '2024-01-15T14:38:45Z',
    type: 'exfiltration',
    title: 'Warning: Email Hash Transmitted',
    description: 'Hashed email address sent to marketing-platform.net',
    severity: 'warning',
  },
  {
    id: 'tl_004',
    timestamp: '2024-01-15T14:35:00Z',
    type: 'scan',
    title: 'Scan Started: social-network.app',
    description: 'Initiated IndexedDB scan for social-network.app',
    severity: 'info',
  },
  {
    id: 'tl_005',
    timestamp: '2024-01-15T14:32:00Z',
    type: 'discovery',
    title: 'Databases Discovered',
    description: 'Found 2 databases with 4 stores on analytics-tracker.io',
    severity: 'info',
  },
  {
    id: 'tl_006',
    timestamp: '2024-01-15T14:28:00Z',
    type: 'endpoint',
    title: 'Endpoints Mapped',
    description: 'Discovered 156 active endpoints on shopping-platform.com',
    severity: 'success',
  },
];
