export interface DNSQuery {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  queryType: DNSQueryType;
  queryName: string;
  responseCode: DNSResponseCode;
  latency: number;
  queryCount: number;
  path: DNSNode[];
  ttl: number;
  cached: boolean;
  blocked: boolean;
  anomaly?: boolean;
  geoLocation?: GeoLocation;
  serverChain?: string[];
}

export type DNSQueryType = 
  | 'A' 
  | 'AAAA' 
  | 'CNAME' 
  | 'MX' 
  | 'TXT' 
  | 'NS' 
  | 'SOA' 
  | 'PTR' 
  | 'SRV'
  | 'DNSKEY'
  | 'CAA';

export type DNSResponseCode = 
  | 'NOERROR' 
  | 'NXDOMAIN' 
  | 'SERVFAIL' 
  | 'REFUSED' 
  | 'FORMERR'
  | 'NOTIMP'
  | 'TIMEOUT';

export interface DNSNode {
  id: string;
  name: string;
  type: 'client' | 'resolver' | 'authoritative' | 'cache' | 'forwarder';
  ip: string;
  latency: number;
  timestamp: string;
  geoLocation?: GeoLocation;
}

export interface GeoLocation {
  lat: number;
  lng: number;
  country: string;
  city: string;
  isp?: string;
}

export interface FilterOptions {
  queryTypes: DNSQueryType[];
  sources: string[];
  responseCodes: DNSResponseCode[];
  minLatency: number;
  maxLatency: number;
  showAnomalies: boolean;
  timeRange?: TimeRange;
  servers?: string[];
  domains?: string[];
}

export interface TimeRange {
  start: Date;
  end: Date;
}

export type VisualizationType = 
  | 'flow' 
  | 'sankey' 
  | 'chain' 
  | 'heatmap' 
  | 'comparison';

export interface FlowLink {
  source: string;
  target: string;
  value: number;
  type: 'query' | 'response' | 'forward' | 'cache';
  latency: number;
  queries: DNSQuery[];
}

export interface SankeyNode {
  id: string;
  name: string;
  group: number;
  value: number;
}

export interface SankeyLink {
  source: string;
  target: string;
  value: number;
  queries: number;
}

export interface HeatmapData {
  lat: number;
  lng: number;
  value: number;
  count: number;
  avgLatency: number;
  maxLatency: number;
  minLatency: number;
}

export interface AnomalyAlert {
  id: string;
  timestamp: string;
  type: 'latency' | 'volume' | 'error' | 'pattern';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  queries: DNSQuery[];
}

export interface ExportOptions {
  format: 'png' | 'svg' | 'mp4' | 'gif';
  quality: 'low' | 'medium' | 'high';
  fps?: number;
  duration?: number;
  width?: number;
  height?: number;
}