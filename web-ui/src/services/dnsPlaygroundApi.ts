import { api } from './api';

export interface DNSQueryRequest {
  domain: string;
  type: string;
  server?: string;
  dnssec?: boolean;
  recursion?: boolean;
  ednsClientSubnet?: string;
  timeout?: number;
}

export interface DNSTraceRequest {
  domain: string;
  detailed?: boolean;
}

export interface DNSValidateRequest {
  type: string;
  value: string;
}

export interface DNSPropagationRequest {
  domain: string;
  recordType: string;
  server: string;
  expectedValue?: string;
}

export interface DNSBenchmarkRequest {
  domain: string;
  queryType: string;
  iterations: number;
  concurrent?: boolean;
}

export interface DNSSECValidateRequest {
  domain: string;
}

export interface DNSCompareRequest {
  domain: string;
  servers?: string[];
}

export const dnsPlaygroundApi = {
  // DNS Query Tester
  query: (data: DNSQueryRequest) => 
    api.post('/dns-playground/query', data),

  // DNS Lookup Trace
  trace: (data: DNSTraceRequest) => 
    api.post('/dns-playground/trace', data),

  // Record Validator
  validateRecord: (data: DNSValidateRequest) => 
    api.post('/dns-playground/validate', data),

  // Propagation Checker
  checkPropagation: (data: DNSPropagationRequest) => 
    api.post('/dns-playground/propagation', data),

  // Performance Benchmark
  benchmark: (data: DNSBenchmarkRequest) => 
    api.post('/dns-playground/benchmark', data),

  // DNSSEC Validator
  validateDNSSEC: (data: DNSSECValidateRequest) => 
    api.post('/dns-playground/dnssec', data),

  // Server Comparison
  compareServers: (data: DNSCompareRequest) => 
    api.post('/dns-playground/compare', data),

  // Attack Simulation
  simulateAttack: (scenario: string, params?: any) => 
    api.post('/dns-playground/attack-simulate', { scenario, ...params }),

  // Export functions
  exportResults: (format: string, data: any) => 
    api.post('/dns-playground/export', { format, data }),

  generateShareLink: (data: any) => 
    api.post('/dns-playground/share', data),

  getSharedData: (shareId: string) => 
    api.get(`/dns-playground/share/${shareId}`),

  // Monitoring integration
  testAlert: (config: any) => 
    api.post('/dns-playground/test-alert', config),

  getMonitoringStatus: () => 
    api.get('/dns-playground/monitoring-status'),
};

// Mock implementations for development
// These would be replaced with actual backend implementations
if (process.env.NODE_ENV === 'development') {
  const mockDelay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  // Override with mock implementations
  const originalQuery = dnsPlaygroundApi.query;
  dnsPlaygroundApi.query = async (data: DNSQueryRequest) => {
    await mockDelay(300 + Math.random() * 700);
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        answers: [
          { name: data.domain, type: data.type, ttl: 300, data: '192.168.1.1', class: 'IN' },
        ],
        flags: {
          recursionDesired: true,
          recursionAvailable: true,
          authoritative: false,
          truncated: false,
          authenticData: data.dnssec || false,
          checkingDisabled: false,
          responseCode: 'NOERROR',
        },
        sections: {
          question: 1,
          answer: 1,
          authority: 0,
          additional: 0,
        },
      },
    };
  };

  const originalTrace = dnsPlaygroundApi.trace;
  dnsPlaygroundApi.trace = async (data: DNSTraceRequest) => {
    await mockDelay(1000 + Math.random() * 1000);
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        startTime: new Date().toISOString(),
        endTime: new Date(Date.now() + 1000).toISOString(),
        totalTime: 1000 + Math.random() * 500,
        success: true,
        dnssecValidated: Math.random() > 0.5,
        hops: [
          {
            id: 'hop1',
            level: 0,
            type: 'root',
            server: '198.41.0.4',
            serverName: 'a.root-servers.net',
            location: 'USA',
            query: data.domain,
            queryType: 'A',
            response: 'Referral to .com',
            responseTime: 15 + Math.random() * 10,
            ttl: 172800,
            flags: { authoritative: true, recursion: false, dnssec: true },
            answers: [],
            timestamp: new Date(),
            cached: false,
          },
          {
            id: 'hop2',
            level: 1,
            type: 'tld',
            server: '192.5.6.30',
            serverName: 'a.gtld-servers.net',
            location: 'USA',
            query: data.domain,
            queryType: 'A',
            response: 'Referral to example.com nameservers',
            responseTime: 25 + Math.random() * 15,
            ttl: 172800,
            flags: { authoritative: true, recursion: false, dnssec: true },
            answers: [],
            timestamp: new Date(),
            cached: false,
          },
          {
            id: 'hop3',
            level: 2,
            type: 'authoritative',
            server: '93.184.216.34',
            serverName: 'ns1.example.com',
            location: 'Europe',
            query: data.domain,
            queryType: 'A',
            response: '93.184.216.34',
            responseTime: 45 + Math.random() * 20,
            ttl: 300,
            flags: { authoritative: true, recursion: false, dnssec: false },
            answers: [{ name: data.domain, type: 'A', data: '93.184.216.34' }],
            timestamp: new Date(),
            cached: false,
          },
        ],
        finalAnswer: { name: data.domain, type: 'A', data: '93.184.216.34' },
      },
    };
  };

  const originalValidate = dnsPlaygroundApi.validateRecord;
  dnsPlaygroundApi.validateRecord = async (data: DNSValidateRequest) => {
    await mockDelay(200);
    const isValid = Math.random() > 0.3;
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        valid: isValid,
        errors: isValid ? [] : [
          { field: 'syntax', message: 'Invalid record syntax', severity: 'error', rule: 'RFC1035' },
        ],
        warnings: isValid ? [
          { field: 'ttl', message: 'TTL is very low (< 60 seconds)', suggestion: 'Consider increasing TTL to at least 300' },
        ] : [],
        suggestions: isValid ? ['Consider adding a trailing dot to the domain name'] : [],
      },
    };
  };

  const originalPropagation = dnsPlaygroundApi.checkPropagation;
  dnsPlaygroundApi.checkPropagation = async (data: DNSPropagationRequest) => {
    await mockDelay(300 + Math.random() * 200);
    const propagated = Math.random() > 0.3;
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        response: propagated ? (data.expectedValue || '192.168.1.1') : 'NXDOMAIN',
        ttl: propagated ? 300 : undefined,
        propagated,
      },
    };
  };

  const originalBenchmark = dnsPlaygroundApi.benchmark;
  dnsPlaygroundApi.benchmark = async (data: DNSBenchmarkRequest) => {
    await mockDelay(2000);
    const results = Array.from({ length: data.iterations }, (_, i) => ({
      iteration: i + 1,
      responseTime: 20 + Math.random() * 80,
      success: Math.random() > 0.05,
    }));
    
    const responseTimes = results.filter(r => r.success).map(r => r.responseTime);
    const sorted = [...responseTimes].sort((a, b) => a - b);
    
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        results,
        stats: {
          average: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length,
          min: Math.min(...responseTimes),
          max: Math.max(...responseTimes),
          p95: sorted[Math.floor(sorted.length * 0.95)],
          successRate: (results.filter(r => r.success).length / results.length) * 100,
        },
      },
    };
  };

  const originalDNSSEC = dnsPlaygroundApi.validateDNSSEC;
  dnsPlaygroundApi.validateDNSSEC = async (data: DNSSECValidateRequest) => {
    await mockDelay(1500);
    const valid = Math.random() > 0.3;
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        valid,
        chainOfTrust: valid,
        keys: valid ? [
          { type: 'DNSKEY', algorithm: 'RSA-SHA256', keyTag: 12345 },
          { type: 'DS', algorithm: 'RSA-SHA256', keyTag: 12345 },
        ] : [],
        errors: valid ? [] : ['Chain of trust broken at TLD level'],
      },
    };
  };

  const originalCompare = dnsPlaygroundApi.compareServers;
  dnsPlaygroundApi.compareServers = async (data: DNSCompareRequest) => {
    await mockDelay(1000);
    const servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222'];
    return {
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any,
      data: {
        comparisons: servers.map(server => ({
          server,
          responseTime: 10 + Math.random() * 90,
          response: '192.168.1.1',
          dnssec: Math.random() > 0.5,
          status: Math.random() > 0.1 ? 'success' : 'failed',
        })),
      },
    };
  };
}

export default dnsPlaygroundApi;