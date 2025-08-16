import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Typography,
  Tab,
  Tabs,
  Paper,
  LinearProgress,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';

import GeographicHeatMap from '../components/visualizations/GeographicHeatMap';
import RealTimeQueryGraph from '../components/visualizations/RealTimeQueryGraph';
import ResponseTimeHistogram from '../components/visualizations/ResponseTimeHistogram';
import DomainsTreemap from '../components/visualizations/DomainsTreemap';
import NetworkTopology from '../components/visualizations/NetworkTopology';
import QueryTypeBreakdown from '../components/visualizations/QueryTypeBreakdown';
import TimeSeriesAnalysis from '../components/visualizations/TimeSeriesAnalysis';
import { analyticsApi } from '../services/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
};

const AdvancedDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);

  // Fetch geographic data
  const { data: geoData, isLoading: geoLoading } = useQuery({
    queryKey: ['geo-data'],
    queryFn: async () => {
      const response = await analyticsApi.geography({ period: '24h' });
      return response.data.map((item: any) => ({
        lat: item.latitude,
        lng: item.longitude,
        city: item.city,
        country: item.country,
        queries: item.queries,
        avgResponseTime: item.avgResponseTime,
        lastSeen: item.lastSeen,
      }));
    },
    refetchInterval: 60000,
  });

  // Fetch real-time query data
  const { data: queryData } = useQuery({
    queryKey: ['realtime-queries'],
    queryFn: async () => {
      const response = await analyticsApi.queries({ 
        period: '1h',
        interval: '1m',
      });
      return response.data.map((item: any) => ({
        timestamp: new Date(item.timestamp),
        queries: item.queries,
        cached: item.cached || 0,
        blocked: item.blocked || 0,
        responseTime: item.avgResponseTime,
      }));
    },
    refetchInterval: 5000,
  });

  // Fetch response time distribution
  const { data: responseTimeData } = useQuery({
    queryKey: ['response-time-dist'],
    queryFn: async () => {
      const response = await analyticsApi.performance({ period: '24h' });
      return response.data.distribution?.map((item: any) => ({
        bucket: item.bucket,
        count: item.count,
        percentage: item.percentage,
      })) || [];
    },
    refetchInterval: 60000,
  });

  // Fetch domain data for treemap
  const { data: domainData } = useQuery({
    queryKey: ['domain-treemap'],
    queryFn: async () => {
      const response = await analyticsApi.topDomains({ limit: 50 });
      return response.data.map((item: any) => ({
        name: item.domain,
        queries: item.queries,
        avgResponseTime: item.avgResponseTime,
        cacheHitRate: item.cacheHitRate,
        category: item.category || 'Other',
      }));
    },
    refetchInterval: 60000,
  });

  // Mock network topology data
  const networkNodes = [
    { id: '1', name: 'Client Pool 1', type: 'client' as const, status: 'healthy' as const, queries: 15000, responseTime: 12, location: 'US-East' },
    { id: '2', name: 'Client Pool 2', type: 'client' as const, status: 'healthy' as const, queries: 12000, responseTime: 15, location: 'US-West' },
    { id: '3', name: 'Resolver 1', type: 'resolver' as const, status: 'healthy' as const, queries: 27000, responseTime: 8, location: 'US-Central' },
    { id: '4', name: 'Cache Server', type: 'cache' as const, status: 'healthy' as const, queries: 25000, responseTime: 2, location: 'US-Central' },
    { id: '5', name: 'Auth DNS 1', type: 'authoritative' as const, status: 'healthy' as const, queries: 5000, responseTime: 20, location: 'US-East' },
    { id: '6', name: 'Auth DNS 2', type: 'authoritative' as const, status: 'degraded' as const, queries: 3000, responseTime: 45, location: 'EU-West' },
    { id: '7', name: 'Root Server', type: 'root' as const, status: 'healthy' as const, queries: 1000, responseTime: 30, location: 'Global' },
  ];

  const networkLinks = [
    { source: '1', target: '3', value: 15000, latency: 12, packetLoss: 0.1 },
    { source: '2', target: '3', value: 12000, latency: 15, packetLoss: 0.2 },
    { source: '3', target: '4', value: 25000, latency: 2 },
    { source: '3', target: '5', value: 5000, latency: 20 },
    { source: '3', target: '6', value: 3000, latency: 45, packetLoss: 2.5 },
    { source: '3', target: '7', value: 1000, latency: 30 },
  ];

  // Fetch query type breakdown
  const { data: queryTypeData } = useQuery({
    queryKey: ['query-types'],
    queryFn: async () => {
      const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR'];
      return types.map((type, index) => ({
        type,
        count: Math.floor(Math.random() * 10000) + 1000,
        percentage: 0,
        avgResponseTime: Math.floor(Math.random() * 50) + 10,
        trend: Math.floor(Math.random() * 20) - 10,
      })).map((item, _, arr) => {
        const total = arr.reduce((sum, i) => sum + i.count, 0);
        return { ...item, percentage: (item.count / total) * 100 };
      });
    },
    refetchInterval: 60000,
  });

  // Fetch time series data for analysis
  const { data: timeSeriesData } = useQuery({
    queryKey: ['time-series'],
    queryFn: async () => {
      const response = await analyticsApi.queries({ 
        period: '24h',
        interval: '5m',
      });
      return response.data.map((item: any) => ({
        timestamp: new Date(item.timestamp),
        value: item.queries,
        predicted: item.predicted,
      }));
    },
    refetchInterval: 60000,
  });

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  if (geoLoading) {
    return <LinearProgress />;
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        Advanced Data Visualization Dashboard
      </Typography>

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={handleTabChange} variant="scrollable" scrollButtons="auto">
          <Tab label="Overview" />
          <Tab label="Geographic Analysis" />
          <Tab label="Performance Metrics" />
          <Tab label="Network Topology" />
          <Tab label="Time Series Analysis" />
        </Tabs>
      </Paper>

      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} lg={8}>
            <RealTimeQueryGraph
              data={queryData}
              height={400}
              title="Real-time Query Rate with Zoom & Pan"
              showAnomalies={true}
            />
          </Grid>
          <Grid item xs={12} lg={4}>
            <QueryTypeBreakdown
              data={queryTypeData}
              height={400}
              chartType="donut"
              showTrends={true}
            />
          </Grid>
          <Grid item xs={12}>
            <DomainsTreemap
              data={domainData}
              height={500}
              title="Top Queried Domains Treemap"
              colorBy="queries"
            />
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={activeTab} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <GeographicHeatMap
              data={geoData}
              height={600}
              title="DNS Query Origins Heat Map"
              onLocationClick={(location) => console.log('Location clicked:', location)}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <QueryTypeBreakdown
              data={queryTypeData}
              height={400}
              chartType="sunburst"
              title="Query Types by Response Time"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <ResponseTimeHistogram
              data={responseTimeData}
              height={400}
              title="Response Time by Geography"
              showPercentiles={true}
            />
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={activeTab} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <ResponseTimeHistogram
              data={responseTimeData}
              height={450}
              title="DNS Response Time Distribution"
              showPercentiles={true}
              binSize={10}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <RealTimeQueryGraph
              data={queryData}
              height={450}
              title="Query Performance Monitor"
              showAnomalies={false}
            />
          </Grid>
          <Grid item xs={12}>
            <TimeSeriesAnalysis
              data={timeSeriesData}
              height={500}
              title="Performance Trend Analysis"
              metric="Response Time (ms)"
              showPredictions={true}
            />
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={activeTab} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <NetworkTopology
              nodes={networkNodes}
              links={networkLinks}
              height={600}
              title="DNS Infrastructure Network Topology"
              onNodeClick={(node) => console.log('Node clicked:', node)}
              onLinkClick={(link) => console.log('Link clicked:', link)}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <DomainsTreemap
              data={domainData}
              height={400}
              title="Domain Distribution by Cache Hit Rate"
              colorBy="cacheHitRate"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <QueryTypeBreakdown
              data={queryTypeData}
              height={400}
              chartType="pie"
              title="Infrastructure Load Distribution"
            />
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={activeTab} index={4}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <TimeSeriesAnalysis
              data={timeSeriesData}
              height={550}
              title="Advanced Time Series Analysis with Anomaly Detection"
              metric="Queries per Second"
              showPredictions={true}
              anomalyThreshold={2.5}
              onAnomalyDetected={(anomalies) => {
                console.log(`Detected ${anomalies.length} anomalies`);
              }}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <RealTimeQueryGraph
              data={queryData}
              height={400}
              title="Anomaly Correlation Analysis"
              showAnomalies={true}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <ResponseTimeHistogram
              data={responseTimeData}
              height={400}
              title="Anomaly Impact Distribution"
              showPercentiles={true}
            />
          </Grid>
        </Grid>
      </TabPanel>
    </Box>
  );
};

export default AdvancedDashboard;