import React, { useState, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
} from 'recharts';
import {
  Speed as SpeedIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface APIEndpointStats {
  endpoint: string;
  method: string;
  avgDuration: number;
  minDuration: number;
  maxDuration: number;
  p50: number;
  p95: number;
  p99: number;
  requestCount: number;
  errorCount: number;
  successRate: number;
  totalSize: number;
}

const getStatusColor = (status: number) => {
  if (status >= 200 && status < 300) return '#4caf50';
  if (status >= 300 && status < 400) return '#ff9800';
  if (status >= 400 && status < 500) return '#f44336';
  if (status >= 500) return '#9c27b0';
  return '#757575';
};

const getPercentile = (values: number[], percentile: number): number => {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)] || 0;
};

export const APIMonitor: React.FC = () => {
  const { performanceData, trackAPICall } = usePerformanceMonitor();
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('1h');
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'timeline' | 'distribution' | 'table'>('timeline');

  const filteredMetrics = useMemo(() => {
    const now = Date.now();
    const ranges = {
      '1h': 3600000,
      '6h': 21600000,
      '24h': 86400000,
      '7d': 604800000,
    };
    
    const cutoff = now - ranges[timeRange];
    
    return performanceData.apiMetrics.filter(metric => {
      const matchesTime = metric.timestamp >= cutoff;
      const matchesEndpoint = selectedEndpoint === 'all' || metric.endpoint === selectedEndpoint;
      return matchesTime && matchesEndpoint;
    });
  }, [performanceData.apiMetrics, timeRange, selectedEndpoint]);

  const endpointStats = useMemo(() => {
    const grouped = filteredMetrics.reduce((acc, metric) => {
      const key = `${metric.method} ${metric.endpoint}`;
      if (!acc[key]) {
        acc[key] = {
          endpoint: metric.endpoint,
          method: metric.method,
          durations: [],
          statuses: [],
          sizes: [],
        };
      }
      acc[key].durations.push(metric.duration);
      acc[key].statuses.push(metric.status);
      if (metric.size) acc[key].sizes.push(metric.size);
      return acc;
    }, {} as Record<string, any>);

    return Object.entries(grouped).map(([key, data]) => {
      const durations = data.durations;
      const successCount = data.statuses.filter((s: number) => s >= 200 && s < 300).length;
      const errorCount = data.statuses.filter((s: number) => s >= 400).length;
      
      return {
        endpoint: data.endpoint,
        method: data.method,
        avgDuration: durations.reduce((a: number, b: number) => a + b, 0) / durations.length,
        minDuration: Math.min(...durations),
        maxDuration: Math.max(...durations),
        p50: getPercentile(durations, 50),
        p95: getPercentile(durations, 95),
        p99: getPercentile(durations, 99),
        requestCount: durations.length,
        errorCount,
        successRate: (successCount / durations.length) * 100,
        totalSize: data.sizes.reduce((a: number, b: number) => a + b, 0),
      } as APIEndpointStats;
    });
  }, [filteredMetrics]);

  const timelineData = useMemo(() => {
    const grouped = filteredMetrics.reduce((acc, metric) => {
      const minute = Math.floor(metric.timestamp / 60000) * 60000;
      if (!acc[minute]) {
        acc[minute] = {
          time: minute,
          avgDuration: [],
          errorCount: 0,
          successCount: 0,
        };
      }
      acc[minute].avgDuration.push(metric.duration);
      if (metric.status >= 400) {
        acc[minute].errorCount++;
      } else {
        acc[minute].successCount++;
      }
      return acc;
    }, {} as Record<number, any>);

    return Object.values(grouped).map((data: any) => ({
      time: new Date(data.time).toLocaleTimeString(),
      avgDuration: data.avgDuration.reduce((a: number, b: number) => a + b, 0) / data.avgDuration.length,
      errorCount: data.errorCount,
      successCount: data.successCount,
      errorRate: (data.errorCount / (data.errorCount + data.successCount)) * 100,
    }));
  }, [filteredMetrics]);

  const distributionData = useMemo(() => {
    const buckets = [0, 100, 200, 500, 1000, 2000, 5000, 10000];
    const distribution = buckets.map((bucket, index) => {
      const nextBucket = buckets[index + 1] || Infinity;
      const count = filteredMetrics.filter(
        m => m.duration >= bucket && m.duration < nextBucket
      ).length;
      return {
        range: nextBucket === Infinity ? `>${bucket}ms` : `${bucket}-${nextBucket}ms`,
        count,
      };
    });
    return distribution.filter(d => d.count > 0);
  }, [filteredMetrics]);

  const uniqueEndpoints = useMemo(() => {
    const endpoints = new Set(performanceData.apiMetrics.map(m => m.endpoint));
    return Array.from(endpoints);
  }, [performanceData.apiMetrics]);

  const overallStats = useMemo(() => {
    if (filteredMetrics.length === 0) return null;
    
    const durations = filteredMetrics.map(m => m.duration);
    const errorCount = filteredMetrics.filter(m => m.status >= 400).length;
    
    return {
      avgDuration: durations.reduce((a, b) => a + b, 0) / durations.length,
      p95: getPercentile(durations, 95),
      errorRate: (errorCount / filteredMetrics.length) * 100,
      totalRequests: filteredMetrics.length,
    };
  }, [filteredMetrics]);

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">API Response Time Monitor</Typography>
        <Box display="flex" gap={2}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time Range</InputLabel>
            <Select
              value={timeRange}
              label="Time Range"
              onChange={(e: SelectChangeEvent) => setTimeRange(e.target.value as any)}
            >
              <MenuItem value="1h">Last Hour</MenuItem>
              <MenuItem value="6h">Last 6 Hours</MenuItem>
              <MenuItem value="24h">Last 24 Hours</MenuItem>
              <MenuItem value="7d">Last 7 Days</MenuItem>
            </Select>
          </FormControl>
          
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Endpoint</InputLabel>
            <Select
              value={selectedEndpoint}
              label="Endpoint"
              onChange={(e: SelectChangeEvent) => setSelectedEndpoint(e.target.value)}
            >
              <MenuItem value="all">All Endpoints</MenuItem>
              {uniqueEndpoints.map(endpoint => (
                <MenuItem key={endpoint} value={endpoint}>{endpoint}</MenuItem>
              ))}
            </Select>
          </FormControl>
          
          <IconButton size="small" onClick={() => window.location.reload()}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {overallStats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Avg Response Time
                </Typography>
                <Typography variant="h4">
                  {overallStats.avgDuration.toFixed(0)}ms
                </Typography>
                <Chip
                  size="small"
                  icon={<SpeedIcon />}
                  label={overallStats.avgDuration < 200 ? 'Fast' : overallStats.avgDuration < 1000 ? 'Normal' : 'Slow'}
                  color={overallStats.avgDuration < 200 ? 'success' : overallStats.avgDuration < 1000 ? 'default' : 'warning'}
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  P95 Response Time
                </Typography>
                <Typography variant="h4">
                  {overallStats.p95.toFixed(0)}ms
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Error Rate
                </Typography>
                <Typography variant="h4" color={overallStats.errorRate > 5 ? 'error' : 'inherit'}>
                  {overallStats.errorRate.toFixed(1)}%
                </Typography>
                {overallStats.errorRate > 5 && (
                  <Chip
                    size="small"
                    icon={<WarningIcon />}
                    label="High error rate"
                    color="error"
                  />
                )}
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Requests
                </Typography>
                <Typography variant="h4">
                  {overallStats.totalRequests}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Box sx={{ mb: 2 }}>
        <Chip
          label="Timeline"
          onClick={() => setViewMode('timeline')}
          color={viewMode === 'timeline' ? 'primary' : 'default'}
          sx={{ mr: 1 }}
        />
        <Chip
          label="Distribution"
          onClick={() => setViewMode('distribution')}
          color={viewMode === 'distribution' ? 'primary' : 'default'}
          sx={{ mr: 1 }}
        />
        <Chip
          label="Endpoints"
          onClick={() => setViewMode('table')}
          color={viewMode === 'table' ? 'primary' : 'default'}
        />
      </Box>

      {viewMode === 'timeline' && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Response Time Timeline
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis label={{ value: 'Duration (ms)', angle: -90, position: 'insideLeft' }} />
                    <RechartsTooltip />
                    <Legend />
                    <Area type="monotone" dataKey="avgDuration" stroke="#8884d8" fill="#8884d8" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Error Rate Timeline
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis label={{ value: 'Error Rate (%)', angle: -90, position: 'insideLeft' }} />
                    <RechartsTooltip />
                    <Line type="monotone" dataKey="errorRate" stroke="#f44336" />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {viewMode === 'distribution' && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Response Time Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={distributionData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="range" />
                    <YAxis label={{ value: 'Request Count', angle: -90, position: 'insideLeft' }} />
                    <RechartsTooltip />
                    <Bar dataKey="count" fill="#82ca9d" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Response Time Scatter
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <ScatterChart>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" domain={['dataMin', 'dataMax']} type="number" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()} />
                    <YAxis dataKey="duration" label={{ value: 'Duration (ms)', angle: -90, position: 'insideLeft' }} />
                    <RechartsTooltip 
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                      formatter={(value: any) => `${value}ms`}
                    />
                    <Scatter data={filteredMetrics} fill="#8884d8" />
                  </ScatterChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {viewMode === 'table' && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Endpoint Performance
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Endpoint</TableCell>
                    <TableCell>Method</TableCell>
                    <TableCell align="right">Avg (ms)</TableCell>
                    <TableCell align="right">P50 (ms)</TableCell>
                    <TableCell align="right">P95 (ms)</TableCell>
                    <TableCell align="right">P99 (ms)</TableCell>
                    <TableCell align="right">Requests</TableCell>
                    <TableCell align="right">Success Rate</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {endpointStats.map((stat, index) => (
                    <TableRow key={index}>
                      <TableCell>{stat.endpoint}</TableCell>
                      <TableCell>
                        <Chip label={stat.method} size="small" />
                      </TableCell>
                      <TableCell align="right">{stat.avgDuration.toFixed(0)}</TableCell>
                      <TableCell align="right">{stat.p50.toFixed(0)}</TableCell>
                      <TableCell align="right">{stat.p95.toFixed(0)}</TableCell>
                      <TableCell align="right">{stat.p99.toFixed(0)}</TableCell>
                      <TableCell align="right">{stat.requestCount}</TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          {stat.successRate >= 99 ? (
                            <CheckCircleIcon color="success" fontSize="small" />
                          ) : stat.successRate >= 95 ? (
                            <WarningIcon color="warning" fontSize="small" />
                          ) : (
                            <ErrorIcon color="error" fontSize="small" />
                          )}
                          <Typography variant="body2" sx={{ ml: 0.5 }}>
                            {stat.successRate.toFixed(1)}%
                          </Typography>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};