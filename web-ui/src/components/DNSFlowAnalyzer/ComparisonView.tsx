import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Divider,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
} from '@mui/material';
import { TrendingUp, TrendingDown, TrendingFlat, CompareArrows } from '@mui/icons-material';
import { DNSQuery, TimeRange } from './types';
import { Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface ComparisonViewProps {
  leftQueries: DNSQuery[];
  rightQueries: DNSQuery[];
  timeRange: TimeRange;
}

interface ComparisonMetrics {
  totalQueries: number;
  avgLatency: number;
  maxLatency: number;
  minLatency: number;
  errorRate: number;
  cacheHitRate: number;
  queryTypes: Map<string, number>;
  responseCodes: Map<string, number>;
  topDomains: Map<string, number>;
}

const ComparisonView: React.FC<ComparisonViewProps> = ({
  leftQueries,
  rightQueries,
  timeRange,
}) => {
  const calculateMetrics = (queries: DNSQuery[]): ComparisonMetrics => {
    const metrics: ComparisonMetrics = {
      totalQueries: queries.length,
      avgLatency: 0,
      maxLatency: 0,
      minLatency: Infinity,
      errorRate: 0,
      cacheHitRate: 0,
      queryTypes: new Map(),
      responseCodes: new Map(),
      topDomains: new Map(),
    };

    if (queries.length === 0) return metrics;

    let totalLatency = 0;
    let errorCount = 0;
    let cacheHits = 0;

    queries.forEach(query => {
      totalLatency += query.latency;
      metrics.maxLatency = Math.max(metrics.maxLatency, query.latency);
      metrics.minLatency = Math.min(metrics.minLatency, query.latency);

      if (query.responseCode !== 'NOERROR') {
        errorCount++;
      }

      if (query.cached) {
        cacheHits++;
      }

      // Count query types
      const typeCount = metrics.queryTypes.get(query.queryType) || 0;
      metrics.queryTypes.set(query.queryType, typeCount + 1);

      // Count response codes
      const codeCount = metrics.responseCodes.get(query.responseCode) || 0;
      metrics.responseCodes.set(query.responseCode, codeCount + 1);

      // Count domains
      const domain = query.queryName?.split('.').slice(-2).join('.') || 'unknown';
      const domainCount = metrics.topDomains.get(domain) || 0;
      metrics.topDomains.set(domain, domainCount + 1);
    });

    metrics.avgLatency = totalLatency / queries.length;
    metrics.errorRate = (errorCount / queries.length) * 100;
    metrics.cacheHitRate = (cacheHits / queries.length) * 100;

    return metrics;
  };

  const leftMetrics = calculateMetrics(leftQueries);
  const rightMetrics = calculateMetrics(rightQueries);

  const getChangeIndicator = (left: number, right: number) => {
    const change = ((right - left) / left) * 100;
    if (Math.abs(change) < 1) {
      return { icon: <TrendingFlat />, color: 'info', value: '0%' };
    } else if (change > 0) {
      return { icon: <TrendingUp />, color: 'error', value: `+${change.toFixed(1)}%` };
    } else {
      return { icon: <TrendingDown />, color: 'success', value: `${change.toFixed(1)}%` };
    }
  };

  const createComparisonChart = () => {
    const labels = ['Queries', 'Avg Latency', 'Error Rate', 'Cache Hits'];
    const leftData = [
      leftMetrics.totalQueries,
      leftMetrics.avgLatency,
      leftMetrics.errorRate,
      leftMetrics.cacheHitRate,
    ];
    const rightData = [
      rightMetrics.totalQueries,
      rightMetrics.avgLatency,
      rightMetrics.errorRate,
      rightMetrics.cacheHitRate,
    ];

    return {
      labels,
      datasets: [
        {
          label: 'Period 1',
          data: leftData,
          backgroundColor: 'rgba(54, 162, 235, 0.5)',
          borderColor: 'rgba(54, 162, 235, 1)',
          borderWidth: 1,
        },
        {
          label: 'Period 2',
          data: rightData,
          backgroundColor: 'rgba(255, 99, 132, 0.5)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 1,
        },
      ],
    };
  };

  const createLatencyDistribution = () => {
    const buckets = [0, 50, 100, 150, 200, 300, 500, 1000];
    const leftDistribution = new Array(buckets.length - 1).fill(0);
    const rightDistribution = new Array(buckets.length - 1).fill(0);

    leftQueries.forEach(query => {
      for (let i = 0; i < buckets.length - 1; i++) {
        if (query.latency >= buckets[i] && query.latency < buckets[i + 1]) {
          leftDistribution[i]++;
          break;
        }
      }
    });

    rightQueries.forEach(query => {
      for (let i = 0; i < buckets.length - 1; i++) {
        if (query.latency >= buckets[i] && query.latency < buckets[i + 1]) {
          rightDistribution[i]++;
          break;
        }
      }
    });

    return {
      labels: buckets.slice(0, -1).map((b, i) => `${b}-${buckets[i + 1]}ms`),
      datasets: [
        {
          label: 'Period 1',
          data: leftDistribution,
          backgroundColor: 'rgba(54, 162, 235, 0.5)',
        },
        {
          label: 'Period 2',
          data: rightDistribution,
          backgroundColor: 'rgba(255, 99, 132, 0.5)',
        },
      ],
    };
  };

  const MetricCard = ({ title, leftValue, rightValue, format = 'number' }: any) => {
    const formatValue = (value: number) => {
      switch (format) {
        case 'ms':
          return `${value.toFixed(1)}ms`;
        case 'percent':
          return `${value.toFixed(1)}%`;
        default:
          return value.toFixed(0);
      }
    };

    const change = getChangeIndicator(leftValue, rightValue);

    return (
      <Card>
        <CardContent>
          <Typography variant="subtitle2" color="textSecondary" gutterBottom>
            {title}
          </Typography>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={5}>
              <Typography variant="h6">
                {formatValue(leftValue)}
              </Typography>
            </Grid>
            <Grid item xs={2}>
              <Box sx={{ display: 'flex', justifyContent: 'center', color: change.color }}>
                {change.icon}
              </Box>
            </Grid>
            <Grid item xs={5}>
              <Typography variant="h6">
                {formatValue(rightValue)}
              </Typography>
            </Grid>
          </Grid>
          <Box sx={{ mt: 1, textAlign: 'center' }}>
            <Chip
              size="small"
              label={change.value}
              color={change.color as any}
              variant="outlined"
            />
          </Box>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box sx={{ width: '100%', height: '100%', overflow: 'auto' }}>
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <CompareArrows />
          <Typography variant="h6">
            Side-by-Side Comparison
          </Typography>
        </Box>
        <Grid container spacing={2}>
          <Grid item xs={6}>
            <Typography variant="subtitle1" gutterBottom>
              Period 1: {leftQueries.length} queries
            </Typography>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="subtitle1" gutterBottom>
              Period 2: {rightQueries.length} queries
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      <Grid container spacing={2}>
        {/* Key Metrics */}
        <Grid item xs={12}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <MetricCard
                title="Total Queries"
                leftValue={leftMetrics.totalQueries}
                rightValue={rightMetrics.totalQueries}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <MetricCard
                title="Average Latency"
                leftValue={leftMetrics.avgLatency}
                rightValue={rightMetrics.avgLatency}
                format="ms"
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <MetricCard
                title="Error Rate"
                leftValue={leftMetrics.errorRate}
                rightValue={rightMetrics.errorRate}
                format="percent"
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <MetricCard
                title="Cache Hit Rate"
                leftValue={leftMetrics.cacheHitRate}
                rightValue={rightMetrics.cacheHitRate}
                format="percent"
              />
            </Grid>
          </Grid>
        </Grid>

        {/* Comparison Chart */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Metrics Comparison
            </Typography>
            <Bar
              data={createComparisonChart()}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'top' as const,
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                  },
                },
              }}
            />
          </Paper>
        </Grid>

        {/* Latency Distribution */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Latency Distribution
            </Typography>
            <Bar
              data={createLatencyDistribution()}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'top' as const,
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                  },
                },
              }}
            />
          </Paper>
        </Grid>

        {/* Query Types Comparison */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Query Types Distribution
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell align="right">Period 1</TableCell>
                    <TableCell align="right">Period 2</TableCell>
                    <TableCell align="right">Change</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {Array.from(new Set([...leftMetrics.queryTypes.keys(), ...rightMetrics.queryTypes.keys()]))
                    .map(type => {
                      const left = leftMetrics.queryTypes.get(type) || 0;
                      const right = rightMetrics.queryTypes.get(type) || 0;
                      const change = left > 0 ? ((right - left) / left) * 100 : 100;
                      return (
                        <TableRow key={type}>
                          <TableCell>{type}</TableCell>
                          <TableCell align="right">{left}</TableCell>
                          <TableCell align="right">{right}</TableCell>
                          <TableCell align="right">
                            <Chip
                              size="small"
                              label={`${change > 0 ? '+' : ''}${change.toFixed(1)}%`}
                              color={change > 0 ? 'error' : 'success'}
                              variant="outlined"
                            />
                          </TableCell>
                        </TableRow>
                      );
                    })}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Response Codes Comparison */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Response Codes Distribution
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Code</TableCell>
                    <TableCell align="right">Period 1</TableCell>
                    <TableCell align="right">Period 2</TableCell>
                    <TableCell align="right">Change</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {Array.from(new Set([...leftMetrics.responseCodes.keys(), ...rightMetrics.responseCodes.keys()]))
                    .map(code => {
                      const left = leftMetrics.responseCodes.get(code) || 0;
                      const right = rightMetrics.responseCodes.get(code) || 0;
                      const change = left > 0 ? ((right - left) / left) * 100 : 100;
                      return (
                        <TableRow key={code}>
                          <TableCell>
                            <Chip
                              label={code}
                              size="small"
                              color={code === 'NOERROR' ? 'success' : 'error'}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell align="right">{left}</TableCell>
                          <TableCell align="right">{right}</TableCell>
                          <TableCell align="right">
                            {change > 0 ? '+' : ''}{change.toFixed(1)}%
                          </TableCell>
                        </TableRow>
                      );
                    })}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ComparisonView;