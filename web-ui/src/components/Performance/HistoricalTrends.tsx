import React, { useState, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent,
  ToggleButton,
  ToggleButtonGroup,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
  CompareArrows as CompareIcon,
  DateRange as DateRangeIcon,
} from '@mui/icons-material';
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
  Tooltip,
  Legend,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Cell,
} from 'recharts';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface TrendData {
  timestamp: string;
  LCP: number;
  FID: number;
  CLS: number;
  FCP: number;
  TTFB: number;
  avgRenderTime: number;
  memoryUsage: number;
  apiResponseTime: number;
}

interface ComparisonData {
  metric: string;
  current: number;
  previous: number;
  change: number;
  trend: 'up' | 'down' | 'stable';
}

const generateHistoricalData = (days: number): TrendData[] => {
  const data: TrendData[] = [];
  const now = Date.now();
  const interval = (days * 24 * 60 * 60 * 1000) / 100; // 100 data points
  
  for (let i = 0; i < 100; i++) {
    const timestamp = new Date(now - (100 - i) * interval);
    data.push({
      timestamp: timestamp.toLocaleDateString(),
      LCP: 2000 + Math.random() * 1000 + (i > 50 ? 200 : 0),
      FID: 50 + Math.random() * 100 + (i > 70 ? 50 : 0),
      CLS: 0.05 + Math.random() * 0.1 + (i > 80 ? 0.05 : 0),
      FCP: 1500 + Math.random() * 500,
      TTFB: 400 + Math.random() * 400,
      avgRenderTime: 30 + Math.random() * 50,
      memoryUsage: 50 + Math.random() * 30 + (i * 0.2),
      apiResponseTime: 100 + Math.random() * 200,
    });
  }
  
  return data;
};

export const HistoricalTrends: React.FC = () => {
  const { performanceData } = usePerformanceMonitor();
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [viewMode, setViewMode] = useState<'trends' | 'comparison' | 'radar'>('trends');
  const [selectedMetrics, setSelectedMetrics] = useState<string[]>(['LCP', 'FID', 'CLS']);

  const historicalData = useMemo(() => {
    const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
    return generateHistoricalData(days);
  }, [timeRange]);

  const comparisonData = useMemo((): ComparisonData[] => {
    const midPoint = Math.floor(historicalData.length / 2);
    const firstHalf = historicalData.slice(0, midPoint);
    const secondHalf = historicalData.slice(midPoint);
    
    const metrics = ['LCP', 'FID', 'CLS', 'FCP', 'TTFB', 'avgRenderTime', 'memoryUsage', 'apiResponseTime'];
    
    return metrics.map(metric => {
      const firstAvg = firstHalf.reduce((sum, d) => sum + (d as any)[metric], 0) / firstHalf.length;
      const secondAvg = secondHalf.reduce((sum, d) => sum + (d as any)[metric], 0) / secondHalf.length;
      const change = ((secondAvg - firstAvg) / firstAvg) * 100;
      
      return {
        metric,
        current: secondAvg,
        previous: firstAvg,
        change,
        trend: Math.abs(change) < 5 ? 'stable' : change > 0 ? 'up' : 'down',
      };
    });
  }, [historicalData]);

  const radarData = useMemo(() => {
    const latest = historicalData[historicalData.length - 1];
    const oldest = historicalData[0];
    
    return [
      {
        metric: 'LCP',
        current: (2500 - latest.LCP) / 25, // Normalize to 0-100
        previous: (2500 - oldest.LCP) / 25,
        fullMark: 100,
      },
      {
        metric: 'FID',
        current: (100 - latest.FID) / 1, // Normalize to 0-100
        previous: (100 - oldest.FID) / 1,
        fullMark: 100,
      },
      {
        metric: 'CLS',
        current: (0.1 - latest.CLS) * 1000, // Normalize to 0-100
        previous: (0.1 - oldest.CLS) * 1000,
        fullMark: 100,
      },
      {
        metric: 'FCP',
        current: (1800 - latest.FCP) / 18, // Normalize to 0-100
        previous: (1800 - oldest.FCP) / 18,
        fullMark: 100,
      },
      {
        metric: 'TTFB',
        current: (600 - latest.TTFB) / 6, // Normalize to 0-100
        previous: (600 - oldest.TTFB) / 6,
        fullMark: 100,
      },
    ];
  }, [historicalData]);

  const getTrendIcon = (trend: 'up' | 'down' | 'stable', metric: string) => {
    const isGoodUp = ['memoryUsage', 'LCP', 'FID', 'CLS', 'FCP', 'TTFB', 'apiResponseTime', 'avgRenderTime'].includes(metric);
    
    if (trend === 'stable') return <TrendingFlatIcon />;
    if (trend === 'up') {
      return isGoodUp ? <TrendingUpIcon color="error" /> : <TrendingUpIcon color="success" />;
    }
    return isGoodUp ? <TrendingDownIcon color="success" /> : <TrendingDownIcon color="error" />;
  };

  const getMetricLabel = (metric: string): string => {
    const labels: Record<string, string> = {
      LCP: 'Largest Contentful Paint',
      FID: 'First Input Delay',
      CLS: 'Cumulative Layout Shift',
      FCP: 'First Contentful Paint',
      TTFB: 'Time to First Byte',
      avgRenderTime: 'Avg Render Time',
      memoryUsage: 'Memory Usage',
      apiResponseTime: 'API Response Time',
    };
    return labels[metric] || metric;
  };

  const getMetricUnit = (metric: string): string => {
    if (metric === 'CLS') return '';
    if (metric === 'memoryUsage') return '%';
    return 'ms';
  };

  const handleMetricToggle = (metric: string) => {
    setSelectedMetrics(prev => 
      prev.includes(metric) 
        ? prev.filter(m => m !== metric)
        : [...prev, metric]
    );
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Historical Performance Trends
      </Typography>

      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <ToggleButtonGroup
          value={viewMode}
          exclusive
          onChange={(e, value) => value && setViewMode(value)}
        >
          <ToggleButton value="trends">
            <DateRangeIcon sx={{ mr: 1 }} />
            Trends
          </ToggleButton>
          <ToggleButton value="comparison">
            <CompareIcon sx={{ mr: 1 }} />
            Comparison
          </ToggleButton>
          <ToggleButton value="radar">
            Radar View
          </ToggleButton>
        </ToggleButtonGroup>

        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Time Range</InputLabel>
          <Select
            value={timeRange}
            label="Time Range"
            onChange={(e: SelectChangeEvent) => setTimeRange(e.target.value as any)}
          >
            <MenuItem value="7d">Last 7 Days</MenuItem>
            <MenuItem value="30d">Last 30 Days</MenuItem>
            <MenuItem value="90d">Last 90 Days</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {viewMode === 'trends' && (
        <>
          <Box mb={2}>
            {['LCP', 'FID', 'CLS', 'FCP', 'TTFB'].map(metric => (
              <Chip
                key={metric}
                label={metric}
                onClick={() => handleMetricToggle(metric)}
                color={selectedMetrics.includes(metric) ? 'primary' : 'default'}
                sx={{ mr: 1 }}
              />
            ))}
          </Box>

          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Core Web Vitals Trends
                  </Typography>
                  <ResponsiveContainer width="100%" height={400}>
                    <LineChart data={historicalData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      {selectedMetrics.includes('LCP') && (
                        <Line type="monotone" dataKey="LCP" stroke="#8884d8" name="LCP (ms)" />
                      )}
                      {selectedMetrics.includes('FID') && (
                        <Line type="monotone" dataKey="FID" stroke="#82ca9d" name="FID (ms)" />
                      )}
                      {selectedMetrics.includes('CLS') && (
                        <Line 
                          type="monotone" 
                          dataKey="CLS" 
                          stroke="#ffc658" 
                          name="CLS" 
                          yAxisId="right"
                        />
                      )}
                      {selectedMetrics.includes('FCP') && (
                        <Line type="monotone" dataKey="FCP" stroke="#ff7c7c" name="FCP (ms)" />
                      )}
                      {selectedMetrics.includes('TTFB') && (
                        <Line type="monotone" dataKey="TTFB" stroke="#8dd1e1" name="TTFB (ms)" />
                      )}
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Memory Usage Trend
                  </Typography>
                  <ResponsiveContainer width="100%" height={250}>
                    <AreaChart data={historicalData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <Tooltip />
                      <Area 
                        type="monotone" 
                        dataKey="memoryUsage" 
                        stroke="#9b59b6" 
                        fill="#9b59b6" 
                        fillOpacity={0.6}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    API Response Time Trend
                  </Typography>
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={historicalData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <Tooltip />
                      <Line 
                        type="monotone" 
                        dataKey="apiResponseTime" 
                        stroke="#e74c3c" 
                        strokeWidth={2}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </>
      )}

      {viewMode === 'comparison' && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Period-over-Period Comparison
                </Typography>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Comparing first half vs second half of selected period
                </Typography>
                
                <TableContainer component={Paper} sx={{ mt: 2 }}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Metric</TableCell>
                        <TableCell align="right">Previous Period</TableCell>
                        <TableCell align="right">Current Period</TableCell>
                        <TableCell align="right">Change</TableCell>
                        <TableCell align="center">Trend</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {comparisonData.map((data) => (
                        <TableRow key={data.metric}>
                          <TableCell>{getMetricLabel(data.metric)}</TableCell>
                          <TableCell align="right">
                            {data.previous.toFixed(2)} {getMetricUnit(data.metric)}
                          </TableCell>
                          <TableCell align="right">
                            {data.current.toFixed(2)} {getMetricUnit(data.metric)}
                          </TableCell>
                          <TableCell align="right">
                            <Chip
                              label={`${data.change > 0 ? '+' : ''}${data.change.toFixed(1)}%`}
                              size="small"
                              color={
                                Math.abs(data.change) < 5 ? 'default' :
                                (['memoryUsage', 'LCP', 'FID', 'CLS', 'FCP', 'TTFB', 'apiResponseTime', 'avgRenderTime'].includes(data.metric) 
                                  ? (data.change > 0 ? 'error' : 'success')
                                  : (data.change > 0 ? 'success' : 'error'))
                              }
                            />
                          </TableCell>
                          <TableCell align="center">
                            {getTrendIcon(data.trend, data.metric)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Change Visualization
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={comparisonData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="metric" />
                    <YAxis />
                    <Tooltip formatter={(value: any) => `${value.toFixed(1)}%`} />
                    <Bar dataKey="change" fill="#8884d8">
                      {comparisonData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`}
                          fill={
                            Math.abs(entry.change) < 5 ? '#95a5a6' :
                            (['memoryUsage', 'LCP', 'FID', 'CLS', 'FCP', 'TTFB', 'apiResponseTime', 'avgRenderTime'].includes(entry.metric)
                              ? (entry.change > 0 ? '#e74c3c' : '#27ae60')
                              : (entry.change > 0 ? '#27ae60' : '#e74c3c'))
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {viewMode === 'radar' && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Performance Radar
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Higher values indicate better performance
            </Typography>
            
            <ResponsiveContainer width="100%" height={400}>
              <RadarChart data={radarData}>
                <PolarGrid />
                <PolarAngleAxis dataKey="metric" />
                <PolarRadiusAxis angle={90} domain={[0, 100]} />
                <Radar
                  name="Current"
                  dataKey="current"
                  stroke="#8884d8"
                  fill="#8884d8"
                  fillOpacity={0.6}
                />
                <Radar
                  name="Previous"
                  dataKey="previous"
                  stroke="#82ca9d"
                  fill="#82ca9d"
                  fillOpacity={0.6}
                />
                <Legend />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};