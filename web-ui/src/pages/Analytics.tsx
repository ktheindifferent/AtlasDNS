import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Chip,
  useTheme,
} from '@mui/material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
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
} from 'recharts';
// import { DateRangePicker } from '@mui/x-date-pickers-pro/DateRangePicker';
import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '../services/api';
import { Download, TrendingUp, QueryStats, Speed, Public } from '@mui/icons-material';
import { format } from 'date-fns';

const Analytics: React.FC = () => {
  const theme = useTheme();
  const [dateRange, setDateRange] = useState<[Date | null, Date | null]>([
    new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    new Date(),
  ]);
  const [period, setPeriod] = useState('7d');

  // Fetch query analytics
  const { data: queryData } = useQuery({
    queryKey: ['analytics-queries', period],
    queryFn: async () => {
      const response = await analyticsApi.queries({ period, interval: '1h' });
      return response.data;
    },
  });

  // Fetch performance metrics
  const { data: performanceData } = useQuery({
    queryKey: ['analytics-performance', period],
    queryFn: async () => {
      const response = await analyticsApi.performance({ period });
      return response.data;
    },
  });

  // Fetch geographic distribution
  const { data: geoData } = useQuery({
    queryKey: ['analytics-geography', period],
    queryFn: async () => {
      const response = await analyticsApi.geography({ period });
      return response.data;
    },
  });

  // Fetch top domains
  const { data: topDomains } = useQuery({
    queryKey: ['analytics-top-domains', period],
    queryFn: async () => {
      const response = await analyticsApi.topDomains({ period, limit: 10 });
      return response.data;
    },
  });

  // Fetch response codes
  const { data: responseCodeData } = useQuery({
    queryKey: ['analytics-response-codes', period],
    queryFn: async () => {
      const response = await analyticsApi.responseCodes({ period });
      return response.data;
    },
  });

  const pieColors = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

  const handleExport = async () => {
    try {
      const response = await analyticsApi.export({ period, format: 'csv' });
      // Handle file download
      const blob = new Blob([response.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analytics-${period}.csv`;
      a.click();
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" fontWeight="bold">
          Analytics Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Period</InputLabel>
            <Select
              value={period}
              onChange={(e) => setPeriod(e.target.value)}
              label="Period"
            >
              <MenuItem value="1h">Last Hour</MenuItem>
              <MenuItem value="24h">Last 24 Hours</MenuItem>
              <MenuItem value="7d">Last 7 Days</MenuItem>
              <MenuItem value="30d">Last 30 Days</MenuItem>
              <MenuItem value="90d">Last 90 Days</MenuItem>
            </Select>
          </FormControl>
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={handleExport}
          >
            Export
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <QueryStats color="primary" />
                <Typography color="text.secondary" variant="body2">
                  Total Queries
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {performanceData?.totalQueries?.toLocaleString() || '0'}
              </Typography>
              <Chip
                label="+12.5%"
                size="small"
                color="success"
                icon={<TrendingUp />}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Speed color="success" />
                <Typography color="text.secondary" variant="body2">
                  Avg Response Time
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {performanceData?.avgResponseTime || '0'}ms
              </Typography>
              <Chip
                label="-5.2%"
                size="small"
                color="success"
                icon={<TrendingUp />}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Public color="info" />
                <Typography color="text.secondary" variant="body2">
                  Unique Clients
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {performanceData?.uniqueClients?.toLocaleString() || '0'}
              </Typography>
              <Chip
                label="+8.3%"
                size="small"
                color="success"
                icon={<TrendingUp />}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Speed color="warning" />
                <Typography color="text.secondary" variant="body2">
                  Cache Hit Rate
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {performanceData?.cacheHitRate || '0'}%
              </Typography>
              <Chip
                label="+2.1%"
                size="small"
                color="success"
                icon={<TrendingUp />}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Query Volume Chart */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Query Volume Over Time
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={queryData}>
                  <defs>
                    <linearGradient id="colorQueries" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={theme.palette.primary.main} stopOpacity={0.8}/>
                      <stop offset="95%" stopColor={theme.palette.primary.main} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => format(new Date(value), 'MMM dd HH:mm')}
                  />
                  <YAxis />
                  <Tooltip />
                  <Area 
                    type="monotone" 
                    dataKey="queries" 
                    stroke={theme.palette.primary.main} 
                    fillOpacity={1} 
                    fill="url(#colorQueries)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Response Time and Top Domains */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Response Time Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={queryData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => format(new Date(value), 'HH:mm')}
                  />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="avgResponseTime" 
                    stroke={theme.palette.success.main} 
                    name="Avg Response Time (ms)"
                  />
                  <Line 
                    type="monotone" 
                    dataKey="p95ResponseTime" 
                    stroke={theme.palette.warning.main} 
                    name="P95 Response Time (ms)"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Domains
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={topDomains} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="domain" type="category" width={120} />
                  <Tooltip />
                  <Bar dataKey="queries" fill={theme.palette.primary.main} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Response Codes and Geographic Distribution */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Response Codes
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={responseCodeData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={(entry) => `${entry.name}: ${entry.value}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {responseCodeData?.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={pieColors[index % pieColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Geographic Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={geoData?.slice(0, 10)}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="country" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="queries" fill={theme.palette.info.main} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Analytics;