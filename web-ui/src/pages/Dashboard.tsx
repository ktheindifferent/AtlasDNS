import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Button,
  IconButton,
  Tooltip,
  LinearProgress,
  Chip,
  Alert,
  useTheme,
  alpha,
} from '@mui/material';
import {
  TrendingUp,
  TrendingDown,
  Dns,
  Speed,
  Security,
  Storage,
  Refresh,
  MoreVert,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  CloudQueue,
  QueryStats,
  Timer,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
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
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { format, subDays } from 'date-fns';

import { analyticsApi, monitoringApi, zoneApi } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import StatCard from '../components/StatCard';
import ActivityFeed from '../components/ActivityFeed';
import QuickActions from '../components/QuickActions';

interface DashboardStats {
  totalQueries: number;
  queriesChange: number;
  avgResponseTime: number;
  responseTimeChange: number;
  activeZones: number;
  zonesChange: number;
  cacheHitRate: number;
  cacheHitRateChange: number;
  threats: number;
  threatsChange: number;
  uptime: number;
}

interface QueryData {
  timestamp: string;
  queries: number;
  responseTime: number;
}

const Dashboard: React.FC = () => {
  const theme = useTheme();
  const { messages, connected } = useWebSocket('/dashboard');
  const [realtimeData, setRealtimeData] = useState<QueryData[]>([]);

  // Fetch dashboard stats
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await analyticsApi.overview({ period: '24h' });
      return response.data as DashboardStats;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch query trends
  const { data: queryTrends, isLoading: trendsLoading } = useQuery({
    queryKey: ['query-trends'],
    queryFn: async () => {
      const response = await analyticsApi.queries({ 
        period: '7d',
        interval: '1h',
      });
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });

  // Fetch response code distribution
  const { data: responseCodeData } = useQuery({
    queryKey: ['response-codes'],
    queryFn: async () => {
      const response = await analyticsApi.responseCodes({ period: '24h' });
      return response.data;
    },
    refetchInterval: 60000,
  });

  // Fetch top domains
  const { data: topDomains } = useQuery({
    queryKey: ['top-domains'],
    queryFn: async () => {
      const response = await analyticsApi.topDomains({ limit: 10 });
      return response.data;
    },
    refetchInterval: 60000,
  });

  // Fetch system status
  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => {
      const response = await monitoringApi.status();
      return response.data;
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Handle real-time updates
  useEffect(() => {
    if (messages.length > 0) {
      const latestMessage = messages[messages.length - 1];
      if (latestMessage.type === 'query-update') {
        setRealtimeData(prev => {
          const newData = [...prev, latestMessage.data];
          // Keep only last 50 data points
          return newData.slice(-50);
        });
      }
    }
  }, [messages]);

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  const getChangeIcon = (change: number) => {
    if (change > 0) return <TrendingUp fontSize="small" color="success" />;
    if (change < 0) return <TrendingDown fontSize="small" color="error" />;
    return null;
  };

  const pieColors = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  if (statsLoading || trendsLoading) {
    return <LinearProgress />;
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" fontWeight="bold">
          Dashboard
        </Typography>
        <Box>
          <Chip
            icon={connected ? <CheckCircle /> : <ErrorIcon />}
            label={connected ? 'Connected' : 'Disconnected'}
            color={connected ? 'success' : 'error'}
            size="small"
            sx={{ mr: 2 }}
          />
          <Tooltip title="Refresh">
            <IconButton onClick={() => refetchStats()}>
              <Refresh />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* System Alert */}
      {systemStatus?.alerts && systemStatus.alerts.length > 0 && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {systemStatus.alerts[0].message}
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Total Queries"
            value={formatNumber(stats?.totalQueries || 0)}
            change={stats?.queriesChange || 0}
            icon={<QueryStats />}
            color={theme.palette.primary.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Avg Response Time"
            value={`${stats?.avgResponseTime || 0}ms`}
            change={stats?.responseTimeChange || 0}
            icon={<Timer />}
            color={theme.palette.success.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Active Zones"
            value={stats?.activeZones || 0}
            change={stats?.zonesChange || 0}
            icon={<Dns />}
            color={theme.palette.info.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Cache Hit Rate"
            value={`${stats?.cacheHitRate || 0}%`}
            change={stats?.cacheHitRateChange || 0}
            icon={<Storage />}
            color={theme.palette.warning.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Threats Blocked"
            value={formatNumber(stats?.threats || 0)}
            change={stats?.threatsChange || 0}
            icon={<Security />}
            color={theme.palette.error.main}
          />
        </Grid>
      </Grid>

      {/* Charts Row 1 */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Query Trends Chart */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Query Trends (7 Days)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={queryTrends}>
                  <defs>
                    <linearGradient id="colorQueries" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={theme.palette.primary.main} stopOpacity={0.8}/>
                      <stop offset="95%" stopColor={theme.palette.primary.main} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => format(new Date(value), 'MMM dd')}
                  />
                  <YAxis />
                  <RechartsTooltip />
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

        {/* Response Codes Pie Chart */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Response Codes (24h)
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
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row 2 */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Real-time Query Monitor */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Real-time Query Monitor
              </Typography>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={realtimeData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => format(new Date(value), 'HH:mm:ss')}
                  />
                  <YAxis />
                  <RechartsTooltip />
                  <Line 
                    type="monotone" 
                    dataKey="queries" 
                    stroke={theme.palette.primary.main} 
                    dot={false}
                    strokeWidth={2}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="responseTime" 
                    stroke={theme.palette.secondary.main} 
                    dot={false}
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Top Domains */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Domains
              </Typography>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={topDomains} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="domain" type="category" width={150} />
                  <RechartsTooltip />
                  <Bar dataKey="queries" fill={theme.palette.primary.main} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Bottom Row */}
      <Grid container spacing={3}>
        {/* Activity Feed */}
        <Grid item xs={12} md={4}>
          <ActivityFeed />
        </Grid>

        {/* Quick Actions */}
        <Grid item xs={12} md={4}>
          <QuickActions />
        </Grid>

        {/* System Health */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Health
              </Typography>
              <Box sx={{ mt: 2 }}>
                {systemStatus?.services?.map((service: any) => (
                  <Box
                    key={service.name}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      mb: 2,
                    }}
                  >
                    <Typography variant="body2">{service.name}</Typography>
                    <Chip
                      size="small"
                      label={service.status}
                      color={service.status === 'healthy' ? 'success' : 'error'}
                      icon={service.status === 'healthy' ? <CheckCircle /> : <ErrorIcon />}
                    />
                  </Box>
                ))}
              </Box>
              <Box sx={{ mt: 3 }}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Uptime
                </Typography>
                <Typography variant="h5" fontWeight="bold">
                  {stats?.uptime || 0}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={stats?.uptime || 0}
                  sx={{ mt: 1 }}
                  color={stats?.uptime >= 99.9 ? 'success' : 'warning'}
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;