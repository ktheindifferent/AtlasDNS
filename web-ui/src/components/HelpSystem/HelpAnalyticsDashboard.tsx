import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Divider,
  Button,
  IconButton,
  Tooltip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  CheckCircle as ResolvedIcon,
  Cancel as UnresolvedIcon,
  Timer as DurationIcon,
  QuestionAnswer as InteractionIcon,
  Psychology as AIIcon,
  Search as SearchIcon,
  VideoLibrary as VideoIcon,
  Help as HelpIcon,
  People as UsersIcon,
  Star as SatisfactionIcon,
  Download as ExportIcon,
  Refresh as RefreshIcon,
  DateRange as DateIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import { loadAnalytics } from '../../store/slices/helpSlice';
import { HelpAnalytics } from './types';

const HelpAnalyticsDashboard: React.FC = () => {
  const theme = useTheme();
  const dispatch = useDispatch();
  
  const { analytics, loading } = useSelector((state: RootState) => state.help);
  
  const [timeRange, setTimeRange] = useState<'day' | 'week' | 'month'>('week');
  const [refreshing, setRefreshing] = useState(false);
  
  useEffect(() => {
    loadAnalyticsData();
  }, []);
  
  const loadAnalyticsData = async () => {
    setRefreshing(true);
    try {
      await dispatch(loadAnalytics()).unwrap();
    } finally {
      setRefreshing(false);
    }
  };
  
  if (loading || !analytics) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }
  
  // Calculate metrics
  const resolutionRate = (analytics.resolvedQueries / analytics.totalInteractions) * 100;
  const avgSatisfaction = analytics.userSatisfaction;
  const peakHour = analytics.peakHelpHours.reduce((max, current) => 
    current.count > max.count ? current : max
  );
  
  // Prepare chart data
  const interactionTrendData = [
    { name: 'Mon', interactions: 145, resolved: 120 },
    { name: 'Tue', interactions: 189, resolved: 156 },
    { name: 'Wed', interactions: 234, resolved: 198 },
    { name: 'Thu', interactions: 256, resolved: 220 },
    { name: 'Fri', interactions: 278, resolved: 245 },
    { name: 'Sat', interactions: 134, resolved: 110 },
    { name: 'Sun', interactions: 98, resolved: 78 },
  ];
  
  const topicDistribution = analytics.mostSearchedTopics.map(topic => ({
    name: topic.topic,
    value: topic.count,
  }));
  
  const COLORS = [
    theme.palette.primary.main,
    theme.palette.secondary.main,
    theme.palette.success.main,
    theme.palette.warning.main,
    theme.palette.error.main,
  ];
  
  const interactionTypes = [
    { type: 'Chat', count: 456, icon: <AIIcon />, color: theme.palette.primary.main },
    { type: 'Search', count: 234, icon: <SearchIcon />, color: theme.palette.secondary.main },
    { type: 'FAQ', count: 189, icon: <HelpIcon />, color: theme.palette.info.main },
    { type: 'Video', count: 78, icon: <VideoIcon />, color: theme.palette.error.main },
    { type: 'Wizard', count: 45, icon: <AIIcon />, color: theme.palette.warning.main },
  ];
  
  return (
    <Box>
      {/* Header */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h4" gutterBottom>
              Help System Analytics
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Monitor and analyze help system usage and effectiveness
            </Typography>
          </Box>
          <Box display="flex" gap={2}>
            <Button
              variant="outlined"
              startIcon={<DateIcon />}
              onClick={() => {/* Open date picker */}}
            >
              {timeRange === 'day' ? 'Today' : timeRange === 'week' ? 'This Week' : 'This Month'}
            </Button>
            <IconButton onClick={loadAnalyticsData} disabled={refreshing}>
              <RefreshIcon />
            </IconButton>
            <Button
              variant="contained"
              startIcon={<ExportIcon />}
              onClick={() => {/* Export analytics */}}
            >
              Export
            </Button>
          </Box>
        </Box>
      </Paper>
      
      {/* Key Metrics */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" gutterBottom variant="overline">
                    Total Interactions
                  </Typography>
                  <Typography variant="h4">
                    {analytics.totalInteractions.toLocaleString()}
                  </Typography>
                  <Box display="flex" alignItems="center" mt={1}>
                    <TrendingUpIcon sx={{ fontSize: 16, color: theme.palette.success.main, mr: 0.5 }} />
                    <Typography variant="body2" color="success.main">
                      +12% from last period
                    </Typography>
                  </Box>
                </Box>
                <Avatar sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                  <InteractionIcon color="primary" />
                </Avatar>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" gutterBottom variant="overline">
                    Resolution Rate
                  </Typography>
                  <Typography variant="h4">
                    {resolutionRate.toFixed(1)}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={resolutionRate}
                    sx={{ mt: 1, height: 6, borderRadius: 3 }}
                    color="success"
                  />
                </Box>
                <Avatar sx={{ bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                  <ResolvedIcon color="success" />
                </Avatar>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" gutterBottom variant="overline">
                    Avg Resolution Time
                  </Typography>
                  <Typography variant="h4">
                    {analytics.averageResolutionTime}s
                  </Typography>
                  <Box display="flex" alignItems="center" mt={1}>
                    <TrendingDownIcon sx={{ fontSize: 16, color: theme.palette.success.main, mr: 0.5 }} />
                    <Typography variant="body2" color="success.main">
                      -8% improvement
                    </Typography>
                  </Box>
                </Box>
                <Avatar sx={{ bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                  <DurationIcon color="info" />
                </Avatar>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" gutterBottom variant="overline">
                    User Satisfaction
                  </Typography>
                  <Box display="flex" alignItems="baseline">
                    <Typography variant="h4">
                      {avgSatisfaction.toFixed(1)}
                    </Typography>
                    <Typography variant="h6" color="text.secondary" sx={{ ml: 0.5 }}>
                      /5
                    </Typography>
                  </Box>
                  <Box display="flex" mt={1}>
                    {[1, 2, 3, 4, 5].map(star => (
                      <SatisfactionIcon
                        key={star}
                        sx={{
                          fontSize: 16,
                          color: star <= avgSatisfaction ? theme.palette.warning.main : theme.palette.grey[300],
                        }}
                      />
                    ))}
                  </Box>
                </Box>
                <Avatar sx={{ bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                  <SatisfactionIcon color="warning" />
                </Avatar>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      
      {/* Charts */}
      <Grid container spacing={3}>
        {/* Interaction Trend */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Interaction Trend
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={interactionTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <ChartTooltip />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="interactions"
                  stackId="1"
                  stroke={theme.palette.primary.main}
                  fill={alpha(theme.palette.primary.main, 0.6)}
                  name="Total Interactions"
                />
                <Area
                  type="monotone"
                  dataKey="resolved"
                  stackId="2"
                  stroke={theme.palette.success.main}
                  fill={alpha(theme.palette.success.main, 0.6)}
                  name="Resolved"
                />
              </AreaChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        
        {/* Topic Distribution */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Popular Topics
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={topicDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {topicDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <ChartTooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        
        {/* Interaction Types */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Interaction Types
            </Typography>
            <List>
              {interactionTypes.map((type) => (
                <ListItem key={type.type}>
                  <ListItemIcon>
                    <Avatar sx={{ bgcolor: alpha(type.color, 0.1), color: type.color }}>
                      {type.icon}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={type.type}
                    secondary={`${type.count} interactions`}
                  />
                  <Box sx={{ minWidth: 100 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(type.count / 1000) * 100}
                      sx={{
                        height: 8,
                        borderRadius: 4,
                        bgcolor: alpha(type.color, 0.1),
                        '& .MuiLinearProgress-bar': {
                          bgcolor: type.color,
                        },
                      }}
                    />
                  </Box>
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>
        
        {/* Common Issues */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Common Issues
            </Typography>
            <List>
              {analytics.commonIssues.map((issue, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <Chip label={index + 1} size="small" />
                  </ListItemIcon>
                  <ListItemText
                    primary={issue.issue}
                    secondary={`Reported ${issue.frequency} times`}
                  />
                  <Tooltip title="View troubleshooting guide">
                    <IconButton size="small">
                      <HelpIcon />
                    </IconButton>
                  </Tooltip>
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>
        
        {/* Peak Usage Hours */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Peak Usage Hours
            </Typography>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={analytics.peakHelpHours}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" />
                <YAxis />
                <ChartTooltip />
                <Bar dataKey="count" fill={theme.palette.primary.main} />
              </BarChart>
            </ResponsiveContainer>
            <Box display="flex" justifyContent="center" mt={2}>
              <Chip
                icon={<DateIcon />}
                label={`Peak hour: ${peakHour.hour}:00 with ${peakHour.count} interactions`}
                color="primary"
              />
            </Box>
          </Paper>
        </Grid>
        
        {/* Contextual Patterns */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Contextual Usage Patterns
            </Typography>
            <Grid container spacing={2}>
              {analytics.contextualPatterns.map((pattern, index) => (
                <Grid item xs={12} sm={6} md={4} key={index}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle2" color="text.secondary">
                        {pattern.context.page}
                        {pattern.context.action && ` > ${pattern.context.action}`}
                      </Typography>
                      <Typography variant="h6">
                        {pattern.frequency} interactions
                      </Typography>
                      <Box display="flex" alignItems="center" mt={1}>
                        <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                          Resolution rate:
                        </Typography>
                        <Chip
                          label={`${(pattern.resolutionRate * 100).toFixed(0)}%`}
                          size="small"
                          color={pattern.resolutionRate > 0.8 ? 'success' : 'warning'}
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default HelpAnalyticsDashboard;