import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Alert,
  LinearProgress,
  Chip,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Memory as MemoryIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
};

const getMemoryStatus = (usedPercent: number) => {
  if (usedPercent < 50) return { color: 'success', label: 'Healthy', icon: <CheckCircleIcon /> };
  if (usedPercent < 75) return { color: 'warning', label: 'Moderate', icon: <WarningIcon /> };
  if (usedPercent < 90) return { color: 'error', label: 'High', icon: <ErrorIcon /> };
  return { color: 'error', label: 'Critical', icon: <ErrorIcon /> };
};

export const MemoryMonitor: React.FC = () => {
  const { performanceData, memoryLeakWarning, clearMetrics } = usePerformanceMonitor();
  const [gcEvents, setGcEvents] = useState<Array<{ time: number; freed: number }>>([]);
  const [leakSuspects, setLeakSuspects] = useState<string[]>([]);

  useEffect(() => {
    // Detect potential memory leaks
    if (performanceData.memoryMetrics.length > 10) {
      const recent = performanceData.memoryMetrics.slice(-10);
      const isIncreasing = recent.every((m, i) => 
        i === 0 || m.usedJSHeapSize >= recent[i - 1].usedJSHeapSize * 0.98
      );
      
      if (isIncreasing) {
        const suspects = [
          'Event listeners not being removed',
          'Large arrays or objects in closures',
          'Detached DOM nodes',
          'Timers not being cleared',
        ];
        setLeakSuspects(suspects);
      }
    }
  }, [performanceData.memoryMetrics]);

  const currentMemory = performanceData.memoryMetrics[performanceData.memoryMetrics.length - 1];
  const memoryHistory = performanceData.memoryMetrics.slice(-50).map((m, index) => ({
    time: new Date(m.timestamp).toLocaleTimeString(),
    used: m.usedJSHeapSize,
    total: m.totalJSHeapSize,
    limit: m.jsHeapSizeLimit,
    usedMB: m.usedJSHeapSize / (1024 * 1024),
    totalMB: m.totalJSHeapSize / (1024 * 1024),
  }));

  const memoryTrend = () => {
    if (performanceData.memoryMetrics.length < 2) return 'stable';
    const recent = performanceData.memoryMetrics.slice(-10);
    const older = performanceData.memoryMetrics.slice(-20, -10);
    
    if (older.length === 0) return 'stable';
    
    const recentAvg = recent.reduce((sum, m) => sum + m.usedJSHeapSize, 0) / recent.length;
    const olderAvg = older.reduce((sum, m) => sum + m.usedJSHeapSize, 0) / older.length;
    
    const change = ((recentAvg - olderAvg) / olderAvg) * 100;
    
    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  };

  const trend = memoryTrend();
  const usedPercent = currentMemory ? (currentMemory.usedJSHeapSize / currentMemory.jsHeapSizeLimit) * 100 : 0;
  const status = getMemoryStatus(usedPercent);

  const handleGarbageCollection = () => {
    if ('gc' in window) {
      (window as any).gc();
      const newGcEvent = {
        time: Date.now(),
        freed: currentMemory ? currentMemory.usedJSHeapSize * 0.2 : 0, // Estimate
      };
      setGcEvents(prev => [...prev, newGcEvent].slice(-10));
    } else {
      alert('Manual garbage collection is not available. Run Chrome with --expose-gc flag.');
    }
  };

  const memoryRecommendations = [
    {
      condition: usedPercent > 75,
      text: 'High memory usage detected. Consider optimizing large data structures.',
      severity: 'warning',
    },
    {
      condition: trend === 'increasing',
      text: 'Memory usage is trending upward. Monitor for potential leaks.',
      severity: 'info',
    },
    {
      condition: memoryLeakWarning,
      text: 'Potential memory leak detected! Review event listeners and closures.',
      severity: 'error',
    },
    {
      condition: performanceData.componentMetrics.filter(m => m.renderTime > 100).length > 10,
      text: 'Slow component renders may be causing memory pressure.',
      severity: 'warning',
    },
  ];

  const activeRecommendations = memoryRecommendations.filter(r => r.condition);

  if (!currentMemory) {
    return (
      <Box p={3}>
        <Alert severity="info">
          Memory monitoring is initializing. Data will appear shortly...
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Memory Usage Monitor
      </Typography>

      {memoryLeakWarning && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="subtitle1" fontWeight="bold">
            Memory Leak Warning!
          </Typography>
          <Typography variant="body2">
            Memory usage has been consistently increasing. This may indicate a memory leak.
          </Typography>
        </Alert>
      )}

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Used Memory
                  </Typography>
                  <Typography variant="h5">
                    {formatBytes(currentMemory.usedJSHeapSize)}
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={usedPercent}
                    sx={{
                      mt: 1,
                      height: 8,
                      borderRadius: 4,
                      bgcolor: 'grey.300',
                      '& .MuiLinearProgress-bar': {
                        bgcolor: status.color === 'success' ? 'success.main' : 
                               status.color === 'warning' ? 'warning.main' : 'error.main',
                      },
                    }}
                  />
                </Box>
                <MemoryIcon sx={{ fontSize: 40, color: 'text.secondary' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Allocated
              </Typography>
              <Typography variant="h5">
                {formatBytes(currentMemory.totalJSHeapSize)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                of {formatBytes(currentMemory.jsHeapSizeLimit)} limit
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Memory Status
              </Typography>
              <Box display="flex" alignItems="center" gap={1}>
                {status.icon}
                <Typography variant="h5" color={`${status.color}.main`}>
                  {status.label}
                </Typography>
              </Box>
              <Chip
                label={`${usedPercent.toFixed(1)}% used`}
                size="small"
                color={status.color as any}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Trend
              </Typography>
              <Box display="flex" alignItems="center" gap={1}>
                {trend === 'increasing' ? (
                  <TrendingUpIcon color="error" />
                ) : trend === 'decreasing' ? (
                  <TrendingDownIcon color="success" />
                ) : (
                  <TrendingUpIcon color="action" />
                )}
                <Typography variant="h5" textTransform="capitalize">
                  {trend}
                </Typography>
              </Box>
              <Button
                size="small"
                startIcon={<DeleteIcon />}
                onClick={handleGarbageCollection}
                sx={{ mt: 1 }}
              >
                Force GC
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Memory Usage Over Time
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={memoryHistory}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis label={{ value: 'Memory (MB)', angle: -90, position: 'insideLeft' }} />
                  <Tooltip formatter={(value: any) => `${value.toFixed(2)} MB`} />
                  <Area
                    type="monotone"
                    dataKey="usedMB"
                    stroke="#8884d8"
                    fill="#8884d8"
                    fillOpacity={0.6}
                    name="Used"
                  />
                  <Area
                    type="monotone"
                    dataKey="totalMB"
                    stroke="#82ca9d"
                    fill="#82ca9d"
                    fillOpacity={0.3}
                    name="Allocated"
                  />
                  <ReferenceLine
                    y={currentMemory.jsHeapSizeLimit / (1024 * 1024)}
                    stroke="red"
                    strokeDasharray="5 5"
                    label="Heap Limit"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Memory Health Check
              </Typography>
              {activeRecommendations.length === 0 ? (
                <Alert severity="success">
                  Memory usage is healthy. No issues detected.
                </Alert>
              ) : (
                <List>
                  {activeRecommendations.map((rec, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        {rec.severity === 'error' ? <ErrorIcon color="error" /> :
                         rec.severity === 'warning' ? <WarningIcon color="warning" /> :
                         <CheckCircleIcon color="info" />}
                      </ListItemIcon>
                      <ListItemText primary={rec.text} />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>

          {leakSuspects.length > 0 && (
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="error">
                  Potential Leak Sources
                </Typography>
                <List dense>
                  {leakSuspects.map((suspect, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <WarningIcon color="error" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={suspect} />
                    </ListItem>
                  ))}
                </List>
                <Button
                  fullWidth
                  variant="outlined"
                  color="primary"
                  onClick={clearMetrics}
                  sx={{ mt: 2 }}
                >
                  Clear Metrics & Reset
                </Button>
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>

      {gcEvents.length > 0 && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Garbage Collection Events
            </Typography>
            <Grid container spacing={2}>
              {gcEvents.map((event, index) => (
                <Grid item key={index}>
                  <Chip
                    label={`GC at ${new Date(event.time).toLocaleTimeString()}`}
                    size="small"
                    color="primary"
                  />
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};