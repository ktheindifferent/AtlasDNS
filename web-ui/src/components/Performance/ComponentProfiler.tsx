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
  LinearProgress,
  IconButton,
  Collapse,
  Alert,
  FormControlLabel,
  Switch,
  Tooltip,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Speed as SpeedIcon,
  Memory as MemoryIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Treemap,
  Cell,
} from 'recharts';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface ComponentStats {
  name: string;
  renderCount: number;
  avgRenderTime: number;
  minRenderTime: number;
  maxRenderTime: number;
  lastRenderTime: number;
  totalRenderTime: number;
  renders: Array<{
    time: number;
    timestamp: number;
  }>;
}

const COLORS = ['#4caf50', '#8bc34a', '#ffeb3b', '#ff9800', '#f44336'];

const getRenderTimeColor = (time: number): string => {
  if (time < 16) return '#4caf50'; // Good - under 1 frame
  if (time < 50) return '#8bc34a'; // OK
  if (time < 100) return '#ffeb3b'; // Warning
  if (time < 200) return '#ff9800'; // Bad
  return '#f44336'; // Very bad
};

const getRenderTimeLabel = (time: number): string => {
  if (time < 16) return 'Excellent';
  if (time < 50) return 'Good';
  if (time < 100) return 'Fair';
  if (time < 200) return 'Slow';
  return 'Very Slow';
};

export const ComponentProfiler: React.FC = () => {
  const { performanceData } = usePerformanceMonitor();
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [showOnlyProblematic, setShowOnlyProblematic] = useState(false);
  const [sortBy, setSortBy] = useState<'name' | 'count' | 'avg' | 'total'>('total');

  const componentStats = useMemo(() => {
    const stats: Record<string, ComponentStats> = {};
    
    performanceData.componentMetrics.forEach(metric => {
      if (!stats[metric.componentName]) {
        stats[metric.componentName] = {
          name: metric.componentName,
          renderCount: 0,
          avgRenderTime: 0,
          minRenderTime: Infinity,
          maxRenderTime: 0,
          lastRenderTime: 0,
          totalRenderTime: 0,
          renders: [],
        };
      }
      
      const stat = stats[metric.componentName];
      stat.renderCount++;
      stat.totalRenderTime += metric.renderTime;
      stat.minRenderTime = Math.min(stat.minRenderTime, metric.renderTime);
      stat.maxRenderTime = Math.max(stat.maxRenderTime, metric.renderTime);
      stat.lastRenderTime = metric.renderTime;
      stat.renders.push({
        time: metric.renderTime,
        timestamp: metric.timestamp,
      });
    });
    
    Object.values(stats).forEach(stat => {
      stat.avgRenderTime = stat.totalRenderTime / stat.renderCount;
      if (stat.minRenderTime === Infinity) stat.minRenderTime = 0;
    });
    
    return Object.values(stats);
  }, [performanceData.componentMetrics]);

  const sortedStats = useMemo(() => {
    const filtered = showOnlyProblematic 
      ? componentStats.filter(s => s.avgRenderTime > 50)
      : componentStats;
    
    return [...filtered].sort((a, b) => {
      switch (sortBy) {
        case 'name':
          return a.name.localeCompare(b.name);
        case 'count':
          return b.renderCount - a.renderCount;
        case 'avg':
          return b.avgRenderTime - a.avgRenderTime;
        case 'total':
          return b.totalRenderTime - a.totalRenderTime;
        default:
          return 0;
      }
    });
  }, [componentStats, showOnlyProblematic, sortBy]);

  const treemapData = useMemo(() => {
    return sortedStats.slice(0, 20).map(stat => ({
      name: stat.name,
      size: stat.totalRenderTime,
      renderCount: stat.renderCount,
      avgTime: stat.avgRenderTime,
    }));
  }, [sortedStats]);

  const slowestComponents = useMemo(() => {
    return [...componentStats]
      .sort((a, b) => b.avgRenderTime - a.avgRenderTime)
      .slice(0, 10);
  }, [componentStats]);

  const mostFrequentComponents = useMemo(() => {
    return [...componentStats]
      .sort((a, b) => b.renderCount - a.renderCount)
      .slice(0, 10);
  }, [componentStats]);

  const toggleRowExpansion = (name: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(name)) {
      newExpanded.delete(name);
    } else {
      newExpanded.add(name);
    }
    setExpandedRows(newExpanded);
  };

  const totalRenderTime = componentStats.reduce((sum, stat) => sum + stat.totalRenderTime, 0);
  const totalRenderCount = componentStats.reduce((sum, stat) => sum + stat.renderCount, 0);
  const problematicCount = componentStats.filter(s => s.avgRenderTime > 50).length;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Component Render Performance
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Components
              </Typography>
              <Typography variant="h4">{componentStats.length}</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Renders
              </Typography>
              <Typography variant="h4">{totalRenderCount}</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Avg Render Time
              </Typography>
              <Typography variant="h4">
                {totalRenderCount > 0 ? (totalRenderTime / totalRenderCount).toFixed(1) : 0}ms
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: problematicCount > 0 ? 'error.light' : 'success.light' }}>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Slow Components
              </Typography>
              <Typography variant="h4">{problematicCount}</Typography>
              {problematicCount > 0 && (
                <Chip
                  icon={<WarningIcon />}
                  label="Need optimization"
                  color="error"
                  size="small"
                  sx={{ mt: 1 }}
                />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {problematicCount > 0 && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {problematicCount} component{problematicCount > 1 ? 's' : ''} with average render time above 50ms detected. 
          Consider optimizing with React.memo, useMemo, or useCallback.
        </Alert>
      )}

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Slowest Components (by avg render time)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={slowestComponents} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={150} />
                  <RechartsTooltip formatter={(value: any) => `${value.toFixed(1)}ms`} />
                  <Bar dataKey="avgRenderTime" fill="#ff9800" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Most Frequent Renders
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={mostFrequentComponents} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={150} />
                  <RechartsTooltip />
                  <Bar dataKey="renderCount" fill="#2196f3" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Render Time Distribution
          </Typography>
          <ResponsiveContainer width="100%" height={300}>
            <Treemap
              data={treemapData}
              dataKey="size"
              aspectRatio={4 / 3}
              stroke="#fff"
            >
              <RechartsTooltip
                content={({ active, payload }) => {
                  if (active && payload && payload[0]) {
                    const data = payload[0].payload;
                    return (
                      <Paper sx={{ p: 1 }}>
                        <Typography variant="body2">{data.name}</Typography>
                        <Typography variant="caption">
                          Total: {data.size.toFixed(1)}ms
                        </Typography>
                        <br />
                        <Typography variant="caption">
                          Avg: {data.avgTime.toFixed(1)}ms
                        </Typography>
                        <br />
                        <Typography variant="caption">
                          Renders: {data.renderCount}
                        </Typography>
                      </Paper>
                    );
                  }
                  return null;
                }}
              />
              {treemapData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={getRenderTimeColor(entry.avgTime)} />
              ))}
            </Treemap>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Component Details</Typography>
            <FormControlLabel
              control={
                <Switch
                  checked={showOnlyProblematic}
                  onChange={(e) => setShowOnlyProblematic(e.target.checked)}
                />
              }
              label="Show only slow components"
            />
          </Box>

          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell />
                  <TableCell 
                    onClick={() => setSortBy('name')}
                    sx={{ cursor: 'pointer', fontWeight: sortBy === 'name' ? 'bold' : 'normal' }}
                  >
                    Component
                  </TableCell>
                  <TableCell 
                    align="right"
                    onClick={() => setSortBy('count')}
                    sx={{ cursor: 'pointer', fontWeight: sortBy === 'count' ? 'bold' : 'normal' }}
                  >
                    Renders
                  </TableCell>
                  <TableCell 
                    align="right"
                    onClick={() => setSortBy('avg')}
                    sx={{ cursor: 'pointer', fontWeight: sortBy === 'avg' ? 'bold' : 'normal' }}
                  >
                    Avg Time
                  </TableCell>
                  <TableCell align="right">Min</TableCell>
                  <TableCell align="right">Max</TableCell>
                  <TableCell align="right">Last</TableCell>
                  <TableCell 
                    align="right"
                    onClick={() => setSortBy('total')}
                    sx={{ cursor: 'pointer', fontWeight: sortBy === 'total' ? 'bold' : 'normal' }}
                  >
                    Total Time
                  </TableCell>
                  <TableCell align="center">Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedStats.map((stat) => (
                  <React.Fragment key={stat.name}>
                    <TableRow>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => toggleRowExpansion(stat.name)}
                        >
                          {expandedRows.has(stat.name) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                        </IconButton>
                      </TableCell>
                      <TableCell>{stat.name}</TableCell>
                      <TableCell align="right">{stat.renderCount}</TableCell>
                      <TableCell align="right">
                        <Typography
                          variant="body2"
                          sx={{ color: getRenderTimeColor(stat.avgRenderTime) }}
                        >
                          {stat.avgRenderTime.toFixed(1)}ms
                        </Typography>
                      </TableCell>
                      <TableCell align="right">{stat.minRenderTime.toFixed(1)}ms</TableCell>
                      <TableCell align="right">{stat.maxRenderTime.toFixed(1)}ms</TableCell>
                      <TableCell align="right">{stat.lastRenderTime.toFixed(1)}ms</TableCell>
                      <TableCell align="right">{stat.totalRenderTime.toFixed(1)}ms</TableCell>
                      <TableCell align="center">
                        <Tooltip title={getRenderTimeLabel(stat.avgRenderTime)}>
                          <Chip
                            size="small"
                            icon={stat.avgRenderTime < 50 ? <CheckCircleIcon /> : <WarningIcon />}
                            label={getRenderTimeLabel(stat.avgRenderTime)}
                            sx={{
                              bgcolor: getRenderTimeColor(stat.avgRenderTime),
                              color: 'white',
                            }}
                          />
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell colSpan={9} sx={{ py: 0 }}>
                        <Collapse in={expandedRows.has(stat.name)} timeout="auto" unmountOnExit>
                          <Box sx={{ margin: 2 }}>
                            <Typography variant="subtitle2" gutterBottom>
                              Recent Render Times
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              {stat.renders.slice(-20).map((render, index) => (
                                <Chip
                                  key={index}
                                  label={`${render.time.toFixed(1)}ms`}
                                  size="small"
                                  sx={{
                                    bgcolor: getRenderTimeColor(render.time),
                                    color: 'white',
                                  }}
                                />
                              ))}
                            </Box>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Box>
  );
};