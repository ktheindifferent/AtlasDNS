import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  Alert,
} from '@mui/material';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  Treemap,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import {
  FolderOpen as FolderIcon,
  Assessment as AssessmentIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

interface BundleModule {
  name: string;
  size: number;
  gzipSize: number;
  parsedSize: number;
  path: string;
  children?: BundleModule[];
}

interface BundleStats {
  totalSize: number;
  gzipSize: number;
  parsedSize: number;
  modules: BundleModule[];
  chunks: Array<{
    name: string;
    size: number;
    modules: string[];
  }>;
  assets: Array<{
    name: string;
    size: number;
    type: string;
  }>;
}

const COLORS = [
  '#8884d8',
  '#82ca9d',
  '#ffc658',
  '#ff7c7c',
  '#8dd1e1',
  '#d084d0',
  '#ffb347',
  '#67b7dc',
];

const formatSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload[0]) {
    return (
      <Paper sx={{ p: 1 }}>
        <Typography variant="body2">
          {payload[0].name}: {formatSize(payload[0].value)}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {((payload[0].value / payload[0].payload.total) * 100).toFixed(1)}% of total
        </Typography>
      </Paper>
    );
  }
  return null;
};

export const BundleAnalyzer: React.FC = () => {
  const [bundleStats, setBundleStats] = useState<BundleStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedView, setSelectedView] = useState<'treemap' | 'pie' | 'table'>('treemap');

  useEffect(() => {
    // Simulate loading bundle stats
    // In a real implementation, this would fetch from webpack-bundle-analyzer or similar
    setTimeout(() => {
      const mockStats: BundleStats = {
        totalSize: 2457600,
        gzipSize: 819200,
        parsedSize: 1638400,
        modules: [
          { name: 'react', size: 128000, gzipSize: 42667, parsedSize: 85333, path: 'node_modules/react' },
          { name: 'react-dom', size: 768000, gzipSize: 256000, parsedSize: 512000, path: 'node_modules/react-dom' },
          { name: '@mui/material', size: 512000, gzipSize: 170667, parsedSize: 341333, path: 'node_modules/@mui/material' },
          { name: 'recharts', size: 384000, gzipSize: 128000, parsedSize: 256000, path: 'node_modules/recharts' },
          { name: 'd3', size: 256000, gzipSize: 85333, parsedSize: 170667, path: 'node_modules/d3' },
          { name: 'axios', size: 51200, gzipSize: 17067, parsedSize: 34133, path: 'node_modules/axios' },
          { name: 'app code', size: 358400, gzipSize: 119467, parsedSize: 238933, path: 'src' },
        ],
        chunks: [
          { name: 'main', size: 1638400, modules: ['app', 'react', 'react-dom', '@mui/material'] },
          { name: 'vendor', size: 614400, modules: ['recharts', 'd3'] },
          { name: 'async', size: 204800, modules: ['lazy-loaded-components'] },
        ],
        assets: [
          { name: 'main.js', size: 1638400, type: 'js' },
          { name: 'vendor.js', size: 614400, type: 'js' },
          { name: 'main.css', size: 102400, type: 'css' },
          { name: 'images', size: 102400, type: 'img' },
        ],
      };
      setBundleStats(mockStats);
      setLoading(false);
    }, 1000);
  }, []);

  const getTreemapData = () => {
    if (!bundleStats) return [];
    return bundleStats.modules.map(module => ({
      name: module.name,
      size: module.size,
      gzipSize: module.gzipSize,
      total: bundleStats.totalSize,
    }));
  };

  const getPieData = () => {
    if (!bundleStats) return [];
    return bundleStats.modules.map(module => ({
      name: module.name,
      value: module.size,
      total: bundleStats.totalSize,
    }));
  };

  const getAssetTypeData = () => {
    if (!bundleStats) return [];
    const grouped = bundleStats.assets.reduce((acc, asset) => {
      if (!acc[asset.type]) acc[asset.type] = 0;
      acc[asset.type] += asset.size;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(grouped).map(([type, size]) => ({
      type,
      size,
    }));
  };

  if (loading) {
    return (
      <Box p={3}>
        <LinearProgress />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Analyzing bundle...
        </Typography>
      </Box>
    );
  }

  if (!bundleStats) {
    return (
      <Alert severity="error">
        Failed to load bundle statistics. Make sure webpack-bundle-analyzer is configured.
      </Alert>
    );
  }

  const compressionRatio = ((1 - bundleStats.gzipSize / bundleStats.totalSize) * 100).toFixed(1);
  const isLargeBundle = bundleStats.totalSize > 1024 * 1024 * 2; // 2MB

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Bundle Size Analyzer
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Bundle Size
              </Typography>
              <Typography variant="h4" color={isLargeBundle ? 'error' : 'primary'}>
                {formatSize(bundleStats.totalSize)}
              </Typography>
              {isLargeBundle && (
                <Chip
                  icon={<WarningIcon />}
                  label="Large bundle"
                  color="warning"
                  size="small"
                  sx={{ mt: 1 }}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Gzipped Size
              </Typography>
              <Typography variant="h4" color="success.main">
                {formatSize(bundleStats.gzipSize)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {compressionRatio}% compression
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Parsed Size
              </Typography>
              <Typography variant="h4">
                {formatSize(bundleStats.parsedSize)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Modules Count
              </Typography>
              <Typography variant="h4">
                {bundleStats.modules.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ mb: 2 }}>
        <Button
          variant={selectedView === 'treemap' ? 'contained' : 'outlined'}
          onClick={() => setSelectedView('treemap')}
          sx={{ mr: 1 }}
        >
          Treemap
        </Button>
        <Button
          variant={selectedView === 'pie' ? 'contained' : 'outlined'}
          onClick={() => setSelectedView('pie')}
          sx={{ mr: 1 }}
        >
          Pie Chart
        </Button>
        <Button
          variant={selectedView === 'table' ? 'contained' : 'outlined'}
          onClick={() => setSelectedView('table')}
        >
          Table
        </Button>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Module Distribution
              </Typography>
              
              {selectedView === 'treemap' && (
                <ResponsiveContainer width="100%" height={400}>
                  <Treemap
                    data={getTreemapData()}
                    dataKey="size"
                    aspectRatio={4 / 3}
                    stroke="#fff"
                    fill="#8884d8"
                  >
                    <Tooltip content={<CustomTooltip />} />
                  </Treemap>
                </ResponsiveContainer>
              )}

              {selectedView === 'pie' && (
                <ResponsiveContainer width="100%" height={400}>
                  <PieChart>
                    <Pie
                      data={getPieData()}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                      outerRadius={150}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {getPieData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              )}

              {selectedView === 'table' && (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Module</TableCell>
                        <TableCell align="right">Size</TableCell>
                        <TableCell align="right">Gzipped</TableCell>
                        <TableCell align="right">% of Total</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {bundleStats.modules.map((module) => (
                        <TableRow key={module.name}>
                          <TableCell>
                            <Box display="flex" alignItems="center">
                              <FolderIcon fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                              {module.name}
                            </Box>
                          </TableCell>
                          <TableCell align="right">{formatSize(module.size)}</TableCell>
                          <TableCell align="right">{formatSize(module.gzipSize)}</TableCell>
                          <TableCell align="right">
                            {((module.size / bundleStats.totalSize) * 100).toFixed(1)}%
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Asset Types
              </Typography>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={getAssetTypeData()}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="type" />
                  <YAxis tickFormatter={(value) => formatSize(value)} />
                  <Tooltip
                    formatter={(value: number) => formatSize(value)}
                  />
                  <Bar dataKey="size" fill="#82ca9d" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Optimization Suggestions
              </Typography>
              <Box sx={{ '& > *': { mb: 1 } }}>
                {isLargeBundle && (
                  <Alert severity="warning">
                    Bundle size exceeds 2MB. Consider code splitting.
                  </Alert>
                )}
                {bundleStats.modules.some(m => m.name.includes('moment')) && (
                  <Alert severity="info">
                    Consider using date-fns instead of moment.js for smaller bundle size.
                  </Alert>
                )}
                {bundleStats.modules.some(m => m.size > 500000) && (
                  <Alert severity="info">
                    Large modules detected. Consider lazy loading or dynamic imports.
                  </Alert>
                )}
                <Alert severity="success">
                  Gzip compression is reducing bundle size by {compressionRatio}%.
                </Alert>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};