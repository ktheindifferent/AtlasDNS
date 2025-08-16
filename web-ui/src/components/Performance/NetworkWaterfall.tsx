import React, { useMemo, useState } from 'react';
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
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  FileDownload as FileDownloadIcon,
  Image as ImageIcon,
  Code as CodeIcon,
  Description as DocumentIcon,
  FontDownload as FontIcon,
  Api as ApiIcon,
  Warning as WarningIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface NetworkResource {
  name: string;
  url: string;
  type: string;
  startTime: number;
  duration: number;
  size: number;
  transferSize: number;
  status: 'success' | 'slow' | 'failed';
  protocol: string;
}

const getResourceIcon = (type: string) => {
  switch (type) {
    case 'script':
    case 'javascript':
      return <CodeIcon fontSize="small" />;
    case 'stylesheet':
    case 'css':
      return <CodeIcon fontSize="small" color="secondary" />;
    case 'image':
    case 'img':
      return <ImageIcon fontSize="small" />;
    case 'font':
      return <FontIcon fontSize="small" />;
    case 'document':
    case 'html':
      return <DocumentIcon fontSize="small" />;
    case 'xhr':
    case 'fetch':
    case 'api':
      return <ApiIcon fontSize="small" />;
    default:
      return <FileDownloadIcon fontSize="small" />;
  }
};

const getResourceColor = (type: string) => {
  const colors: Record<string, string> = {
    script: '#f39c12',
    stylesheet: '#3498db',
    image: '#27ae60',
    font: '#9b59b6',
    document: '#e74c3c',
    xhr: '#1abc9c',
    fetch: '#1abc9c',
  };
  return colors[type] || '#95a5a6';
};

const formatSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
};

export const NetworkWaterfall: React.FC = () => {
  const { performanceData } = usePerformanceMonitor();
  const [filterType, setFilterType] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'startTime' | 'duration' | 'size'>('startTime');

  const resources = useMemo(() => {
    return performanceData.resourceTimings.map(timing => {
      const url = new URL(timing.name, window.location.origin);
      const filename = url.pathname.split('/').pop() || url.hostname;
      
      let type = timing.initiatorType;
      if (type === 'xmlhttprequest') type = 'xhr';
      if (type === 'img') type = 'image';
      if (type === 'link' && timing.name.includes('.css')) type = 'stylesheet';
      if (type === 'script' && timing.name.includes('.js')) type = 'script';
      
      const status = timing.duration > 1000 ? 'slow' : 
                    timing.duration === 0 ? 'failed' : 'success';
      
      return {
        name: filename,
        url: timing.name,
        type,
        startTime: timing.startTime,
        duration: timing.duration,
        size: timing.decodedBodySize,
        transferSize: timing.transferSize,
        status,
        protocol: url.protocol.replace(':', ''),
      } as NetworkResource;
    });
  }, [performanceData.resourceTimings]);

  const filteredResources = useMemo(() => {
    let filtered = filterType === 'all' ? resources : 
                   resources.filter(r => r.type === filterType);
    
    return filtered.sort((a, b) => {
      switch (sortBy) {
        case 'duration':
          return b.duration - a.duration;
        case 'size':
          return b.size - a.size;
        default:
          return a.startTime - b.startTime;
      }
    });
  }, [resources, filterType, sortBy]);

  const resourceTypes = useMemo(() => {
    const types = new Set(resources.map(r => r.type));
    return Array.from(types);
  }, [resources]);

  const stats = useMemo(() => {
    const totalSize = resources.reduce((sum, r) => sum + r.size, 0);
    const totalTransferSize = resources.reduce((sum, r) => sum + r.transferSize, 0);
    const totalDuration = Math.max(...resources.map(r => r.startTime + r.duration), 0);
    const slowResources = resources.filter(r => r.duration > 1000).length;
    
    const byType = resources.reduce((acc, r) => {
      if (!acc[r.type]) acc[r.type] = { count: 0, size: 0 };
      acc[r.type].count++;
      acc[r.type].size += r.size;
      return acc;
    }, {} as Record<string, { count: number; size: number }>);
    
    return {
      totalSize,
      totalTransferSize,
      totalDuration,
      slowResources,
      resourceCount: resources.length,
      byType,
      compressionSaved: totalSize - totalTransferSize,
    };
  }, [resources]);

  const timelineScale = useMemo(() => {
    if (filteredResources.length === 0) return { min: 0, max: 1000 };
    const min = Math.min(...filteredResources.map(r => r.startTime));
    const max = Math.max(...filteredResources.map(r => r.startTime + r.duration));
    return { min, max };
  }, [filteredResources]);

  const WaterfallBar: React.FC<{ resource: NetworkResource }> = ({ resource }) => {
    const { min, max } = timelineScale;
    const range = max - min || 1;
    const startPercent = ((resource.startTime - min) / range) * 100;
    const widthPercent = (resource.duration / range) * 100;
    
    return (
      <Box sx={{ position: 'relative', height: 20, bgcolor: 'grey.100' }}>
        <Tooltip title={`${resource.name}: ${formatDuration(resource.duration)}`}>
          <Box
            sx={{
              position: 'absolute',
              left: `${startPercent}%`,
              width: `${widthPercent}%`,
              height: '100%',
              bgcolor: getResourceColor(resource.type),
              opacity: resource.status === 'failed' ? 0.3 : 0.8,
              borderLeft: '1px solid white',
              minWidth: 2,
              '&:hover': {
                opacity: 1,
              },
            }}
          />
        </Tooltip>
      </Box>
    );
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Network Waterfall
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Resources
              </Typography>
              <Typography variant="h4">{stats.resourceCount}</Typography>
              {stats.slowResources > 0 && (
                <Chip
                  size="small"
                  icon={<WarningIcon />}
                  label={`${stats.slowResources} slow`}
                  color="warning"
                  sx={{ mt: 1 }}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Size
              </Typography>
              <Typography variant="h4">{formatSize(stats.totalSize)}</Typography>
              <Typography variant="body2" color="text.secondary">
                Transfer: {formatSize(stats.totalTransferSize)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Load Time
              </Typography>
              <Typography variant="h4">{formatDuration(stats.totalDuration)}</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Compression Saved
              </Typography>
              <Typography variant="h4" color="success.main">
                {formatSize(stats.compressionSaved)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stats.totalSize > 0 ? 
                  `${((stats.compressionSaved / stats.totalSize) * 100).toFixed(1)}% reduced` : 
                  '0% reduced'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Resource Breakdown
          </Typography>
          <Grid container spacing={2}>
            {Object.entries(stats.byType).map(([type, data]) => (
              <Grid item key={type}>
                <Chip
                  icon={getResourceIcon(type)}
                  label={`${type}: ${data.count} (${formatSize(data.size)})`}
                  sx={{ bgcolor: getResourceColor(type), color: 'white' }}
                />
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Resource Timeline</Typography>
            <Box display="flex" gap={2}>
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Filter</InputLabel>
                <Select
                  value={filterType}
                  label="Filter"
                  onChange={(e: SelectChangeEvent) => setFilterType(e.target.value)}
                >
                  <MenuItem value="all">All Types</MenuItem>
                  {resourceTypes.map(type => (
                    <MenuItem key={type} value={type}>{type}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Sort By</InputLabel>
                <Select
                  value={sortBy}
                  label="Sort By"
                  onChange={(e: SelectChangeEvent) => setSortBy(e.target.value as any)}
                >
                  <MenuItem value="startTime">Start Time</MenuItem>
                  <MenuItem value="duration">Duration</MenuItem>
                  <MenuItem value="size">Size</MenuItem>
                </Select>
              </FormControl>
            </Box>
          </Box>

          <TableContainer component={Paper} sx={{ maxHeight: 600 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right">Transfer</TableCell>
                  <TableCell align="right">Duration</TableCell>
                  <TableCell sx={{ minWidth: 300 }}>Timeline</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredResources.map((resource, index) => (
                  <TableRow key={index} hover>
                    <TableCell>
                      <Tooltip title={resource.type}>
                        {getResourceIcon(resource.type)}
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={resource.url}>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                          {resource.name}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell align="right">
                      <Typography variant="body2">
                        {formatSize(resource.size)}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Typography variant="body2">
                        {formatSize(resource.transferSize)}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Chip
                        label={formatDuration(resource.duration)}
                        size="small"
                        color={resource.status === 'slow' ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <WaterfallBar resource={resource} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Box>
  );
};