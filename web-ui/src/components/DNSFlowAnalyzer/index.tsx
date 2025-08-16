import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  IconButton,
  Button,
  ButtonGroup,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Slider,
  Switch,
  FormControlLabel,
  Tooltip,
  SelectChangeEvent,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  PlayArrow,
  Pause,
  SkipNext,
  SkipPrevious,
  FastRewind,
  FastForward,
  Download,
  FilterList,
  CompareArrows,
  Stream,
  Warning,
  Timeline,
  NetworkCheck,
  Map as MapIcon,
  AccountTree,
  BubbleChart,
} from '@mui/icons-material';
import FlowDiagram from './FlowDiagram';
import SankeyDiagram from './SankeyDiagram';
import QueryChainVisualization from './QueryChainVisualization';
import LatencyHeatmap from './LatencyHeatmap';
import ComparisonView from './ComparisonView';
import FilterPanel from './FilterPanel';
import ExportPanel from './ExportPanel';
import { useWebSocket } from '../../hooks/useWebSocket';
import { DNSQuery, FilterOptions, TimeRange, VisualizationType } from './types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`dns-flow-tabpanel-${index}`}
      aria-labelledby={`dns-flow-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
};

const DNSFlowAnalyzer: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [currentTime, setCurrentTime] = useState(0);
  const [timeRange, setTimeRange] = useState<TimeRange>({
    start: new Date(Date.now() - 3600000),
    end: new Date(),
  });
  const [filters, setFilters] = useState<FilterOptions>({
    queryTypes: [],
    sources: [],
    responseCodes: [],
    minLatency: 0,
    maxLatency: 1000,
    showAnomalies: true,
  });
  const [comparisonMode, setComparisonMode] = useState(false);
  const [streamingMode, setStreamingMode] = useState(false);
  const [queries, setQueries] = useState<DNSQuery[]>([]);
  const [anomalies, setAnomalies] = useState<DNSQuery[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const playbackIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket connection for real-time streaming
  const { data: wsData, isConnected } = useWebSocket('/api/dns/stream', {
    enabled: streamingMode,
  });

  useEffect(() => {
    if (wsData && streamingMode) {
      const newQuery = wsData as DNSQuery;
      setQueries(prev => [...prev.slice(-999), newQuery]);
      
      // Check for anomalies
      if (detectAnomaly(newQuery)) {
        setAnomalies(prev => [...prev.slice(-99), newQuery]);
      }
    }
  }, [wsData, streamingMode]);

  useEffect(() => {
    if (isPlaying) {
      playbackIntervalRef.current = setInterval(() => {
        setCurrentTime(prev => {
          const next = prev + (100 * playbackSpeed);
          const duration = timeRange.end.getTime() - timeRange.start.getTime();
          return next >= duration ? 0 : next;
        });
      }, 100);
    } else if (playbackIntervalRef.current) {
      clearInterval(playbackIntervalRef.current);
    }

    return () => {
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current);
      }
    };
  }, [isPlaying, playbackSpeed, timeRange]);

  const detectAnomaly = (query: DNSQuery): boolean => {
    // Simple anomaly detection logic
    return query.latency > 500 || 
           query.responseCode !== 'NOERROR' ||
           query.queryCount > 100;
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handlePlayPause = () => {
    setIsPlaying(!isPlaying);
  };

  const handleSpeedChange = (event: Event, newValue: number | number[]) => {
    setPlaybackSpeed(newValue as number);
  };

  const handleTimeSliderChange = (event: Event, newValue: number | number[]) => {
    setCurrentTime(newValue as number);
  };

  const handleFilterChange = (newFilters: FilterOptions) => {
    setFilters(newFilters);
  };

  const handleExport = (format: 'png' | 'svg' | 'mp4', element: HTMLElement) => {
    // Export logic will be implemented in ExportPanel
  };

  const getFilteredQueries = (): DNSQuery[] => {
    return queries.filter(query => {
      if (filters.queryTypes.length > 0 && !filters.queryTypes.includes(query.queryType)) {
        return false;
      }
      if (filters.sources.length > 0 && !filters.sources.includes(query.source)) {
        return false;
      }
      if (filters.responseCodes.length > 0 && !filters.responseCodes.includes(query.responseCode)) {
        return false;
      }
      if (query.latency < filters.minLatency || query.latency > filters.maxLatency) {
        return false;
      }
      return true;
    });
  };

  const getTimeFilteredQueries = (): DNSQuery[] => {
    const filtered = getFilteredQueries();
    const currentTimestamp = timeRange.start.getTime() + currentTime;
    return filtered.filter(query => {
      const queryTime = new Date(query.timestamp).getTime();
      return queryTime <= currentTimestamp;
    });
  };

  return (
    <Box sx={{ width: '100%', height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Header Controls */}
      <Paper sx={{ p: 2, borderRadius: 0 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Typography variant="h5" component="h1">
                DNS Query Flow Analyzer
              </Typography>
              {streamingMode && (
                <Chip
                  icon={<Stream />}
                  label="Live Streaming"
                  color="success"
                  size="small"
                  variant="outlined"
                />
              )}
              {anomalies.length > 0 && (
                <Chip
                  icon={<Warning />}
                  label={`${anomalies.length} Anomalies`}
                  color="error"
                  size="small"
                />
              )}
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={streamingMode}
                    onChange={(e) => setStreamingMode(e.target.checked)}
                  />
                }
                label="Real-time Mode"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={comparisonMode}
                    onChange={(e) => setComparisonMode(e.target.checked)}
                  />
                }
                label="Comparison Mode"
              />
              <FilterPanel filters={filters} onChange={handleFilterChange} />
              <ExportPanel onExport={handleExport} />
            </Box>
          </Grid>
        </Grid>

        {/* Playback Controls */}
        {!streamingMode && (
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2} alignItems="center">
              <Grid item>
                <ButtonGroup variant="outlined" size="small">
                  <IconButton onClick={() => setCurrentTime(0)}>
                    <SkipPrevious />
                  </IconButton>
                  <IconButton onClick={() => setPlaybackSpeed(Math.max(0.25, playbackSpeed - 0.25))}>
                    <FastRewind />
                  </IconButton>
                  <IconButton onClick={handlePlayPause}>
                    {isPlaying ? <Pause /> : <PlayArrow />}
                  </IconButton>
                  <IconButton onClick={() => setPlaybackSpeed(Math.min(4, playbackSpeed + 0.25))}>
                    <FastForward />
                  </IconButton>
                  <IconButton onClick={() => setCurrentTime(timeRange.end.getTime() - timeRange.start.getTime())}>
                    <SkipNext />
                  </IconButton>
                </ButtonGroup>
              </Grid>
              <Grid item xs>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Typography variant="body2">Timeline:</Typography>
                  <Slider
                    value={currentTime}
                    onChange={handleTimeSliderChange}
                    min={0}
                    max={timeRange.end.getTime() - timeRange.start.getTime()}
                    valueLabelDisplay="auto"
                    valueLabelFormat={(value) => {
                      const date = new Date(timeRange.start.getTime() + value);
                      return date.toLocaleTimeString();
                    }}
                  />
                </Box>
              </Grid>
              <Grid item>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="body2">Speed:</Typography>
                  <Slider
                    value={playbackSpeed}
                    onChange={handleSpeedChange}
                    min={0.25}
                    max={4}
                    step={0.25}
                    marks
                    valueLabelDisplay="auto"
                    valueLabelFormat={(value) => `${value}x`}
                    sx={{ width: 100 }}
                  />
                </Box>
              </Grid>
            </Grid>
          </Box>
        )}
      </Paper>

      {/* Visualization Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={activeTab} onChange={handleTabChange} variant="scrollable" scrollButtons="auto">
          <Tab icon={<Timeline />} label="Flow Diagram" />
          <Tab icon={<AccountTree />} label="Sankey Diagram" />
          <Tab icon={<NetworkCheck />} label="Query Chain" />
          <Tab icon={<MapIcon />} label="Latency Heatmap" />
          {comparisonMode && <Tab icon={<CompareArrows />} label="Comparison" />}
        </Tabs>
      </Box>

      {/* Visualization Content */}
      <Box sx={{ flex: 1, overflow: 'hidden' }}>
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
            <CircularProgress />
          </Box>
        ) : (
          <>
            <TabPanel value={activeTab} index={0}>
              <FlowDiagram
                queries={getTimeFilteredQueries()}
                anomalies={filters.showAnomalies ? anomalies : []}
                currentTime={currentTime}
                isPlaying={isPlaying}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={1}>
              <SankeyDiagram
                queries={getTimeFilteredQueries()}
                height={600}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={2}>
              <QueryChainVisualization
                queries={getTimeFilteredQueries()}
                selectedQuery={queries[0]}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={3}>
              <LatencyHeatmap
                queries={getTimeFilteredQueries()}
                width={1200}
                height={600}
              />
            </TabPanel>
            {comparisonMode && (
              <TabPanel value={activeTab} index={4}>
                <ComparisonView
                  leftQueries={queries.slice(0, Math.floor(queries.length / 2))}
                  rightQueries={queries.slice(Math.floor(queries.length / 2))}
                  timeRange={timeRange}
                />
              </TabPanel>
            )}
          </>
        )}
      </Box>

      {/* Status Bar */}
      <Paper sx={{ p: 1, borderRadius: 0 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item>
            <Typography variant="body2" color="textSecondary">
              Queries: {getFilteredQueries().length}
            </Typography>
          </Grid>
          <Grid item>
            <Typography variant="body2" color="textSecondary">
              Time Range: {timeRange.start.toLocaleString()} - {timeRange.end.toLocaleString()}
            </Typography>
          </Grid>
          {streamingMode && (
            <Grid item>
              <Typography variant="body2" color={isConnected ? 'success.main' : 'error.main'}>
                {isConnected ? 'Connected' : 'Disconnected'}
              </Typography>
            </Grid>
          )}
        </Grid>
      </Paper>
    </Box>
  );
};

export default DNSFlowAnalyzer;