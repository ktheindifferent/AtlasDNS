import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  CircularProgress,
} from '@mui/material';
import {
  PlayIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  GlobeAltIcon,
  MapPinIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

interface DNSServer {
  id: string;
  name: string;
  location: string;
  provider: string;
  ip: string;
  continent: string;
  latency?: number;
}

interface PropagationResult {
  server: DNSServer;
  status: 'checking' | 'success' | 'failed' | 'timeout';
  response?: string;
  responseTime?: number;
  ttl?: number;
  propagated: boolean;
  error?: string;
  timestamp: Date;
}

interface PropagationCheck {
  id: string;
  domain: string;
  recordType: string;
  expectedValue: string;
  startTime: Date;
  results: Map<string, PropagationResult>;
  overallStatus: 'running' | 'complete' | 'partial';
  propagatedCount: number;
  totalCount: number;
}

const DNS_SERVERS: DNSServer[] = [
  { id: 'google-us', name: 'Google US', location: 'United States', provider: 'Google', ip: '8.8.8.8', continent: 'NA' },
  { id: 'google-eu', name: 'Google EU', location: 'Europe', provider: 'Google', ip: '8.8.4.4', continent: 'EU' },
  { id: 'cloudflare', name: 'Cloudflare', location: 'Global', provider: 'Cloudflare', ip: '1.1.1.1', continent: 'Global' },
  { id: 'quad9', name: 'Quad9', location: 'Switzerland', provider: 'Quad9', ip: '9.9.9.9', continent: 'EU' },
  { id: 'opendns', name: 'OpenDNS', location: 'United States', provider: 'Cisco', ip: '208.67.222.222', continent: 'NA' },
  { id: 'adguard', name: 'AdGuard', location: 'Cyprus', provider: 'AdGuard', ip: '94.140.14.14', continent: 'EU' },
  { id: 'comodo', name: 'Comodo', location: 'United States', provider: 'Comodo', ip: '8.26.56.26', continent: 'NA' },
  { id: 'level3', name: 'Level3', location: 'United States', provider: 'CenturyLink', ip: '209.244.0.3', continent: 'NA' },
  { id: 'verisign', name: 'Verisign', location: 'United States', provider: 'Verisign', ip: '64.6.64.6', continent: 'NA' },
  { id: 'neustar', name: 'Neustar', location: 'United States', provider: 'Neustar', ip: '156.154.70.1', continent: 'NA' },
  { id: 'yandex', name: 'Yandex', location: 'Russia', provider: 'Yandex', ip: '77.88.8.8', continent: 'EU' },
  { id: 'cleanbrowsing', name: 'CleanBrowsing', location: 'United States', provider: 'CleanBrowsing', ip: '185.228.168.9', continent: 'NA' },
];

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'];

const PropagationChecker: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [domain, setDomain] = useState('');
  const [recordType, setRecordType] = useState('A');
  const [expectedValue, setExpectedValue] = useState('');
  const [checking, setChecking] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [propagationCheck, setPropagationCheck] = useState<PropagationCheck | null>(null);
  const [selectedServers, setSelectedServers] = useState<string[]>(DNS_SERVERS.map(s => s.id));

  const checkPropagation = useCallback(async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setChecking(true);
    
    const check: PropagationCheck = {
      id: `check-${Date.now()}`,
      domain: domain.trim(),
      recordType,
      expectedValue: expectedValue.trim(),
      startTime: new Date(),
      results: new Map(),
      overallStatus: 'running',
      propagatedCount: 0,
      totalCount: selectedServers.length,
    };

    setPropagationCheck(check);

    const serversToCheck = DNS_SERVERS.filter(s => selectedServers.includes(s.id));
    
    for (const server of serversToCheck) {
      check.results.set(server.id, {
        server,
        status: 'checking',
        propagated: false,
        timestamp: new Date(),
      });
    }

    setPropagationCheck({...check});

    try {
      const promises = serversToCheck.map(async (server) => {
        try {
          const startTime = Date.now();
          const response = await dnsPlaygroundApi.checkPropagation({
            domain: domain.trim(),
            recordType,
            server: server.ip,
            expectedValue: expectedValue.trim() || undefined,
          });

          const result: PropagationResult = {
            server,
            status: 'success',
            response: response.data.response,
            responseTime: Date.now() - startTime,
            ttl: response.data.ttl,
            propagated: response.data.propagated,
            timestamp: new Date(),
          };

          check.results.set(server.id, result);
          if (result.propagated) {
            check.propagatedCount++;
          }
        } catch (error: any) {
          check.results.set(server.id, {
            server,
            status: 'failed',
            propagated: false,
            error: error.message,
            timestamp: new Date(),
          });
        }

        setPropagationCheck({...check});
      });

      await Promise.all(promises);

      check.overallStatus = check.propagatedCount === check.totalCount ? 'complete' : 'partial';
      setPropagationCheck({...check});

      const percentage = Math.round((check.propagatedCount / check.totalCount) * 100);
      enqueueSnackbar(
        `Propagation check complete: ${percentage}% propagated (${check.propagatedCount}/${check.totalCount})`,
        { variant: percentage === 100 ? 'success' : 'info' }
      );
    } catch (error: any) {
      enqueueSnackbar(error.message || 'Propagation check failed', { variant: 'error' });
    } finally {
      setChecking(false);
    }
  }, [domain, recordType, expectedValue, selectedServers, enqueueSnackbar]);

  useEffect(() => {
    if (autoRefresh && !checking) {
      const interval = setInterval(() => {
        checkPropagation();
      }, refreshInterval * 1000);

      return () => clearInterval(interval);
    }
  }, [autoRefresh, refreshInterval, checking, checkPropagation]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'success';
      case 'failed': return 'error';
      case 'timeout': return 'warning';
      case 'checking': return 'info';
      default: return 'default';
    }
  };

  const getContinentColor = (continent: string) => {
    const colors: Record<string, string> = {
      'NA': '#2196f3',
      'EU': '#4caf50',
      'AS': '#ff9800',
      'SA': '#9c27b0',
      'AF': '#f44336',
      'OC': '#00bcd4',
      'Global': '#757575',
    };
    return colors[continent] || '#757575';
  };

  const propagationPercentage = propagationCheck 
    ? Math.round((propagationCheck.propagatedCount / propagationCheck.totalCount) * 100)
    : 0;

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Propagation Checker
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Check DNS propagation across multiple global DNS servers
            </Typography>

            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Domain Name"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <FormControl fullWidth>
                  <InputLabel>Record Type</InputLabel>
                  <Select
                    value={recordType}
                    onChange={(e) => setRecordType(e.target.value)}
                    label="Record Type"
                  >
                    {RECORD_TYPES.map(type => (
                      <MenuItem key={type} value={type}>{type}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Expected Value (Optional)"
                  value={expectedValue}
                  onChange={(e) => setExpectedValue(e.target.value)}
                  placeholder="192.168.1.1"
                  helperText="Leave empty to check any value"
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={checking ? 
                    <CircularProgress size={20} color="inherit" /> : 
                    <PlayIcon style={{ width: 20, height: 20 }} />
                  }
                  onClick={checkPropagation}
                  disabled={checking}
                >
                  {checking ? 'Checking...' : 'Check'}
                </Button>
              </Grid>
            </Grid>

            <Box sx={{ mt: 2, display: 'flex', gap: 2, alignItems: 'center' }}>
              <FormControl size="small">
                <InputLabel>Auto Refresh</InputLabel>
                <Select
                  value={autoRefresh ? refreshInterval : 0}
                  onChange={(e) => {
                    const value = Number(e.target.value);
                    if (value === 0) {
                      setAutoRefresh(false);
                    } else {
                      setAutoRefresh(true);
                      setRefreshInterval(value);
                    }
                  }}
                  label="Auto Refresh"
                  sx={{ minWidth: 150 }}
                >
                  <MenuItem value={0}>Disabled</MenuItem>
                  <MenuItem value={30}>30 seconds</MenuItem>
                  <MenuItem value={60}>1 minute</MenuItem>
                  <MenuItem value={120}>2 minutes</MenuItem>
                  <MenuItem value={300}>5 minutes</MenuItem>
                </Select>
              </FormControl>
              
              {autoRefresh && (
                <Chip
                  icon={<ArrowPathIcon style={{ width: 16, height: 16 }} />}
                  label={`Refreshing every ${refreshInterval}s`}
                  color="primary"
                  size="small"
                />
              )}
            </Box>
          </Paper>
        </Grid>

        {propagationCheck && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                  <Typography variant="h6">
                    Propagation Status for {propagationCheck.domain}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                    <Chip
                      label={`${propagationPercentage}% Propagated`}
                      color={propagationPercentage === 100 ? 'success' : 'warning'}
                    />
                    <Typography variant="body2" color="text.secondary">
                      {propagationCheck.propagatedCount} of {propagationCheck.totalCount} servers
                    </Typography>
                  </Box>
                </Box>

                <LinearProgress 
                  variant="determinate" 
                  value={propagationPercentage}
                  sx={{ mb: 3, height: 8, borderRadius: 1 }}
                  color={propagationPercentage === 100 ? 'success' : 'primary'}
                />

                <TableContainer component={Paper} variant="outlined">
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Server</TableCell>
                        <TableCell>Location</TableCell>
                        <TableCell>Provider</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Response</TableCell>
                        <TableCell align="right">Response Time</TableCell>
                        <TableCell align="right">TTL</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Array.from(propagationCheck.results.values()).map((result) => (
                        <TableRow key={result.server.id}>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <GlobeAltIcon style={{ width: 16, height: 16 }} />
                              {result.server.name}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip
                              icon={<MapPinIcon style={{ width: 14, height: 14 }} />}
                              label={result.server.location}
                              size="small"
                              style={{ 
                                backgroundColor: getContinentColor(result.server.continent) + '20',
                                color: getContinentColor(result.server.continent),
                                borderColor: getContinentColor(result.server.continent),
                              }}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell>{result.server.provider}</TableCell>
                          <TableCell>
                            {result.status === 'checking' ? (
                              <CircularProgress size={20} />
                            ) : result.propagated ? (
                              <Chip
                                icon={<CheckCircleIcon style={{ width: 16, height: 16 }} />}
                                label="Propagated"
                                color="success"
                                size="small"
                              />
                            ) : (
                              <Chip
                                icon={result.status === 'failed' ? 
                                  <XCircleIcon style={{ width: 16, height: 16 }} /> :
                                  <ExclamationTriangleIcon style={{ width: 16, height: 16 }} />
                                }
                                label={result.status === 'failed' ? 'Failed' : 'Not Propagated'}
                                color={result.status === 'failed' ? 'error' : 'warning'}
                                size="small"
                              />
                            )}
                          </TableCell>
                          <TableCell>
                            {result.response ? (
                              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                {result.response}
                              </Typography>
                            ) : result.error ? (
                              <Typography variant="body2" color="error">
                                {result.error}
                              </Typography>
                            ) : (
                              '-'
                            )}
                          </TableCell>
                          <TableCell align="right">
                            {result.responseTime ? (
                              <Chip
                                icon={<ClockIcon style={{ width: 14, height: 14 }} />}
                                label={`${result.responseTime}ms`}
                                size="small"
                                variant="outlined"
                              />
                            ) : '-'}
                          </TableCell>
                          <TableCell align="right">
                            {result.ttl ? `${result.ttl}s` : '-'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                {propagationPercentage < 100 && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    DNS propagation is still in progress. Full propagation typically takes 4-48 hours depending on TTL values.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default PropagationChecker;