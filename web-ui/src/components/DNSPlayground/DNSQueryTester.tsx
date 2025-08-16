import React, { useState, useCallback } from 'react';
import {
  Box,
  Grid,
  TextField,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Paper,
  Typography,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  IconButton,
  Tooltip,
  LinearProgress,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControlLabel,
  Switch,
} from '@mui/material';
import {
  PlayIcon,
  ArrowPathIcon,
  ClockIcon,
  ServerIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChevronDownIcon,
  DocumentDuplicateIcon,
} from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

interface QueryResult {
  id: string;
  domain: string;
  type: string;
  server: string;
  timestamp: Date;
  responseTime: number;
  status: 'success' | 'error' | 'timeout';
  answers: DNSAnswer[];
  flags: DNSFlags;
  sections: DNSSections;
  raw?: string;
}

interface DNSAnswer {
  name: string;
  type: string;
  class: string;
  ttl: number;
  data: string;
  priority?: number;
  weight?: number;
  port?: number;
}

interface DNSFlags {
  recursionDesired: boolean;
  recursionAvailable: boolean;
  authoritative: boolean;
  truncated: boolean;
  authenticData: boolean;
  checkingDisabled: boolean;
  responseCode: string;
}

interface DNSSections {
  question: number;
  answer: number;
  authority: number;
  additional: number;
}

const QUERY_TYPES = [
  'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR',
  'SRV', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG',
  'SPF', 'TLSA', 'SSHFP', 'ANY'
];

const DNS_SERVERS = [
  { name: 'System Default', value: 'system' },
  { name: 'Google Public DNS', value: '8.8.8.8' },
  { name: 'Cloudflare', value: '1.1.1.1' },
  { name: 'Quad9', value: '9.9.9.9' },
  { name: 'OpenDNS', value: '208.67.222.222' },
  { name: 'AdGuard DNS', value: '94.140.14.14' },
  { name: 'Custom', value: 'custom' },
];

const DNSQueryTester: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [domain, setDomain] = useState('example.com');
  const [queryType, setQueryType] = useState('A');
  const [dnsServer, setDnsServer] = useState('system');
  const [customServer, setCustomServer] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<QueryResult[]>([]);
  const [advancedOptions, setAdvancedOptions] = useState(false);
  const [dnssec, setDnssec] = useState(false);
  const [recursion, setRecursion] = useState(true);
  const [ednsClientSubnet, setEdnsClientSubnet] = useState('');
  const [timeout, setTimeout] = useState(5000);

  const executeQuery = useCallback(async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setLoading(true);
    const startTime = Date.now();

    try {
      const serverToUse = dnsServer === 'custom' ? customServer : dnsServer;
      
      const response = await dnsPlaygroundApi.query({
        domain: domain.trim(),
        type: queryType,
        server: serverToUse,
        dnssec,
        recursion,
        ednsClientSubnet: ednsClientSubnet || undefined,
        timeout,
      });

      const result: QueryResult = {
        id: `query-${Date.now()}-${Math.random()}`,
        domain: domain.trim(),
        type: queryType,
        server: serverToUse === 'system' ? 'System Default' : serverToUse,
        timestamp: new Date(),
        responseTime: Date.now() - startTime,
        status: 'success',
        answers: response.data.answers || [],
        flags: response.data.flags || {},
        sections: response.data.sections || {},
        raw: response.data.raw,
      };

      setResults(prev => [result, ...prev.slice(0, 9)]);
      enqueueSnackbar('DNS query executed successfully', { variant: 'success' });
    } catch (error: any) {
      const result: QueryResult = {
        id: `query-${Date.now()}-${Math.random()}`,
        domain: domain.trim(),
        type: queryType,
        server: dnsServer === 'custom' ? customServer : dnsServer,
        timestamp: new Date(),
        responseTime: Date.now() - startTime,
        status: error.code === 'ETIMEDOUT' ? 'timeout' : 'error',
        answers: [],
        flags: {} as DNSFlags,
        sections: {} as DNSSections,
      };

      setResults(prev => [result, ...prev.slice(0, 9)]);
      enqueueSnackbar(error.message || 'DNS query failed', { variant: 'error' });
    } finally {
      setLoading(false);
    }
  }, [domain, queryType, dnsServer, customServer, dnssec, recursion, ednsClientSubnet, timeout, enqueueSnackbar]);

  const clearResults = () => {
    setResults([]);
    enqueueSnackbar('Results cleared', { variant: 'info' });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    enqueueSnackbar('Copied to clipboard', { variant: 'success' });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'success';
      case 'error': return 'error';
      case 'timeout': return 'warning';
      default: return 'default';
    }
  };

  const formatResponseCode = (code: string) => {
    const codes: Record<string, string> = {
      'NOERROR': 'No Error',
      'FORMERR': 'Format Error',
      'SERVFAIL': 'Server Failure',
      'NXDOMAIN': 'Non-Existent Domain',
      'NOTIMP': 'Not Implemented',
      'REFUSED': 'Query Refused',
    };
    return codes[code] || code;
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Query Configuration
            </Typography>
            
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Domain Name"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  onKeyPress={(e) => e.key === 'Enter' && executeQuery()}
                />
              </Grid>
              
              <Grid item xs={12} md={2}>
                <FormControl fullWidth>
                  <InputLabel>Query Type</InputLabel>
                  <Select
                    value={queryType}
                    onChange={(e) => setQueryType(e.target.value)}
                    label="Query Type"
                  >
                    {QUERY_TYPES.map(type => (
                      <MenuItem key={type} value={type}>{type}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={3}>
                <FormControl fullWidth>
                  <InputLabel>DNS Server</InputLabel>
                  <Select
                    value={dnsServer}
                    onChange={(e) => setDnsServer(e.target.value)}
                    label="DNS Server"
                  >
                    {DNS_SERVERS.map(server => (
                      <MenuItem key={server.value} value={server.value}>
                        {server.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              
              {dnsServer === 'custom' && (
                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="Custom Server IP"
                    value={customServer}
                    onChange={(e) => setCustomServer(e.target.value)}
                    placeholder="192.168.1.1"
                  />
                </Grid>
              )}
              
              <Grid item xs={12} md={3}>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={<PlayIcon style={{ width: 20, height: 20 }} />}
                    onClick={executeQuery}
                    disabled={loading}
                  >
                    Execute Query
                  </Button>
                  <Tooltip title="Clear Results">
                    <IconButton onClick={clearResults} disabled={results.length === 0}>
                      <ArrowPathIcon style={{ width: 20, height: 20 }} />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Grid>
            </Grid>

            <Accordion 
              expanded={advancedOptions} 
              onChange={(e, expanded) => setAdvancedOptions(expanded)}
              sx={{ mt: 2 }}
            >
              <AccordionSummary expandIcon={<ChevronDownIcon style={{ width: 20, height: 20 }} />}>
                <Typography>Advanced Options</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={3}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={dnssec}
                          onChange={(e) => setDnssec(e.target.checked)}
                        />
                      }
                      label="Enable DNSSEC"
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={recursion}
                          onChange={(e) => setRecursion(e.target.checked)}
                        />
                      }
                      label="Recursion"
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="EDNS Client Subnet"
                      value={ednsClientSubnet}
                      onChange={(e) => setEdnsClientSubnet(e.target.value)}
                      placeholder="192.168.1.0/24"
                      size="small"
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      type="number"
                      label="Timeout (ms)"
                      value={timeout}
                      onChange={(e) => setTimeout(Number(e.target.value))}
                      inputProps={{ min: 100, max: 30000 }}
                      size="small"
                    />
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>

            {loading && <LinearProgress sx={{ mt: 2 }} />}
          </Paper>
        </Grid>

        {results.map((result) => (
          <Grid item xs={12} key={result.id}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <Typography variant="h6">
                      {result.domain} ({result.type})
                    </Typography>
                    <Chip 
                      label={result.status.toUpperCase()} 
                      color={getStatusColor(result.status) as any}
                      size="small"
                    />
                    {result.flags.authenticData && (
                      <Chip
                        icon={<ShieldCheckIcon style={{ width: 16, height: 16 }} />}
                        label="DNSSEC"
                        color="primary"
                        size="small"
                      />
                    )}
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <Chip
                      icon={<ClockIcon style={{ width: 16, height: 16 }} />}
                      label={`${result.responseTime}ms`}
                      variant="outlined"
                      size="small"
                    />
                    <Chip
                      icon={<ServerIcon style={{ width: 16, height: 16 }} />}
                      label={result.server}
                      variant="outlined"
                      size="small"
                    />
                    <Typography variant="caption" color="text.secondary">
                      {result.timestamp.toLocaleTimeString()}
                    </Typography>
                  </Box>
                </Box>

                {result.status === 'success' && (
                  <>
                    <Box sx={{ mb: 2 }}>
                      <Grid container spacing={2}>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="text.secondary">Response Code</Typography>
                          <Typography>{formatResponseCode(result.flags.responseCode)}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="text.secondary">Answers</Typography>
                          <Typography>{result.sections.answer}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="text.secondary">Authority</Typography>
                          <Typography>{result.sections.authority}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="text.secondary">Additional</Typography>
                          <Typography>{result.sections.additional}</Typography>
                        </Grid>
                      </Grid>
                    </Box>

                    {result.answers.length > 0 && (
                      <TableContainer component={Paper} variant="outlined">
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Name</TableCell>
                              <TableCell>Type</TableCell>
                              <TableCell>TTL</TableCell>
                              <TableCell>Data</TableCell>
                              <TableCell align="right">Actions</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {result.answers.map((answer, idx) => (
                              <TableRow key={idx}>
                                <TableCell>{answer.name}</TableCell>
                                <TableCell>
                                  <Chip label={answer.type} size="small" />
                                </TableCell>
                                <TableCell>{answer.ttl}s</TableCell>
                                <TableCell>
                                  {answer.type === 'MX' && answer.priority !== undefined
                                    ? `${answer.priority} ${answer.data}`
                                    : answer.type === 'SRV' && answer.priority !== undefined
                                    ? `${answer.priority} ${answer.weight} ${answer.port} ${answer.data}`
                                    : answer.data}
                                </TableCell>
                                <TableCell align="right">
                                  <IconButton
                                    size="small"
                                    onClick={() => copyToClipboard(answer.data)}
                                  >
                                    <DocumentDuplicateIcon style={{ width: 16, height: 16 }} />
                                  </IconButton>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}

                    {result.answers.length === 0 && (
                      <Alert severity="info">
                        No records found for this query
                      </Alert>
                    )}
                  </>
                )}

                {result.status === 'error' && (
                  <Alert severity="error" icon={<ExclamationTriangleIcon style={{ width: 20, height: 20 }} />}>
                    Query failed. Please check your domain name and try again.
                  </Alert>
                )}

                {result.status === 'timeout' && (
                  <Alert severity="warning">
                    Query timed out after {timeout}ms. Try increasing the timeout or using a different server.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default DNSQueryTester;