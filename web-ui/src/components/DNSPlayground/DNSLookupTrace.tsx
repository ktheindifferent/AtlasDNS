import React, { useState, useCallback, useEffect, useRef } from 'react';
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
  IconButton,
  Tooltip,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Collapse,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  PlayIcon,
  ServerIcon,
  ArrowRightIcon,
  ClockIcon,
  GlobeAltIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  MapPinIcon,
} from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import * as d3 from 'd3';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

interface TraceHop {
  id: string;
  level: number;
  type: 'root' | 'tld' | 'authoritative' | 'recursive' | 'cache';
  server: string;
  serverName?: string;
  location?: string;
  query: string;
  queryType: string;
  response: string;
  responseTime: number;
  ttl?: number;
  flags: {
    authoritative: boolean;
    recursion: boolean;
    dnssec: boolean;
  };
  answers: any[];
  timestamp: Date;
  cached: boolean;
  error?: string;
}

interface TraceResult {
  id: string;
  domain: string;
  startTime: Date;
  endTime: Date;
  totalTime: number;
  hops: TraceHop[];
  finalAnswer: any;
  dnssecValidated: boolean;
  success: boolean;
}

const DNSLookupTrace: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const svgRef = useRef<SVGSVGElement>(null);
  const [domain, setDomain] = useState('example.com');
  const [loading, setLoading] = useState(false);
  const [traceResult, setTraceResult] = useState<TraceResult | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [expandedHops, setExpandedHops] = useState<Set<string>>(new Set());
  const [visualizationType, setVisualizationType] = useState<'tree' | 'flow'>('tree');

  const performTrace = useCallback(async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setLoading(true);
    setTraceResult(null);
    setActiveStep(0);

    try {
      const response = await dnsPlaygroundApi.trace({
        domain: domain.trim(),
        detailed: true,
      });

      const result: TraceResult = {
        id: `trace-${Date.now()}`,
        domain: domain.trim(),
        startTime: new Date(response.data.startTime),
        endTime: new Date(response.data.endTime),
        totalTime: response.data.totalTime,
        hops: response.data.hops || [],
        finalAnswer: response.data.finalAnswer,
        dnssecValidated: response.data.dnssecValidated || false,
        success: response.data.success,
      };

      setTraceResult(result);
      
      if (result.hops.length > 0) {
        animateSteps(result.hops.length);
      }

      enqueueSnackbar('DNS trace completed successfully', { variant: 'success' });
    } catch (error: any) {
      enqueueSnackbar(error.message || 'Failed to perform DNS trace', { variant: 'error' });
    } finally {
      setLoading(false);
    }
  }, [domain, enqueueSnackbar]);

  const animateSteps = (totalSteps: number) => {
    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep < totalSteps) {
        setActiveStep(currentStep);
        currentStep++;
      } else {
        clearInterval(interval);
      }
    }, 500);
  };

  const toggleHopExpansion = (hopId: string) => {
    setExpandedHops(prev => {
      const newSet = new Set(prev);
      if (newSet.has(hopId)) {
        newSet.delete(hopId);
      } else {
        newSet.add(hopId);
      }
      return newSet;
    });
  };

  const getServerTypeColor = (type: string) => {
    switch (type) {
      case 'root': return '#9c27b0';
      case 'tld': return '#2196f3';
      case 'authoritative': return '#4caf50';
      case 'recursive': return '#ff9800';
      case 'cache': return '#607d8b';
      default: return '#757575';
    }
  };

  const getServerTypeIcon = (type: string) => {
    switch (type) {
      case 'root': return <GlobeAltIcon style={{ width: 20, height: 20 }} />;
      case 'tld': return <ServerIcon style={{ width: 20, height: 20 }} />;
      case 'authoritative': return <ShieldCheckIcon style={{ width: 20, height: 20 }} />;
      case 'recursive': return <ArrowRightIcon style={{ width: 20, height: 20 }} />;
      case 'cache': return <ClockIcon style={{ width: 20, height: 20 }} />;
      default: return <ServerIcon style={{ width: 20, height: 20 }} />;
    }
  };

  useEffect(() => {
    if (!traceResult || !svgRef.current || visualizationType !== 'tree') return;

    const width = 800;
    const height = 400;
    const margin = { top: 20, right: 120, bottom: 20, left: 120 };

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const treeData = {
      name: 'Query',
      children: traceResult.hops.map(hop => ({
        name: hop.serverName || hop.server,
        type: hop.type,
        responseTime: hop.responseTime,
        cached: hop.cached,
      })),
    };

    const treeLayout = d3.tree()
      .size([height - margin.top - margin.bottom, width - margin.left - margin.right]);

    const root = d3.hierarchy(treeData);
    const treeNodes = treeLayout(root);

    const link = g.selectAll('.link')
      .data(treeNodes.links())
      .enter().append('path')
      .attr('class', 'link')
      .attr('d', d3.linkHorizontal<any, any>()
        .x((d) => d.y)
        .y((d) => d.x))
      .style('fill', 'none')
      .style('stroke', '#ccc')
      .style('stroke-width', 2);

    const node = g.selectAll('.node')
      .data(treeNodes.descendants())
      .enter().append('g')
      .attr('class', 'node')
      .attr('transform', (d: any) => `translate(${d.y},${d.x})`);

    node.append('circle')
      .attr('r', 8)
      .style('fill', (d: any) => d.data.type ? getServerTypeColor(d.data.type) : '#999')
      .style('stroke', '#fff')
      .style('stroke-width', 2);

    node.append('text')
      .attr('dy', '.35em')
      .attr('x', (d: any) => d.children ? -13 : 13)
      .style('text-anchor', (d: any) => d.children ? 'end' : 'start')
      .style('font-size', '12px')
      .text((d: any) => d.data.name);

    node.append('title')
      .text((d: any) => `${d.data.name}\nResponse Time: ${d.data.responseTime}ms\nCached: ${d.data.cached ? 'Yes' : 'No'}`);

  }, [traceResult, visualizationType]);

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Lookup Trace
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Visualize the complete DNS resolution path from root servers to final answer
            </Typography>

            <Grid container spacing={2} alignItems="center" sx={{ mt: 2 }}>
              <Grid item xs={12} md={8}>
                <TextField
                  fullWidth
                  label="Domain Name"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  onKeyPress={(e) => e.key === 'Enter' && performTrace()}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<PlayIcon style={{ width: 20, height: 20 }} />}
                  onClick={performTrace}
                  disabled={loading}
                >
                  Start Trace
                </Button>
              </Grid>
            </Grid>

            {loading && <LinearProgress sx={{ mt: 2 }} />}
          </Paper>
        </Grid>

        {traceResult && (
          <>
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">
                      Trace Results for {traceResult.domain}
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Chip
                        label={traceResult.success ? 'Success' : 'Failed'}
                        color={traceResult.success ? 'success' : 'error'}
                        size="small"
                      />
                      {traceResult.dnssecValidated && (
                        <Chip
                          icon={<ShieldCheckIcon style={{ width: 16, height: 16 }} />}
                          label="DNSSEC Valid"
                          color="primary"
                          size="small"
                        />
                      )}
                      <Chip
                        icon={<ClockIcon style={{ width: 16, height: 16 }} />}
                        label={`${traceResult.totalTime}ms`}
                        variant="outlined"
                        size="small"
                      />
                    </Box>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Resolution Path
                      </Typography>
                      <Stepper activeStep={activeStep} orientation="vertical">
                        {traceResult.hops.map((hop, index) => (
                          <Step key={hop.id}>
                            <StepLabel
                              StepIconComponent={() => getServerTypeIcon(hop.type)}
                              optional={
                                <Typography variant="caption">
                                  {hop.responseTime}ms {hop.cached && '(cached)'}
                                </Typography>
                              }
                            >
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="body2">
                                  {hop.serverName || hop.server}
                                </Typography>
                                {hop.location && (
                                  <Chip
                                    icon={<MapPinIcon style={{ width: 14, height: 14 }} />}
                                    label={hop.location}
                                    size="small"
                                    variant="outlined"
                                  />
                                )}
                              </Box>
                            </StepLabel>
                            <StepContent>
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="body2" color="text.secondary">
                                  Query: {hop.query} ({hop.queryType})
                                </Typography>
                                <Typography variant="body2" color="text.secondary">
                                  Response: {hop.response}
                                </Typography>
                                {hop.error && (
                                  <Alert severity="error" sx={{ mt: 1 }}>
                                    {hop.error}
                                  </Alert>
                                )}
                                <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
                                  {hop.flags.authoritative && (
                                    <Chip label="Authoritative" size="small" />
                                  )}
                                  {hop.flags.recursion && (
                                    <Chip label="Recursive" size="small" />
                                  )}
                                  {hop.flags.dnssec && (
                                    <Chip label="DNSSEC" size="small" color="primary" />
                                  )}
                                </Box>
                              </Box>
                            </StepContent>
                          </Step>
                        ))}
                      </Stepper>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Visual Trace Map
                      </Typography>
                      <Paper variant="outlined" sx={{ p: 2, overflow: 'auto' }}>
                        <svg ref={svgRef}></svg>
                      </Paper>

                      {traceResult.finalAnswer && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>
                            Final Answer
                          </Typography>
                          <Paper variant="outlined" sx={{ p: 2 }}>
                            <Typography variant="body2" component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                              {JSON.stringify(traceResult.finalAnswer, null, 2)}
                            </Typography>
                          </Paper>
                        </Box>
                      )}
                    </Grid>
                  </Grid>

                  <Divider sx={{ my: 3 }} />

                  <Typography variant="subtitle2" gutterBottom>
                    Detailed Hop Information
                  </Typography>
                  <List>
                    {traceResult.hops.map((hop) => (
                      <React.Fragment key={hop.id}>
                        <ListItem>
                          <ListItemIcon>
                            {getServerTypeIcon(hop.type)}
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="body1">
                                  {hop.serverName || hop.server}
                                </Typography>
                                <Chip
                                  label={hop.type.toUpperCase()}
                                  size="small"
                                  style={{ backgroundColor: getServerTypeColor(hop.type), color: 'white' }}
                                />
                              </Box>
                            }
                            secondary={
                              <Box>
                                <Typography variant="body2" color="text.secondary">
                                  {hop.query} → {hop.response} ({hop.responseTime}ms)
                                </Typography>
                                {hop.ttl && (
                                  <Typography variant="caption" color="text.secondary">
                                    TTL: {hop.ttl}s
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                          <IconButton
                            size="small"
                            onClick={() => toggleHopExpansion(hop.id)}
                          >
                            {expandedHops.has(hop.id) ? 
                              <ChevronDownIcon style={{ width: 20, height: 20 }} /> : 
                              <ChevronRightIcon style={{ width: 20, height: 20 }} />
                            }
                          </IconButton>
                        </ListItem>
                        <Collapse in={expandedHops.has(hop.id)}>
                          <Box sx={{ pl: 9, pr: 2, pb: 2 }}>
                            <Paper variant="outlined" sx={{ p: 2 }}>
                              <Typography variant="body2" component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                                {JSON.stringify(hop.answers, null, 2)}
                              </Typography>
                            </Paper>
                          </Box>
                        </Collapse>
                      </React.Fragment>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </>
        )}
      </Grid>
    </Box>
  );
};

export default DNSLookupTrace;