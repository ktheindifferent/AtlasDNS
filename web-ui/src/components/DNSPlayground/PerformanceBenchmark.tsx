import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Grid,
  Card,
  CardContent,
  Slider,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  LinearProgress,
  Alert,
  Chip,
} from '@mui/material';
import { PlayIcon, ChartBarIcon, ClockIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

const PerformanceBenchmark: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [domain, setDomain] = useState('example.com');
  const [iterations, setIterations] = useState(10);
  const [queryType, setQueryType] = useState('A');
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);

  const runBenchmark = useCallback(async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setRunning(true);
    setResults([]);
    setStats(null);

    try {
      const response = await dnsPlaygroundApi.benchmark({
        domain: domain.trim(),
        queryType,
        iterations,
        concurrent: false,
      });

      setResults(response.data.results);
      setStats(response.data.stats);
      enqueueSnackbar('Benchmark completed successfully', { variant: 'success' });
    } catch (error: any) {
      enqueueSnackbar(error.message || 'Benchmark failed', { variant: 'error' });
    } finally {
      setRunning(false);
    }
  }, [domain, queryType, iterations, enqueueSnackbar]);

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Performance Benchmark
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Measure DNS query performance and response times
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
                  <InputLabel>Query Type</InputLabel>
                  <Select
                    value={queryType}
                    onChange={(e) => setQueryType(e.target.value)}
                    label="Query Type"
                  >
                    <MenuItem value="A">A</MenuItem>
                    <MenuItem value="AAAA">AAAA</MenuItem>
                    <MenuItem value="MX">MX</MenuItem>
                    <MenuItem value="TXT">TXT</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography gutterBottom>Iterations: {iterations}</Typography>
                <Slider
                  value={iterations}
                  onChange={(e, val) => setIterations(val as number)}
                  min={1}
                  max={100}
                  marks={[
                    { value: 1, label: '1' },
                    { value: 25, label: '25' },
                    { value: 50, label: '50' },
                    { value: 100, label: '100' },
                  ]}
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<PlayIcon style={{ width: 20, height: 20 }} />}
                  onClick={runBenchmark}
                  disabled={running}
                >
                  Run Benchmark
                </Button>
              </Grid>
            </Grid>

            {running && <LinearProgress sx={{ mt: 2 }} />}
          </Paper>
        </Grid>

        {stats && (
          <Grid item xs={12}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="text.secondary" gutterBottom>
                      Average Response Time
                    </Typography>
                    <Typography variant="h4">
                      {stats.average?.toFixed(2)}ms
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="text.secondary" gutterBottom>
                      Min / Max
                    </Typography>
                    <Typography variant="h4">
                      {stats.min?.toFixed(2)} / {stats.max?.toFixed(2)}ms
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="text.secondary" gutterBottom>
                      Success Rate
                    </Typography>
                    <Typography variant="h4">
                      {stats.successRate?.toFixed(1)}%
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="text.secondary" gutterBottom>
                      P95 Latency
                    </Typography>
                    <Typography variant="h4">
                      {stats.p95?.toFixed(2)}ms
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Grid>
        )}

        {results.length > 0 && (
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Response Time Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={results}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="iteration" />
                  <YAxis label={{ value: 'Response Time (ms)', angle: -90, position: 'insideLeft' }} />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="responseTime" stroke="#8884d8" name="Response Time" />
                </LineChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default PerformanceBenchmark;