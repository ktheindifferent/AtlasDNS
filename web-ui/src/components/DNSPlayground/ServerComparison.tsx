import React, { useState } from 'react';
import { Box, Paper, TextField, Button, Typography, Grid, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Chip } from '@mui/material';
import { ServerIcon, PlayIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

const ServerComparison: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [domain, setDomain] = useState('');
  const [comparing, setComparing] = useState(false);
  const [results, setResults] = useState<any[]>([]);

  const compareServers = async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setComparing(true);
    try {
      const response = await dnsPlaygroundApi.compareServers({ domain: domain.trim() });
      setResults(response.data.comparisons);
      enqueueSnackbar('Server comparison completed', { variant: 'success' });
    } catch (error: any) {
      enqueueSnackbar(error.message || 'Comparison failed', { variant: 'error' });
    } finally {
      setComparing(false);
    }
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Server Comparison
            </Typography>
            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} md={8}>
                <TextField
                  fullWidth
                  label="Domain Name"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<ServerIcon style={{ width: 20, height: 20 }} />}
                  onClick={compareServers}
                  disabled={comparing}
                >
                  Compare Servers
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {results.length > 0 && (
          <Grid item xs={12}>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Server</TableCell>
                    <TableCell>Response Time</TableCell>
                    <TableCell>Response</TableCell>
                    <TableCell>DNSSEC</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {results.map((result, idx) => (
                    <TableRow key={idx}>
                      <TableCell>{result.server}</TableCell>
                      <TableCell>{result.responseTime}ms</TableCell>
                      <TableCell>{result.response}</TableCell>
                      <TableCell>
                        <Chip
                          label={result.dnssec ? 'Yes' : 'No'}
                          color={result.dnssec ? 'success' : 'default'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={result.status}
                          color={result.status === 'success' ? 'success' : 'error'}
                          size="small"
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default ServerComparison;