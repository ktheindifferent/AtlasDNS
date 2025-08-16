import React, { useState } from 'react';
import { Box, Paper, TextField, Button, Typography, Grid, Alert, Card, CardContent, Chip, LinearProgress } from '@mui/material';
import { ShieldCheckIcon, PlayIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

const DNSSECValidator: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [domain, setDomain] = useState('');
  const [validating, setValidating] = useState(false);
  const [results, setResults] = useState<any>(null);

  const validateDNSSEC = async () => {
    if (!domain.trim()) {
      enqueueSnackbar('Please enter a domain name', { variant: 'warning' });
      return;
    }

    setValidating(true);
    try {
      const response = await dnsPlaygroundApi.validateDNSSEC({ domain: domain.trim() });
      setResults(response.data);
      enqueueSnackbar('DNSSEC validation completed', { variant: 'success' });
    } catch (error: any) {
      enqueueSnackbar(error.message || 'Validation failed', { variant: 'error' });
    } finally {
      setValidating(false);
    }
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNSSEC Validation Tester
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
                  startIcon={<ShieldCheckIcon style={{ width: 20, height: 20 }} />}
                  onClick={validateDNSSEC}
                  disabled={validating}
                >
                  Validate DNSSEC
                </Button>
              </Grid>
            </Grid>
            {validating && <LinearProgress sx={{ mt: 2 }} />}
          </Paper>
        </Grid>

        {results && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">DNSSEC Validation Results</Typography>
                  <Chip
                    label={results.valid ? 'Valid' : 'Invalid'}
                    color={results.valid ? 'success' : 'error'}
                  />
                </Box>
                {results.chainOfTrust && (
                  <Alert severity={results.valid ? 'success' : 'error'} sx={{ mt: 2 }}>
                    {results.valid 
                      ? 'DNSSEC chain of trust is valid and secure'
                      : 'DNSSEC validation failed - chain of trust broken'}
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

export default DNSSECValidator;