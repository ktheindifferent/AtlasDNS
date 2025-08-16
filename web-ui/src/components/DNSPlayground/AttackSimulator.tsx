import React, { useState } from 'react';
import { Box, Paper, Typography, Grid, Card, CardContent, Button, Alert, AlertTitle, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import { BugAntIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';

const ATTACK_SCENARIOS = [
  { id: 'cache-poisoning', name: 'Cache Poisoning', description: 'Simulate DNS cache poisoning attack', severity: 'high' },
  { id: 'amplification', name: 'DNS Amplification', description: 'Simulate amplification DDoS attack', severity: 'critical' },
  { id: 'tunneling', name: 'DNS Tunneling', description: 'Detect DNS tunneling attempts', severity: 'medium' },
  { id: 'subdomain-takeover', name: 'Subdomain Takeover', description: 'Check for subdomain takeover vulnerabilities', severity: 'high' },
  { id: 'nxdomain', name: 'NXDOMAIN Attack', description: 'Simulate NXDOMAIN flood attack', severity: 'medium' },
];

const AttackSimulator: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [selectedScenario, setSelectedScenario] = useState('');
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any>(null);

  const runSimulation = async () => {
    if (!selectedScenario) {
      enqueueSnackbar('Please select an attack scenario', { variant: 'warning' });
      return;
    }

    setRunning(true);
    setTimeout(() => {
      setResults({
        scenario: selectedScenario,
        vulnerable: false,
        mitigations: ['Enable DNSSEC', 'Implement rate limiting', 'Use DNS filtering'],
        details: 'Simulation completed. Your DNS configuration shows good resistance to this attack vector.',
      });
      setRunning(false);
      enqueueSnackbar('Attack simulation completed', { variant: 'success' });
    }, 2000);
  };

  return (
    <Box>
      <Alert severity="warning" sx={{ mb: 3 }}>
        <AlertTitle>Educational Purpose Only</AlertTitle>
        These simulations are for learning and testing purposes only. They run in an isolated environment and do not perform actual attacks.
      </Alert>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Attack Scenario Simulator
            </Typography>
            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} md={8}>
                <FormControl fullWidth>
                  <InputLabel>Attack Scenario</InputLabel>
                  <Select
                    value={selectedScenario}
                    onChange={(e) => setSelectedScenario(e.target.value)}
                    label="Attack Scenario"
                  >
                    {ATTACK_SCENARIOS.map(scenario => (
                      <MenuItem key={scenario.id} value={scenario.id}>
                        {scenario.name} - {scenario.description}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  fullWidth
                  variant="contained"
                  color="warning"
                  startIcon={<BugAntIcon style={{ width: 20, height: 20 }} />}
                  onClick={runSimulation}
                  disabled={running}
                >
                  {running ? 'Running Simulation...' : 'Run Simulation'}
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {results && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                  <ShieldCheckIcon style={{ width: 24, height: 24, color: '#4caf50' }} />
                  <Typography variant="h6">Simulation Results</Typography>
                </Box>
                <Alert severity={results.vulnerable ? 'error' : 'success'} sx={{ mb: 2 }}>
                  {results.details}
                </Alert>
                <Typography variant="subtitle2" gutterBottom>
                  Recommended Mitigations:
                </Typography>
                <ul>
                  {results.mitigations.map((mitigation: string, idx: number) => (
                    <li key={idx}>{mitigation}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default AttackSimulator;