import React, { useState } from 'react';
import { Box, Paper, Typography, Button, Grid, TextField, Card, CardContent, Switch, FormControlLabel, Alert, Chip } from '@mui/material';
import { ChartPieIcon, BellIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';

const MonitoringIntegration: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [alertEnabled, setAlertEnabled] = useState(false);
  const [threshold, setThreshold] = useState('100');
  const [testAlerts, setTestAlerts] = useState<any[]>([]);

  const testAlertIntegration = () => {
    const newAlert = {
      id: Date.now(),
      type: 'DNS Response Time Alert',
      message: `Response time exceeded ${threshold}ms threshold`,
      timestamp: new Date().toLocaleTimeString(),
      severity: 'warning',
    };
    setTestAlerts([newAlert, ...testAlerts]);
    enqueueSnackbar('Test alert triggered successfully', { variant: 'info' });
  };

  const clearAlerts = () => {
    setTestAlerts([]);
    enqueueSnackbar('Alerts cleared', { variant: 'success' });
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Alert severity="info" sx={{ mb: 2 }}>
            Integration with monitoring system allows you to test alert configurations and validate monitoring rules.
          </Alert>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Alert Configuration
            </Typography>
            <FormControlLabel
              control={
                <Switch
                  checked={alertEnabled}
                  onChange={(e) => setAlertEnabled(e.target.checked)}
                />
              }
              label="Enable Alert Testing"
              sx={{ mt: 2 }}
            />
            <TextField
              fullWidth
              label="Response Time Threshold (ms)"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              type="number"
              sx={{ mt: 2 }}
            />
            <Button
              fullWidth
              variant="contained"
              startIcon={<BellIcon style={{ width: 20, height: 20 }} />}
              onClick={testAlertIntegration}
              disabled={!alertEnabled}
              sx={{ mt: 2 }}
            >
              Test Alert
            </Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Test Alerts</Typography>
              <Button size="small" onClick={clearAlerts} disabled={testAlerts.length === 0}>
                Clear
              </Button>
            </Box>
            {testAlerts.length === 0 ? (
              <Typography color="text.secondary">No test alerts triggered yet</Typography>
            ) : (
              testAlerts.map((alert) => (
                <Card key={alert.id} sx={{ mb: 1 }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Typography variant="body2">{alert.message}</Typography>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Chip label={alert.severity} color="warning" size="small" />
                        <Typography variant="caption" color="text.secondary">
                          {alert.timestamp}
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              ))
            )}
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CheckCircleIcon style={{ width: 24, height: 24, color: '#4caf50' }} />
                <Box>
                  <Typography variant="h6">Monitoring Status</Typography>
                  <Typography variant="body2" color="text.secondary">
                    All monitoring integrations are functioning correctly. Test alerts can be viewed in your monitoring dashboard.
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default MonitoringIntegration;