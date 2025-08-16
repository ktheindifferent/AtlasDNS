import React, { useState } from 'react';
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
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Switch,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  NotificationsActive as NotificationIcon,
  NotificationsOff as NotificationOffIcon,
} from '@mui/icons-material';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface Budget {
  id: string;
  metric: string;
  threshold: number;
  unit: string;
  enabled: boolean;
  alertLevel: 'warning' | 'error';
  description?: string;
}

interface BudgetStatus {
  budget: Budget;
  currentValue: number;
  status: 'pass' | 'warning' | 'fail';
  percentUsed: number;
}

const defaultBudgets: Budget[] = [
  { id: '1', metric: 'LCP', threshold: 2500, unit: 'ms', enabled: true, alertLevel: 'error', description: 'Largest Contentful Paint' },
  { id: '2', metric: 'FID', threshold: 100, unit: 'ms', enabled: true, alertLevel: 'error', description: 'First Input Delay' },
  { id: '3', metric: 'CLS', threshold: 0.1, unit: 'score', enabled: true, alertLevel: 'warning', description: 'Cumulative Layout Shift' },
  { id: '4', metric: 'FCP', threshold: 1800, unit: 'ms', enabled: true, alertLevel: 'warning', description: 'First Contentful Paint' },
  { id: '5', metric: 'TTFB', threshold: 600, unit: 'ms', enabled: true, alertLevel: 'warning', description: 'Time to First Byte' },
  { id: '6', metric: 'bundleSize', threshold: 2048, unit: 'kb', enabled: true, alertLevel: 'error', description: 'JavaScript Bundle Size' },
  { id: '7', metric: 'imageSize', threshold: 1024, unit: 'kb', enabled: true, alertLevel: 'warning', description: 'Total Image Size' },
  { id: '8', metric: 'requestCount', threshold: 50, unit: 'requests', enabled: true, alertLevel: 'warning', description: 'Total HTTP Requests' },
];

export const PerformanceBudget: React.FC = () => {
  const { performanceData, budgetAlerts, setBudget } = usePerformanceMonitor();
  const [budgets, setBudgets] = useState<Budget[]>(defaultBudgets);
  const [editDialog, setEditDialog] = useState(false);
  const [editingBudget, setEditingBudget] = useState<Budget | null>(null);
  const [notifications, setNotifications] = useState(true);

  const getCurrentValue = (metric: string): number => {
    switch (metric) {
      case 'LCP':
      case 'FID':
      case 'CLS':
      case 'FCP':
      case 'TTFB': {
        const metrics = performanceData.webVitals.filter(m => m.name === metric);
        return metrics.length > 0 ? metrics[metrics.length - 1].value : 0;
      }
      case 'bundleSize':
        // Simulated value - in production, this would come from webpack stats
        return 1856;
      case 'imageSize':
        // Calculate from resource timings
        return performanceData.resourceTimings
          .filter(r => r.initiatorType === 'img')
          .reduce((sum, r) => sum + r.decodedBodySize, 0) / 1024;
      case 'requestCount':
        return performanceData.resourceTimings.length;
      default:
        return 0;
    }
  };

  const getBudgetStatus = (budget: Budget): BudgetStatus => {
    const currentValue = getCurrentValue(budget.metric);
    const percentUsed = (currentValue / budget.threshold) * 100;
    
    let status: 'pass' | 'warning' | 'fail' = 'pass';
    if (percentUsed >= 100) {
      status = budget.alertLevel === 'error' ? 'fail' : 'warning';
    } else if (percentUsed >= 80) {
      status = 'warning';
    }
    
    return {
      budget,
      currentValue,
      status,
      percentUsed: Math.min(percentUsed, 100),
    };
  };

  const budgetStatuses = budgets
    .filter(b => b.enabled)
    .map(getBudgetStatus)
    .sort((a, b) => b.percentUsed - a.percentUsed);

  const failedBudgets = budgetStatuses.filter(s => s.status === 'fail');
  const warningBudgets = budgetStatuses.filter(s => s.status === 'warning');
  const passingBudgets = budgetStatuses.filter(s => s.status === 'pass');

  const overallHealth = () => {
    if (failedBudgets.length > 0) return 'critical';
    if (warningBudgets.length > 2) return 'warning';
    if (warningBudgets.length > 0) return 'attention';
    return 'healthy';
  };

  const health = overallHealth();

  const handleEditBudget = (budget: Budget) => {
    setEditingBudget(budget);
    setEditDialog(true);
  };

  const handleDeleteBudget = (id: string) => {
    setBudgets(budgets.filter(b => b.id !== id));
  };

  const handleToggleBudget = (id: string) => {
    setBudgets(budgets.map(b => 
      b.id === id ? { ...b, enabled: !b.enabled } : b
    ));
  };

  const handleSaveBudget = () => {
    if (editingBudget) {
      if (editingBudget.id) {
        setBudgets(budgets.map(b => 
          b.id === editingBudget.id ? editingBudget : b
        ));
      } else {
        setBudgets([...budgets, { ...editingBudget, id: Date.now().toString() }]);
      }
      
      // Update the performance monitor
      setBudget(editingBudget.metric, editingBudget.threshold, editingBudget.unit as any);
    }
    setEditDialog(false);
    setEditingBudget(null);
  };

  const handleAddBudget = () => {
    setEditingBudget({
      id: '',
      metric: '',
      threshold: 0,
      unit: 'ms',
      enabled: true,
      alertLevel: 'warning',
    });
    setEditDialog(true);
  };

  const getHealthColor = () => {
    switch (health) {
      case 'critical': return 'error.main';
      case 'warning': return 'warning.main';
      case 'attention': return 'info.main';
      default: return 'success.main';
    }
  };

  const getHealthIcon = () => {
    switch (health) {
      case 'critical': return <ErrorIcon />;
      case 'warning': return <WarningIcon />;
      case 'attention': return <WarningIcon />;
      default: return <CheckCircleIcon />;
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Performance Budget</Typography>
        <Box display="flex" gap={2}>
          <Button
            startIcon={notifications ? <NotificationIcon /> : <NotificationOffIcon />}
            onClick={() => setNotifications(!notifications)}
            variant="outlined"
          >
            {notifications ? 'Notifications On' : 'Notifications Off'}
          </Button>
          <Button
            startIcon={<AddIcon />}
            onClick={handleAddBudget}
            variant="contained"
          >
            Add Budget
          </Button>
        </Box>
      </Box>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: getHealthColor(), color: 'white' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="h6">Overall Health</Typography>
                  <Typography variant="h4" textTransform="capitalize">
                    {health}
                  </Typography>
                </Box>
                <Box sx={{ fontSize: 48 }}>
                  {getHealthIcon()}
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Passing
              </Typography>
              <Typography variant="h4" color="success.main">
                {passingBudgets.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Warnings
              </Typography>
              <Typography variant="h4" color="warning.main">
                {warningBudgets.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Failed
              </Typography>
              <Typography variant="h4" color="error.main">
                {failedBudgets.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {budgetAlerts.length > 0 && notifications && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="subtitle1" fontWeight="bold">
            Recent Budget Violations
          </Typography>
          <List dense>
            {budgetAlerts.slice(-3).map((alert, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={`${alert.metric}: ${alert.value} (threshold: ${alert.threshold})`}
                  secondary={new Date(alert.timestamp).toLocaleString()}
                />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Budget Status
          </Typography>
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Metric</TableCell>
                  <TableCell>Current</TableCell>
                  <TableCell>Budget</TableCell>
                  <TableCell>Usage</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="center">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {budgets.map((budget) => {
                  const status = getBudgetStatus(budget);
                  return (
                    <TableRow key={budget.id} sx={{ opacity: budget.enabled ? 1 : 0.5 }}>
                      <TableCell>
                        <Box>
                          <Typography variant="body2" fontWeight="bold">
                            {budget.metric}
                          </Typography>
                          {budget.description && (
                            <Typography variant="caption" color="text.secondary">
                              {budget.description}
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        {status.currentValue.toFixed(budget.unit === 'score' ? 2 : 0)} {budget.unit}
                      </TableCell>
                      <TableCell>
                        {budget.threshold} {budget.unit}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ width: 150 }}>
                          <Box display="flex" alignItems="center" gap={1}>
                            <LinearProgress
                              variant="determinate"
                              value={status.percentUsed}
                              sx={{
                                flex: 1,
                                height: 8,
                                borderRadius: 4,
                                bgcolor: 'grey.300',
                                '& .MuiLinearProgress-bar': {
                                  bgcolor: status.status === 'fail' ? 'error.main' :
                                          status.status === 'warning' ? 'warning.main' : 'success.main',
                                },
                              }}
                            />
                            <Typography variant="caption">
                              {status.percentUsed.toFixed(0)}%
                            </Typography>
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          icon={status.status === 'fail' ? <ErrorIcon /> :
                               status.status === 'warning' ? <WarningIcon /> :
                               <CheckCircleIcon />}
                          label={status.status === 'fail' ? 'Failed' :
                                status.status === 'warning' ? 'Warning' : 'Pass'}
                          color={status.status === 'fail' ? 'error' :
                                status.status === 'warning' ? 'warning' : 'success'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Switch
                          checked={budget.enabled}
                          onChange={() => handleToggleBudget(budget.id)}
                          size="small"
                        />
                        <IconButton size="small" onClick={() => handleEditBudget(budget)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={() => handleDeleteBudget(budget.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      <Dialog open={editDialog} onClose={() => setEditDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editingBudget?.id ? 'Edit Budget' : 'Add Budget'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Metric Name"
                value={editingBudget?.metric || ''}
                onChange={(e) => setEditingBudget(prev => prev ? { ...prev, metric: e.target.value } : null)}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={editingBudget?.description || ''}
                onChange={(e) => setEditingBudget(prev => prev ? { ...prev, description: e.target.value } : null)}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                type="number"
                label="Threshold"
                value={editingBudget?.threshold || 0}
                onChange={(e) => setEditingBudget(prev => prev ? { ...prev, threshold: Number(e.target.value) } : null)}
              />
            </Grid>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Unit</InputLabel>
                <Select
                  value={editingBudget?.unit || 'ms'}
                  label="Unit"
                  onChange={(e) => setEditingBudget(prev => prev ? { ...prev, unit: e.target.value } : null)}
                >
                  <MenuItem value="ms">Milliseconds</MenuItem>
                  <MenuItem value="kb">Kilobytes</MenuItem>
                  <MenuItem value="mb">Megabytes</MenuItem>
                  <MenuItem value="score">Score</MenuItem>
                  <MenuItem value="requests">Requests</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Alert Level</InputLabel>
                <Select
                  value={editingBudget?.alertLevel || 'warning'}
                  label="Alert Level"
                  onChange={(e) => setEditingBudget(prev => prev ? { ...prev, alertLevel: e.target.value as any } : null)}
                >
                  <MenuItem value="warning">Warning</MenuItem>
                  <MenuItem value="error">Error</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialog(false)}>Cancel</Button>
          <Button onClick={handleSaveBudget} variant="contained">Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};