import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  AppBar,
  Toolbar,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Divider,
  Paper,
  Grid,
  Chip
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Save as SaveIcon,
  Add as AddIcon,
  Settings as SettingsIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import Dashboard from '../components/Dashboard/Dashboard';
import { DashboardConfig } from '../components/Dashboard/types';

const DashboardDemo: React.FC = () => {
  const [currentDashboard, setCurrentDashboard] = useState('default');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [showInfo, setShowInfo] = useState(true);

  const sampleConfig: DashboardConfig = {
    id: 'sample',
    name: 'Sample Dashboard',
    widgets: [
      {
        id: 'metric1',
        type: 'metric',
        title: 'Total Revenue',
        data: {
          value: 125420,
          label: 'Total Revenue',
          trend: 'up',
          change: 12.5,
          unit: '$'
        }
      },
      {
        id: 'metric2',
        type: 'metric',
        title: 'Active Users',
        data: {
          value: 3421,
          label: 'Active Users',
          trend: 'up',
          change: 8.3,
          unit: ''
        }
      },
      {
        id: 'chart1',
        type: 'chart',
        title: 'Sales Trend',
        customSettings: {
          chartType: 'line'
        }
      },
      {
        id: 'table1',
        type: 'table',
        title: 'Recent Orders'
      },
      {
        id: 'gauge1',
        type: 'gauge',
        title: 'System Performance'
      },
      {
        id: 'alert1',
        type: 'alert',
        title: 'System Alerts'
      },
      {
        id: 'realtime1',
        type: 'realtime',
        title: 'Live Metrics',
        customSettings: {
          maxDataPoints: 20
        }
      }
    ],
    layouts: {
      lg: [
        { i: 'metric1', x: 0, y: 0, w: 3, h: 3 },
        { i: 'metric2', x: 3, y: 0, w: 3, h: 3 },
        { i: 'chart1', x: 6, y: 0, w: 6, h: 6 },
        { i: 'table1', x: 0, y: 3, w: 6, h: 8 },
        { i: 'gauge1', x: 6, y: 6, w: 3, h: 4 },
        { i: 'alert1', x: 9, y: 6, w: 3, h: 4 },
        { i: 'realtime1', x: 6, y: 10, w: 6, h: 6 }
      ]
    },
    createdAt: new Date(),
    updatedAt: new Date()
  };

  const handleDashboardSave = (config: DashboardConfig) => {
    console.log('Dashboard saved:', config);
    alert('Dashboard configuration saved successfully!');
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const switchDashboard = (id: string) => {
    setCurrentDashboard(id);
    handleMenuClose();
  };

  return (
    <Box sx={{ flexGrow: 1, height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <AppBar position="static">
        <Toolbar>
          <DashboardIcon sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Interactive Dashboard System
          </Typography>
          
          <Button
            color="inherit"
            startIcon={<DashboardIcon />}
            onClick={handleMenuOpen}
          >
            Dashboards
          </Button>
          
          <IconButton color="inherit" onClick={() => setShowInfo(!showInfo)}>
            <InfoIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={() => switchDashboard('default')}>
          Default Dashboard
          {currentDashboard === 'default' && <Chip label="Current" size="small" sx={{ ml: 1 }} />}
        </MenuItem>
        <MenuItem onClick={() => switchDashboard('sample')}>
          Sample Dashboard
          {currentDashboard === 'sample' && <Chip label="Current" size="small" sx={{ ml: 1 }} />}
        </MenuItem>
        <MenuItem onClick={() => switchDashboard('empty')}>
          Empty Dashboard
          {currentDashboard === 'empty' && <Chip label="Current" size="small" sx={{ ml: 1 }} />}
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleMenuClose}>
          <AddIcon sx={{ mr: 1 }} />
          Create New Dashboard
        </MenuItem>
      </Menu>

      {showInfo && (
        <Paper elevation={0} sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
          <Container maxWidth="lg">
            <Typography variant="h6" gutterBottom>
              Dashboard Features
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Typography variant="subtitle2" fontWeight="bold">
                  Drag & Drop
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Rearrange widgets by dragging them to new positions
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="subtitle2" fontWeight="bold">
                  Resize Widgets
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Drag the bottom-right corner to resize any widget
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="subtitle2" fontWeight="bold">
                  Add/Remove
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Use the speed dial button to add widgets, X to remove
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="subtitle2" fontWeight="bold">
                  Export/Import
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Save and load dashboard configurations as JSON
                </Typography>
              </Grid>
            </Grid>
            
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Available Widget Types:
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Chip label="Metric Cards" size="small" />
                <Chip label="Charts" size="small" />
                <Chip label="Data Tables" size="small" />
                <Chip label="Gauges" size="small" />
                <Chip label="Text/Notes" size="small" />
                <Chip label="Alerts" size="small" />
                <Chip label="Real-time Data" size="small" />
                <Chip label="Custom Widgets" size="small" color="primary" />
              </Box>
            </Box>

            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="text.secondary">
                Toggle between Edit and View modes using the lock icon in the bottom-left corner.
                All dashboard configurations are automatically saved to localStorage.
              </Typography>
            </Box>
          </Container>
        </Paper>
      )}

      <Box sx={{ flex: 1, overflow: 'auto', backgroundColor: '#fafafa' }}>
        <Dashboard
          key={currentDashboard}
          dashboardId={currentDashboard}
          initialConfig={currentDashboard === 'sample' ? sampleConfig : undefined}
          onSave={handleDashboardSave}
          readOnly={false}
        />
      </Box>
    </Box>
  );
};

export default DashboardDemo;