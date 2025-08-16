import React, { useState } from 'react';
import {
  Box,
  Container,
  Tabs,
  Tab,
  Paper,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Badge,
  Tooltip,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  Button,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Speed as SpeedIcon,
  Assessment as AssessmentIcon,
  Api as ApiIcon,
  Memory as MemoryIcon,
  NetworkCheck as NetworkIcon,
  AccountTree as ComponentIcon,
  TrendingUp as TrendsIcon,
  AttachMoney as BudgetIcon,
  Notifications as NotificationsIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Menu as MenuIcon,
} from '@mui/icons-material';

import { RUMDashboard } from './RUMDashboard';
import { BundleAnalyzer } from './BundleAnalyzer';
import { APIMonitor } from './APIMonitor';
import { ComponentProfiler } from './ComponentProfiler';
import { MemoryMonitor } from './MemoryMonitor';
import { NetworkWaterfall } from './NetworkWaterfall';
import { PerformanceBudget } from './PerformanceBudget';
import { HistoricalTrends } from './HistoricalTrends';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`performance-tabpanel-${index}`}
      aria-labelledby={`performance-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
};

export const PerformanceDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { performanceData, budgetAlerts, memoryLeakWarning, clearMetrics } = usePerformanceMonitor();

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleExportData = () => {
    const data = {
      timestamp: new Date().toISOString(),
      performanceData,
      budgetAlerts,
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `performance-data-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleRefresh = () => {
    clearMetrics();
    window.location.reload();
  };

  const alertCount = budgetAlerts.length + (memoryLeakWarning ? 1 : 0);

  const navigationItems = [
    { icon: <SpeedIcon />, label: 'Core Web Vitals', index: 0 },
    { icon: <AssessmentIcon />, label: 'Bundle Analysis', index: 1 },
    { icon: <ApiIcon />, label: 'API Monitoring', index: 2 },
    { icon: <ComponentIcon />, label: 'Component Profiling', index: 3 },
    { icon: <MemoryIcon />, label: 'Memory Usage', index: 4 },
    { icon: <NetworkIcon />, label: 'Network Waterfall', index: 5 },
    { icon: <BudgetIcon />, label: 'Performance Budget', index: 6 },
    { icon: <TrendsIcon />, label: 'Historical Trends', index: 7 },
  ];

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={() => setDrawerOpen(!drawerOpen)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          
          <DashboardIcon sx={{ mr: 2 }} />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Performance Monitoring Dashboard
          </Typography>
          
          <Tooltip title="Export Data">
            <IconButton color="inherit" onClick={handleExportData}>
              <DownloadIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Refresh">
            <IconButton color="inherit" onClick={handleRefresh}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Alerts">
            <IconButton color="inherit">
              <Badge badgeContent={alertCount} color="error">
                <NotificationsIcon />
              </Badge>
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Settings">
            <IconButton color="inherit">
              <SettingsIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      <Drawer
        variant="temporary"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        sx={{
          width: 280,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: 280,
            boxSizing: 'border-box',
            mt: 8,
          },
        }}
      >
        <Box sx={{ overflow: 'auto' }}>
          <List>
            {navigationItems.map((item) => (
              <ListItem
                button
                key={item.index}
                selected={activeTab === item.index}
                onClick={() => {
                  setActiveTab(item.index);
                  setDrawerOpen(false);
                }}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItem>
            ))}
          </List>
          <Divider />
          <Box sx={{ p: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Last updated: {new Date().toLocaleTimeString()}
            </Typography>
          </Box>
        </Box>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, mt: 8 }}>
        <Container maxWidth={false}>
          {alertCount > 0 && (
            <Alert 
              severity="warning" 
              sx={{ mb: 3 }}
              action={
                <Button color="inherit" size="small" onClick={() => setActiveTab(6)}>
                  View Budgets
                </Button>
              }
            >
              {alertCount} performance {alertCount === 1 ? 'issue' : 'issues'} detected
            </Alert>
          )}

          <Paper sx={{ width: '100%', mb: 2 }}>
            <Tabs
              value={activeTab}
              onChange={handleTabChange}
              variant="scrollable"
              scrollButtons="auto"
              aria-label="performance monitoring tabs"
            >
              <Tab icon={<SpeedIcon />} label="Core Web Vitals" />
              <Tab icon={<AssessmentIcon />} label="Bundle Analysis" />
              <Tab icon={<ApiIcon />} label="API Monitoring" />
              <Tab icon={<ComponentIcon />} label="Component Profiling" />
              <Tab icon={<MemoryIcon />} label="Memory Usage" />
              <Tab icon={<NetworkIcon />} label="Network" />
              <Tab icon={<BudgetIcon />} label="Budget" />
              <Tab icon={<TrendsIcon />} label="Trends" />
            </Tabs>
          </Paper>

          <TabPanel value={activeTab} index={0}>
            <RUMDashboard />
          </TabPanel>
          
          <TabPanel value={activeTab} index={1}>
            <BundleAnalyzer />
          </TabPanel>
          
          <TabPanel value={activeTab} index={2}>
            <APIMonitor />
          </TabPanel>
          
          <TabPanel value={activeTab} index={3}>
            <ComponentProfiler />
          </TabPanel>
          
          <TabPanel value={activeTab} index={4}>
            <MemoryMonitor />
          </TabPanel>
          
          <TabPanel value={activeTab} index={5}>
            <NetworkWaterfall />
          </TabPanel>
          
          <TabPanel value={activeTab} index={6}>
            <PerformanceBudget />
          </TabPanel>
          
          <TabPanel value={activeTab} index={7}>
            <HistoricalTrends />
          </TabPanel>
        </Container>
      </Box>
    </Box>
  );
};