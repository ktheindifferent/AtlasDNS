import React, { useState } from 'react';
import {
  Box,
  Container,
  Paper,
  Tabs,
  Tab,
  Typography,
  Alert,
  AlertTitle,
} from '@mui/material';
import {
  BugAntIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  ServerIcon,
  DocumentArrowDownIcon,
  BeakerIcon,
  MapIcon,
  ClockIcon,
  ChartPieIcon,
} from '@heroicons/react/24/outline';

import DNSQueryTester from '../components/DNSPlayground/DNSQueryTester';
import DNSLookupTrace from '../components/DNSPlayground/DNSLookupTrace';
import RecordValidator from '../components/DNSPlayground/RecordValidator';
import PropagationChecker from '../components/DNSPlayground/PropagationChecker';
import PerformanceBenchmark from '../components/DNSPlayground/PerformanceBenchmark';
import DNSSECValidator from '../components/DNSPlayground/DNSSECValidator';
import AttackSimulator from '../components/DNSPlayground/AttackSimulator';
import ServerComparison from '../components/DNSPlayground/ServerComparison';
import ExportManager from '../components/DNSPlayground/ExportManager';
import MonitoringIntegration from '../components/DNSPlayground/MonitoringIntegration';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`dns-playground-tabpanel-${index}`}
      aria-labelledby={`dns-playground-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

function a11yProps(index: number) {
  return {
    id: `dns-playground-tab-${index}`,
    'aria-controls': `dns-playground-tabpanel-${index}`,
  };
}

const DNSPlayground: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  return (
    <Container maxWidth="xl">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          DNS Testing Playground
        </Typography>
        <Typography variant="body1" color="text.secondary" gutterBottom>
          Interactive sandbox environment for DNS configuration testing and validation
        </Typography>
        
        <Alert severity="info" sx={{ mt: 2 }}>
          <AlertTitle>Isolated Testing Environment</AlertTitle>
          All tests run in an isolated sandbox that doesn't affect production DNS. You can safely experiment with different configurations and scenarios.
        </Alert>
      </Box>

      <Paper sx={{ width: '100%' }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={activeTab}
            onChange={handleTabChange}
            variant="scrollable"
            scrollButtons="auto"
            aria-label="DNS playground tabs"
          >
            <Tab
              icon={<MagnifyingGlassIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Query Tester"
              {...a11yProps(0)}
            />
            <Tab
              icon={<MapIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Lookup Trace"
              {...a11yProps(1)}
            />
            <Tab
              icon={<ShieldCheckIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Record Validator"
              {...a11yProps(2)}
            />
            <Tab
              icon={<ClockIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Propagation"
              {...a11yProps(3)}
            />
            <Tab
              icon={<ChartBarIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Performance"
              {...a11yProps(4)}
            />
            <Tab
              icon={<ShieldCheckIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="DNSSEC"
              {...a11yProps(5)}
            />
            <Tab
              icon={<BugAntIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Attack Simulator"
              {...a11yProps(6)}
            />
            <Tab
              icon={<ServerIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Server Compare"
              {...a11yProps(7)}
            />
            <Tab
              icon={<DocumentArrowDownIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Export"
              {...a11yProps(8)}
            />
            <Tab
              icon={<ChartPieIcon style={{ width: 20, height: 20 }} />}
              iconPosition="start"
              label="Monitoring"
              {...a11yProps(9)}
            />
          </Tabs>
        </Box>

        <Box sx={{ p: 3 }}>
          <TabPanel value={activeTab} index={0}>
            <DNSQueryTester />
          </TabPanel>
          <TabPanel value={activeTab} index={1}>
            <DNSLookupTrace />
          </TabPanel>
          <TabPanel value={activeTab} index={2}>
            <RecordValidator />
          </TabPanel>
          <TabPanel value={activeTab} index={3}>
            <PropagationChecker />
          </TabPanel>
          <TabPanel value={activeTab} index={4}>
            <PerformanceBenchmark />
          </TabPanel>
          <TabPanel value={activeTab} index={5}>
            <DNSSECValidator />
          </TabPanel>
          <TabPanel value={activeTab} index={6}>
            <AttackSimulator />
          </TabPanel>
          <TabPanel value={activeTab} index={7}>
            <ServerComparison />
          </TabPanel>
          <TabPanel value={activeTab} index={8}>
            <ExportManager />
          </TabPanel>
          <TabPanel value={activeTab} index={9}>
            <MonitoringIntegration />
          </TabPanel>
        </Box>
      </Paper>
    </Container>
  );
};

export default DNSPlayground;