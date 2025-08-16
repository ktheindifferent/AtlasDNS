import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Grid,
  List,
  ListItem,
  Button,
  Chip,
  Alert,
  IconButton,
} from '@mui/material';
import {
  ContentCopy as Copy,
  Delete,
  Edit,
  Share,
  Info,
  TouchApp,
} from '@mui/icons-material';
import {
  PullToRefresh,
  LongPressMenu,
  PinchZoomContainer,
  SwipeableListItemExample,
  GestureHelp,
  ContextMenuItem,
} from '../components/gestures';
import { motion } from 'framer-motion';
import { Line } from 'react-chartjs-2';

const GestureDemo: React.FC = () => {
  const [refreshCount, setRefreshCount] = useState(0);
  const [lastAction, setLastAction] = useState('No action yet');
  const [showHelp, setShowHelp] = useState(false);
  const [items, setItems] = useState([
    { id: 1, title: 'DNS Zone 1', subtitle: 'example.com' },
    { id: 2, title: 'DNS Zone 2', subtitle: 'test.org' },
    { id: 3, title: 'DNS Zone 3', subtitle: 'demo.net' },
  ]);

  const handleRefresh = async () => {
    await new Promise(resolve => setTimeout(resolve, 1500));
    setRefreshCount(prev => prev + 1);
    setLastAction('Data refreshed');
  };

  const contextMenuItems: ContextMenuItem[] = [
    {
      label: 'Copy',
      icon: <Copy fontSize="small" />,
      action: () => setLastAction('Copy action triggered'),
      shortcut: 'Ctrl+C',
    },
    {
      label: 'Edit',
      icon: <Edit fontSize="small" />,
      action: () => setLastAction('Edit action triggered'),
      shortcut: 'Ctrl+E',
    },
    {
      label: 'Share',
      icon: <Share fontSize="small" />,
      action: () => setLastAction('Share action triggered'),
      shortcut: 'Ctrl+S',
      divider: true,
    },
    {
      label: 'Delete',
      icon: <Delete fontSize="small" />,
      action: () => setLastAction('Delete action triggered'),
      shortcut: 'Delete',
    },
  ];

  const chartData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    datasets: [
      {
        label: 'DNS Queries',
        data: [65, 59, 80, 81, 56, 55],
        fill: false,
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Monthly DNS Query Statistics',
      },
    },
  };

  return (
    <Container maxWidth="lg">
      <PullToRefresh onRefresh={handleRefresh}>
        <Box sx={{ py: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 2 }}>
            <TouchApp color="primary" sx={{ fontSize: 40 }} />
            <Typography variant="h4" component="h1">
              Touch Gesture Demo
            </Typography>
            <IconButton onClick={() => setShowHelp(true)} color="primary">
              <Info />
            </IconButton>
          </Box>

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              Last Action: <strong>{lastAction}</strong> | 
              Refresh Count: <strong>{refreshCount}</strong>
            </Typography>
          </Alert>

          <Grid container spacing={3}>
            {/* Pull to Refresh Demo */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Pull to Refresh
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Pull down from the top of the page to refresh data
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Chip label="Touch: Pull down" size="small" />
                    <Chip label="Keyboard: F5" size="small" variant="outlined" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Long Press Context Menu Demo */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Long Press Context Menu
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Long press or right-click the box below
                  </Typography>
                  
                  <LongPressMenu items={contextMenuItems}>
                    <Card
                      variant="outlined"
                      sx={{
                        p: 3,
                        mt: 2,
                        bgcolor: 'primary.light',
                        color: 'primary.contrastText',
                        textAlign: 'center',
                      }}
                    >
                      <Typography variant="h6">
                        Long Press Me
                      </Typography>
                      <Typography variant="body2">
                        Hold for 500ms to open menu
                      </Typography>
                    </Card>
                  </LongPressMenu>
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Chip label="Touch: Long press" size="small" />
                    <Chip label="Mouse: Right-click" size="small" variant="outlined" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Pinch to Zoom Demo */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Pinch to Zoom
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Pinch to zoom the chart below
                  </Typography>
                  
                  <Box sx={{ height: 300, mt: 2 }}>
                    <PinchZoomContainer>
                      <Line data={chartData} options={chartOptions} />
                    </PinchZoomContainer>
                  </Box>
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Chip label="Touch: Pinch" size="small" />
                    <Chip label="Double tap: Reset" size="small" />
                    <Chip label="Keyboard: Ctrl +/-" size="small" variant="outlined" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Swipeable List Items Demo */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Swipeable List Items
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Swipe left or right on list items for quick actions
                  </Typography>
                  
                  <List sx={{ mt: 2 }}>
                    {items.map((item) => (
                      <motion.div
                        key={item.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <SwipeableListItemExample
                          title={item.title}
                          subtitle={item.subtitle}
                          onEdit={() => setLastAction(`Edit ${item.title}`)}
                          onDelete={() => {
                            setItems(prev => prev.filter(i => i.id !== item.id));
                            setLastAction(`Deleted ${item.title}`);
                          }}
                          onArchive={() => setLastAction(`Archived ${item.title}`)}
                        />
                      </motion.div>
                    ))}
                  </List>
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Chip label="Swipe left: Delete" size="small" color="error" />
                    <Chip label="Swipe right: Archive" size="small" color="warning" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Gesture Shortcuts Info */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Global Gesture Shortcuts
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    These gestures work throughout the app
                  </Typography>
                  
                  <Grid container spacing={2} sx={{ mt: 1 }}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Navigation Gestures
                      </Typography>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <Chip label="Swipe between tabs" size="small" variant="outlined" />
                        <Chip label="3-finger swipe up: Dashboard" size="small" variant="outlined" />
                        <Chip label="3-finger swipe left/right: Back/Forward" size="small" variant="outlined" />
                        <Chip label="Edge swipe: Navigate back" size="small" variant="outlined" />
                      </Box>
                    </Grid>
                    
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Accessibility Features
                      </Typography>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <Chip label="All gestures have keyboard alternatives" size="small" color="success" />
                        <Chip label="Haptic feedback on actions" size="small" color="success" />
                        <Chip label="Visual feedback for all interactions" size="small" color="success" />
                        <Chip label="Screen reader compatible" size="small" color="success" />
                      </Box>
                    </Grid>
                  </Grid>
                  
                  <Button
                    variant="contained"
                    onClick={() => setShowHelp(true)}
                    sx={{ mt: 2 }}
                  >
                    View All Gestures
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Box>
      </PullToRefresh>
      
      <GestureHelp open={showHelp} onClose={() => setShowHelp(false)} />
    </Container>
  );
};

export default GestureDemo;