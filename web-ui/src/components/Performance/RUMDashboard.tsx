import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  LinearProgress,
  Chip,
  Alert,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  Speed as SpeedIcon,
  Timer as TimerIcon,
  TouchApp as TouchAppIcon,
  ViewQuilt as ViewQuiltIcon,
  NetworkCheck as NetworkCheckIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { usePerformanceMonitor } from '../../hooks/usePerformanceMonitor';

interface MetricCardProps {
  title: string;
  value: number;
  unit: string;
  rating: 'good' | 'needs-improvement' | 'poor';
  description: string;
  icon: React.ReactNode;
  threshold: { good: number; poor: number };
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  unit,
  rating,
  description,
  icon,
  threshold,
}) => {
  const getColor = () => {
    switch (rating) {
      case 'good':
        return '#4caf50';
      case 'needs-improvement':
        return '#ff9800';
      case 'poor':
        return '#f44336';
      default:
        return '#757575';
    }
  };

  const getProgress = () => {
    if (value <= threshold.good) return (value / threshold.good) * 33;
    if (value <= threshold.poor) return 33 + ((value - threshold.good) / (threshold.poor - threshold.good)) * 33;
    return 66 + Math.min(((value - threshold.poor) / threshold.poor) * 34, 34);
  };

  return (
    <Card sx={{ height: '100%', position: 'relative' }}>
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          <Box sx={{ color: getColor(), mr: 2 }}>{icon}</Box>
          <Box flex={1}>
            <Typography variant="h6" component="div">
              {title}
            </Typography>
            <Typography variant="h4" sx={{ color: getColor(), fontWeight: 'bold' }}>
              {value.toFixed(unit === 'ms' ? 0 : 2)} {unit}
            </Typography>
          </Box>
          <Tooltip title={description}>
            <IconButton size="small">
              <InfoIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
        
        <LinearProgress
          variant="determinate"
          value={getProgress()}
          sx={{
            height: 8,
            borderRadius: 4,
            backgroundColor: '#e0e0e0',
            '& .MuiLinearProgress-bar': {
              backgroundColor: getColor(),
              borderRadius: 4,
            },
          }}
        />
        
        <Box display="flex" justifyContent="space-between" mt={1}>
          <Typography variant="caption" color="text.secondary">
            Good ≤ {threshold.good}{unit}
          </Typography>
          <Chip
            label={rating.replace('-', ' ')}
            size="small"
            sx={{
              backgroundColor: getColor(),
              color: 'white',
              textTransform: 'capitalize',
            }}
          />
          <Typography variant="caption" color="text.secondary">
            Poor ≥ {threshold.poor}{unit}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export const RUMDashboard: React.FC = () => {
  const { performanceData, budgetAlerts, memoryLeakWarning } = usePerformanceMonitor();

  const getLatestMetric = (name: string) => {
    const metrics = performanceData.webVitals.filter(m => m.name === name);
    return metrics[metrics.length - 1];
  };

  const coreWebVitals = [
    {
      name: 'LCP',
      title: 'Largest Contentful Paint',
      description: 'Measures loading performance. To provide a good user experience, LCP should occur within 2.5 seconds.',
      icon: <SpeedIcon fontSize="large" />,
      unit: 'ms',
      threshold: { good: 2500, poor: 4000 },
    },
    {
      name: 'FID',
      title: 'First Input Delay',
      description: 'Measures interactivity. To provide a good user experience, pages should have a FID of 100 milliseconds or less.',
      icon: <TouchAppIcon fontSize="large" />,
      unit: 'ms',
      threshold: { good: 100, poor: 300 },
    },
    {
      name: 'CLS',
      title: 'Cumulative Layout Shift',
      description: 'Measures visual stability. To provide a good user experience, pages should maintain a CLS of 0.1 or less.',
      icon: <ViewQuiltIcon fontSize="large" />,
      unit: '',
      threshold: { good: 0.1, poor: 0.25 },
    },
    {
      name: 'FCP',
      title: 'First Contentful Paint',
      description: 'Measures the time from page start to when the first text or image is painted.',
      icon: <TimerIcon fontSize="large" />,
      unit: 'ms',
      threshold: { good: 1800, poor: 3000 },
    },
    {
      name: 'TTFB',
      title: 'Time to First Byte',
      description: 'Measures the time it takes for a browser to receive the first byte of page content.',
      icon: <NetworkCheckIcon fontSize="large" />,
      unit: 'ms',
      threshold: { good: 600, poor: 1800 },
    },
  ];

  const getUserExperienceScore = () => {
    const metrics = coreWebVitals.slice(0, 3).map(v => getLatestMetric(v.name));
    const validMetrics = metrics.filter(m => m);
    
    if (validMetrics.length === 0) return 0;
    
    const scores = validMetrics.map(m => {
      const vital = coreWebVitals.find(v => v.name === m.name);
      if (!vital) return 0;
      
      if (m.rating === 'good') return 100;
      if (m.rating === 'needs-improvement') return 50;
      return 0;
    });
    
    return scores.reduce((a: number, b: number) => a + b, 0) / scores.length;
  };

  const experienceScore = getUserExperienceScore();

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Real User Monitoring Dashboard
      </Typography>
      
      {memoryLeakWarning && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          Potential memory leak detected! Memory usage has been consistently increasing.
        </Alert>
      )}
      
      {budgetAlerts.length > 0 && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Performance budget exceeded for: {budgetAlerts[budgetAlerts.length - 1].metric}
        </Alert>
      )}
      
      <Card sx={{ mb: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
        <CardContent>
          <Typography variant="h6" sx={{ color: 'white' }}>
            User Experience Score
          </Typography>
          <Typography variant="h2" sx={{ color: 'white', fontWeight: 'bold' }}>
            {experienceScore.toFixed(0)}%
          </Typography>
          <LinearProgress
            variant="determinate"
            value={experienceScore}
            sx={{
              height: 10,
              borderRadius: 5,
              backgroundColor: 'rgba(255, 255, 255, 0.3)',
              '& .MuiLinearProgress-bar': {
                backgroundColor: 'white',
                borderRadius: 5,
              },
            }}
          />
          <Typography variant="body2" sx={{ color: 'white', mt: 1 }}>
            Based on Core Web Vitals (LCP, FID, CLS)
          </Typography>
        </CardContent>
      </Card>
      
      <Grid container spacing={3}>
        {coreWebVitals.map((vital) => {
          const metric = getLatestMetric(vital.name);
          
          if (!metric) {
            return (
              <Grid item xs={12} sm={6} md={4} key={vital.name}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Box display="flex" alignItems="center">
                      <Box sx={{ color: '#757575', mr: 2 }}>{vital.icon}</Box>
                      <Box>
                        <Typography variant="h6">{vital.title}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Collecting data...
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            );
          }
          
          return (
            <Grid item xs={12} sm={6} md={4} key={vital.name}>
              <MetricCard
                title={vital.title}
                value={metric.value}
                unit={vital.unit}
                rating={metric.rating}
                description={vital.description}
                icon={vital.icon}
                threshold={vital.threshold}
              />
            </Grid>
          );
        })}
      </Grid>
      
      <Box mt={3}>
        <Typography variant="h6" gutterBottom>
          Performance Timeline
        </Typography>
        <Card>
          <CardContent>
            <Box sx={{ overflowX: 'auto' }}>
              {performanceData.webVitals.length > 0 ? (
                <Box sx={{ minWidth: 600, height: 200 }}>
                  {/* Timeline visualization would go here */}
                  <Typography color="text.secondary">
                    {performanceData.webVitals.length} metrics collected
                  </Typography>
                </Box>
              ) : (
                <Typography color="text.secondary">
                  No performance data collected yet. Metrics will appear as users interact with the application.
                </Typography>
              )}
            </Box>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
};