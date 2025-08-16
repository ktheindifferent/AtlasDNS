import React, { useState, useEffect } from 'react';
import { Box, Alert, AlertTitle, Chip } from '@mui/material';
import { WidgetConfig } from '../types';

interface AlertData {
  severity: 'error' | 'warning' | 'info' | 'success';
  title: string;
  message: string;
  timestamp?: Date;
  count?: number;
}

interface AlertWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const AlertWidget: React.FC<AlertWidgetProps> = ({ config, onUpdate }) => {
  const [alerts, setAlerts] = useState<AlertData[]>([]);

  useEffect(() => {
    const mockAlerts: AlertData[] = config.data?.alerts || [
      {
        severity: 'error',
        title: 'System Error',
        message: 'Database connection failed',
        timestamp: new Date(),
        count: 3
      },
      {
        severity: 'warning',
        title: 'Performance Warning',
        message: 'High CPU usage detected',
        timestamp: new Date(),
        count: 1
      }
    ];
    
    setAlerts(mockAlerts);
    
    if (!config.data && onUpdate) {
      onUpdate({ data: { alerts: mockAlerts } });
    }

    if (config.refreshInterval) {
      const interval = setInterval(() => {
        const severities: AlertData['severity'][] = ['error', 'warning', 'info', 'success'];
        const newAlert: AlertData = {
          severity: severities[Math.floor(Math.random() * severities.length)],
          title: `Alert ${Date.now()}`,
          message: 'New alert generated',
          timestamp: new Date(),
          count: Math.floor(Math.random() * 5) + 1
        };
        
        setAlerts(prev => [newAlert, ...prev].slice(0, 5));
        onUpdate?.({ data: { alerts: [newAlert, ...alerts].slice(0, 5) } });
      }, config.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [config.data, config.refreshInterval]);

  if (alerts.length === 0) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="info">No alerts</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 1, height: '100%', overflow: 'auto' }}>
      {alerts.map((alert, index) => (
        <Alert 
          key={index} 
          severity={alert.severity}
          sx={{ mb: 1 }}
          action={
            alert.count && alert.count > 1 ? (
              <Chip label={alert.count} size="small" />
            ) : null
          }
        >
          <AlertTitle>{alert.title}</AlertTitle>
          {alert.message}
        </Alert>
      ))}
    </Box>
  );
};

export default AlertWidget;