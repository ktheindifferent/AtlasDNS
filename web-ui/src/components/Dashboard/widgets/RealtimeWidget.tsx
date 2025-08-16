import React, { useState, useEffect, useRef } from 'react';
import { Box, Typography, Chip, LinearProgress } from '@mui/material';
import { Line } from 'react-chartjs-2';
import io, { Socket } from 'socket.io-client';
import { WidgetConfig } from '../types';

interface RealtimeData {
  timestamp: Date;
  value: number;
  label?: string;
}

interface RealtimeWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const RealtimeWidget: React.FC<RealtimeWidgetProps> = ({ config, onUpdate }) => {
  const [data, setData] = useState<RealtimeData[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [latestValue, setLatestValue] = useState<number>(0);
  const socketRef = useRef<Socket | null>(null);
  const maxDataPoints = config.customSettings?.maxDataPoints || 20;

  useEffect(() => {
    const wsUrl = config.customSettings?.websocketUrl || 'http://localhost:3001';
    const channel = config.customSettings?.channel || `widget_${config.id}`;

    socketRef.current = io(wsUrl, {
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    socketRef.current.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      socketRef.current?.emit('subscribe', { channel, widgetId: config.id });
    });

    socketRef.current.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    });

    socketRef.current.on('data', (message: any) => {
      const newData: RealtimeData = {
        timestamp: new Date(),
        value: message.value || Math.random() * 100,
        label: message.label
      };

      setData(prev => {
        const updated = [...prev, newData];
        return updated.slice(-maxDataPoints);
      });
      
      setLatestValue(newData.value);
    });

    socketRef.current.on('error', (error: any) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    });

    const simulateData = setInterval(() => {
      if (!isConnected) {
        const newData: RealtimeData = {
          timestamp: new Date(),
          value: Math.random() * 100 + Math.sin(Date.now() / 1000) * 20,
          label: 'Simulated'
        };

        setData(prev => {
          const updated = [...prev, newData];
          return updated.slice(-maxDataPoints);
        });
        
        setLatestValue(newData.value);
      }
    }, 1000);

    return () => {
      clearInterval(simulateData);
      if (socketRef.current) {
        socketRef.current.emit('unsubscribe', { channel, widgetId: config.id });
        socketRef.current.disconnect();
      }
    };
  }, [config.id, config.customSettings, maxDataPoints]);

  const chartData = {
    labels: data.map(d => 
      d.timestamp.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      })
    ),
    datasets: [
      {
        label: 'Real-time Data',
        data: data.map(d => d.value),
        borderColor: isConnected ? '#4caf50' : '#ff9800',
        backgroundColor: isConnected ? 'rgba(76, 175, 80, 0.1)' : 'rgba(255, 152, 0, 0.1)',
        tension: 0.4,
        fill: true
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 0
    },
    scales: {
      x: {
        display: true,
        ticks: {
          maxTicksLimit: 5
        }
      },
      y: {
        display: true,
        beginAtZero: true
      }
    },
    plugins: {
      legend: {
        display: false
      }
    }
  };

  return (
    <Box sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Typography variant="h5" fontWeight="bold">
          {latestValue.toFixed(2)}
        </Typography>
        <Chip 
          label={isConnected ? 'Live' : 'Simulated'} 
          color={isConnected ? 'success' : 'warning'}
          size="small"
          variant={isConnected ? 'filled' : 'outlined'}
        />
      </Box>
      
      {data.length === 0 && (
        <LinearProgress color={isConnected ? 'success' : 'warning'} />
      )}
      
      <Box sx={{ flex: 1, position: 'relative', minHeight: 0 }}>
        {data.length > 0 && (
          <Line data={chartData} options={chartOptions} />
        )}
      </Box>
      
      <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
        {isConnected 
          ? `Connected to ${config.customSettings?.websocketUrl || 'default server'}`
          : 'Using simulated data (WebSocket not connected)'}
      </Typography>
    </Box>
  );
};

export default RealtimeWidget;