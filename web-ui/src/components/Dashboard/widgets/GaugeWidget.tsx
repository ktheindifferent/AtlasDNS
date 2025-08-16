import React, { useEffect, useState } from 'react';
import { Box, Typography, LinearProgress } from '@mui/material';
import { WidgetConfig } from '../types';
import { generateMockData } from '../utils';

interface GaugeData {
  value: number;
  min: number;
  max: number;
  label: string;
  unit?: string;
  thresholds?: {
    low: number;
    medium: number;
    high: number;
  };
}

interface GaugeWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const GaugeWidget: React.FC<GaugeWidgetProps> = ({ config, onUpdate }) => {
  const [data, setData] = useState<GaugeData | null>(null);

  useEffect(() => {
    const mockData = config.data || generateMockData('gauge');
    setData(mockData);
    
    if (!config.data && onUpdate) {
      onUpdate({ data: mockData });
    }

    if (config.refreshInterval) {
      const interval = setInterval(() => {
        const newData = generateMockData('gauge');
        setData(newData);
        onUpdate?.({ data: newData });
      }, config.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [config.data, config.refreshInterval]);

  if (!data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        Loading...
      </Box>
    );
  }

  const normalizedValue = ((data.value - data.min) / (data.max - data.min)) * 100;
  
  const getColor = () => {
    if (!data.thresholds) return 'primary';
    if (data.value < data.thresholds.low) return 'error';
    if (data.value < data.thresholds.medium) return 'warning';
    if (data.value < data.thresholds.high) return 'info';
    return 'success';
  };

  const getColorValue = () => {
    const color = getColor();
    switch (color) {
      case 'error': return '#f44336';
      case 'warning': return '#ff9800';
      case 'info': return '#2196f3';
      case 'success': return '#4caf50';
      default: return '#3f51b5';
    }
  };

  return (
    <Box sx={{ 
      p: 2, 
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center'
    }}>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        {data.label}
      </Typography>
      
      <Box sx={{ position: 'relative', mb: 2 }}>
        <svg viewBox="0 0 200 120" style={{ width: '100%', height: 'auto' }}>
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke="#e0e0e0"
            strokeWidth="15"
          />
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke={getColorValue()}
            strokeWidth="15"
            strokeDasharray={`${normalizedValue * 2.51} 251`}
            style={{ transition: 'stroke-dasharray 0.5s ease' }}
          />
          <text
            x="100"
            y="90"
            textAnchor="middle"
            fontSize="28"
            fontWeight="bold"
            fill={getColorValue()}
          >
            {data.value}{data.unit || ''}
          </text>
          <text
            x="100"
            y="110"
            textAnchor="middle"
            fontSize="12"
            fill="#666"
          >
            {data.min} - {data.max}
          </text>
        </svg>
      </Box>

      <LinearProgress 
        variant="determinate" 
        value={normalizedValue}
        color={getColor() as any}
        sx={{ height: 8, borderRadius: 4 }}
      />
    </Box>
  );
};

export default GaugeWidget;