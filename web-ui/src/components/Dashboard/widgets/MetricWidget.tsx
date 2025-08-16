import React, { useEffect, useState } from 'react';
import { Box, Typography, Chip } from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon
} from '@mui/icons-material';
import { MetricData, WidgetConfig } from '../types';
import { generateMockData, formatNumber } from '../utils';

interface MetricWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const MetricWidget: React.FC<MetricWidgetProps> = ({ config, onUpdate }) => {
  const [data, setData] = useState<MetricData | null>(null);

  useEffect(() => {
    const mockData = config.data || generateMockData('metric');
    setData(mockData);
    
    if (!config.data && onUpdate) {
      onUpdate({ data: mockData });
    }

    if (config.refreshInterval) {
      const interval = setInterval(() => {
        const newData = generateMockData('metric');
        setData(newData);
        onUpdate?.({ data: newData });
      }, config.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [config.data, config.refreshInterval]);

  if (!data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          Loading...
        </Typography>
      </Box>
    );
  }

  const getTrendIcon = () => {
    switch (data.trend) {
      case 'up':
        return <TrendingUpIcon fontSize="small" />;
      case 'down':
        return <TrendingDownIcon fontSize="small" />;
      default:
        return <TrendingFlatIcon fontSize="small" />;
    }
  };

  const getTrendColor = () => {
    switch (data.trend) {
      case 'up':
        return 'success';
      case 'down':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box sx={{ 
      p: 2, 
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center'
    }}>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        {data.label}
      </Typography>
      
      <Typography variant="h3" component="div" sx={{ my: 1 }}>
        {data.unit}{typeof data.value === 'number' ? formatNumber(data.value) : data.value}
      </Typography>
      
      {data.change !== undefined && (
        <Chip
          icon={getTrendIcon()}
          label={`${data.change > 0 ? '+' : ''}${data.change.toFixed(1)}%`}
          color={getTrendColor()}
          size="small"
          variant="outlined"
        />
      )}
    </Box>
  );
};

export default MetricWidget;